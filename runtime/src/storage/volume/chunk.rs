//! Per-chunk bookkeeping: run geometry, chunk checksum states, the dense
//! chunk map, and the committed-CRC read cache.
//!
//! Chunks and blocks coincide in this format (checksum granularity ==
//! tearing granularity), so these types are the substrate every data path
//! plans against: [`RunMeta`] places logical bytes physically, [`ChunkMap`]
//! tracks each backed chunk's checksum state and verified bit, and
//! [`CrcCache`] holds committed values paged in from the blob's checksum
//! extents (see `paging`). Everything here is pure bookkeeping — no I/O.

use super::{
    alloc::{block_align, Extent},
    BLOCK,
};
use commonware_utils::bitmap::BitMap;
use std::collections::{BTreeMap, BTreeSet};

/// The chunk index containing logical byte `offset`. Chunks and blocks
/// coincide in this format (checksum granularity == tearing granularity).
pub(super) const fn chunk_of(offset: u64) -> u64 {
    offset / BLOCK
}

/// A run in RAM: logical bytes `[logical, logical + len)` live at
/// `[physical, physical + len)`. Starts are BLOCK-aligned; `len` is exact
/// (a run's final block may be partially written). `capacity` is the
/// allocated extent length (`>= block_align(len)`), into which the run may
/// grow in place. `born` is the seq of the commit that will first reference
/// this extent (freeze-rule exemption for post-snapshot extents).
#[derive(Clone, Copy, Debug)]
pub(super) struct RunMeta {
    pub physical: u64,
    pub len: u64,
    pub capacity: u64,
    pub born: u64,
}

impl RunMeta {
    /// The extent backing this run (its whole allocated capacity).
    pub const fn extent(&self) -> Extent {
        Extent {
            offset: self.physical,
            len: self.capacity,
        }
    }
}

/// Per-chunk checksum state: the CRC32C over the chunk's written span, and
/// whether the span's on-disk bytes are known to match it.
///
/// The CRC is either computed ([`ChunkCrc::Ready`]) or deferred
/// ([`ChunkCrc::Pending`]): a pending chunk's authoritative span bytes live
/// in the blob's overlay (see [`BlobInner::overlay`](super::state::BlobInner::overlay)), written through to
/// disk but not yet checksummed. Deferral amortizes repeated sub-block
/// rewrites of the same chunk: the CRC is computed once — at snapshot
/// capture, overlay eviction, or resize — instead of on every write. Reads
/// of a pending chunk are served from the overlay directly.
///
/// `verified` is set once per process lifetime: by a read that checked the
/// chunk, or by construction when every byte under the CRC came from process
/// memory (write payloads, gap zeros, tail buffers, overlay entries, or a
/// COW read-back that was itself checked against the old CRC at assembly).
/// Disk read-backs spliced into CRC assembly (prefix/suffix sourcing, resize
/// boundary recomputation) are likewise checked against the chunk's expected
/// CRC, so the assembled chunk inherits that CRC's provenance — unverified
/// only when the expected value was resident unverified state. A pending
/// chunk carries the bit its finalized CRC will have. Verified chunks are
/// read exactly (no span widening) with no CRC pass. The bit travels with
/// the entry: rewrites and relocations re-decide it at publish, and dropping
/// the entry drops it. All chunks start unverified at hydration except the
/// frontier chunk, which hydration itself verifies.
#[derive(Clone, Copy, Debug)]
pub(super) struct ChunkState {
    pub crc: ChunkCrc,
    pub verified: bool,
}

/// A chunk's CRC32C: computed, deferred to the blob's overlay, or left on
/// disk in the blob's committed checksum extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChunkCrc {
    /// CRC32C over the chunk's written span.
    Ready(u32),
    /// Not computed yet: the chunk's overlay entry holds its authoritative
    /// span bytes (every pending chunk is overlay-resident).
    Pending,
    /// Not resident: the chunk is untouched since hydration, so its exact
    /// CRC is the committed value in the blob's checksum extents on disk,
    /// loaded on demand (see [`load_committed_page`](super::paging::load_committed_page)). Residency is sticky
    /// (every write installs the CRCs it computes and nothing revokes
    /// them), so an unloaded chunk's committed value is immutable: delta
    /// commits keep untouched values by reference, and a full rewrite
    /// re-encodes them unchanged.
    Unloaded,
}

/// Chunks per CRC page: the dense store's page granularity and the unit
/// loaded from a committed checksum extent (1024 chunks of 4 bytes = one
/// [`BLOCK`] of values, mirroring the overlay's 1024-chunk pattern).
pub(super) const CRC_PAGE_CHUNKS: u64 = 1024;

/// Resident-mask words per CRC page.
const CRC_PAGE_WORDS: usize = (CRC_PAGE_CHUNKS / 64) as usize;

/// One page of resident CRC values within a [`Segment`].
#[derive(Debug)]
struct CrcPage {
    /// Bit `i` set: `values[i]` holds the CRC of the page's chunk `i`.
    resident: [u64; CRC_PAGE_WORDS],
    /// Value slots for the page's covered chunks, sized to the segment's
    /// coverage of the page and growing with it.
    values: Vec<u32>,
}

/// One contiguous backed chunk range's dense state: an unverified bit per
/// chunk, plus pages of resident CRC values allocated only where a value
/// is actually held. A fully hydrated-and-verified range therefore costs
/// one bit per chunk. A fully process-written range costs ~4.2 bytes per
/// chunk.
#[derive(Debug)]
struct Segment {
    /// Chunk count: the segment spans `[start, start + len)` where
    /// `start` is its key in [`ChunkMap::segments`].
    len: u64,
    /// Chunks below this segment-relative index were pruned out of
    /// coverage: dead slots whose bits and values are cleared and never
    /// consulted (the segment covers `[start + lead, start + len)`).
    /// Monotonic, and always < `len` (a fully dead segment is removed).
    lead: u64,
    /// Per-chunk unverified bits (set = unverified), so an all-verified
    /// span is provable word-at-a-time (see [`ChunkMap::span_verified`]).
    unverified: BitMap,
    /// Resident CRC values in pages of [`CRC_PAGE_CHUNKS`] chunks.
    pages: Vec<Option<Box<CrcPage>>>,
}

impl Segment {
    /// A segment of `len` chunks, all unverified with no resident values.
    fn new(len: u64) -> Self {
        Self {
            len,
            lead: 0,
            unverified: BitMap::ones(len),
            pages: (0..len.div_ceil(CRC_PAGE_CHUNKS)).map(|_| None).collect(),
        }
    }

    /// Value slots page `page` covers in a segment of `len` chunks.
    fn page_cover(len: u64, page: usize) -> usize {
        (len - page as u64 * CRC_PAGE_CHUNKS).min(CRC_PAGE_CHUNKS) as usize
    }

    /// The resident CRC of segment-relative chunk `rel`, if any.
    fn resident(&self, rel: u64) -> Option<u32> {
        let page = self.pages[(rel / CRC_PAGE_CHUNKS) as usize].as_deref()?;
        let slot = (rel % CRC_PAGE_CHUNKS) as usize;
        (page.resident[slot / 64] >> (slot % 64) & 1 == 1).then(|| page.values[slot])
    }

    /// Install a resident CRC for segment-relative chunk `rel`.
    fn set_resident(&mut self, rel: u64, value: u32) {
        let len = self.len;
        let idx = (rel / CRC_PAGE_CHUNKS) as usize;
        let page = self.pages[idx].get_or_insert_with(|| {
            Box::new(CrcPage {
                resident: [0; CRC_PAGE_WORDS],
                values: vec![0; Self::page_cover(len, idx)],
            })
        });
        let slot = (rel % CRC_PAGE_CHUNKS) as usize;
        page.resident[slot / 64] |= 1 << (slot % 64);
        page.values[slot] = value;
    }

    /// Drop the resident CRC of segment-relative chunk `rel`, if any.
    fn clear_resident(&mut self, rel: u64) {
        if let Some(page) = self.pages[(rel / CRC_PAGE_CHUNKS) as usize].as_deref_mut() {
            let slot = (rel % CRC_PAGE_CHUNKS) as usize;
            page.resident[slot / 64] &= !(1 << (slot % 64));
        }
    }

    /// Append one chunk with `state`, whose CRC must not be
    /// [`ChunkCrc::Unloaded`]. Pending-set membership is the caller's.
    fn push(&mut self, state: ChunkState) {
        self.len += 1;
        self.unverified.push(!state.verified);
        let idx = ((self.len - 1) / CRC_PAGE_CHUNKS) as usize;
        if idx == self.pages.len() {
            self.pages.push(None);
        }
        // Keep an allocated page's slot coverage in step with the segment
        // (its new slot starts non-resident: truncation may have left a
        // stale bit behind).
        if let Some(page) = self.pages[idx].as_deref_mut() {
            if page.values.len() < Self::page_cover(self.len, idx) {
                page.values.push(0);
            }
            let slot = ((self.len - 1) % CRC_PAGE_CHUNKS) as usize;
            page.resident[slot / 64] &= !(1 << (slot % 64));
        }
        if let ChunkCrc::Ready(value) = state.crc {
            self.set_resident(self.len - 1, value);
        }
    }

    /// Kill the first `lead` chunks (prefix prune): their unverified bits
    /// clear (returning how many were set), their resident values drop,
    /// and coverage becomes `[start + lead, start + len)`. O(pruned).
    fn drop_front(&mut self, lead: u64) -> u64 {
        debug_assert!(self.lead < lead && lead < self.len);
        let mut cleared = 0;
        for rel in self.lead..lead {
            if self.unverified.get(rel) {
                self.unverified.set(rel, false);
                cleared += 1;
            }
        }
        // Pages wholly dead drop; the page containing the new lead clears
        // its dead resident bits (values remain, never consulted).
        for idx in (self.lead / CRC_PAGE_CHUNKS) as usize..(lead / CRC_PAGE_CHUNKS) as usize {
            self.pages[idx] = None;
        }
        for rel in (lead / CRC_PAGE_CHUNKS * CRC_PAGE_CHUNKS).max(self.lead)..lead {
            self.clear_resident(rel);
        }
        self.lead = lead;
        cleared
    }

    /// Shrink to `new_len` chunks (0 < `new_len` < `len`).
    fn truncate(&mut self, new_len: u64) {
        debug_assert!(0 < new_len && new_len < self.len);
        self.unverified.truncate(new_len);
        let pages = new_len.div_ceil(CRC_PAGE_CHUNKS) as usize;
        self.pages.truncate(pages);
        if let Some(page) = self.pages[pages - 1].as_deref_mut() {
            let keep = Self::page_cover(new_len, pages - 1);
            page.values.truncate(keep);
            // Clear the resident bits of the dropped slots.
            let word = keep / 64;
            let partial = !keep.is_multiple_of(64);
            if partial {
                page.resident[word] &= (1u64 << (keep % 64)) - 1;
            }
            for w in &mut page.resident[word + usize::from(partial)..] {
                *w = 0;
            }
        }
        self.len = new_len;
    }
}

/// Per-chunk checksum state over every backed chunk, stored densely: one
/// [`Segment`] per contiguous backed chunk range, with running counts of
/// the chunks that are unverified or pending. The counts let a read prove
/// "every backed chunk is verified with a ready CRC" in O(1) — the common
/// steady state — without walking anything, and the per-segment unverified
/// bits prove the same for one requested span word-at-a-time (see
/// [`Self::span_verified`]). All mutation goes through
/// methods that keep the counts exact.
///
/// A chunk's CRC is resident when it was computed this process, and a
/// covered chunk without one reports [`ChunkCrc::Unloaded`] (see there).
/// Pending
/// chunks are tracked in a small side set (they are overlay-resident, so
/// at most `OVERLAY_CHUNKS`, see `state`), which overrides any stale resident value.
#[derive(Debug, Default)]
pub(super) struct ChunkMap {
    /// Dense state per contiguous backed chunk range, keyed by first
    /// chunk. Segments never overlap. Ranges created out of order may
    /// touch without merging (adjacent segments read exactly like one).
    segments: BTreeMap<u64, Segment>,
    /// Chunks with a pending (deferred) CRC.
    pending: BTreeSet<u64>,
    /// Chunks with `verified == false`.
    unverified: u64,
}

impl ChunkMap {
    /// Whether every backed chunk is verified with a ready CRC.
    pub fn all_verified(&self) -> bool {
        self.unverified == 0 && self.pending.is_empty()
    }

    pub fn get(&self, chunk: u64) -> Option<ChunkState> {
        let (&start, seg) = self.segments.range(..=chunk).next_back()?;
        let rel = chunk
            .checked_sub(start)
            .filter(|&r| r < seg.len && r >= seg.lead)?;
        Some(ChunkState {
            crc: self.crc_of(seg, rel, chunk),
            verified: !seg.unverified.get(rel),
        })
    }

    /// Whether every chunk in `[first, last]` is covered and verified with
    /// no pending CRC (a pending chunk's overlay is authoritative, so its
    /// disk bytes may not be served). Word-at-a-time over the unverified
    /// bits: the check costs O(span/64) with no per-chunk state lookups.
    pub fn span_verified(&self, first: u64, last: u64) -> bool {
        if !self.pending.is_empty() && self.pending.range(first..=last).next().is_some() {
            return false;
        }
        let start = self
            .segments
            .range(..=first)
            .next_back()
            .map_or(first, |(&s, _)| s);
        let mut next = first;
        for (&s, seg) in self.segments.range(start..=last) {
            if s > next {
                return false;
            }
            let end = s + seg.len;
            if end <= next {
                continue;
            }
            // Pruned lead slots are not covered (their cleared bits must
            // not prove them verified).
            if next < s + seg.lead {
                return false;
            }
            if !seg.unverified.is_unset(next - s..(last + 1).min(end) - s) {
                return false;
            }
            next = end;
            if next > last {
                return true;
            }
        }
        false
    }

    /// The CRC state of `chunk` at segment-relative index `rel` of `seg`.
    fn crc_of(&self, seg: &Segment, rel: u64, chunk: u64) -> ChunkCrc {
        debug_assert!(rel >= seg.lead, "pruned chunk consulted");
        if !self.pending.is_empty() && self.pending.contains(&chunk) {
            return ChunkCrc::Pending;
        }
        seg.resident(rel)
            .map_or(ChunkCrc::Unloaded, ChunkCrc::Ready)
    }

    /// The states of every covered chunk in `[first, last]`, ascending.
    pub fn iter_range(
        &self,
        first: u64,
        last: u64,
    ) -> impl Iterator<Item = (u64, ChunkState)> + '_ {
        let start = self
            .segments
            .range(..=first)
            .next_back()
            .map_or(first, |(&s, _)| s);
        self.segments
            .range(start..=last)
            .flat_map(move |(&s, seg)| {
                let lo = first.max(s + seg.lead);
                let hi = last.min(s + seg.len - 1);
                (lo..=hi).map(move |chunk| {
                    let rel = chunk - s;
                    (
                        chunk,
                        ChunkState {
                            crc: self.crc_of(seg, rel, chunk),
                            verified: !seg.unverified.get(rel),
                        },
                    )
                })
            })
    }

    /// Insert or replace a chunk's state (a known CRC state, never
    /// [`ChunkCrc::Unloaded`] — only hydration seeds unloaded chunks).
    pub fn insert(&mut self, chunk: u64, state: ChunkState) {
        debug_assert!(
            state.crc != ChunkCrc::Unloaded,
            "insert carries a known CRC"
        );
        if let Some((&start, seg)) = self.segments.range_mut(..=chunk).next_back() {
            let rel = chunk - start;
            if rel < seg.len {
                debug_assert!(rel >= seg.lead, "write below the pruned floor");
                // Replace in place.
                match (seg.unverified.get(rel), state.verified) {
                    (false, false) => self.unverified += 1,
                    (true, true) => self.unverified -= 1,
                    _ => {}
                }
                seg.unverified.set(rel, !state.verified);
                match state.crc {
                    ChunkCrc::Ready(value) => {
                        self.pending.remove(&chunk);
                        seg.set_resident(rel, value);
                    }
                    ChunkCrc::Pending => {
                        self.pending.insert(chunk);
                        seg.clear_resident(rel);
                    }
                    ChunkCrc::Unloaded => unreachable!("asserted above"),
                }
                return;
            }
            if rel == seg.len {
                // Extend the segment (coverage grows contiguously).
                seg.push(state);
                if !state.verified {
                    self.unverified += 1;
                }
                if state.crc == ChunkCrc::Pending {
                    self.pending.insert(chunk);
                }
                return;
            }
        }
        // A new backed range.
        let mut seg = Segment::new(0);
        seg.push(state);
        self.segments.insert(chunk, seg);
        if !state.verified {
            self.unverified += 1;
        }
        if state.crc == ChunkCrc::Pending {
            self.pending.insert(chunk);
        }
    }

    /// Mark a chunk verified, guarded on its CRC still being the one the
    /// caller checked its bytes against. Pending chunks were rewritten
    /// since the check, and resident values must match. An unloaded
    /// chunk's committed value is immutable (residency is sticky), so it
    /// is necessarily the value the caller loaded and checked.
    pub fn mark_verified(&mut self, chunk: u64, crc: u32) {
        let Some((&start, seg)) = self.segments.range_mut(..=chunk).next_back() else {
            return;
        };
        let rel = chunk - start;
        if rel >= seg.len || rel < seg.lead || !seg.unverified.get(rel) {
            return;
        }
        if !self.pending.is_empty() && self.pending.contains(&chunk) {
            return;
        }
        if seg.resident(rel).is_some_and(|value| value != crc) {
            return;
        }
        seg.unverified.set(rel, false);
        self.unverified -= 1;
    }

    /// Mark a chunk verified unconditionally (hydration, whose own loads
    /// establish the bit).
    pub fn set_verified(&mut self, chunk: u64) {
        let Some((&start, seg)) = self.segments.range_mut(..=chunk).next_back() else {
            return;
        };
        let rel = chunk - start;
        if rel < seg.len && rel >= seg.lead && seg.unverified.get(rel) {
            seg.unverified.set(rel, false);
            self.unverified -= 1;
        }
    }

    /// Defer a resident chunk's CRC to its (just spliced) overlay entry.
    pub fn make_pending(&mut self, chunk: u64) {
        let (&start, seg) = self
            .segments
            .range_mut(..=chunk)
            .next_back()
            .expect("resident chunk has crc");
        let rel = chunk - start;
        assert!(rel < seg.len && rel >= seg.lead, "resident chunk has crc");
        if self.pending.insert(chunk) {
            seg.clear_resident(rel);
        }
    }

    /// Finalize a chunk's pending CRC from its span content (computed only
    /// when the chunk is in fact pending).
    pub fn finalize(&mut self, chunk: u64, crc: impl FnOnce() -> u32) {
        if !self.pending.remove(&chunk) {
            return;
        }
        let (&start, seg) = self
            .segments
            .range_mut(..=chunk)
            .next_back()
            .expect("pending chunk is covered");
        seg.set_resident(chunk - start, crc());
    }

    pub fn clear(&mut self) {
        self.segments.clear();
        self.pending.clear();
        self.unverified = 0;
    }

    /// Drop every chunk beyond `last_kept` (shrink).
    pub fn truncate(&mut self, last_kept: u64) {
        drop(self.pending.split_off(&(last_kept + 1)));
        for (_, seg) in self.segments.split_off(&(last_kept + 1)) {
            self.unverified -= seg.unverified.count_ones();
        }
        if let Some((&start, seg)) = self.segments.range_mut(..=last_kept).next_back() {
            let keep = last_kept + 1 - start;
            if keep < seg.len {
                for rel in keep..seg.len {
                    if seg.unverified.get(rel) {
                        self.unverified -= 1;
                    }
                }
                seg.truncate(keep);
            }
        }
    }

    /// Drop every chunk below `first_kept` (prefix prune): pending
    /// membership and resident values go, cleared unverified bits leave
    /// the running count, and a straddling segment keeps its suffix in
    /// place behind a dead lead — O(pruned), no re-keying.
    pub fn truncate_front(&mut self, first_kept: u64) {
        self.pending = self.pending.split_off(&first_kept);
        let mut dead: Vec<u64> = Vec::new();
        for (&start, seg) in self.segments.range_mut(..first_kept) {
            if start + seg.len <= first_kept {
                dead.push(start);
            } else if start + seg.lead < first_kept {
                self.unverified -= seg.drop_front(first_kept - start);
            }
        }
        for start in dead {
            let seg = self.segments.remove(&start).expect("listed");
            self.unverified -= seg.unverified.count_ones();
        }
    }

    /// Seed dense state for every chunk covered by `runs` (hydration): all
    /// unverified, with CRCs left on disk ([`ChunkCrc::Unloaded`]).
    pub fn seed(&mut self, runs: &BTreeMap<u64, RunMeta>) {
        debug_assert!(self.segments.is_empty(), "seed into an empty map");
        let mut open: Option<(u64, u64)> = None;
        for (&logical, run) in runs {
            let lo = chunk_of(logical);
            let hi = chunk_of(logical + run.len - 1);
            match &mut open {
                // Runs never share a chunk, but adjacent runs may cover
                // adjacent chunks: coalesce into one segment.
                Some((_, end)) if lo <= *end + 1 => *end = hi,
                _ => {
                    if let Some((s, e)) = open.replace((lo, hi)) {
                        self.seed_segment(s, e);
                    }
                }
            }
        }
        if let Some((s, e)) = open {
            self.seed_segment(s, e);
        }
    }

    /// Seed one all-unverified segment covering chunks `[first, last]`.
    fn seed_segment(&mut self, first: u64, last: u64) {
        let len = last - first + 1;
        self.segments.insert(first, Segment::new(len));
        self.unverified += len;
    }

    /// Whether any covered chunk in `[from, end)` lacks a resident CRC
    /// (its value lives only in the committed checksum extents on disk).
    /// Pending chunks count as resident: their value is derivable from the
    /// overlay. Word-at-a-time, so a fully resident blob scans
    /// chunks/64 words.
    pub fn has_unloaded(&self, from: u64, end: u64) -> bool {
        for (&start, seg) in &self.segments {
            if start >= end {
                break;
            }
            let cover = (end - start).min(seg.len);
            // Slots below the scan start and below the dead lead are not
            // consulted.
            let skip = seg.lead.max(from.saturating_sub(start));
            for (idx, page) in seg.pages.iter().enumerate() {
                let base = idx as u64 * CRC_PAGE_CHUNKS;
                if base >= cover {
                    break;
                }
                if base + CRC_PAGE_CHUNKS <= skip {
                    continue;
                }
                let low = (skip.saturating_sub(base).min(CRC_PAGE_CHUNKS)) as usize;
                let slots = ((cover - base).min(CRC_PAGE_CHUNKS)) as usize;
                if low >= slots {
                    continue;
                }
                let Some(page) = page.as_deref() else {
                    // An unallocated page holds no values. Only its pending
                    // chunks (overlay-resident) are covered elsewhere.
                    let lo = start + base + low as u64;
                    let hi = start + base + slots as u64;
                    if self.pending.range(lo..hi).count() < slots - low {
                        return true;
                    }
                    continue;
                };
                for word in low / 64..slots.div_ceil(64) {
                    let mut covered = if (word + 1) * 64 <= slots {
                        u64::MAX
                    } else {
                        (1u64 << (slots % 64)) - 1
                    };
                    if word * 64 < low {
                        covered &= !((1u64 << (low % 64)) - 1);
                    }
                    let mut missing = !page.resident[word] & covered;
                    if missing == 0 {
                        continue;
                    }
                    if self.pending.is_empty() {
                        return true;
                    }
                    while missing != 0 {
                        let bit = missing.trailing_zeros() as u64;
                        let chunk = start + base + word as u64 * 64 + bit;
                        if !self.pending.contains(&chunk) {
                            return true;
                        }
                        missing &= missing - 1;
                    }
                }
            }
        }
        false
    }

    /// Assert the running counts against a full recount (tests only).
    #[cfg(test)]
    pub fn audit(&self) {
        let mut unverified = 0;
        let mut pending = 0;
        for (&start, seg) in &self.segments {
            assert_eq!(
                seg.unverified.len(),
                seg.len,
                "unverified bitmap sized to segment"
            );
            assert!(seg.lead < seg.len, "fully dead segment retained");
            for rel in 0..seg.lead {
                assert!(!seg.unverified.get(rel), "dead slot counted unverified");
                assert!(seg.resident(rel).is_none(), "dead slot holds a value");
                assert!(!self.pending.contains(&(start + rel)), "dead slot pending");
            }
            for (_, state) in self.iter_range(start, start + seg.len - 1) {
                if !state.verified {
                    unverified += 1;
                }
                if state.crc == ChunkCrc::Pending {
                    pending += 1;
                }
            }
        }
        for &chunk in &self.pending {
            let state = self.get(chunk).expect("pending chunk is covered");
            assert_eq!(state.crc, ChunkCrc::Pending, "pending set is authoritative");
        }
        assert_eq!(
            (self.unverified, self.pending.len()),
            (unverified, pending),
            "chunk counts drifted"
        );
    }
}

/// Cap on a blob's cached committed-CRC pages (16 pages of 1024 values is
/// 64 KiB, covering 64 MiB of data). A page is needed once per chunk
/// lifetime — a verified chunk never consults its CRC again — so the cache
/// only has to ride out the current read burst (a sequential scan reuses
/// one page for 1024 consecutive chunks).
const CRC_CACHE_PAGES: usize = 16;

/// Committed CRC values loaded from the blob's checksum extents for
/// verification, cached in pages with LRU stamps (the overlay's pattern).
///
/// Entries serve chunks without a resident CRC (residency always wins), so
/// entries never need invalidation: an unloaded chunk's committed value is
/// immutable (see [`ChunkCrc::Unloaded`]), and values cached for chunks
/// that later became resident or uncovered are simply never consulted.
#[derive(Debug, Default)]
pub(super) struct CrcCache {
    clock: u64,
    /// Loaded windows keyed by page index (chunk / [`CRC_PAGE_CHUNKS`]).
    pages: BTreeMap<u64, CachedCrcs>,
}

/// One cached window: committed values for chunks `[first, first + len)`,
/// the intersection of a page with the checksum ref it was loaded from.
#[derive(Debug)]
struct CachedCrcs {
    stamp: u64,
    first: u64,
    values: Vec<u32>,
}

impl CrcCache {
    /// The cached committed CRC of `chunk`, refreshing its page's LRU
    /// stamp.
    pub fn get(&mut self, chunk: u64) -> Option<u32> {
        self.clock += 1;
        let stamp = self.clock;
        let page = self.pages.get_mut(&(chunk / CRC_PAGE_CHUNKS))?;
        page.stamp = stamp;
        let rel = chunk.checked_sub(page.first)?;
        page.values.get(rel as usize).copied()
    }

    /// Insert or replace the window starting at chunk `first`, evicting
    /// the least-recently-used page beyond the cap.
    pub fn insert(&mut self, first: u64, values: Vec<u32>) {
        self.clock += 1;
        let stamp = self.clock;
        self.pages.insert(
            first / CRC_PAGE_CHUNKS,
            CachedCrcs {
                stamp,
                first,
                values,
            },
        );
        if self.pages.len() > CRC_CACHE_PAGES {
            let lru = self
                .pages
                .iter()
                .min_by_key(|(_, page)| page.stamp)
                .map(|(&page, _)| page)
                .expect("cache is nonempty");
            self.pages.remove(&lru);
        }
    }
}

/// Merge adjacent runs that are logically AND physically contiguous with no
/// padding gap (the earlier run's written length fills its extent exactly,
/// so the later run's extent begins where the earlier run's data ends).
///
/// A merged run references the same physical bytes as its components — no
/// extent is freed or allocated — and keeps the final component's spare
/// capacity as its growth room. `born` becomes the minimum (oldest) of the
/// components, which never widens the freeze-rule exemption. Callers must
/// still guarantee every run is frozen (born <= the current snapshot seq),
/// since a young component would silently lose its exemption otherwise.
/// Holes are never crossed: they break logical contiguity by definition.
pub(super) fn merge_frozen_runs(runs: &mut BTreeMap<u64, RunMeta>) {
    /// Whether `run` at `logical` extends `head` (at `head_logical`) with
    /// logical and physical contiguity and no padding gap in `head`.
    const fn extends(head_logical: u64, head: &RunMeta, logical: u64, run: &RunMeta) -> bool {
        head_logical + head.len == logical
            && head.physical + head.len == run.physical
            && head.capacity == head.len
    }

    // Common case: nothing to merge (coalesced by a previous pass). One
    // borrowed scan proves it without rebuilding the map.
    if !runs
        .iter()
        .zip(runs.iter().skip(1))
        .any(|((&l0, r0), (&l1, r1))| extends(l0, r0, l1, r1))
    {
        return;
    }

    let mut head: Option<(u64, RunMeta)> = None;
    for (logical, run) in std::mem::take(runs) {
        match &mut head {
            Some((head_logical, merged)) if extends(*head_logical, merged, logical, &run) => {
                merged.len += run.len;
                merged.capacity += run.capacity;
                merged.born = merged.born.min(run.born);
                debug_assert!(
                    merged.capacity >= block_align(merged.len),
                    "merged capacity below block-aligned length"
                );
            }
            _ => {
                if let Some((l, r)) = head.replace((logical, run)) {
                    runs.insert(l, r);
                }
            }
        }
    }
    if let Some((l, r)) = head {
        runs.insert(l, r);
    }
}
