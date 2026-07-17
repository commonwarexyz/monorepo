//! Volume state and data paths (write, read, resize).
//!
//! Locking:
//! - `State` and each blob's `BlobInner` sit behind synchronous mutexes,
//!   never held across an await.
//! - Each blob has an async `write_lock` serializing its mutations (and the
//!   commit snapshotter) across inner I/O — this keeps chunk CRC state
//!   coherent with issued bytes. Under it, writers interleave brief
//!   state-lock sections with I/O freely.
//! - Readers take no locks across I/O: they snapshot backing + checksum
//!   state (per-chunk CRC and verified bit) and a relocation `generation`,
//!   read, verify what needs verifying, and retry if the generation moved.
//!   Chunks with a deferred (pending) CRC are served from the blob's
//!   in-memory overlay under the state lock instead of from disk.
//!   Chunks already verified this process are read exactly and skip the CRC
//!   pass, so the generation is re-checked after the read (a relocated
//!   extent may have been recycled mid-read). Unverified chunks are read as
//!   whole block-aligned spans — coalesced with adjacent bytes into one
//!   inner read — and verified in passing, so every read doubles as
//!   verification progress. In-place rewrites (uncommitted bytes, young
//!   extents) move no generation, so on a mismatch with an unchanged
//!   generation the reader briefly takes the write lock and re-verifies the
//!   quiesced chunk before reporting corruption. Extent reuse or an
//!   in-place rewrite under an in-flight read causes a retry, never a false
//!   corruption report.
//! - Expected CRCs load lazily: hydration seeds chunk state without values
//!   (see [`ChunkCrc::Unloaded`]), and the first read to verify a chunk
//!   loads the covering page from the blob's committed checksum extents —
//!   the extent's guard CRC is verified on the first touch of each ref —
//!   into a bounded per-blob cache. A fully verified blob therefore holds
//!   bitmaps, not its checksum array.
//!
//! Write placement follows the freeze rule (see module docs): bytes covered
//! by the last confirmed table or the in-flight snapshot are never rewritten
//! in place — writes touching them relocate the chunk (copy-on-write).
//! Chunks whose backing extent was allocated after the last snapshot are
//! exempt (invisible to every durable table), as are bytes at or beyond the
//! freeze boundary (appends into the shared tail chunk; the shadow block
//! covers its frozen prefix against tearing).

use super::{
    alloc::{block_align, Extent},
    layout::{ChecksumRef, Entry},
    BLOCK,
};
use crate::{Blob as _, BufferPool, Error, IoBuf, IoBufs, IoBufsMut};
use bytes::{BufMut as _, Bytes};
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;
use commonware_utils::{
    bitmap::BitMap,
    sync::{AsyncMutex, Mutex},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

/// Log2 of [`BLOCK`].
pub(super) const BLOCK_BITS: u32 = BLOCK.trailing_zeros();

/// Per-blob verification-chunk geometry: a chunk — the unit of checksum
/// coverage, read verification, and delta manifests — spans
/// `BLOCK << group` bytes (`group` fixed at blob creation, see
/// [`super::layout::Entry::group`]). Blocks remain the physical tear,
/// alignment, and allocation granularity. Geometry invariant: every run's
/// logical start is chunk-aligned and every run's capacity is a whole
/// number of chunks, so each chunk is backed by (a contiguous slice of)
/// exactly one run and its written span is contiguous from the chunk base.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Geometry {
    /// Log2 of blocks per chunk (0 = the [`BLOCK`] default).
    pub group: u8,
}

/// The largest verification group a blob may request, as log2 of blocks
/// per chunk (2^8 blocks = 1 MiB): bounds the tail buffer, the first-touch
/// read amplification, and COW copies.
const MAX_GROUP: u8 = 8;

impl Geometry {
    /// Derive a blob's geometry from its creation options.
    ///
    /// # Panics
    ///
    /// Panics if the requested verification group is not a power-of-two
    /// multiple of [`BLOCK`] of at most `BLOCK << MAX_GROUP` (a caller
    /// contract: the hint is a compile-time constant of the structure
    /// configuring it).
    pub fn from_options(options: &crate::BlobOptions) -> Self {
        let Some(bytes) = options.verification_group else {
            return Self::default();
        };
        assert!(
            bytes.is_power_of_two() && (BLOCK..=BLOCK << MAX_GROUP).contains(&bytes),
            "verification group must be a power-of-two multiple of {BLOCK} at most {}: {bytes}",
            BLOCK << MAX_GROUP
        );
        Self {
            group: (bytes / BLOCK).trailing_zeros() as u8,
        }
    }

    /// The chunk size in bytes.
    pub const fn chunk_size(self) -> u64 {
        BLOCK << self.group
    }

    /// The chunk index containing logical byte `offset`.
    pub const fn chunk_of(self, offset: u64) -> u64 {
        offset >> (BLOCK_BITS + self.group as u32)
    }

    /// Round `len` up to a whole number of chunks.
    pub const fn chunk_align(self, len: u64) -> u64 {
        len.div_ceil(self.chunk_size()) * self.chunk_size()
    }
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

/// Per-chunk checksum state: the CRC32C over the chunk's written span, and
/// whether the span's on-disk bytes are known to match it.
///
/// The CRC is either computed ([`ChunkCrc::Ready`]) or deferred
/// ([`ChunkCrc::Pending`]): a pending chunk's authoritative span bytes live
/// in the blob's overlay (see [`BlobInner::overlay`]), written through to
/// disk but not yet checksummed. Deferral amortizes repeated sub-block
/// rewrites of the same chunk: the CRC is computed once — at snapshot
/// capture, overlay eviction, or resize — instead of on every write. Reads
/// of a pending chunk are served from the overlay directly.
///
/// `verified` is set once per process lifetime: by a read that checked the
/// chunk, or by construction when every byte under the CRC came from process
/// memory (write payloads, gap zeros, tail buffers, overlay entries, or a
/// COW read-back that was itself checked against the old CRC at assembly).
/// Chunks whose CRC assembly spliced in unchecked disk read-backs (partial
/// in-place prefix/suffix read-backs, resize boundary recomputation) stay
/// unverified, so their first read still runs the full check. A pending
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
    /// loaded on demand (see [`load_committed_page`]). Residency is sticky
    /// (every write installs the CRCs it computes and nothing revokes
    /// them), so an unloaded chunk's committed value is immutable: delta
    /// commits keep untouched values by reference, and a full rewrite
    /// re-encodes them unchanged.
    Unloaded,
}

/// Chunks per CRC page: the dense store's page granularity and the unit
/// loaded from a committed checksum extent (1024 chunks of 4 bytes = one
/// [`BLOCK`] of values, mirroring the overlay's 1024-chunk pattern).
const CRC_PAGE_CHUNKS: u64 = 1024;

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
    /// Chunk count: the segment covers `[start, start + len)` where
    /// `start` is its key in [`ChunkMap::segments`].
    len: u64,
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
/// at most [`OVERLAY_CHUNKS`]), which overrides any stale resident value.
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
        let rel = chunk.checked_sub(start).filter(|&r| r < seg.len)?;
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
                let lo = first.max(s);
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
        if rel >= seg.len || !seg.unverified.get(rel) {
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
        if rel < seg.len && seg.unverified.get(rel) {
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
        assert!(rel < seg.len, "resident chunk has crc");
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

    /// Seed dense state for every chunk covered by `runs` (hydration): all
    /// unverified, with CRCs left on disk ([`ChunkCrc::Unloaded`]).
    pub fn seed(&mut self, runs: &BTreeMap<u64, RunMeta>, geo: Geometry) {
        debug_assert!(self.segments.is_empty(), "seed into an empty map");
        let mut open: Option<(u64, u64)> = None;
        for (&logical, run) in runs {
            let lo = geo.chunk_of(logical);
            let hi = geo.chunk_of(logical + run.len - 1);
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

    /// Whether any covered chunk below `end` lacks a resident CRC (its
    /// value lives only in the committed checksum extents on disk).
    /// Pending chunks count as resident: their value is derivable from the
    /// overlay. Word-at-a-time, so a fully resident blob scans
    /// chunks/64 words.
    pub fn has_unloaded(&self, end: u64) -> bool {
        for (&start, seg) in &self.segments {
            if start >= end {
                break;
            }
            let cover = (end - start).min(seg.len);
            for (idx, page) in seg.pages.iter().enumerate() {
                let base = idx as u64 * CRC_PAGE_CHUNKS;
                if base >= cover {
                    break;
                }
                let slots = ((cover - base).min(CRC_PAGE_CHUNKS)) as usize;
                let Some(page) = page.as_deref() else {
                    // An unallocated page holds no values. Only its pending
                    // chunks (overlay-resident) are covered elsewhere.
                    let lo = start + base;
                    if self.pending.range(lo..lo + slots as u64).count() < slots {
                        return true;
                    }
                    continue;
                };
                for word in 0..slots.div_ceil(64) {
                    let covered = if (word + 1) * 64 <= slots {
                        u64::MAX
                    } else {
                        (1u64 << (slots % 64)) - 1
                    };
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

/// Cap on a blob's overlay entries (chunks kept in RAM for deferred CRCs),
/// for the default one-block chunk. Coarser chunks scale the entry cap
/// down by their group factor so the BYTE budget is constant.
///
/// Sized to cover the sub-chunk-rewrite working set of a table-like blob
/// (e.g. a hash-table head region) between syncs — 1024 chunks is 4 MiB —
/// while keeping per-blob RAM bounded. Only chunks that demonstrate
/// splice-style rewrites are ever resident, and overflow degrades
/// gracefully: eviction finalizes the chunk's CRC, and a later rewrite of
/// the evicted chunk falls back to the read-back path.
const OVERLAY_CHUNKS: usize = 1024;

/// One overlay entry: the full written span of a chunk, with an LRU stamp.
#[derive(Debug)]
pub(super) struct OverlayEntry {
    stamp: u64,
    bytes: Vec<u8>,
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

/// Per-blob mutable state.
#[derive(Debug, Default)]
pub(super) struct BlobInner {
    /// Verification-chunk geometry, immutable and fixed at creation.
    pub geo: Geometry,
    /// Current logical size (includes uncommitted writes).
    pub size: u64,
    /// Freeze boundary: bytes below are covered by the last confirmed table
    /// or the in-flight snapshot.
    pub freeze_size: u64,
    /// Written runs keyed by logical start; gaps are holes (zeros).
    pub runs: BTreeMap<u64, RunMeta>,
    /// Checksum state per backed chunk, over the chunk's written span.
    pub crcs: ChunkMap,
    /// Bytes of the frontier chunk's written span (from its chunk base),
    /// kept in memory so append CRCs and commit shadows never read back.
    /// Meaningful only when `frontier_chunk` is backed.
    pub tail: Vec<u8>,
    /// Chunk `tail` describes.
    pub tail_chunk: u64,
    /// The tail buffer generalized: full span bytes of recently
    /// splice-rewritten chunks, bounded by [`OVERLAY_CHUNKS`] (LRU). Entries
    /// are populated by writes only (never by reads) and mirror the disk
    /// (every write is written through); a [`ChunkCrc::Pending`] chunk is
    /// always resident, and its entry is the authoritative source for CRC
    /// finalization, reads, prefix/suffix sourcing, and COW.
    pub overlay: BTreeMap<u64, OverlayEntry>,
    /// Monotonic clock for overlay LRU stamps.
    pub overlay_clock: u64,
    /// Chunks whose content changed since the last snapshot.
    pub dirty_chunks: BTreeSet<u64>,
    /// Committed CRC pages loaded for verification (bounded LRU).
    pub crc_cache: CrcCache,
    /// Committed checksum refs whose extent guard was verified this
    /// process (or whose bytes this process assembled and wrote, see
    /// `commit::finalize`). Loads from a guarded ref read only the page
    /// window they need instead of streaming the whole extent.
    pub crc_guarded: Vec<ChecksumRef>,
    /// Bumped on any relocation/drop of backing (COW, resize-down, remove).
    pub generation: u64,
    /// Durable shadow block from the last commit covering this blob.
    pub shadow: Option<u64>,
    /// The entry the last confirmed commit wrote for this blob (None until
    /// first committed with content). Used verbatim for blobs a commit does
    /// not capture — never derived from live state, which may already
    /// contain uncommitted writes.
    pub committed_entry: Option<Entry>,
    /// Extents dropped by uncommitted state changes (COW, resize-down),
    /// released once a commit CAPTURING this blob confirms. Freeing at the
    /// next commit would recycle extents that commit's table (serving this
    /// blob's cached committed entry) still references.
    pub pending_frees: Vec<Extent>,
    /// Batches currently holding staged state for this blob. While nonzero,
    /// snapshot capture must not merge this blob's runs: staged overlays
    /// (see [`StagedBlob`]) reference base runs by key.
    pub staged_batches: usize,
    /// Unlinked from the namespace (handles may still read).
    pub removed: bool,
}

impl BlobInner {
    /// The run covering logical byte `at`, if any: `(logical start, run)`.
    pub fn covering(&self, at: u64) -> Option<(u64, RunMeta)> {
        self.runs
            .range(..=at)
            .next_back()
            .filter(|(&l, r)| at < l + r.len)
            .map(|(&l, r)| (l, *r))
    }

    /// The backed span of `chunk`: `(physical base, span len)`, or None for
    /// a hole. Every chunk is covered by at most one run (the geometry
    /// invariant: run starts are chunk-aligned).
    pub fn chunk_span(&self, chunk: u64) -> Option<(u64, u64)> {
        let chunk_start = chunk * self.geo.chunk_size();
        let (logical, run) = self.covering(chunk_start)?;
        let span = (logical + run.len - chunk_start).min(self.geo.chunk_size());
        Some((run.physical + (chunk_start - logical), span))
    }

    /// The overlay bytes of `chunk` (its full written span), refreshing its
    /// LRU stamp.
    pub fn overlay_get(&mut self, chunk: u64) -> Option<&[u8]> {
        self.overlay_clock += 1;
        let stamp = self.overlay_clock;
        let entry = self.overlay.get_mut(&chunk)?;
        entry.stamp = stamp;
        Some(&entry.bytes)
    }

    /// Insert or refresh `chunk`'s overlay entry, evicting (and finalizing)
    /// the least-recently-used entry beyond the cap (a constant byte
    /// budget: coarser chunks hold proportionally fewer entries).
    pub fn overlay_insert(&mut self, chunk: u64, bytes: Vec<u8>) {
        self.overlay_clock += 1;
        let stamp = self.overlay_clock;
        self.overlay.insert(chunk, OverlayEntry { stamp, bytes });
        if self.overlay.len() > (OVERLAY_CHUNKS >> self.geo.group).max(1) {
            let lru = self
                .overlay
                .iter()
                .min_by_key(|(_, entry)| entry.stamp)
                .map(|(&chunk, _)| chunk)
                .expect("overlay is nonempty");
            let entry = self.overlay.remove(&lru).expect("listed key");
            self.finalize_chunk(lru, &entry.bytes);
        }
    }

    /// Splice `data` at span offset `at` into the resident entry of `chunk`.
    pub fn overlay_splice(&mut self, chunk: u64, at: usize, data: &[u8]) {
        self.overlay_clock += 1;
        let stamp = self.overlay_clock;
        let entry = self
            .overlay
            .get_mut(&chunk)
            .expect("splice targets a resident chunk");
        entry.stamp = stamp;
        entry.bytes[at..at + data.len()].copy_from_slice(data);
    }

    /// Drop `chunk`'s overlay entry without finalizing (the caller installs
    /// a ready CRC for it).
    pub fn overlay_remove(&mut self, chunk: u64) {
        self.overlay.remove(&chunk);
    }

    /// Finalize every pending CRC from its overlay bytes; entries stay
    /// resident. The caller holds the blob's write lock (quiesced writer).
    pub fn overlay_finalize(&mut self) {
        let Self { crcs, overlay, .. } = self;
        for (&chunk, entry) in overlay.iter() {
            crcs.finalize(chunk, || Crc32::checksum(&entry.bytes));
        }
    }

    /// Finalize one chunk's pending CRC from `bytes` (its span content).
    fn finalize_chunk(&mut self, chunk: u64, bytes: &[u8]) {
        self.crcs.finalize(chunk, || Crc32::checksum(bytes));
    }
}

/// Metadata extents referenced by a blob's last confirmed table entry:
/// one extent per checksum ref (parallel to the entry's `checksums`), plus
/// the shadow block. Tracked so a commit that supersedes a piece of the
/// entry frees exactly the extents the new entry stops referencing: the
/// shadow is rewritten every commit, while checksum extents survive delta
/// commits and are freed only by a full rewrite (or removal).
#[derive(Debug, Default)]
pub(super) struct CommittedMeta {
    pub checksums: Vec<Extent>,
    pub shadow: Option<Extent>,
}

impl CommittedMeta {
    /// All extents, for wholesale release on removal.
    pub fn into_extents(self) -> impl Iterator<Item = Extent> {
        self.checksums.into_iter().chain(self.shadow)
    }
}

/// A blob shared between open handles and the volume state.
#[derive(Debug)]
pub(super) struct BlobCore {
    pub id: u64,
    pub partition: String,
    pub name: Vec<u8>,
    pub version: u16,
    /// Serializes writers and the commit snapshotter across inner I/O.
    pub write_lock: AsyncMutex<()>,
    pub inner: Mutex<BlobInner>,
}

/// Volume-wide mutable state.
pub(super) struct State {
    /// partition -> name -> blob id. Partition existence is first-class.
    pub partitions: BTreeMap<String, BTreeMap<Vec<u8>, u64>>,
    /// Blobs opened this run (live or removed-with-handles), by id.
    pub open: BTreeMap<u64, Arc<BlobCore>>,
    /// Handle count per open blob id.
    pub handles: BTreeMap<u64, usize>,
    /// Committed entries for blobs NOT opened this run (with their
    /// partition names), served verbatim into every table and hydrated into
    /// `open` on first open.
    pub dormant: BTreeMap<u64, (String, Entry)>,
    pub alloc: super::alloc::Allocator,
    /// (extent, free once this seq confirms, optional removed-blob gate).
    pub pending_free: Vec<(Extent, u64, Option<u64>)>,
    /// Seq of the next commit.
    pub seq: u64,
    /// Seq of the most recent snapshot (freeze epoch for `RunMeta::born`).
    pub snapshot_seq: u64,
    /// Highest confirmed commit seq.
    pub confirmed_seq: u64,
    /// Superblock slot holding the last confirmed commit.
    pub sacred_slot: u8,
    /// The last confirmed table's extent (freed when superseded).
    pub table_extent: Option<Extent>,
    /// Checksum/shadow extents referenced by the last confirmed table, per
    /// blob id (freed when a newer entry supersedes them).
    pub committed_meta: BTreeMap<u64, CommittedMeta>,
    /// Chunks recovery CRC-checked while verifying the adopted commit's
    /// delta manifest, per blob id. Consumed at hydration to seed verified
    /// bits so first reads skip re-verification.
    pub recovery_verified: BTreeMap<u64, Vec<u64>>,
    /// Next blob id (persisted; never reused).
    pub next_id: u64,
    /// Blob ids with uncommitted content changes.
    pub dirty: BTreeSet<u64>,
    /// Namespace changed (create/remove) since the last commit.
    pub meta_dirty: bool,
    /// Applied-but-uncommitted batch groups: disjoint blob-id sets, merged
    /// when batches share blobs, cleared when a commit captures them. A
    /// commit's capture set is expanded across these (never-split).
    pub groups: Vec<BTreeSet<u64>>,
    /// Cached encoded table entries by blob id, so table assembly re-encodes
    /// only captured blobs. Invalidated per blob on capture/removal and
    /// wholesale when the partition list changes (encodings embed partition
    /// indexes).
    pub encoded: BTreeMap<u64, Bytes>,
    /// Bumped whenever the partition LIST changes (not its contents).
    pub partition_epoch: u64,
    /// `partition_epoch` the `encoded` cache was built against.
    pub encoded_epoch: u64,
    /// Bytes of the volume file known to exist (growth high-water mark).
    pub provisioned: u64,
}

impl State {
    /// Queue an extent for reuse once `free_at` confirms (and, for removed
    /// blobs' extents, once the last handle drops).
    pub fn defer_free(&mut self, extent: Extent, free_at: u64, gate: Option<u64>) {
        self.pending_free.push((extent, free_at, gate));
    }

    /// Expand `roots` across applied-batch groups: the capture set of a
    /// commit rooted at these blobs (never-split rule).
    pub fn expand_capture(&self, roots: &[u64]) -> BTreeSet<u64> {
        let mut capture: BTreeSet<u64> = roots.iter().copied().collect();
        for group in &self.groups {
            if group.iter().any(|id| capture.contains(id)) {
                capture.extend(group.iter().copied());
            }
        }
        capture
    }

    /// Merge `ids` into the applied-batch groups (shared blobs coalesce).
    pub fn merge_group(&mut self, ids: impl IntoIterator<Item = u64>) {
        let mut merged: BTreeSet<u64> = ids.into_iter().collect();
        if merged.is_empty() {
            return;
        }
        self.groups.retain(|group| {
            if group.iter().any(|id| merged.contains(id)) {
                merged.extend(group.iter().copied());
                false
            } else {
                true
            }
        });
        self.groups.push(merged);
    }

    /// Apply deferred frees eligible under the current confirmed seq.
    pub fn apply_frees(&mut self) {
        let confirmed = self.confirmed_seq;
        let mut kept = Vec::with_capacity(self.pending_free.len());
        for (extent, free_at, gate) in self.pending_free.drain(..) {
            let gated = match gate {
                Some(id) => self.handles.get(&id).copied().unwrap_or(0) > 0,
                None => false,
            };
            if free_at <= confirmed && !gated {
                self.alloc.free(extent);
            } else {
                kept.push((extent, free_at, gate));
            }
        }
        self.pending_free = kept;
    }
}

/// Capture roots pooled by syncs queued on the commit lock, with the
/// completion latch their commit resolves.
///
/// Whichever queued sync acquires the commit lock first drains the pool and
/// commits the UNION, so one fsync acknowledges every pooled sync (commit
/// coalescing, see `commit::commit`). The ticket is swapped out atomically
/// with the roots at drain: a ticket therefore resolves exactly when a
/// commit whose snapshot began after every covered registration completes,
/// and a failed commit resolves it with the poisoning error (every pooled
/// sync was promised durability).
#[derive(Default)]
pub(super) struct PendingCommit {
    pub roots: BTreeSet<u64>,
    pub ticket: Arc<OnceLock<Result<(), Error>>>,
}

/// The volume once recovery has run.
pub(super) struct Ready<S: crate::Storage> {
    /// The single inner blob backing the volume.
    pub file: S::Blob,
    pub state: Mutex<State>,
    /// Serializes commits.
    pub commit_lock: AsyncMutex<()>,
    /// Roots (and ticket) of syncs queued for the next commit.
    pub pending: Mutex<PendingCommit>,
    /// Latched on the first failed commit: a failed fsync leaves the page
    /// cache undefined, so a later "successful" commit could vouch for bytes
    /// that never land. Every subsequent operation fails.
    pub poisoned: OnceLock<Error>,
    pub pool: BufferPool,
    /// Grow the volume file in steps of this many bytes (0 = grow on write).
    pub growth_quantum: u64,
    /// Serializes file growth (rare: once per quantum).
    pub provision_lock: AsyncMutex<()>,
}

impl<S: crate::Storage> Ready<S> {
    pub fn check_poisoned(&self) -> Result<(), Error> {
        self.poisoned.get().map_or(Ok(()), |e| Err(e.clone()))
    }
}

/// Grow the volume file (zero extension) so `end` is provisioned, in whole
/// growth quanta. Growth is monotonic: the file is never shrunk, and space
/// freed by the allocator is reused rather than returned.
pub(super) async fn ensure_provisioned<S: crate::Storage>(
    ready: &Ready<S>,
    end: u64,
) -> Result<(), Error> {
    if ready.growth_quantum == 0 || end <= ready.state.lock().provisioned {
        return Ok(());
    }
    let _guard = ready.provision_lock.lock().await;
    if end <= ready.state.lock().provisioned {
        return Ok(());
    }
    let target = end.div_ceil(ready.growth_quantum) * ready.growth_quantum;
    ready.file.resize(target).await?;
    ready.state.lock().provisioned = target;
    Ok(())
}

/// A run staged by a batch: the run it will publish at apply, plus whether
/// its extent is batch-private (allocated by the batch, invisible to every
/// snapshot and table, hence always writable in place).
#[derive(Clone, Copy, Debug)]
pub(super) struct StagedRun {
    pub meta: RunMeta,
    pub private: bool,
}

/// A batch's staged overlay for one blob: run splices, size, CRCs, and tail
/// state that publish only at apply. Invisible to readers and commits.
///
/// While an overlay holds staged content, the batch is the blob's ONE
/// writer (the [`crate::Blob`] contract's writer exclusivity applied to the
/// batch as a deferred writer): a direct write into the staged region would
/// rewrite bytes whose staged expected content the overlay already recorded
/// — found by the model (`storage::volume::model`).
#[derive(Debug, Default)]
pub(super) struct StagedBlob {
    /// Staged logical size.
    pub size: u64,
    /// Overlay runs keyed by logical start (replacing base runs at the same
    /// key). Merged with the base runs, coverage stays non-overlapping.
    pub runs: BTreeMap<u64, StagedRun>,
    /// Base run keys superseded by the overlay (splices, staged shrink).
    pub removed: BTreeSet<u64>,
    /// Staged chunk checksum state.
    pub crcs: BTreeMap<u64, ChunkState>,
    /// Staged frontier span: (chunk, bytes of its written span).
    pub tail: Option<(u64, Vec<u8>)>,
    /// Base extents replaced by staged COW/shrink (pending-freed at apply).
    pub replaced: Vec<Extent>,
    /// Extents allocated by the batch, still referenced by the overlay
    /// (freed if the batch is dropped unapplied).
    pub fresh: Vec<Extent>,
    /// Whether apply must bump the read generation (relocation or shrink).
    pub relocated: bool,
}

impl StagedBlob {
    /// Start an overlay over a blob whose published size is `size`.
    pub fn new(size: u64) -> Self {
        Self {
            size,
            ..Default::default()
        }
    }

    /// The merged (overlay-over-base) run covering `at`:
    /// (logical start, run, private).
    pub fn covering(&self, inner: &BlobInner, at: u64) -> Option<(u64, RunMeta, bool)> {
        if let Some((&l, sr)) = self.runs.range(..=at).next_back() {
            if at < l + sr.meta.len {
                return Some((l, sr.meta, sr.private));
            }
        }
        inner
            .runs
            .range(..=at)
            .next_back()
            .filter(|(l, r)| {
                !self.removed.contains(l) && !self.runs.contains_key(l) && at < **l + r.len
            })
            .map(|(&l, r)| (l, *r, false))
    }

    /// The first merged backed logical start at or after `from`.
    pub fn next_backed(&self, inner: &BlobInner, from: u64) -> Option<u64> {
        let overlay = self.runs.range(from..).next().map(|(&l, _)| l);
        let base = inner
            .runs
            .range(from..)
            .find(|(l, _)| !self.removed.contains(l) && !self.runs.contains_key(l))
            .map(|(&l, _)| l);
        match (overlay, base) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The merged backed span of `chunk`: (physical base, span len).
    pub fn chunk_span(&self, inner: &BlobInner, chunk: u64) -> Option<(u64, u64)> {
        let chunk_start = chunk * inner.geo.chunk_size();
        let (logical, run, _) = self.covering(inner, chunk_start)?;
        let span = (logical + run.len - chunk_start).min(inner.geo.chunk_size());
        Some((run.physical + (chunk_start - logical), span))
    }
}

/// One chunk's checksum outcome for a planned stretch.
enum CrcUpdate {
    /// Computed eagerly (with its verified-by-construction bit). Publish
    /// drops any overlay entry for the chunk (its bytes were rewritten
    /// without an overlay refresh).
    Ready(ChunkState),
    /// Deferred: `bytes` becomes (or refreshes) the chunk's overlay entry —
    /// the authoritative span — and the CRC is finalized later. `verified`
    /// is the bit the finalized chunk will carry. Base mode only.
    Pending { bytes: Vec<u8>, verified: bool },
    /// Overlay fast path: splice `data` at span offset `at` into the
    /// chunk's resident entry and mark its CRC pending (the chunk's
    /// verified bit is unchanged: the splice is written through, and the
    /// rest of the span keeps its provenance). Base mode only.
    Splice { at: usize, data: IoBuf },
}

/// One planned stretch: a single inner write plus its state updates,
/// published only after the write completes (a failed write publishes
/// nothing; its bytes land in space no table references).
struct Stretch {
    /// First logical byte NOT covered by this stretch.
    end: u64,
    /// Physical write position.
    physical: u64,
    /// Write payload, issued verbatim at `physical`: the caller's slice(s)
    /// passed zero-copy, plus any pool-allocated zero-fill or COW assembly.
    bytes: IoBufs,
    /// Run insert/replace: (logical start, run).
    run: (u64, RunMeta),
    /// Chunk checksum updates, ascending by chunk.
    crcs: Vec<(u64, CrcUpdate)>,
    /// Bytes of the final affected chunk's written span (chunk, span bytes),
    /// used to refresh the tail buffer when this stretch reaches the blob's
    /// write frontier. `None` only for an overlay fast-path stretch, whose
    /// span is derived from the spliced overlay entry at publish.
    last_span: Option<(u64, Vec<u8>)>,
    /// COW: the replaced chunk's block to defer-free (+ generation bump).
    replaced: Option<Extent>,
    /// Extent allocated for this stretch (Fresh/COW), for staged-overlay
    /// bookkeeping. Unused by the publish path (the run records it).
    allocated: Option<Extent>,
    /// Staged mode: whether the written extent is batch-private.
    private: bool,
}

/// Write `data` at `offset`. The blob's `write_lock` MUST be held.
pub(super) async fn write_locked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    offset: u64,
    data: IoBuf,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    if data.is_empty() {
        return Ok(());
    }
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or(Error::OffsetOverflow)?;

    let mut cursor = offset;
    while cursor < end {
        let stretch = plan_stretch(ready, blob, None, cursor, end, &data, offset).await?;
        ensure_provisioned(ready, stretch.physical + stretch.bytes.len() as u64).await?;
        ready
            .file
            .write_at(stretch.physical, stretch.bytes.clone())
            .await?;
        cursor = stretch.end;
        publish_stretch(ready, blob, stretch);
    }

    // Publish the size extension once all stretches landed.
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();
    if end > inner.size {
        inner.size = end;
    }
    state.dirty.insert(blob.id);
    Ok(())
}

/// Stage `data` at `offset` into a batch overlay: the same planning and
/// write-through as [`write_locked`], but every state change accumulates in
/// `staged` instead of the blob's published state. The blob's `write_lock`
/// MUST be held.
pub(super) async fn stage_write<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: &mut StagedBlob,
    offset: u64,
    data: IoBuf,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    if data.is_empty() {
        return Ok(());
    }
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or(Error::OffsetOverflow)?;

    let mut cursor = offset;
    while cursor < end {
        let stretch = plan_stretch(ready, blob, Some(staged), cursor, end, &data, offset).await?;
        ensure_provisioned(ready, stretch.physical + stretch.bytes.len() as u64).await?;
        ready
            .file
            .write_at(stretch.physical, stretch.bytes.clone())
            .await?;
        cursor = stretch.end;
        let inner = blob.inner.lock();
        publish_staged(&inner, staged, stretch);
    }
    staged.size = staged.size.max(end);
    Ok(())
}

/// Plan the next stretch starting at `cursor` (performing any COW/CRC
/// read-backs needed to make the plan self-contained).
///
/// With `staged` set, planning runs against the merged overlay-over-base
/// view and follows the batch placement rule: batch-private extents are
/// writable in place; published extents only at or beyond BOTH the
/// published size and the freeze boundary (bytes no snapshot can capture);
/// everything else relocates to a fresh extent published only at apply.
/// Staged stretches always compute CRCs eagerly (deferral is base-only).
async fn plan_stretch<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    cursor: u64,
    end: u64,
    data: &IoBuf,
    data_base: u64,
) -> Result<Stretch, Error> {
    /// How a COW sources the old span it splices into.
    enum CowSource {
        /// Disk read-back, checked against the span's expected CRC.
        Disk { expected: u32 },
        /// The chunk's overlay bytes: its current content (process memory,
        /// written through), needing no read and no re-check.
        Overlay(Vec<u8>),
    }
    enum Plan {
        /// Write in place within an existing run's extent, extending it as
        /// far as `stretch_end` (bounded by the extent capacity). Includes
        /// zero-fill of `[fill_from, cursor)` (unwritten gap below the
        /// write inside the run's frontier chunk).
        InPlace {
            stretch_end: u64,
            run_logical: u64,
            run: RunMeta,
            fill_from: u64,
            private: bool,
        },
        /// Overlay fast path: a rewrite of an overlay-resident chunk, fully
        /// inside its written span. The payload is written at its exact
        /// offset and spliced into the overlay entry — no read-back, no CRC
        /// pass (the chunk's CRC goes pending).
        Overlay {
            stretch_end: u64,
            physical: u64,
            run_logical: u64,
            run: RunMeta,
            private: bool,
        },
        /// Fresh extent for `[chunk_base, stretch_end)` (zero-lead below the
        /// write; the chunk base is unbacked).
        Fresh {
            stretch_end: u64,
            extent: Extent,
            chunk_base: u64,
            seq: u64,
        },
        /// The cursor's chunk may not be written in place: COW its backed
        /// span.
        Cow {
            span_physical: u64,
            span_len: u64,
            extent: Extent,
            seq: u64,
            source: CowSource,
        },
    }

    /// A planning attempt: a plan, or a committed CRC to load first.
    enum Outcome {
        Plan(Plan),
        NeedCrc(u64),
    }

    // The blob's chunk geometry (immutable once created).
    let geo = blob.inner.lock().geo;

    // The COW of a chunk untouched since hydration needs its committed CRC
    // (the read-back check): loaded outside the locks, memoized, and the
    // plan re-derived. The target chunk is fixed by `cursor`, so the memo
    // guarantees the second attempt resolves.
    let mut loaded_crc: Option<(u64, u32)> = None;
    let plan = loop {
        let outcome = 'plan: {
            let mut state = ready.state.lock();
            let mut inner = blob.inner.lock();
            let chunk = geo.chunk_of(cursor);
            let chunk_start = chunk * geo.chunk_size();

            // Merged coverage and placement: the base view for published
            // writes, the overlay-over-base view for staged writes.
            let covering = staged.map_or_else(
                || {
                    inner
                        .covering(chunk_start)
                        .map(|(logical, run)| (logical, run, false))
                },
                |st| st.covering(&inner, chunk_start),
            );
            match covering {
                Some((run_logical, run, private)) => {
                    let backed_end = run_logical + run.len;
                    let writable = match staged {
                        // Base freeze rule: young extents are exempt; otherwise
                        // only bytes at or beyond the freeze boundary.
                        None => run.born > state.snapshot_seq || cursor >= inner.freeze_size,
                        // Batch placement rule: private extents always; a
                        // published extent only for bytes no snapshot can
                        // capture (at or beyond BOTH the published size and the
                        // freeze boundary; the born exemption does not apply —
                        // young extents are still published to readers).
                        Some(_) => private || cursor >= inner.size.max(inner.freeze_size),
                    };
                    if !writable {
                        let (span_physical, span_len) = staged
                            .map_or_else(
                                || inner.chunk_span(chunk),
                                |st| st.chunk_span(&inner, chunk),
                            )
                            .expect("covered chunk has a span");
                        // Source the old span from the overlay when it is valid
                        // for the merged view (base content the batch has not
                        // staged over), otherwise from a checked disk read-back
                        // whose expected CRC pairs with the merged view that
                        // produced the span (staged overlays win).
                        let staged_crc = staged.and_then(|st| st.crcs.get(&chunk)).copied();
                        let resident = match staged_crc {
                            None => inner.overlay_get(chunk).map(<[u8]>::to_vec),
                            Some(_) => None,
                        };
                        let source = match resident {
                            Some(bytes) => {
                                debug_assert_eq!(bytes.len() as u64, span_len);
                                CowSource::Overlay(bytes)
                            }
                            None => {
                                let crc = staged_crc
                                    .or_else(|| inner.crcs.get(chunk))
                                    .expect("covered chunk has crc")
                                    .crc;
                                let expected = match crc {
                                    ChunkCrc::Ready(expected) => expected,
                                    // Pending chunks are overlay-resident, and
                                    // residency was checked above.
                                    ChunkCrc::Pending => {
                                        unreachable!("pending chunk without overlay entry")
                                    }
                                    // Untouched since hydration: the expected
                                    // CRC is the committed value.
                                    ChunkCrc::Unloaded => {
                                        let known = loaded_crc
                                            .filter(|&(c, _)| c == chunk)
                                            .map(|(_, crc)| crc)
                                            .or_else(|| inner.crc_cache.get(chunk));
                                        match known {
                                            Some(expected) => expected,
                                            None => break 'plan Outcome::NeedCrc(chunk),
                                        }
                                    }
                                };
                                CowSource::Disk { expected }
                            }
                        };
                        let extent = state.alloc.allocate(geo.chunk_size());
                        Outcome::Plan(Plan::Cow {
                            span_physical,
                            span_len,
                            extent,
                            seq: state.seq,
                            source,
                        })
                    } else {
                        // In place. The write may start beyond the backed end
                        // (a gap inside this run's frontier chunk): zero-fill
                        // from the backed end. It may extend past the backing
                        // but only within the extent's capacity.
                        let fill_from = cursor.min(backed_end);
                        let stretch_end = end.min(run_logical + run.capacity);
                        debug_assert!(stretch_end > cursor);
                        // Overlay fast path (base mode): the write stays inside
                        // this chunk's written span and the span is resident.
                        let chunk_end = chunk_start + geo.chunk_size();
                        let span_end = chunk_end.min(backed_end);
                        if staged.is_none()
                            && end.min(chunk_end) <= span_end
                            && inner.overlay_get(chunk).is_some()
                        {
                            let (span_physical, _) =
                                inner.chunk_span(chunk).expect("covered chunk has a span");
                            Outcome::Plan(Plan::Overlay {
                                stretch_end: end.min(chunk_end),
                                physical: span_physical + (cursor - chunk_start),
                                run_logical,
                                run,
                                private,
                            })
                        } else {
                            Outcome::Plan(Plan::InPlace {
                                stretch_end,
                                run_logical,
                                run,
                                fill_from,
                                private,
                            })
                        }
                    }
                }
                None => {
                    // Unbacked chunk: fresh extent from this chunk's base to the
                    // end of the write (or the next backed run, which must not
                    // be overlapped).
                    let next_backed = staged
                        .map_or_else(
                            || inner.runs.range(chunk_start..).next().map(|(&l, _)| l),
                            |st| st.next_backed(&inner, chunk_start),
                        )
                        .unwrap_or(u64::MAX);
                    let stretch_end = end.min(next_backed);
                    // A whole number of chunks: capacity ends stay
                    // chunk-aligned so no later run starts mid-chunk (the
                    // geometry invariant). `next_backed` is chunk-aligned,
                    // so the rounding never overlaps it.
                    let len = geo.chunk_align(stretch_end - chunk_start);
                    let extent = state.alloc.allocate(len);
                    Outcome::Plan(Plan::Fresh {
                        stretch_end,
                        extent,
                        chunk_base: chunk_start,
                        seq: state.seq,
                    })
                }
            }
        };
        match outcome {
            Outcome::Plan(plan) => break plan,
            Outcome::NeedCrc(chunk) => {
                if let Some((first, values)) =
                    Box::pin(load_committed_page(ready, blob, chunk)).await?
                {
                    loaded_crc = Some((chunk, values[(chunk - first) as usize]));
                }
            }
        }
    };

    match plan {
        Plan::Overlay {
            stretch_end,
            physical,
            run_logical,
            run,
            private,
        } => {
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let payload = data.slice(d0..d1);
            let chunk = geo.chunk_of(cursor);
            let at = (cursor - chunk * geo.chunk_size()) as usize;
            Ok(Stretch {
                end: stretch_end,
                physical,
                bytes: payload.clone().into(),
                run: (run_logical, run),
                crcs: vec![(chunk, CrcUpdate::Splice { at, data: payload })],
                last_span: None,
                replaced: None,
                allocated: None,
                private,
            })
        }
        Plan::InPlace {
            stretch_end,
            run_logical,
            run,
            fill_from,
            private,
        } => {
            // Each affected chunk's CRC covers its full written span: the
            // first chunk may have a prefix below `fill_from`, and the last
            // chunk may have a suffix beyond `stretch_end` (an in-place
            // overwrite inside a longer span). Only `[fill_from,
            // stretch_end)` — the gap zero-fill and the new data — is
            // written back, at its exact offset: the caller's payload slice
            // passed zero-copy, preceded by a pooled zero-fill buffer when
            // the gap is nonempty. CRCs stream over the logical pieces —
            // no assembly of the payload.
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let first_chunk = geo.chunk_of(fill_from);
            let last_chunk = geo.chunk_of(stretch_end - 1);
            let base = first_chunk * geo.chunk_size();

            let span_end = (run_logical + run.len).max(stretch_end);
            let chunk_cap = (last_chunk + 1) * geo.chunk_size();
            let suffix_end = span_end.min(chunk_cap);

            let (prefix, prefix_verified) =
                read_span_prefix(ready, blob, staged, &run, run_logical, base, fill_from).await?;
            let has_suffix = suffix_end > stretch_end;
            let (suffix, suffix_verified) = if has_suffix {
                read_span_suffix(
                    ready,
                    blob,
                    staged,
                    &run,
                    run_logical,
                    stretch_end,
                    suffix_end,
                )
                .await?
            } else {
                (Vec::new(), true)
            };
            let gap = (cursor - fill_from) as usize;
            let zeros = (gap > 0).then(|| {
                let mut buf = ready.pool.alloc(gap);
                buf.put_bytes(0, gap);
                buf.freeze()
            });
            let payload = data.slice(d0..d1);

            // The logical pieces of `[base, suffix_end)`, in order.
            let pieces: [(u64, &[u8]); 4] = [
                (base, &prefix),
                (fill_from, zeros.as_ref().map_or(&[][..], |z| z.as_ref())),
                (cursor, payload.as_ref()),
                (stretch_end, &suffix),
            ];

            let mut crcs = Vec::new();
            let mut last_span = None;
            for chunk in first_chunk..=last_chunk {
                let lo = chunk * geo.chunk_size();
                let hi = suffix_end.min(lo + geo.chunk_size());
                // A chunk assembled purely from process memory (payload, gap
                // zeros, tail-buffer or overlay-sourced prefix/suffix) is
                // verified by construction; a chunk that spliced in an
                // unchecked disk read-back is not (see [`ChunkState`]).
                let verified = (chunk != first_chunk || prefix_verified)
                    && (chunk != last_chunk || suffix_verified);
                // Splice-rewritten chunks keep their span in the overlay
                // and defer their CRC (base mode); everything else streams
                // it over the pieces.
                let spliced = (chunk == first_chunk && !prefix.is_empty())
                    || (chunk == last_chunk && has_suffix);
                let update = if spliced && staged.is_none() {
                    CrcUpdate::Pending {
                        bytes: copy_over(&pieces, lo, hi),
                        verified,
                    }
                } else {
                    CrcUpdate::Ready(ChunkState {
                        crc: ChunkCrc::Ready(crc_over(&pieces, lo, hi)),
                        verified,
                    })
                };
                crcs.push((chunk, update));
                if chunk == last_chunk {
                    last_span = Some((chunk, copy_over(&pieces, lo, hi)));
                }
            }

            let bytes = match zeros {
                Some(zeros) => IoBufs::from(vec![zeros, payload]),
                None => payload.into(),
            };
            let new_len = (stretch_end - run_logical).max(run.len);
            Ok(Stretch {
                end: stretch_end,
                physical: run.physical + (fill_from - run_logical),
                bytes,
                run: (
                    run_logical,
                    RunMeta {
                        len: new_len,
                        ..run
                    },
                ),
                crcs,
                last_span,
                replaced: None,
                allocated: None,
                private,
            })
        }
        Plan::Fresh {
            stretch_end,
            extent,
            chunk_base,
            seq,
        } => {
            // The caller's payload slice is issued zero-copy, preceded by a
            // pooled zero-lead when the write starts past the (unbacked)
            // chunk base. CRCs stream over the same bytes — no assembly.
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let lead = (cursor - chunk_base) as usize;
            let zeros = (lead > 0).then(|| {
                let mut buf = ready.pool.alloc(lead);
                buf.put_bytes(0, lead);
                buf.freeze()
            });
            let payload = data.slice(d0..d1);
            let pieces: [(u64, &[u8]); 2] = [
                (chunk_base, zeros.as_ref().map_or(&[][..], |z| z.as_ref())),
                (cursor, payload.as_ref()),
            ];

            let first_chunk = geo.chunk_of(chunk_base);
            let last_chunk = geo.chunk_of(stretch_end - 1);
            let mut crcs = Vec::new();
            let mut last_span = None;
            for chunk in first_chunk..=last_chunk {
                let lo = chunk * geo.chunk_size();
                let hi = stretch_end.min(lo + geo.chunk_size());
                // Assembled purely from process memory (lead zeros + the
                // payload): verified by construction. A chunk written from
                // a sub-block lead (base mode) is a splice-rewrite
                // candidate: keep its span in the overlay and defer its CRC.
                let update = if chunk == first_chunk && lead > 0 && staged.is_none() {
                    CrcUpdate::Pending {
                        bytes: copy_over(&pieces, lo, hi),
                        verified: true,
                    }
                } else {
                    CrcUpdate::Ready(ChunkState {
                        crc: ChunkCrc::Ready(crc_over(&pieces, lo, hi)),
                        verified: true,
                    })
                };
                crcs.push((chunk, update));
                if chunk == last_chunk {
                    last_span = Some((chunk, copy_over(&pieces, lo, hi)));
                }
            }

            let bytes = match zeros {
                Some(zeros) => IoBufs::from(vec![zeros, payload]),
                None => payload.into(),
            };
            Ok(Stretch {
                end: stretch_end,
                physical: extent.offset,
                bytes,
                run: (
                    chunk_base,
                    RunMeta {
                        physical: extent.offset,
                        len: stretch_end - chunk_base,
                        capacity: extent.len,
                        born: seq,
                    },
                ),
                crcs,
                last_span,
                replaced: None,
                allocated: Some(extent),
                private: true,
            })
        }
        Plan::Cow {
            span_physical,
            span_len,
            extent,
            seq,
            source,
        } => {
            let chunk = geo.chunk_of(cursor);
            let chunk_start = chunk * geo.chunk_size();
            let stretch_end = end.min(chunk_start + geo.chunk_size());
            let w0 = (cursor - chunk_start) as usize;
            let w1 = (stretch_end - chunk_start) as usize;
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let exact = (span_len as usize).max(w1);
            let mut buf = ready.pool.alloc(exact);
            match source {
                // The overlay bytes ARE the span's current content.
                CowSource::Overlay(bytes) => buf.put_slice(&bytes),
                // Read the old span (stable: frozen extents are never
                // rewritten, and deferred frees keep them allocated until
                // the next commit confirms) and check it before splicing.
                // The read-back is the whole span, so the check is one CRC
                // pass over bytes already in hand: it surfaces rot loudly
                // at the COW instead of laundering it under a fresh CRC,
                // and it keeps the relocated chunk verified by
                // construction.
                CowSource::Disk { expected } => {
                    let old = ready
                        .file
                        .read_at(span_physical, span_len as usize)
                        .await?
                        .coalesce();
                    if Crc32::checksum(old.as_ref()) != expected {
                        return Err(Error::BlobCorrupt(
                            blob.partition.clone(),
                            hex(&blob.name),
                            format!("chunk {chunk} checksum mismatch"),
                        ));
                    }
                    buf.put_slice(old.as_ref());
                }
            }
            buf.put_bytes(0, exact - span_len as usize);
            buf.as_mut()[w0..w1].copy_from_slice(data.slice(d0..d1).as_ref());

            // A partial rewrite is a splice candidate: keep the relocated
            // span in the overlay and defer its CRC (base mode). Every byte
            // lands on the fresh extent, so the chunk is verified by
            // construction either way.
            let span_bytes = buf.as_ref().to_vec();
            let partial = w0 > 0 || w1 < exact;
            let update = if partial && staged.is_none() {
                CrcUpdate::Pending {
                    bytes: span_bytes.clone(),
                    verified: true,
                }
            } else {
                CrcUpdate::Ready(ChunkState {
                    crc: ChunkCrc::Ready(Crc32::checksum(buf.as_ref())),
                    verified: true,
                })
            };
            let last_span = Some((chunk, span_bytes));

            Ok(Stretch {
                end: stretch_end,
                physical: extent.offset,
                run: (
                    chunk_start,
                    RunMeta {
                        physical: extent.offset,
                        len: exact as u64,
                        capacity: extent.len,
                        born: seq,
                    },
                ),
                crcs: vec![(chunk, update)],
                last_span,
                bytes: buf.freeze().into(),
                // The old run's whole capacity slice for this chunk (span
                // starts at the chunk base, and capacities are
                // chunk-multiples, so the slice is exactly one chunk).
                replaced: Some(Extent {
                    offset: span_physical,
                    len: geo.chunk_size(),
                }),
                allocated: Some(extent),
                private: true,
            })
        }
    }
}

/// CRC32C over `[start, end)` of a logical range assembled from `pieces`:
/// `(piece start, piece bytes)` entries, contiguous and in order. Streams
/// the intersecting slices — no assembly buffer.
fn crc_over(pieces: &[(u64, &[u8])], start: u64, end: u64) -> u32 {
    let mut hasher = Crc32::new();
    let mut covered = 0;
    for &(piece_start, bytes) in pieces {
        let lo = start.max(piece_start);
        let hi = end.min(piece_start + bytes.len() as u64);
        if hi > lo {
            hasher.update(&bytes[(lo - piece_start) as usize..(hi - piece_start) as usize]);
            covered += hi - lo;
        }
    }
    debug_assert_eq!(covered, end - start, "pieces must cover the range");
    hasher.finalize().as_u32()
}

/// The bytes of `[start, end)` assembled from `pieces` (see [`crc_over`]).
fn copy_over(pieces: &[(u64, &[u8])], start: u64, end: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity((end - start) as usize);
    for &(piece_start, bytes) in pieces {
        let lo = start.max(piece_start);
        let hi = end.min(piece_start + bytes.len() as u64);
        if hi > lo {
            out.extend_from_slice(&bytes[(lo - piece_start) as usize..(hi - piece_start) as usize]);
        }
    }
    debug_assert_eq!(out.len() as u64, end - start, "pieces must cover the range");
    out
}

/// Source the first affected chunk's committed prefix `[base, fill_from)`:
/// from an in-memory tail buffer or overlay entry when one describes this
/// chunk, otherwise a read-back (rare: the first splice into a chunk the
/// overlay does not hold).
///
/// The second element reports the provenance the assembled chunk inherits:
/// tail buffers are trusted process memory, overlay bytes carry their
/// chunk's verified bit, and a disk read-back is spliced unchecked, leaving
/// the assembled chunk unverified (see [`ChunkState`]).
async fn read_span_prefix<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    run: &RunMeta,
    run_logical: u64,
    base: u64,
    fill_from: u64,
) -> Result<(Vec<u8>, bool), Error> {
    let prefix_len = (fill_from - base) as usize;
    if prefix_len == 0 {
        return Ok((Vec::new(), true));
    }
    let chunk = blob.inner.lock().geo.chunk_of(base);
    {
        let mut inner = blob.inner.lock();
        // The staged tail wins for chunks the batch touched; published
        // sources are valid only for chunks the batch has not staged over.
        if let Some(st) = staged {
            if let Some((tail_chunk, tail)) = &st.tail {
                if *tail_chunk == chunk && tail.len() >= prefix_len {
                    return Ok((tail[..prefix_len].to_vec(), true));
                }
            }
        }
        if staged.is_none_or(|st| !st.crcs.contains_key(&chunk)) {
            if inner.tail_chunk == chunk && inner.tail.len() >= prefix_len {
                return Ok((inner.tail[..prefix_len].to_vec(), true));
            }
            let verified = inner.crcs.get(chunk).is_some_and(|s| s.verified);
            if let Some(bytes) = inner.overlay_get(chunk) {
                if bytes.len() >= prefix_len {
                    return Ok((bytes[..prefix_len].to_vec(), verified));
                }
            }
        }
    }
    let phys = run.physical + (base - run_logical);
    let prefix = ready
        .file
        .read_at(phys, prefix_len)
        .await?
        .coalesce()
        .as_ref()
        .to_vec();
    Ok((prefix, false))
}

/// Source the last affected chunk's trailing span `[stretch_end,
/// suffix_end)` (an in-place overwrite inside a longer span): from an
/// in-memory tail buffer or overlay entry when one describes this chunk,
/// otherwise a disk read-back. Provenance as for [`read_span_prefix`].
async fn read_span_suffix<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    run: &RunMeta,
    run_logical: u64,
    stretch_end: u64,
    suffix_end: u64,
) -> Result<(Vec<u8>, bool), Error> {
    let geo = blob.inner.lock().geo;
    let chunk = geo.chunk_of(stretch_end - 1);
    let s = (stretch_end - chunk * geo.chunk_size()) as usize;
    let e = (suffix_end - chunk * geo.chunk_size()) as usize;
    {
        let mut inner = blob.inner.lock();
        if let Some(st) = staged {
            if let Some((tail_chunk, tail)) = &st.tail {
                if *tail_chunk == chunk && tail.len() >= e {
                    return Ok((tail[s..e].to_vec(), true));
                }
            }
        }
        if staged.is_none_or(|st| !st.crcs.contains_key(&chunk)) {
            if inner.tail_chunk == chunk && inner.tail.len() >= e {
                return Ok((inner.tail[s..e].to_vec(), true));
            }
            let verified = inner.crcs.get(chunk).is_some_and(|st| st.verified);
            if let Some(bytes) = inner.overlay_get(chunk) {
                if bytes.len() >= e {
                    return Ok((bytes[s..e].to_vec(), verified));
                }
            }
        }
    }
    let phys = run.physical + (stretch_end - run_logical);
    let suffix = ready
        .file
        .read_at(phys, e - s)
        .await?
        .coalesce()
        .as_ref()
        .to_vec();
    Ok((suffix, false))
}

/// Publish a completed stretch. Caller holds the blob write lock.
fn publish_stretch<S: crate::Storage>(ready: &Ready<S>, blob: &BlobCore, stretch: Stretch) {
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();
    let (logical, run) = stretch.run;

    if let Some(replaced) = stretch.replaced {
        cow_remap(&mut inner, logical, run);
        inner.pending_frees.push(replaced);
        inner.generation += 1;
    } else {
        match inner.runs.get_mut(&logical) {
            Some(existing) if existing.physical == run.physical => {
                existing.len = existing.len.max(run.len);
            }
            _ => {
                inner.runs.insert(logical, run);
            }
        }
    }

    let last_chunk = stretch
        .crcs
        .last()
        .map(|&(chunk, _)| chunk)
        .expect("stretch affects at least one chunk");
    for (chunk, update) in stretch.crcs {
        match update {
            CrcUpdate::Ready(chunk_state) => {
                inner.crcs.insert(chunk, chunk_state);
                // The chunk's bytes were rewritten without an overlay
                // refresh: any resident entry is stale.
                inner.overlay_remove(chunk);
            }
            CrcUpdate::Pending { bytes, verified } => {
                inner.crcs.insert(
                    chunk,
                    ChunkState {
                        crc: ChunkCrc::Pending,
                        verified,
                    },
                );
                inner.overlay_insert(chunk, bytes);
            }
            CrcUpdate::Splice { at, data } => {
                inner.overlay_splice(chunk, at, data.as_ref());
                inner.crcs.make_pending(chunk);
            }
        }
        inner.dirty_chunks.insert(chunk);
    }
    // Refresh the tail buffer if this stretch reaches the write frontier
    // (an overlay fast-path stretch derives its span from the spliced
    // overlay entry on the rare frontier hit).
    if stretch.end >= inner.size || last_chunk >= inner.tail_chunk {
        inner.tail = match stretch.last_span {
            Some((chunk, span)) => {
                debug_assert_eq!(chunk, last_chunk);
                span
            }
            None => inner
                .overlay_get(last_chunk)
                .expect("fast-path chunk is resident")
                .to_vec(),
        };
        inner.tail_chunk = last_chunk;
    }
    state.dirty.insert(blob.id);
}

/// Record a completed stretch in a batch overlay. Caller holds the blob
/// write lock.
fn publish_staged(inner: &BlobInner, staged: &mut StagedBlob, stretch: Stretch) {
    let (logical, run) = stretch.run;
    if let Some(extent) = stretch.allocated {
        staged.fresh.push(extent);
    }
    if let Some(replaced) = stretch.replaced {
        cow_remap_staged(inner, staged, logical, run);
        staged.replaced.push(replaced);
        staged.relocated = true;
    } else {
        match staged.runs.get_mut(&logical) {
            Some(existing) if existing.meta.physical == run.physical => {
                existing.meta.len = existing.meta.len.max(run.len);
            }
            _ => {
                staged.runs.insert(
                    logical,
                    StagedRun {
                        meta: run,
                        private: stretch.private,
                    },
                );
            }
        }
    }

    for (chunk, update) in stretch.crcs {
        match update {
            CrcUpdate::Ready(chunk_state) => {
                staged.crcs.insert(chunk, chunk_state);
            }
            // Deferral is base-only (see `plan_stretch`).
            CrcUpdate::Pending { .. } | CrcUpdate::Splice { .. } => {
                unreachable!("staged stretches compute CRCs eagerly")
            }
        }
    }
    // Refresh the staged tail if this stretch reaches the staged frontier.
    let (chunk, span) = stretch
        .last_span
        .expect("staged stretches carry a last span");
    let tail_chunk = staged.tail.as_ref().map(|(c, _)| *c);
    if stretch.end >= staged.size || chunk >= tail_chunk.unwrap_or(inner.tail_chunk) {
        staged.tail = Some((chunk, span));
    }
}

/// Remap one staged-COW'd chunk: split the merged covering run around it in
/// the overlay (mirrors [`cow_remap`] without touching published state).
fn cow_remap_staged(inner: &BlobInner, staged: &mut StagedBlob, chunk_start: u64, fresh: RunMeta) {
    let (old_logical, old_run, old_private) = staged
        .covering(inner, chunk_start)
        .expect("COW of unbacked chunk");
    debug_assert!(!old_private, "private chunks are written in place");
    let old_end = old_logical + old_run.len;
    let chunk_end = chunk_start + inner.geo.chunk_size();

    // Detach the source run from the merged view.
    if staged.runs.remove(&old_logical).is_none() {
        staged.removed.insert(old_logical);
    }
    if old_logical < chunk_start {
        staged.runs.insert(
            old_logical,
            StagedRun {
                meta: RunMeta {
                    len: chunk_start - old_logical,
                    capacity: chunk_start - old_logical,
                    ..old_run
                },
                private: old_private,
            },
        );
    }
    if old_end > chunk_end {
        staged.runs.insert(
            chunk_end,
            StagedRun {
                meta: RunMeta {
                    physical: old_run.physical + (chunk_end - old_logical),
                    len: old_end - chunk_end,
                    capacity: old_run.capacity.saturating_sub(chunk_end - old_logical),
                    born: old_run.born,
                },
                private: old_private,
            },
        );
    }
    staged.runs.insert(
        chunk_start,
        StagedRun {
            meta: fresh,
            private: true,
        },
    );
}

/// Remap one COW'd chunk: split the covering run around it.
fn cow_remap(inner: &mut BlobInner, chunk_start: u64, fresh: RunMeta) {
    let (old_logical, old_run) = inner.covering(chunk_start).expect("COW of unbacked chunk");
    let old_end = old_logical + old_run.len;
    let chunk_end = chunk_start + inner.geo.chunk_size();

    inner.runs.remove(&old_logical);
    if old_logical < chunk_start {
        // The prefix keeps the extent; its capacity ends where the chunk
        // begins (the chunk's old block is deferred-freed separately).
        inner.runs.insert(
            old_logical,
            RunMeta {
                len: chunk_start - old_logical,
                capacity: chunk_start - old_logical,
                ..old_run
            },
        );
    }
    if old_end > chunk_end {
        inner.runs.insert(
            chunk_end,
            RunMeta {
                physical: old_run.physical + (chunk_end - old_logical),
                len: old_end - chunk_end,
                capacity: old_run.capacity.saturating_sub(chunk_end - old_logical),
                born: old_run.born,
            },
        );
    }
    inner.runs.insert(chunk_start, fresh);
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

/// Decode a checksum extent's big-endian CRC values.
pub(super) fn decode_crcs(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
}

/// Read the value window `[w0, w1)` (chunk indexes relative to
/// `r.first_chunk`) of committed checksum extent `r`. With `verify` set,
/// the WHOLE extent is streamed to compute its guard CRC, returned for the
/// caller to check. Otherwise only the window's bytes are read.
async fn read_ref_window<S: crate::Storage>(
    ready: &Ready<S>,
    r: &ChecksumRef,
    w0: u64,
    w1: u64,
    verify: bool,
) -> Result<(Vec<u32>, Option<u32>), Error> {
    if !verify {
        let bytes = ready
            .file
            .read_at(r.offset + w0 * 4, ((w1 - w0) * 4) as usize)
            .await?
            .coalesce();
        return Ok((decode_crcs(bytes.as_ref()).collect(), None));
    }
    /// Streaming step for guard verification of large extents.
    const STEP: u64 = 1 << 22;
    let mut hasher = Crc32::new();
    let mut values = Vec::with_capacity((w1 - w0) as usize);
    let total = r.count as u64 * 4;
    let mut pos = 0;
    while pos < total {
        let len = STEP.min(total - pos);
        let bytes = ready.file.read_at(r.offset + pos, len as usize).await?;
        let bytes = bytes.coalesce();
        hasher.update(bytes.as_ref());
        // Capture the window's intersection with this step.
        let lo = (w0 * 4).max(pos);
        let hi = (w1 * 4).min(pos + len);
        if hi > lo {
            values.extend(decode_crcs(
                &bytes.as_ref()[(lo - pos) as usize..(hi - pos) as usize],
            ));
        }
        pos += len;
    }
    Ok((values, Some(hasher.finalize().as_u32())))
}

/// Load the committed-CRC page covering `chunk` from the blob's checksum
/// extents into its cache, returning the loaded window as
/// `(first chunk, values)`.
///
/// Returns `Ok(None)` when the chunk no longer holds an unloaded CRC
/// (rewritten or shrunk away meanwhile): the caller re-derives its plan.
///
/// The extent's guard CRC is verified on the first touch of each ref (the
/// whole extent is streamed once). Later loads from the same ref read just
/// the page window. Loads race commits, which swap the committed entry and
/// release superseded extents for reuse: like the data path's generation
/// protocol, the ref is re-checked against the then-current committed
/// entry after the read, and `commit::finalize` swaps entries BEFORE
/// applying frees, so a ref that is still referenced was never freed
/// during the read. A removed blob's extents are gated on its open handles
/// (every caller reaches this through one).
///
/// Callers box this future (a cold path): inlining its streaming reads
/// would deepen every read and write future's layout.
pub(super) async fn load_committed_page<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    chunk: u64,
) -> Result<Option<(u64, Vec<u32>)>, Error> {
    loop {
        let (r, verify) = {
            let inner = blob.inner.lock();
            match inner.crcs.get(chunk).map(|s| s.crc) {
                Some(ChunkCrc::Unloaded) => {}
                _ => return Ok(None),
            }
            let covering = inner.committed_entry.as_ref().and_then(|e| {
                e.checksums
                    .iter()
                    .find(|r| r.first_chunk <= chunk && chunk < r.first_chunk + r.count as u64)
            });
            let Some(r) = covering else {
                // Hydration validates that the committed refs cover every
                // committed chunk, and residency is never revoked: an
                // unloaded chunk outside the refs is a bug, never a
                // reachable disk state.
                unreachable!("unloaded chunk outside committed checksum coverage")
            };
            (*r, !inner.crc_guarded.contains(r))
        };
        let page = chunk / CRC_PAGE_CHUNKS;
        let w0 = (page * CRC_PAGE_CHUNKS).max(r.first_chunk) - r.first_chunk;
        let w1 = ((page + 1) * CRC_PAGE_CHUNKS).min(r.first_chunk + r.count as u64) - r.first_chunk;
        let (values, guard) = read_ref_window(ready, &r, w0, w1, verify).await?;
        {
            let mut inner = blob.inner.lock();
            // A commit swapped the entry mid-read (the extent may have been
            // recycled): retry against the current refs.
            if !inner
                .committed_entry
                .as_ref()
                .is_some_and(|e| e.checksums.contains(&r))
            {
                continue;
            }
            if let Some(guard) = guard {
                if guard != r.crc {
                    return Err(Error::BlobCorrupt(
                        blob.partition.clone(),
                        hex(&blob.name),
                        "checksum extent mismatch".into(),
                    ));
                }
                if !inner.crc_guarded.contains(&r) {
                    inner.crc_guarded.push(r);
                }
            }
            inner.crc_cache.insert(r.first_chunk + w0, values.clone());
        }
        return Ok(Some((r.first_chunk + w0, values)));
    }
}

/// Load the full contents of the committed checksum refs `refs`
/// (guard-verified) for a capture's read-modify-write of a full checksum
/// rewrite: chunks untouched this process keep their CRC only on disk, and
/// re-encoding the array needs every value. The caller must hold the
/// commit lock and the blob's write lock, under which the refs' extents
/// stay referenced (their frees are queued by this capture at the earliest
/// and applied only once this commit confirms).
pub(super) async fn load_committed_refs<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    refs: &[ChecksumRef],
) -> Result<Vec<(u64, Vec<u32>)>, Error> {
    let mut out = Vec::with_capacity(refs.len());
    for r in refs {
        let (values, guard) = read_ref_window(ready, r, 0, r.count as u64, true).await?;
        if guard.expect("full reads verify") != r.crc {
            return Err(Error::BlobCorrupt(
                blob.partition.clone(),
                hex(&blob.name),
                "checksum extent mismatch".into(),
            ));
        }
        let mut inner = blob.inner.lock();
        if !inner.crc_guarded.contains(r) {
            inner.crc_guarded.push(*r);
        }
        out.push((r.first_chunk, values));
    }
    Ok(out)
}

/// The committed value of `chunk` within loaded windows (sorted by first
/// chunk, non-overlapping).
pub(super) fn window_value(windows: &[(u64, Vec<u32>)], chunk: u64) -> Option<u32> {
    let i = windows.partition_point(|(first, _)| *first <= chunk);
    let (first, values) = &windows[i.checked_sub(1)?];
    values.get((chunk - first) as usize).copied()
}

/// Insert `window` into a sorted window list (replacing an identical
/// start).
fn insert_window(windows: &mut Vec<(u64, Vec<u32>)>, window: (u64, Vec<u32>)) {
    let i = windows.partition_point(|(first, _)| *first < window.0);
    if windows.get(i).is_some_and(|(first, _)| *first == window.0) {
        windows[i] = window;
    } else {
        windows.insert(i, window);
    }
}

/// Cap on one coalesced inner read issued by [`read_verified`].
const MAX_READ_SPAN: u64 = 1 << 20;

/// One coalesced inner read: a physically and logically contiguous byte
/// range covering the requested slices of verified chunks (read exactly)
/// and the whole written spans of unverified chunks (block-aligned at both
/// ends within the run), so a single read serves the request and carries
/// everything needed to verify every unverified chunk it touches.
struct ReadGroup {
    /// Physical read position.
    physical: u64,
    /// Logical position of the first byte read.
    logical: u64,
    /// Read length in bytes.
    len: u64,
    /// Chunks this read verifies: (chunk logical start, span len, expected
    /// CRC), ascending. Each span lies fully inside the read.
    checks: Vec<(u64, u64, u32)>,
}

impl ReadGroup {
    /// Whether every chunk this group reads is CRC-checked. When false,
    /// some bytes are served on the strength of a prior verification and a
    /// relocation racing the read (whose extent may have been recycled)
    /// forces a retry.
    const fn all_checked(&self, geo: Geometry) -> bool {
        let chunks = geo.chunk_of(self.logical + self.len - 1) - geo.chunk_of(self.logical) + 1;
        self.checks.len() as u64 == chunks
    }
}

/// A derived read plan: the coalesced inner reads (with the chunks each
/// verifies), overlay copies of the requested slices of pending chunks, and
/// the relocation generation the plan is valid against.
struct ReadPlan {
    generation: u64,
    /// The blob's chunk geometry, carried (it is immutable) so post-plan
    /// chunk math needs no lock.
    geo: Geometry,
    /// The first coalesced read. Held out of `rest` so the by-far-common
    /// single-read plan allocates nothing.
    head: Option<ReadGroup>,
    /// Further coalesced reads (fragmented plans only).
    rest: Vec<ReadGroup>,
    /// Overlay copies of pending chunks: (logical start, bytes).
    splices: Vec<(u64, Vec<u8>)>,
}

/// A [`plan_read`] outcome: a servable plan, or the chunks whose committed
/// CRCs must be loaded from disk before one can be derived.
enum Planned {
    Plan(ReadPlan),
    Missing(Vec<u64>),
}

/// Derive the read plan for `[offset, end)` under the blob's state lock.
///
/// Runs and chunk states are walked with two linear range scans in logical
/// order — no per-chunk point queries. Verified chunks contribute exactly
/// the requested bytes of their span (their CRC is never consulted).
/// Unverified chunks contribute their whole written span, block-aligned
/// within the run, which the read then CRC-verifies: every read doubles as
/// verification progress. An unverified chunk's expected CRC comes from
/// its resident value, the caller's loaded windows, or the committed-CRC
/// cache. Chunks with none yield [`Planned::Missing`] and the caller loads
/// their pages from the checksum extents before re-planning. Segments
/// coalesce into one read whenever physically and logically contiguous —
/// verified and unverified alike — bounded by [`MAX_READ_SPAN`].
fn plan_read(inner: &mut BlobInner, offset: u64, end: u64, loaded: &[(u64, Vec<u32>)]) -> Planned {
    // Steady-state fast path: a request covered by one run whose every
    // chunk is verified with a ready CRC is a single exact read — no
    // chunk-state walk at all. Proven volume-wide in O(1) when every
    // backed chunk is verified, or per span otherwise (word-at-a-time over
    // the requested chunks), so never-read ranges elsewhere in the blob do
    // not tax reads of verified territory. Other shapes (holes, run
    // boundaries, unverified or pending chunks in the span) take the full
    // scan.
    let geo = inner.geo;
    let first = geo.chunk_of(offset);
    let last = geo.chunk_of(end - 1);
    if let Some((l, r)) = inner.covering(offset) {
        if end <= l + r.len && (inner.crcs.all_verified() || inner.crcs.span_verified(first, last))
        {
            return Planned::Plan(ReadPlan {
                generation: inner.generation,
                geo,
                head: Some(ReadGroup {
                    physical: r.physical + (offset - l),
                    logical: offset,
                    len: end - offset,
                    checks: Vec::new(),
                }),
                rest: Vec::new(),
                splices: Vec::new(),
            });
        }
    }
    let mut head: Option<ReadGroup> = None;
    let mut rest: Vec<ReadGroup> = Vec::new();
    // Requested slices of pending chunks: (logical start, copy end).
    let mut pending: Vec<(u64, u64)> = Vec::new();
    // Unverified chunks whose expected CRC is not in RAM.
    let mut missing: Vec<u64> = Vec::new();
    {
        // The chunk-state walk borrows the map while the committed-CRC
        // cache is consulted mutably (LRU stamps): split the fields.
        let BlobInner {
            runs: all_runs,
            crcs,
            crc_cache,
            ..
        } = inner;
        // Track the covering run alongside the chunk walk: start at the run
        // at or before the first chunk and advance as chunks pass.
        let start = all_runs
            .range(..=first * geo.chunk_size())
            .next_back()
            .map_or(first * geo.chunk_size(), |(&l, _)| l);
        let mut runs = all_runs.range(start..);
        let mut run: Option<(u64, RunMeta)> = None;
        for (chunk, state) in crcs.iter_range(first, last) {
            let chunk_start = chunk * geo.chunk_size();
            while run.is_none_or(|(l, r)| l + r.len <= chunk_start) {
                match runs.next() {
                    Some((&l, &r)) => run = Some((l, r)),
                    None => break,
                }
            }
            // Runs and chunk states are updated together under the state
            // lock: a chunk state without a covering run is a bug, never a
            // reachable disk state.
            let Some((l, r)) = run.filter(|&(l, r)| l <= chunk_start && chunk_start < l + r.len)
            else {
                unreachable!("chunk state without a covering run")
            };
            let span = (l + r.len - chunk_start).min(geo.chunk_size());
            let lo = offset.max(chunk_start);
            let hi = end.min(chunk_start + span);
            if state.crc == ChunkCrc::Pending {
                // Pending chunk: the overlay is authoritative (there is no
                // finalized CRC to verify a disk read against), so serve
                // its bytes directly. Bytes past the span within the chunk
                // are holes (zeros already in place).
                if hi > lo {
                    pending.push((lo, hi));
                }
                continue;
            }
            let (seg_lo, seg_hi, check) = if state.verified {
                // Bytes past the span within the chunk are holes (zeros
                // already in place). The request may fall entirely in them.
                if hi <= lo {
                    continue;
                }
                (lo, hi, None)
            } else {
                let crc = match state.crc {
                    ChunkCrc::Ready(crc) => Some(crc),
                    ChunkCrc::Unloaded => {
                        window_value(loaded, chunk).or_else(|| crc_cache.get(chunk))
                    }
                    ChunkCrc::Pending => unreachable!("pending chunks are handled above"),
                };
                let Some(crc) = crc else {
                    missing.push(chunk);
                    continue;
                };
                (
                    chunk_start,
                    chunk_start + span,
                    Some((chunk_start, span, crc)),
                )
            };
            let physical = r.physical + (seg_lo - l);
            let tail = if rest.is_empty() {
                head.as_mut()
            } else {
                rest.last_mut()
            };
            match tail {
                Some(g)
                    if g.physical + g.len == physical
                        && g.logical + g.len == seg_lo
                        && g.len + (seg_hi - seg_lo) <= MAX_READ_SPAN =>
                {
                    g.len += seg_hi - seg_lo;
                    g.checks.extend(check);
                }
                _ => {
                    let group = ReadGroup {
                        physical,
                        logical: seg_lo,
                        len: seg_hi - seg_lo,
                        checks: check.into_iter().collect(),
                    };
                    if head.is_none() {
                        head = Some(group);
                    } else {
                        rest.push(group);
                    }
                }
            }
        }
    }
    if !missing.is_empty() {
        return Planned::Missing(missing);
    }
    // Copy the pending slices out of the overlay under the same lock as the
    // plan (coherent regardless of racing writers). A separate mutable pass:
    // overlay reads refresh LRU stamps.
    let splices = pending
        .into_iter()
        .map(|(lo, hi)| {
            let chunk = geo.chunk_of(lo);
            let base = chunk * geo.chunk_size();
            let bytes = inner
                .overlay_get(chunk)
                .expect("pending chunk is overlay-resident");
            (
                lo,
                bytes[(lo - base) as usize..(hi - base) as usize].to_vec(),
            )
        })
        .collect();
    Planned::Plan(ReadPlan {
        generation: inner.generation,
        geo,
        head,
        rest,
        splices,
    })
}

/// Publish the chunks a read verified — only where the state each was
/// checked against still stands — and decide whether the read's outcome is
/// servable. Returns false when a relocation (whose extent may have been
/// recycled) raced the read under bytes served unchecked: the caller must
/// retry. A read whose every byte was CRC-checked stands regardless — a
/// matching checksum proves the planned content.
fn publish_read(blob: &BlobCore, generation: u64, checked: &[(u64, u32)], unchecked: bool) -> bool {
    let mut inner = blob.inner.lock();
    if inner.generation != generation {
        return !unchecked;
    }
    for &(chunk, crc) in checked {
        inner.crcs.mark_verified(chunk, crc);
    }
    true
}

/// Verified read of `[offset, offset + len)`.
///
/// The plan (see [`plan_read`]) reads verified chunks exactly and
/// unverified chunks as whole block-aligned spans, verifying them
/// opportunistically. When the whole request is served by ONE inner read
/// with no widening, the read is zero-copy: the inner read buffer is
/// returned directly, or the caller's buffers (the
/// [`crate::Blob::read_at_buf`] path) are passed straight to the inner
/// blob's `read_at_buf` and any CRC checks run in place. Every other shape
/// reads into pool scratch and copies into the caller's buffers once at
/// the end. The returned buffers always hold exactly `len` bytes with the
/// chunk layout preserved (holes read as zeros).
///
/// Reads take no locks across I/O. A CRC mismatch under an unchanged
/// generation quiesces the (single) writer and re-verifies the chunk
/// before reporting corruption: in-place rewrites of uncommitted bytes are
/// legal and move no generation. Extent reuse or an in-place rewrite under
/// an in-flight read causes a retry, never a false corruption report.
pub(super) async fn read_verified<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    offset: u64,
    len: usize,
    mut caller: Option<IoBufsMut>,
) -> Result<IoBufsMut, Error> {
    ready.check_poisoned()?;
    let end = offset
        .checked_add(len as u64)
        .ok_or(Error::OffsetOverflow)?;

    // Committed-CRC windows loaded for this read (see below), kept across
    // retries: an unloaded chunk's committed value is immutable, so the
    // windows stay valid whatever the retry re-plans.
    let mut loaded: Vec<(u64, Vec<u32>)> = Vec::new();
    'retry: loop {
        let planned = {
            let mut inner = blob.inner.lock();
            if end > inner.size {
                return Err(Error::BlobInsufficientLength);
            }
            if len == 0 {
                return Ok(caller.take().map_or_else(IoBufsMut::default, |mut bufs| {
                    // SAFETY: zero bytes need no initialization.
                    unsafe { bufs.set_len(0) };
                    bufs
                }));
            }
            plan_read(&mut inner, offset, end, &loaded)
        };
        let plan = match planned {
            Planned::Plan(plan) => plan,
            // Unverified chunks whose expected CRC is neither resident nor
            // cached: load their committed pages, then re-plan.
            Planned::Missing(chunks) => {
                for chunk in chunks {
                    if window_value(&loaded, chunk).is_some() {
                        continue;
                    }
                    if let Some(window) = Box::pin(load_committed_page(ready, blob, chunk)).await? {
                        insert_window(&mut loaded, window);
                    }
                }
                continue 'retry;
            }
        };
        let generation = plan.generation;

        // Fast path: ONE inner read serving exactly the request (no
        // widening, no overlay splices). The read lands directly in the
        // caller's buffers (or the inner read buffer is returned as is) and
        // unverified chunks are CRC-checked in place. Checks need one
        // contiguous view, so multi-buffer callers with checks take the
        // pooled path below.
        if let (Some(group), []) = (&plan.head, plan.rest.as_slice()) {
            let exact = group.logical == offset && group.len == len as u64;
            let contiguous = caller.as_ref().is_none_or(IoBufsMut::is_single);
            if plan.splices.is_empty() && exact && (group.checks.is_empty() || contiguous) {
                let from_caller = caller.is_some();
                let bufs = match caller.take() {
                    Some(bufs) => ready.file.read_at_buf(group.physical, len, bufs).await?,
                    None => ready.file.read_at(group.physical, len).await?,
                };
                // An inner `read_at` may return a multi-buffer result:
                // coalesce it for the CRC pass (single buffers are free).
                let bufs = if group.checks.is_empty() || bufs.is_single() {
                    bufs
                } else {
                    IoBufsMut::from(bufs.coalesce())
                };
                let mut ok = true;
                let mut checked: Vec<(u64, u32)> = Vec::with_capacity(group.checks.len());
                if !group.checks.is_empty() {
                    let view = bufs.as_single().expect("coalesced above").as_ref();
                    for &(chunk_start, span, crc) in &group.checks {
                        let at = (chunk_start - group.logical) as usize;
                        if Crc32::checksum(&view[at..at + span as usize]) != crc {
                            ok = false;
                            break;
                        }
                        checked.push((plan.geo.chunk_of(chunk_start), crc));
                    }
                }
                if ok {
                    if publish_read(blob, generation, &checked, !group.all_checked(plan.geo)) {
                        return Ok(bufs);
                    }
                    // The backing relocated (and may have been recycled)
                    // while the read was in flight: re-derive the plan (the
                    // new backing may no longer qualify for this path).
                    // Re-issuing into the same caller buffers is fine: only
                    // the returned state matters.
                    if from_caller {
                        caller = Some(bufs);
                    }
                    continue 'retry;
                }
                // A CRC mismatch (a racing in-place writer, or corruption):
                // fall through to the pooled path, whose quiesce protocol
                // settles which.
                if from_caller {
                    caller = Some(bufs);
                }
            }
        }

        let mut out = ready.pool.alloc_zeroed(len);
        // Chunks this read verified, with the CRC each was checked against
        // (published under the state lock below).
        let mut checked: Vec<(u64, u32)> = Vec::new();
        let mut unchecked = false;
        for group in plan.head.iter().chain(&plan.rest) {
            let bytes = ready
                .file
                .read_at(group.physical, group.len as usize)
                .await?
                .coalesce()
                .freeze();
            // Copy the requested intersection in one pass (verified slices
            // and the requested parts of checked chunks alike). Bytes
            // outside the request — unverified-span widening — serve
            // verification only.
            let r0 = offset.max(group.logical);
            let r1 = end.min(group.logical + group.len);
            if r1 > r0 {
                out.as_mut()[(r0 - offset) as usize..(r1 - offset) as usize].copy_from_slice(
                    &bytes.as_ref()[(r0 - group.logical) as usize..(r1 - group.logical) as usize],
                );
            }
            unchecked |= !group.all_checked(plan.geo);
            for &(chunk_start, span, crc) in &group.checks {
                let at = (chunk_start - group.logical) as usize;
                if Crc32::checksum(&bytes.as_ref()[at..at + span as usize]) == crc {
                    checked.push((plan.geo.chunk_of(chunk_start), crc));
                    continue;
                }
                {
                    let inner = blob.inner.lock();
                    if inner.generation != generation {
                        continue 'retry;
                    }
                }
                // Not a relocation. A writer may legally have rewritten
                // this chunk in place (uncommitted bytes and young extents
                // are not frozen), which moves neither the generation nor,
                // mid-write, the expected CRC: quiesce the (single) writer
                // and re-verify the chunk against its now-stable state
                // before reporting corruption.
                let chunk = plan.geo.chunk_of(chunk_start);
                let _quiesce = blob.write_lock.lock().await;
                /// A quiesced chunk's stable content source.
                enum Stable {
                    Disk { phys: u64, span: u64, crc: u32 },
                    Ram(Vec<u8>),
                }
                let source = loop {
                    let need_load = {
                        let mut inner = blob.inner.lock();
                        if inner.generation != generation {
                            continue 'retry;
                        }
                        match inner.chunk_span(chunk) {
                            None => break None,
                            Some((phys, span)) => {
                                let state = inner.crcs.get(chunk).expect("backed chunk has crc");
                                match state.crc {
                                    ChunkCrc::Ready(crc) => {
                                        break Some(Stable::Disk { phys, span, crc })
                                    }
                                    // The racing writer left the chunk
                                    // pending: its overlay entry is the
                                    // stable content.
                                    ChunkCrc::Pending => {
                                        break Some(Stable::Ram(
                                            inner
                                                .overlay_get(chunk)
                                                .expect("pending chunk is overlay-resident")
                                                .to_vec(),
                                        ))
                                    }
                                    // Untouched since hydration: the stable
                                    // CRC is the committed value.
                                    ChunkCrc::Unloaded => {
                                        match window_value(&loaded, chunk)
                                            .or_else(|| inner.crc_cache.get(chunk))
                                        {
                                            Some(crc) => {
                                                break Some(Stable::Disk { phys, span, crc })
                                            }
                                            None => true,
                                        }
                                    }
                                }
                            }
                        }
                    };
                    debug_assert!(need_load);
                    if let Some(window) = Box::pin(load_committed_page(ready, blob, chunk)).await? {
                        insert_window(&mut loaded, window);
                    }
                };
                let stable: IoBuf = match source {
                    None => continue 'retry,
                    Some(Stable::Disk {
                        phys,
                        span: stable_span,
                        crc: stable_crc,
                    }) => {
                        let reread = ready
                            .file
                            .read_at(phys, stable_span as usize)
                            .await?
                            .coalesce()
                            .freeze();
                        if Crc32::checksum(reread.as_ref()) != stable_crc {
                            return Err(Error::BlobCorrupt(
                                blob.partition.clone(),
                                hex(&blob.name),
                                format!("chunk {chunk} checksum mismatch"),
                            ));
                        }
                        checked.push((chunk, stable_crc));
                        reread
                    }
                    // Served from process memory: nothing was verified
                    // against the disk.
                    Some(Stable::Ram(stable_bytes)) => IoBuf::from(stable_bytes),
                };
                // Replace what the group copy installed for this chunk: the
                // corrected requested slice, and zeros where the stable
                // span ends short of the copied extent.
                let c0 = offset.max(chunk_start);
                let c1 = end.min(chunk_start + stable.len() as u64).max(c0);
                let copied_hi = end.min(chunk_start + span).max(c0);
                if c1 > c0 {
                    out.as_mut()[(c0 - offset) as usize..(c1 - offset) as usize].copy_from_slice(
                        &stable.as_ref()[(c0 - chunk_start) as usize..(c1 - chunk_start) as usize],
                    );
                }
                if copied_hi > c1 {
                    out.as_mut()[(c1 - offset) as usize..(copied_hi - offset) as usize].fill(0);
                }
            }
        }

        // Serve pending chunks from their overlay copies.
        for (lo, bytes) in &plan.splices {
            let at = (lo - offset) as usize;
            out.as_mut()[at..at + bytes.len()].copy_from_slice(bytes);
        }

        if !publish_read(blob, generation, &checked, unchecked) {
            continue 'retry;
        }
        return Ok(match caller.take() {
            Some(mut bufs) => {
                // SAFETY: `len` bytes are filled via copy_from_slice below.
                unsafe { bufs.set_len(len) };
                bufs.copy_from_slice(out.as_ref());
                bufs
            }
            None => out.into(),
        });
    }
}

/// Resize to `len`. The blob's `write_lock` MUST be held.
pub(super) async fn resize_locked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    len: u64,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    let (old_size, geo) = {
        let inner = blob.inner.lock();
        (inner.size, inner.geo)
    };

    if len >= old_size {
        // Zero extension: physically zero the backed portion of the
        // boundary chunk in [old_size, len) through the normal write path
        // (the residue there is arbitrary and the table would otherwise
        // vouch for zeros it never wrote); unbacked regions become holes.
        let zero_to = {
            let inner = blob.inner.lock();
            let boundary = geo.chunk_of(old_size);
            match inner.chunk_span(boundary) {
                Some(_) if !old_size.is_multiple_of(geo.chunk_size()) => {
                    ((boundary + 1) * geo.chunk_size()).min(len)
                }
                _ => old_size,
            }
        };
        if zero_to > old_size {
            let zeros = IoBuf::copy_from_slice(&vec![0u8; (zero_to - old_size) as usize]);
            write_locked(ready, blob, old_size, zeros).await?;
        }
        let mut state = ready.state.lock();
        let mut inner = blob.inner.lock();
        inner.size = inner.size.max(len);
        state.dirty.insert(blob.id);
        return Ok(());
    }

    // Shrink: drop runs beyond the new size, trim the boundary run, refresh
    // the boundary chunk's CRC + tail buffer. Dropped extents are
    // capture-gated: the confirmed table may still reference them through
    // this blob's cached committed entry.
    {
        let mut state = ready.state.lock();
        let mut inner = blob.inner.lock();

        // Deferred CRCs and overlay entries do not survive a shrink (spans
        // at and beyond the boundary move): finalize every pending chunk,
        // then drop the overlay wholesale (resize is cold).
        inner.overlay_finalize();
        inner.overlay.clear();

        let dropped: Vec<u64> = inner.runs.range(len..).map(|(&l, _)| l).collect();
        for l in dropped {
            let run = inner.runs.remove(&l).unwrap();
            inner.pending_frees.push(Extent {
                offset: run.physical,
                len: run.capacity,
            });
        }
        if let Some((l, _)) = inner.covering(len.saturating_sub(1)).filter(|_| len > 0) {
            let run = inner.runs.get_mut(&l).unwrap();
            if l + run.len > len {
                run.len = len - l;
                // Keep the capacity a whole number of chunks (the geometry
                // invariant): a later append grows in place to the chunk
                // boundary instead of starting a run mid-chunk.
                let keep = geo.chunk_align(run.len);
                if run.capacity > keep {
                    let trimmed = Extent {
                        offset: run.physical + keep,
                        len: run.capacity - keep,
                    };
                    run.capacity = keep;
                    inner.pending_frees.push(trimmed);
                }
            }
        }
        if len == 0 {
            inner.crcs.clear();
            inner.dirty_chunks.clear();
            inner.tail.clear();
            inner.tail_chunk = 0;
        } else {
            let boundary = geo.chunk_of(len - 1);
            inner.crcs.truncate(boundary);
            inner.dirty_chunks.retain(|&c| c <= boundary);
            inner.dirty_chunks.insert(boundary);
        }
        inner.generation += 1;
        inner.size = len;
        state.dirty.insert(blob.id);
    }

    // Recompute the boundary chunk's CRC/tail from its (unchanged) bytes.
    if len > 0 {
        let boundary = geo.chunk_of(len - 1);
        let span = {
            let inner = blob.inner.lock();
            inner.chunk_span(boundary)
        };
        if let Some((phys, span_len)) = span {
            let bytes = ready
                .file
                .read_at(phys, span_len as usize)
                .await?
                .coalesce();
            let mut inner = blob.inner.lock();
            // Recomputed from an unchecked read-back: the boundary chunk
            // stays unverified (see [`ChunkState`]).
            let state = ChunkState {
                crc: ChunkCrc::Ready(Crc32::checksum(bytes.as_ref())),
                verified: false,
            };
            inner.crcs.insert(boundary, state);
            inner.tail_chunk = boundary;
            inner.tail = bytes.as_ref().to_vec();
        }
    }
    Ok(())
}

/// Convenience: total pending-free bytes (metrics/tests).
#[allow(dead_code)]
pub(super) fn pending_free_bytes(state: &State) -> u64 {
    state.pending_free.iter().map(|(e, _, _)| e.len).sum()
}
