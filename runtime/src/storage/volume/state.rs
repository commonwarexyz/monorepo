//! The volume's mutable data model: per-blob state, volume-wide state, and
//! the post-recovery handle every operation threads.
//!
//! Locking:
//! - [`State`] and each blob's [`BlobInner`] sit behind synchronous
//!   mutexes, never held across an await.
//! - Each blob has an async `write_lock` serializing its mutations (and the
//!   commit snapshotter) across inner I/O — this keeps chunk CRC state
//!   coherent with issued bytes. Under it, writers interleave brief
//!   state-lock sections with I/O freely.
//! - Lock order, outermost first: the namespace lock ([`Shared::ns_lock`]),
//!   the commit lock ([`Ready::commit_lock`]), a blob's `write_lock`,
//!   [`Ready::state`], a blob's `inner`. A holder may skip levels but never
//!   acquires an earlier lock while holding a later one. Two short-hold
//!   mutexes sit outside the chain: [`Ready::pending`] is taken alone or
//!   directly under the commit lock, and `provision_lock` is taken ahead of
//!   `state` on the write path.
//!
//! The data paths document their own protocols: write placement and the
//! freeze rule in `write`, the lock-free reader protocol in `read`, lazy
//! committed-CRC loading in `paging`.

use super::{
    alloc::{block_align, Allocator, Extent},
    chunk::{chunk_of, merge_frozen_runs, ChunkCrc, ChunkMap, ChunkState, CrcCache, RunMeta},
    layout::{ChecksumRef, Entry},
    Config, Driver, OrderedMap, OrderedSet, BLOCK,
};
use crate::{telemetry::metrics::GaugeExt as _, Blob as _, BufferPool, Error};
use bytes::Bytes;
use commonware_cryptography::Crc32;
use commonware_formatting::hex;
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

/// Cap on a blob's overlay entries (chunks kept in RAM for deferred CRCs).
///
/// Sized to cover the sub-block-rewrite working set of a table-like blob
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

/// Per-blob mutable state.
#[derive(Debug, Default)]
pub(super) struct BlobInner {
    /// Current logical size (includes uncommitted writes).
    size: u64,
    /// Freeze boundary: bytes below are covered by the last confirmed table
    /// or the in-flight snapshot.
    freeze_size: u64,
    /// Pruned floor: bytes below were dropped, and reads, writes, and
    /// resizes into them fail. Byte-exact and monotonic in RAM (the
    /// committed floor regresses across a crash to the adopted commit's);
    /// physical state below is chunk-granular — the floor's own chunk
    /// stays backed with its low bytes logically dead.
    floor: u64,
    /// Written runs keyed by logical start; gaps are holes (zeros).
    /// Aliased so Kani proofs run over the solver-friendly container.
    runs: OrderedMap<u64, RunMeta>,
    /// Checksum state per backed chunk, over the chunk's written span.
    crcs: ChunkMap,
    /// Bytes of the frontier chunk's written span (from its chunk base),
    /// kept in memory so append CRCs and commit shadows never read back.
    /// Meaningful only when `tail_chunk` is backed.
    tail: Vec<u8>,
    /// Chunk `tail` describes.
    tail_chunk: u64,
    /// The tail buffer generalized: full span bytes of recently
    /// splice-rewritten chunks, bounded by [`OVERLAY_CHUNKS`] (LRU). Entries
    /// are populated by writes only (never by reads) and mirror the disk
    /// (every write is written through); a [`ChunkCrc::Pending`] chunk is
    /// always resident, and its entry is the authoritative source for CRC
    /// finalization, reads, prefix/suffix sourcing, and COW.
    /// Aliased so Kani proofs run over the solver-friendly container.
    overlay: OrderedMap<u64, OverlayEntry>,
    /// Monotonic clock for overlay LRU stamps.
    overlay_clock: u64,
    /// Chunks whose content changed since the last snapshot.
    /// Aliased so Kani proofs run over the solver-friendly container.
    dirty_chunks: OrderedSet<u64>,
    /// Committed CRC pages loaded for verification (bounded LRU).
    crc_cache: CrcCache,
    /// Committed checksum refs whose extent guard was verified this
    /// process (or whose bytes this process assembled and wrote, see
    /// `commit::finalize`). Loads from a guarded ref read only the page
    /// window they need instead of streaming the whole extent.
    crc_guarded: Vec<ChecksumRef>,
    /// Bumped on any relocation/drop of backing (COW, resize-down, remove).
    generation: u64,
    /// Durable shadow block from the last commit covering this blob.
    shadow: Option<u64>,
    /// The entry the last confirmed commit wrote for this blob (None until
    /// first committed with content). Used verbatim for blobs a commit does
    /// not capture — never derived from live state, which may already
    /// contain uncommitted writes.
    committed_entry: Option<Entry>,
    /// Extents dropped by uncommitted state changes (COW, resize-down),
    /// released once a commit CAPTURING this blob confirms. Freeing at the
    /// next commit would recycle extents that commit's table (serving this
    /// blob's cached committed entry) still references.
    pending_frees: Vec<Extent>,
    /// Batches currently holding staged state for this blob. While nonzero,
    /// snapshot capture must not merge this blob's runs: staged overlays
    /// (see [`StagedBlob`]) reference base runs by key.
    staged_batches: usize,
    /// Captured by an in-flight commit whose finalize has not run yet: the
    /// blob's next committed entry exists only in the snapshot, so it must
    /// not be demoted against the stale one (see [`State::maybe_demote`]).
    capturing: bool,
    /// Unlinked from the namespace (handles may still read).
    removed: bool,
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
    /// a hole. Every chunk is covered by at most one run.
    pub fn chunk_span(&self, chunk: u64) -> Option<(u64, u64)> {
        let chunk_start = chunk * BLOCK;
        let (logical, run) = self.covering(chunk_start)?;
        let span = (logical + run.len - chunk_start).min(BLOCK);
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
    /// the least-recently-used entry beyond the cap.
    pub fn overlay_insert(&mut self, chunk: u64, bytes: Vec<u8>) {
        self.overlay_clock += 1;
        let stamp = self.overlay_clock;
        self.overlay.insert(chunk, OverlayEntry { stamp, bytes });
        if self.overlay.len() > OVERLAY_CHUNKS {
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

    /// Assert this blob's structural invariants (tests only): run geometry, tail-buffer coherence with the last backed
    /// chunk (the invariant whose silent violation produced the
    /// stale-shadow data loss), chunk-state coverage, counter exactness,
    /// and overlay residency.
    #[cfg(test)]
    pub fn audit(&self) {
        // Run geometry: aligned starts, non-overlapping, exact capacity.
        let mut prev_end = 0;
        for (&logical, run) in &self.runs {
            assert!(
                logical.is_multiple_of(BLOCK) && run.physical.is_multiple_of(BLOCK),
                "unaligned run at {logical}"
            );
            assert!(run.len > 0, "empty run at {logical}");
            // Exact capacity is load-bearing: the COW remaps free only the
            // replaced chunk's block and flow the rest of the extent into
            // the split runs, so slack beyond the aligned length would be
            // orphaned (the staged-shrink leak this audit found).
            assert_eq!(
                run.capacity,
                block_align(run.len),
                "capacity slack at {logical}"
            );
            assert!(logical >= prev_end, "overlapping runs at {logical}");
            prev_end = logical + run.len;
        }

        // Pruned floor: within the size, with no run or tracked chunk
        // state below its chunk (the floor itself may sit mid-chunk: the
        // straddling chunk stays backed, its low bytes logically dead).
        assert!(self.floor <= self.size, "floor beyond size");
        let floor_chunk = chunk_of(self.floor);
        if let Some((&first, _)) = self.runs.first_key_value() {
            assert!(first >= floor_chunk * BLOCK, "run below the floor's chunk");
        }
        assert!(
            self.dirty_chunks.first().is_none_or(|&c| c >= floor_chunk),
            "dirty chunk below the floor"
        );
        assert!(
            self.overlay.keys().next().is_none_or(|&c| c >= floor_chunk),
            "overlay entry below the floor"
        );

        // Tail coherence: the buffer always describes the last BACKED
        // chunk's exact span (or is empty when nothing is backed).
        match self.runs.iter().next_back() {
            None => assert!(self.tail.is_empty(), "tail buffer without backing"),
            Some((&logical, run)) => {
                let last = chunk_of(logical + run.len - 1);
                let (_, span) = self.chunk_span(last).expect("last chunk is backed");
                assert_eq!(self.tail_chunk, last, "tail buffer desynced from runs");
                assert_eq!(self.tail.len() as u64, span, "tail span desynced from runs");
            }
        }

        // Chunk-state coverage matches the backed chunks exactly, and the
        // running unverified/pending counters match a recount.
        self.crcs.audit();
        let max = self
            .runs
            .iter()
            .next_back()
            .map_or(0, |(&l, r)| chunk_of(l + r.len - 1) + 1);
        for chunk in 0..=max {
            assert_eq!(
                self.crcs.get(chunk).is_some(),
                self.chunk_span(chunk).is_some(),
                "chunk state coverage drifted at chunk {chunk}"
            );
        }

        // Every pending CRC is overlay-resident with its full span, and
        // every overlay entry describes a backed chunk.
        for (&chunk, entry) in &self.overlay {
            let (_, span) = self
                .chunk_span(chunk)
                .unwrap_or_else(|| panic!("overlay entry for unbacked chunk {chunk}"));
            if self
                .crcs
                .get(chunk)
                .is_some_and(|s| s.crc == ChunkCrc::Pending)
            {
                assert_eq!(
                    entry.bytes.len() as u64,
                    span,
                    "pending overlay span desynced at chunk {chunk}"
                );
            }
        }
        for chunk in 0..max {
            if self
                .crcs
                .get(chunk)
                .is_some_and(|s| s.crc == ChunkCrc::Pending)
            {
                assert!(
                    self.overlay.contains_key(&chunk),
                    "pending chunk {chunk} without overlay entry"
                );
            }
        }
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
    partitions: BTreeMap<String, BTreeMap<Vec<u8>, u64>>,
    /// Blobs opened this run (live or removed-with-handles), by id.
    open: BTreeMap<u64, Arc<BlobCore>>,
    /// Handle count per open blob id.
    handles: BTreeMap<u64, usize>,
    /// Committed entries for blobs NOT opened this run (with their
    /// partition names), served verbatim into every table and hydrated into
    /// `open` on first open.
    dormant: BTreeMap<u64, (String, Entry)>,
    alloc: super::alloc::Allocator,
    /// (extent, free once this seq confirms, optional removed-blob gate).
    pending_free: Vec<(Extent, u64, Option<u64>)>,
    /// Seq of the next commit.
    seq: u64,
    /// Seq of the most recent snapshot (freeze epoch for `RunMeta::born`).
    snapshot_seq: u64,
    /// Highest confirmed commit seq.
    confirmed_seq: u64,
    /// Superblock slot holding the last confirmed commit.
    sacred_slot: u8,
    /// The last confirmed table's extent (freed when superseded).
    table_extent: Option<Extent>,
    /// Checksum/shadow extents referenced by the last confirmed table, per
    /// blob id (freed when a newer entry supersedes them).
    committed_meta: BTreeMap<u64, CommittedMeta>,
    /// Chunks recovery CRC-checked while verifying the adopted commit's
    /// delta manifest, per blob id. Consumed at hydration to seed verified
    /// bits so first reads skip re-verification.
    recovery_verified: BTreeMap<u64, Vec<u64>>,
    /// Next blob id (persisted; never reused).
    next_id: u64,
    /// Blob ids with uncommitted content changes.
    dirty: BTreeSet<u64>,
    /// Namespace changed (create/remove) since the last commit.
    meta_dirty: bool,
    /// Applied-but-uncommitted batch groups: disjoint blob-id sets, merged
    /// when batches share blobs, cleared when a commit captures them. A
    /// commit's capture set is expanded across these (never-split).
    groups: Vec<BTreeSet<u64>>,
    /// Cached encoded table entries by blob id, so table assembly re-encodes
    /// only captured blobs. Invalidated per blob on capture/removal and
    /// wholesale when the partition list changes (encodings embed partition
    /// indexes).
    encoded: BTreeMap<u64, Bytes>,
    /// Bumped whenever the partition LIST changes (not its contents).
    partition_epoch: u64,
    /// `partition_epoch` the `encoded` cache was built against.
    encoded_epoch: u64,
    /// Bytes of the volume file known to exist (growth high-water mark).
    provisioned: u64,
    /// High-water mark of the allocated span, as observed by the metrics
    /// (monotonic: freeing an extent at the span's end lowers the
    /// allocator's end, never this).
    file_high_water: u64,
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

    /// Demote blob `id` back to dormant if eligible: no handles, no
    /// uncommitted content, no staged batch, not referenced by an
    /// applied-batch group, and not captured by an in-flight commit.
    ///
    /// A demoted blob's hydrated state (runs, chunk map, tail buffer,
    /// overlay, CRC caches, verified bits) is dropped and rebuilt from the
    /// committed entry on the next open, so a process that opens many blobs
    /// transiently does not hold their hydrated state until restart. First
    /// reads after a re-open re-verify chunks (the verified bits do not
    /// survive demotion).
    pub fn maybe_demote(&mut self, id: u64) {
        if self.handles.get(&id).copied().unwrap_or(0) > 0 || self.dirty.contains(&id) {
            return;
        }
        // Group members stay hydrated until a commit resolves the group
        // (bounded: every group is cleared by its covering commit).
        if self.groups.iter().any(|group| group.contains(&id)) {
            return;
        }
        let Some(core) = self.open.get(&id) else {
            return;
        };
        let inner = core.inner.lock();
        if inner.removed || inner.staged_batches != 0 || inner.capturing {
            return;
        }
        // Clean blobs carry no unsynced bookkeeping (capture drains both).
        debug_assert!(
            inner.dirty_chunks.is_empty() && inner.pending_frees.is_empty(),
            "clean blob with unsynced bookkeeping"
        );
        // A clean blob never captured with content serves an empty entry
        // (the same fallback commit assembly uses).
        let entry = inner
            .committed_entry
            .clone()
            .unwrap_or_else(|| Entry::empty(id, core.name.clone(), core.version));
        let partition = core.partition.clone();
        drop(inner);
        self.open.remove(&id);
        self.dormant.insert(id, (partition, entry));
    }

    /// Assert the volume-wide bookkeeping invariants (tests only).
    ///
    /// Always checked: free-index integrity, namespace/dirty/group/handle
    /// consistency, per-blob structural invariants (see
    /// [`BlobInner::audit`]), and extent accounting — every referenced
    /// extent is block-aligned, pairwise disjoint, and disjoint from free
    /// space. With `quiesced` (no in-flight commit and no unapplied batch,
    /// both of which hold freshly allocated extents outside this state),
    /// additionally: committed-metadata parity with the committed entries,
    /// and the exact partition — referenced extents plus the free index
    /// cover the allocatable file with nothing left over (no leaks).
    #[cfg(test)]
    pub fn audit(&self, quiesced: bool) {
        self.alloc.audit();

        // Namespace: every named id resolves to an open or dormant blob.
        for blobs in self.partitions.values() {
            for id in blobs.values() {
                assert!(
                    self.open.contains_key(id) || self.dormant.contains_key(id),
                    "named blob {id} neither open nor dormant"
                );
            }
        }

        // Dirty ids are live open blobs.
        for id in &self.dirty {
            let core = self
                .open
                .get(id)
                .unwrap_or_else(|| panic!("dirty blob {id} not open"));
            assert!(!core.inner.lock().removed, "dirty blob {id} is removed");
        }

        // Applied-batch groups are pairwise disjoint and (quiesced) hold
        // only open blobs: members stay hydrated until a commit resolves
        // the group.
        let mut grouped = BTreeSet::new();
        for group in &self.groups {
            for id in group {
                assert!(grouped.insert(*id), "blob {id} in two applied-batch groups");
                if quiesced {
                    assert!(self.open.contains_key(id), "group member {id} not open");
                }
            }
        }

        // Handle counts reference open blobs (an unapplied batch may hold
        // handles for staged creations not yet published).
        if quiesced {
            for (id, count) in &self.handles {
                assert!(
                    *count == 0 || self.open.contains_key(id),
                    "handles for {id} without an open blob"
                );
            }
        }

        // Recovery-verified seeds are consumed at hydration.
        for id in self.recovery_verified.keys() {
            assert!(
                self.dormant.contains_key(id),
                "recovery-verified chunks for hydrated blob {id}"
            );
        }

        // Collect every extent the state references, running per-blob
        // audits along the way. Removed-with-handles blobs are skipped:
        // unlink moved their extents to `pending_free` (counted there).
        let mut referenced: Vec<(Extent, String)> = Vec::new();
        if let Some(extent) = self.table_extent {
            referenced.push((extent, "table".into()));
        }
        for (extent, _, _) in &self.pending_free {
            referenced.push((*extent, "pending free".into()));
        }
        for (&id, (_, entry)) in &self.dormant {
            for r in &entry.runs {
                referenced.push((r.extent(), format!("dormant {id} run")));
            }
        }
        for (&id, meta) in &self.committed_meta {
            for (i, extent) in meta.checksums.iter().enumerate() {
                referenced.push((*extent, format!("blob {id} checksum ref {i}")));
            }
            if let Some(extent) = meta.shadow {
                referenced.push((extent, format!("blob {id} shadow")));
            }
        }
        for (&id, core) in &self.open {
            let inner = core.inner.lock();
            if inner.removed {
                continue;
            }
            inner.audit();
            for run in inner.runs.values() {
                referenced.push((run.extent(), format!("open {id} run")));
            }
            for extent in &inner.pending_frees {
                referenced.push((*extent, format!("open {id} pending free")));
            }

            // Committed-metadata parity: the tracked meta extents are
            // exactly the extents the committed entry references. Skipped
            // mid-commit, where the snapshot has already swapped the meta
            // while the entry swings only at finalize.
            if quiesced {
                assert_eq!(
                    inner.staged_batches, 0,
                    "blob {id}: staged batch counter leaked"
                );
                match (&inner.committed_entry, self.committed_meta.get(&id)) {
                    (Some(entry), Some(meta)) => assert_meta_parity(id, entry, meta),
                    (Some(_), None) => panic!("blob {id}: committed entry without meta"),
                    (None, Some(_)) => panic!("blob {id}: committed meta without entry"),
                    (None, None) => {}
                }
            }
        }
        if quiesced {
            for (&id, (_, entry)) in &self.dormant {
                let meta = self
                    .committed_meta
                    .get(&id)
                    .unwrap_or_else(|| panic!("dormant blob {id} without committed meta"));
                assert_meta_parity(id, entry, meta);
            }
        }

        // Accounting: aligned, pairwise disjoint, never overlapping free
        // space, and (quiesced) exactly partitioning the allocatable file
        // with the free index.
        let mut total = 0;
        referenced.sort_by_key(|(extent, _)| extent.offset);
        let mut prev: Option<&(Extent, String)> = None;
        for entry in &referenced {
            let (extent, what) = entry;
            assert!(
                extent.offset.is_multiple_of(BLOCK)
                    && extent.len.is_multiple_of(BLOCK)
                    && extent.len > 0,
                "unaligned referenced extent: {what} {extent:?}"
            );
            if let Some((pe, pw)) = prev {
                assert!(
                    pe.offset + pe.len <= extent.offset,
                    "referenced extents overlap: {pw} {pe:?} and {what} {extent:?}"
                );
            }
            assert!(
                !self.alloc.overlaps_free(*extent),
                "referenced extent overlaps free space: {what} {extent:?}"
            );
            total += extent.len;
            prev = Some(entry);
        }
        if quiesced && total + self.alloc.free_bytes() != self.alloc.end() - 2 * BLOCK {
            let mut dump = String::new();
            for (extent, what) in &referenced {
                dump.push_str(&format!(
                    "  ref {}..{} {what}\n",
                    extent.offset,
                    extent.offset + extent.len
                ));
            }
            for (offset, len) in self.alloc.free_ranges() {
                dump.push_str(&format!("  free {}..{}\n", offset, offset + len));
            }
            panic!(
                "extent leak: referenced {} + free {} != allocatable {} (end {})\n{dump}",
                total,
                self.alloc.free_bytes(),
                self.alloc.end() - 2 * BLOCK,
                self.alloc.end()
            );
        }
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

/// Assert `meta` tracks exactly the extents `entry` references (tests only).
#[cfg(test)]
fn assert_meta_parity(id: u64, entry: &Entry, meta: &CommittedMeta) {
    assert_eq!(
        meta.checksums.len(),
        entry.checksums.len(),
        "blob {id}: checksum meta count desynced"
    );
    for (extent, r) in meta.checksums.iter().zip(&entry.checksums) {
        assert_eq!(
            extent.offset, r.offset,
            "blob {id}: checksum meta offset desynced"
        );
        assert_eq!(
            extent.len,
            block_align(r.count as u64 * 4),
            "blob {id}: checksum meta length desynced"
        );
    }
    match (meta.shadow, entry.shadow) {
        (Some(extent), Some(offset)) => {
            assert_eq!(extent.offset, offset, "blob {id}: shadow meta desynced");
        }
        (None, None) => {}
        _ => panic!("blob {id}: shadow meta presence desynced"),
    }
}

/// The volume once recovery has run.
pub(super) struct Ready<S: crate::Storage> {
    /// The single inner blob backing the volume.
    pub file: S::Blob,
    /// Schedules commit futures onto the owning runtime (see
    /// [`super::Driver`]).
    pub driver: super::Driver,
    /// Operational metrics (see the `metrics` module).
    pub metrics: std::sync::Arc<super::metrics::Metrics>,
    pub state: Mutex<State>,
    /// Serializes commits.
    pub commit_lock: AsyncMutex<()>,
    /// Roots (and ticket) of syncs queued for the next commit.
    pub pending: Mutex<super::commit::PendingCommit>,
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

    /// Latch the poison error and its gauge (fused so no site can set one
    /// without the other). First error wins.
    pub fn poison(&self, e: Error) {
        let _ = self.poisoned.set(e);
        let _ = self.metrics.poisoned.try_set(1);
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

impl BlobInner {
    /// Current logical size (includes uncommitted writes).
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Freeze boundary: bytes below are covered by the last confirmed
    /// table or the in-flight snapshot.
    pub const fn freeze_size(&self) -> u64 {
        self.freeze_size
    }

    /// Pruned floor: bytes below were dropped and their reads fail.
    pub const fn floor(&self) -> u64 {
        self.floor
    }

    /// Relocation generation (bumped on any relocation/drop of backing).
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the blob was unlinked from the namespace.
    pub const fn removed(&self) -> bool {
        self.removed
    }

    /// Batches currently holding staged state for this blob.
    pub const fn staged_batches(&self) -> usize {
        self.staged_batches
    }

    /// The entry the last confirmed commit wrote for this blob.
    pub const fn committed_entry(&self) -> Option<&Entry> {
        self.committed_entry.as_ref()
    }

    /// Written runs keyed by logical start (gaps are holes). The map is
    /// aliased so Kani proofs run over the solver-friendly container.
    pub const fn runs(&self) -> &OrderedMap<u64, RunMeta> {
        &self.runs
    }

    /// Checksum state per backed chunk.
    pub const fn crcs(&self) -> &ChunkMap {
        &self.crcs
    }

    /// Checksum state per backed chunk, for mutation ([`ChunkMap`] guards
    /// its own invariants).
    pub const fn crcs_mut(&mut self) -> &mut ChunkMap {
        &mut self.crcs
    }

    /// Committed-CRC page cache ([`CrcCache`] guards its own invariants,
    /// and even lookups stamp its LRU clock).
    pub const fn crc_cache_mut(&mut self) -> &mut CrcCache {
        &mut self.crc_cache
    }

    /// The read planner's split view: runs and chunk states borrowed for
    /// the plan walk while the committed-CRC cache is consulted mutably
    /// (even lookups stamp its LRU clock). The map is aliased so Kani
    /// proofs run over the solver-friendly container.
    pub const fn plan_parts(&mut self) -> (&OrderedMap<u64, RunMeta>, &ChunkMap, &mut CrcCache) {
        (&self.runs, &self.crcs, &mut self.crc_cache)
    }

    /// Bytes of the frontier chunk's written span (meaningful only when
    /// [`Self::tail_chunk`] is backed).
    pub fn tail(&self) -> &[u8] {
        &self.tail
    }

    /// Chunk the tail buffer describes.
    pub const fn tail_chunk(&self) -> u64 {
        self.tail_chunk
    }

    /// Committed checksum refs whose extent guard was verified this
    /// process.
    pub fn crc_guarded(&self) -> &[ChecksumRef] {
        &self.crc_guarded
    }

    /// Record a guard-verified checksum ref (idempotent).
    pub fn record_guarded(&mut self, r: ChecksumRef) {
        if !self.crc_guarded.contains(&r) {
            self.crc_guarded.push(r);
        }
    }

    /// Publish a new logical size.
    pub const fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    /// Publish growth to at least `end`.
    pub fn grow_to(&mut self, end: u64) {
        self.size = self.size.max(end);
    }

    /// Install (or replace) the run at `logical`.
    pub fn install_run(&mut self, logical: u64, meta: RunMeta) {
        self.runs.insert(logical, meta);
    }

    /// Publish a stretch's run at `logical`: extend the existing run in
    /// place when the stretch continued its placement, install otherwise.
    pub fn publish_run(&mut self, logical: u64, run: RunMeta) {
        match self.runs.get_mut(&logical) {
            Some(existing) if existing.physical == run.physical => {
                existing.len = existing.len.max(run.len);
            }
            _ => {
                self.runs.insert(logical, run);
            }
        }
    }

    /// Detach the run at `logical`.
    pub fn remove_run(&mut self, logical: u64) -> Option<RunMeta> {
        self.runs.remove(&logical)
    }

    /// Detach every run at or beyond `from`, in order. The map is aliased
    /// so Kani proofs run over the solver-friendly container.
    pub fn split_runs_from(&mut self, from: u64) -> OrderedMap<u64, RunMeta> {
        self.runs.split_off(&from)
    }

    /// Bump the relocation generation (COW, resize-down, remove): every
    /// in-flight read against the old placement retries.
    pub const fn bump_generation(&mut self) {
        self.generation += 1;
    }

    /// Queue a replaced extent for release once a commit capturing this
    /// blob confirms.
    pub fn defer_content_free(&mut self, extent: Extent) {
        self.pending_frees.push(extent);
    }

    /// Record that `chunk`'s content changed since the last snapshot.
    pub fn mark_chunk_dirty(&mut self, chunk: u64) {
        self.dirty_chunks.insert(chunk);
    }

    /// The lowest chunk whose content changed since the last snapshot.
    pub fn first_dirty_chunk(&self) -> Option<u64> {
        self.dirty_chunks.iter().next().copied()
    }

    /// Keep only the dirty-chunk records `keep` accepts.
    pub fn retain_dirty_chunks(&mut self, keep: impl FnMut(&u64) -> bool) {
        self.dirty_chunks.retain(keep);
    }

    /// Install the frontier span buffer.
    pub fn set_tail(&mut self, chunk: u64, bytes: Vec<u8>) {
        self.tail_chunk = chunk;
        self.tail = bytes;
    }

    /// Drop every overlay entry (resize-down: staged spans are obsolete).
    pub fn clear_overlay(&mut self) {
        self.overlay.clear();
    }

    /// Drop every overlay entry whose chunk no longer defers its CRC (the
    /// entry is only load-bearing while the chunk is
    /// [`super::chunk::ChunkCrc::Pending`]).
    pub fn prune_overlay(&mut self) {
        self.overlay.retain(
            |chunk, _| matches!(self.crcs.get(*chunk), Some(s) if s.crc == ChunkCrc::Pending),
        );
    }

    /// A batch staged state over this blob (snapshot capture must not
    /// merge its runs while the overlay references them by key).
    pub const fn stage_batch(&mut self) {
        self.staged_batches += 1;
    }

    /// The staged batch resolved (applied or dropped).
    pub const fn unstage_batch(&mut self) {
        self.staged_batches -= 1;
    }

    /// Prepare the blob for value capture (the write lock and the state
    /// lock are held): raise the freeze boundary — nothing this snapshot
    /// covers may be rewritten in place until it confirms or rolls back —
    /// block demotion until finalize publishes the new entry, finalize
    /// deferred chunk CRCs from their overlay entries (the checksum
    /// array, tail CRC, and delta manifest must carry exact values), and
    /// freeze the captured runs atomically with the capture (the model
    /// freezes per-run coverage at snapshot time): this entry, its
    /// checksum extents, and its manifest reference every run below, so
    /// the young-extent exemption must not apply to any of them. Runs
    /// created after this point keep `born > snapshot_seq` and stay
    /// exempt: they are genuinely absent from this commit's table.
    ///
    /// With every run frozen, contiguous neighbors coalesce: the entry
    /// encodes fewer runs and every later runs-map descent walks a
    /// shallower map. Skipped while a batch holds staged state for this
    /// blob, whose overlay references base runs by key (merging would
    /// move keys under it).
    pub fn freeze_for_capture(&mut self, seq: u64) {
        self.freeze_size = self.freeze_size.max(self.size);
        self.capturing = true;
        self.overlay_finalize();
        for run in self.runs.values_mut() {
            run.born = run.born.min(seq);
        }
        if self.staged_batches == 0 {
            merge_frozen_runs(&mut self.runs);
        }
    }

    /// Take the chunks whose content changed since the last snapshot
    /// (sorted), leaving the set empty.
    pub fn take_dirty_chunks(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.dirty_chunks).into_iter().collect()
    }

    /// Drain the extents dropped by uncommitted state changes (released
    /// once the capturing commit confirms).
    pub fn drain_pending_frees(&mut self) -> Vec<Extent> {
        std::mem::take(&mut self.pending_frees)
    }

    /// The commit confirmed: `entry` is now the blob's committed
    /// identity. The confirmed size is the exact freeze boundary (a
    /// rewind below the old boundary takes effect here), demotion
    /// unblocks, and the guard memo re-derives: refs this capture wrote
    /// are guard-verified by construction — their bytes were assembled in
    /// process memory, from resident values and old-extent loads that
    /// were themselves guard-checked — and retained refs keep their
    /// standing memo. Everything else (superseded refs) drops out.
    pub fn publish_committed(&mut self, entry: Entry) {
        self.capturing = false;
        self.freeze_size = entry.size;
        self.shadow = entry.shadow;
        let prev = std::mem::take(&mut self.crc_guarded);
        let old_refs = self
            .committed_entry
            .as_ref()
            .map_or(&[][..], |e| &e.checksums[..]);
        self.crc_guarded = entry
            .checksums
            .iter()
            .filter(|r| prev.contains(r) || !old_refs.contains(r))
            .copied()
            .collect();
        self.committed_entry = Some(entry);
    }

    /// Prune bytes below `floor` (byte-exact, above the current floor, at
    /// most `size`): runs wholly below the floor's chunk drop, a
    /// straddling run keeps its suffix in place, and chunk state, overlay
    /// entries, and dirty marks below the floor's chunk drop. Freed extent pieces join `pending_frees` —
    /// the last confirmed table still references them, so they release
    /// only once a commit CAPTURING this blob confirms (the caller marks
    /// the blob dirty). The generation bumps: in-flight reads against the
    /// old placement retry, then fail loudly below the new floor.
    pub fn prune_to(&mut self, floor: u64) {
        debug_assert!(
            floor > self.floor && floor <= self.size,
            "prune floor out of contract"
        );
        // Physical surgery is chunk-granular: the chunk containing the
        // floor survives whole (its low bytes stay on disk for the
        // checksum granularity, logically dead behind the exact floor).
        let chunk_start = chunk_of(floor) * BLOCK;
        let kept = self.runs.split_off(&chunk_start);
        let below = std::mem::replace(&mut self.runs, kept);
        for (logical, run) in below {
            if logical + run.len <= chunk_start {
                self.pending_frees.push(run.extent());
            } else {
                // The straddler keeps its suffix: the pruned prefix blocks
                // free, the rest re-keys at the floor's chunk start.
                let cut = chunk_start - logical;
                self.pending_frees.push(Extent {
                    offset: run.physical,
                    len: cut,
                });
                self.runs.insert(
                    chunk_start,
                    RunMeta {
                        physical: run.physical + cut,
                        len: run.len - cut,
                        capacity: run.capacity - cut,
                        born: run.born,
                    },
                );
            }
        }
        let floor_chunk = chunk_of(floor);
        self.crcs.truncate_front(floor_chunk);
        self.overlay.retain(|&chunk, _| chunk >= floor_chunk);
        self.dirty_chunks = self.dirty_chunks.split_off(&floor_chunk);
        // No runs survive only when trailing holes reach `size` (sparse
        // resize): the tail buffer describes no backed chunk anymore.
        if self.runs.is_empty() {
            self.tail_chunk = 0;
            self.tail = Vec::new();
        }
        self.generation += 1;
        self.floor = floor;
    }

    /// Rebuild live state from a committed entry (hydration): runs with
    /// recovered (frozen) birth, merged, and the dense chunk state seeded
    /// all-unverified with CRC values left on disk. The caller verifies
    /// and installs the frontier span.
    pub fn from_entry(entry: &Entry) -> Self {
        let mut inner = Self {
            size: entry.size,
            freeze_size: entry.size,
            floor: entry.floor,
            shadow: entry.shadow,
            committed_entry: Some(entry.clone()),
            ..Default::default()
        };
        for r in &entry.runs {
            inner.runs.insert(
                r.logical,
                RunMeta {
                    physical: r.physical,
                    len: r.len,
                    capacity: block_align(r.len),
                    born: 0,
                },
            );
        }
        // Recovered runs are all frozen (born 0): coalesce contiguous
        // neighbors. A no-op for entries captured after a merging pass,
        // but an entry captured while a batch held staged state for its
        // blob (which gates capture-time merging) can still carry
        // mergeable runs.
        merge_frozen_runs(&mut inner.runs);
        // Seed the dense chunk state from the merged runs: every backed
        // chunk unverified with its CRC left on disk.
        inner.crcs.seed(&inner.runs);
        inner
    }
}

/// Everything recovery (or first init) adopts from the durable image,
/// from which [`State::boot`] derives the volume's starting state.
pub(super) struct Genesis {
    pub partitions: BTreeMap<String, BTreeMap<Vec<u8>, u64>>,
    pub dormant: BTreeMap<u64, (String, Entry)>,
    pub committed_meta: BTreeMap<u64, CommittedMeta>,
    pub recovery_verified: BTreeMap<u64, Vec<u64>>,
    pub alloc: Allocator,
    /// Seq of the adopted commit (the next commit is `adopted_seq + 1`).
    pub adopted_seq: u64,
    /// Superblock slot holding the adopted commit.
    pub sacred_slot: u8,
    /// The adopted table's extent.
    pub table_extent: Extent,
    pub next_id: u64,
    /// Bytes of the volume file known to exist.
    pub provisioned: u64,
}

impl State {
    /// The volume's starting state for an adopted commit: the next commit
    /// follows the adopted seq, the adopted seq is the snapshot and
    /// confirmation floor, and every runtime set starts empty.
    pub fn boot(genesis: Genesis) -> Self {
        Self {
            partitions: genesis.partitions,
            open: BTreeMap::new(),
            handles: BTreeMap::new(),
            dormant: genesis.dormant,
            alloc: genesis.alloc,
            pending_free: Vec::new(),
            seq: genesis.adopted_seq + 1,
            snapshot_seq: genesis.adopted_seq,
            confirmed_seq: genesis.adopted_seq,
            sacred_slot: genesis.sacred_slot,
            table_extent: Some(genesis.table_extent),
            committed_meta: genesis.committed_meta,
            recovery_verified: genesis.recovery_verified,
            next_id: genesis.next_id,
            dirty: Default::default(),
            meta_dirty: false,
            groups: Vec::new(),
            encoded: Default::default(),
            partition_epoch: 0,
            encoded_epoch: 0,
            provisioned: genesis.provisioned,
            file_high_water: 0,
        }
    }

    /// Seq of the next commit.
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Seq of the most recent snapshot (the freeze epoch).
    pub const fn snapshot_seq(&self) -> u64 {
        self.snapshot_seq
    }

    /// Highest confirmed commit seq.
    #[cfg(test)]
    pub const fn confirmed_seq(&self) -> u64 {
        self.confirmed_seq
    }

    /// Next blob id (persisted, never reused).
    pub const fn next_id(&self) -> u64 {
        self.next_id
    }

    /// partition -> name -> blob id.
    pub const fn partitions(&self) -> &BTreeMap<String, BTreeMap<Vec<u8>, u64>> {
        &self.partitions
    }

    /// Blobs opened this run, by id.
    pub const fn open(&self) -> &BTreeMap<u64, Arc<BlobCore>> {
        &self.open
    }

    /// Committed entries for blobs not opened this run.
    pub const fn dormant(&self) -> &BTreeMap<u64, (String, Entry)> {
        &self.dormant
    }

    /// The open blob `id`, if any.
    pub fn open_blob(&self, id: u64) -> Option<Arc<BlobCore>> {
        self.open.get(&id).cloned()
    }

    /// Whether a commit capturing `capture` would write nothing new: no
    /// namespace change and no captured dirty blob.
    pub fn clean_for(&self, capture: &BTreeSet<u64>) -> bool {
        !self.meta_dirty && !capture.iter().any(|id| self.dirty.contains(id))
    }

    /// Assign the next commit's seq and advance the freeze epoch.
    pub const fn begin_snapshot(&mut self) -> u64 {
        let seq = self.seq;
        self.seq += 1;
        self.snapshot_seq = seq;
        seq
    }

    /// The dirty blob ids within `capture`.
    pub fn dirty_in(&self, capture: &BTreeSet<u64>) -> Vec<u64> {
        self.dirty
            .iter()
            .copied()
            .filter(|id| capture.contains(id))
            .collect()
    }

    /// Record uncommitted content changes for blob `id`.
    pub fn mark_dirty(&mut self, id: u64) {
        self.dirty.insert(id);
    }

    /// Drop blob `id`'s dirty mark (captured, or removed with its dirt).
    pub fn clear_dirty(&mut self, id: u64) {
        self.dirty.remove(&id);
    }

    /// Allocate an extent of `len` bytes.
    pub fn allocate(&mut self, len: u64) -> Extent {
        self.alloc.allocate(len)
    }

    /// Detach blob `id`'s committed metadata extents (the capture decides
    /// what is retained and what is superseded).
    pub fn take_committed_meta(&mut self, id: u64) -> Option<CommittedMeta> {
        self.committed_meta.remove(&id)
    }

    /// Install blob `id`'s new committed metadata extents.
    pub fn install_committed_meta(&mut self, id: u64, meta: CommittedMeta) {
        self.committed_meta.insert(id, meta);
    }

    /// The last confirmed table's extent (superseded on confirmation).
    pub const fn table_extent(&self) -> Option<Extent> {
        self.table_extent
    }

    /// The superblock slot the next commit writes (never the sacred one).
    pub const fn standby_slot(&self) -> u8 {
        1 - self.sacred_slot
    }

    /// Capture the namespace into table entries: captured blobs
    /// re-encode; everything else is served from its cached encoded entry
    /// (encoded lazily on first use), so assembly is O(captured +
    /// concatenation). The table now reflects every namespace change, so
    /// the namespace-dirty flag clears. Returns the partition list and
    /// the entry encodings, table-ordered.
    pub fn table_entries(
        &mut self,
        captured: &mut [(Arc<BlobCore>, Entry)],
    ) -> (Vec<String>, Vec<Bytes>) {
        self.meta_dirty = false;

        // Encodings embed partition indexes: a changed partition LIST
        // invalidates every cached encoding.
        if self.encoded_epoch != self.partition_epoch {
            self.encoded.clear();
            self.encoded_epoch = self.partition_epoch;
        }

        let partitions: Vec<String> = self.partitions.keys().cloned().collect();
        // Indexed lookups: an epoch change re-encodes EVERY entry, so a
        // linear scan per blob would make that commit O(blobs x
        // partitions).
        let pindex: BTreeMap<&str, u32> = partitions
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), i as u32))
            .collect();
        let pindex = |p: &str| *pindex.get(p).expect("known partition");

        // Fresh encodings for captured blobs.
        for (blob, entry) in captured.iter_mut() {
            entry.partition = pindex(&blob.partition);
            self.encoded.insert(entry.id, Bytes::from(entry.encode()));
        }
        // Cache misses among served blobs (first commit after recovery or
        // an epoch change).
        let mut missing: Vec<(u64, Bytes)> = Vec::new();
        for (&id, (partition, entry)) in &self.dormant {
            if self.encoded.contains_key(&id) {
                continue;
            }
            let mut entry = entry.clone();
            entry.partition = pindex(partition);
            missing.push((id, Bytes::from(entry.encode())));
        }
        for (&id, core) in &self.open {
            if self.encoded.contains_key(&id) {
                continue;
            }
            // Served open blob: its cached committed entry (set by the
            // last commit that captured it), or a fresh empty entry
            // (created but never captured). Never derived from live
            // state, which may hold uncommitted writes.
            let inner = core.inner.lock();
            if inner.removed {
                continue;
            }
            let mut entry = inner
                .committed_entry
                .clone()
                .unwrap_or_else(|| Entry::empty(core.id, core.name.clone(), core.version));
            entry.partition = pindex(&core.partition);
            missing.push((id, Bytes::from(entry.encode())));
        }
        for (id, bytes) in missing {
            self.encoded.insert(id, bytes);
        }
        debug_assert_eq!(
            self.encoded.len(),
            self.dormant.len()
                + self
                    .open
                    .values()
                    .filter(|core| !core.inner.lock().removed)
                    .count(),
            "encoded-entry cache out of sync with the namespace"
        );

        (partitions, self.encoded.values().cloned().collect())
    }

    /// The commit at `seq` confirmed: flip the sacred slot, supersede the
    /// old table, and resolve every applied-batch group the capture
    /// covers (capture expansion guarantees all-or-nothing coverage —
    /// never-split). Returns the resolved groups' members.
    pub fn confirm(
        &mut self,
        seq: u64,
        old_table: Option<Extent>,
        table: Extent,
        capture: &BTreeSet<u64>,
    ) -> Vec<u64> {
        self.sacred_slot = 1 - self.sacred_slot;
        self.confirmed_seq = seq;
        if let Some(old) = old_table {
            self.defer_free(old, seq, None);
        }
        self.table_extent = Some(table);
        let mut resolved: Vec<u64> = Vec::new();
        self.groups.retain(|group| {
            let covered = group.iter().any(|id| capture.contains(id));
            debug_assert!(
                !covered || group.iter().all(|id| capture.contains(id)),
                "commit split an applied batch group"
            );
            if covered {
                resolved.extend(group.iter().copied());
            }
            !covered
        });
        resolved
    }

    /// Assign a fresh blob id.
    pub const fn reserve_blob_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Count a new handle on blob `id`.
    pub fn count_handle(&mut self, id: u64) {
        *self.handles.entry(id).or_insert(0) += 1;
    }

    #[cfg(test)]
    pub fn handle_count(&self, id: u64) -> usize {
        self.handles.get(&id).copied().unwrap_or(0)
    }

    /// Publish `core` under `partition`/`name`: the blob becomes served
    /// and the namespace change joins the next table.
    pub fn publish_named(&mut self, partition: &str, name: Vec<u8>, core: Arc<BlobCore>) {
        if !self.partitions.contains_key(partition) {
            self.partition_epoch += 1;
        }
        self.partitions
            .entry(partition.into())
            .or_default()
            .insert(name, core.id);
        self.open.insert(core.id, core);
        self.meta_dirty = true;
    }

    /// Remove `name` under `partition` (or, with `None`, the whole
    /// partition) from the namespace: every named blob unlinks, and the
    /// namespace change joins the next table. Returns the unlinked ids.
    pub fn remove_named(
        &mut self,
        partition: &str,
        name: Option<&[u8]>,
    ) -> Result<Vec<u64>, Error> {
        let Some(blobs) = self.partitions.get(partition) else {
            return Err(Error::PartitionMissing(partition.into()));
        };
        let ids: Vec<u64> = match name {
            Some(name) => {
                let Some(&id) = blobs.get(name) else {
                    return Err(Error::BlobMissing(partition.into(), hex(name)));
                };
                vec![id]
            }
            None => blobs.values().copied().collect(),
        };
        for &id in &ids {
            unlink(self, id);
        }
        match name {
            Some(name) => {
                self.partitions
                    .get_mut(partition)
                    .expect("checked")
                    .remove(name);
            }
            None => {
                self.partitions.remove(partition);
                self.partition_epoch += 1;
            }
        }
        self.meta_dirty = true;
        Ok(ids)
    }

    /// Promote dormant blob `id` to open as `core` (its hydrated state).
    pub fn wake_dormant(&mut self, id: u64, core: Arc<BlobCore>) {
        self.dormant.remove(&id);
        self.open.insert(id, core);
    }

    /// Take the chunks recovery CRC-verified for blob `id` (consumed at
    /// hydration to seed verified bits).
    pub fn take_recovery_verified(&mut self, id: u64) -> Option<Vec<u64>> {
        self.recovery_verified.remove(&id)
    }

    /// Raise and return the allocated-span high-water mark (monotonic:
    /// freeing an extent at the span's end lowers the allocator's end,
    /// never this).
    pub fn high_water(&mut self) -> u64 {
        self.file_high_water = self.file_high_water.max(self.alloc.end());
        self.file_high_water
    }

    /// Free bytes in the allocator's index.
    pub const fn free_bytes(&self) -> u64 {
        self.alloc.free_bytes()
    }

    /// Bytes queued for reuse but not yet released.
    pub fn pending_free_bytes(&self) -> u64 {
        self.pending_free.iter().map(|(e, _, _)| e.len).sum()
    }
}

pub(super) struct Shared<S: crate::Storage> {
    pub inner: S,
    pub pool: BufferPool,
    pub cfg: Config,
    pub driver: Driver,
    pub metrics: Arc<super::metrics::Metrics>,
    /// Set once recovery has completed (fast path).
    pub ready: OnceLock<Arc<Ready<S>>>,
    /// Serializes recovery (single-flight) and namespace changes.
    pub ns_lock: AsyncMutex<()>,
}

/// Tracks one open handle (shared by clones); the drop of the last clone
/// releases removal-gated extents.
pub(super) struct HandleTracker<S: crate::Storage> {
    pub ready: Arc<Ready<S>>,
    pub id: u64,
}

impl<S: crate::Storage> Drop for HandleTracker<S> {
    fn drop(&mut self) {
        let mut state = self.ready.state.lock();
        let count = state
            .handles
            .get_mut(&self.id)
            .expect("open handle is counted");
        assert!(*count > 0, "open handle is counted");
        *count -= 1;
        if *count == 0 {
            state.handles.remove(&self.id);
            // Drop the blob entirely if it was removed (no name references
            // it and no handle can reach it anymore); otherwise demote a
            // clean blob's hydrated state back to dormant.
            let removed = state
                .open
                .get(&self.id)
                .is_some_and(|b| b.inner.lock().removed);
            if removed {
                state.open.remove(&self.id);
            } else {
                state.maybe_demote(self.id);
            }
            state.apply_frees();
            self.ready.metrics.observe_state(&mut state);
        }
    }
}

/// Unlink one blob id: mark removed, queue every extent it references for
/// reuse once the removal commits (and its last handle drops).
///
/// The very next commit — whatever it captures — drops the entry from the
/// table, so removal frees gate only on that commit's seq (plus the handle
/// gate for extents still readable through open handles).
pub(super) fn unlink(state: &mut State, id: u64) {
    let seq = state.seq;
    let gate = Some(id);
    state.encoded.remove(&id);
    if let Some(core) = state.open.get(&id).cloned() {
        let mut inner = core.inner.lock();
        inner.removed = true;
        inner.generation += 1;
        // The runs map keeps its entries — reads through live handles
        // stay served — but every extent is queued now, released once the
        // removal commits and the last handle drops (the gate). Mutations
        // of a removed blob are rejected (see `write::write_locked`), so
        // no new extent can enter the map after this point.
        for run in inner.runs.values() {
            state.defer_free(run.extent(), seq, gate);
        }
        // Capture-gated frees resolve with the removal commit: the entry
        // that referenced them is dropped (never readable via handles).
        for extent in std::mem::take(&mut inner.pending_frees) {
            state.defer_free(extent, seq, None);
        }
        state.dirty.remove(&id);
        // Committed metadata extents (checksums + shadow).
        if let Some(meta) = state.committed_meta.remove(&id) {
            for extent in meta.into_extents() {
                state.defer_free(extent, seq, gate);
            }
        }
        // No handles: nothing can read it; drop immediately.
        if state.handles.get(&id).copied().unwrap_or(0) == 0 {
            drop(inner);
            state.open.remove(&id);
        }
    } else if let Some((_, entry)) = state.dormant.remove(&id) {
        for r in &entry.runs {
            state.defer_free(r.extent(), seq, None);
        }
        if let Some(meta) = state.committed_meta.remove(&id) {
            for extent in meta.into_extents() {
                state.defer_free(extent, seq, None);
            }
        }
    }
    state.recovery_verified.remove(&id);
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
    /// The smallest staged size this overlay passed through. A staged
    /// shrink drops base coverage that a later staged regrow does not
    /// restore, so publish truncates the published chunk state to THIS
    /// boundary — the final size alone would keep vacated states alive.
    pub min_size: u64,
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
            min_size: size,
            ..Default::default()
        }
    }

    /// Reset the overlay's base to the blob's CURRENT published size: a
    /// membership-only touch ([`super::Batch::sync`]) snapshots a size
    /// that direct writes may legally outgrow before staging begins.
    pub fn rebase(&mut self, size: u64) {
        debug_assert!(
            self.runs.is_empty() && self.crcs.is_empty() && self.tail.is_none(),
            "rebase precedes staging"
        );
        self.size = size;
        self.min_size = size;
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
        let chunk_start = chunk * BLOCK;
        let (logical, run, _) = self.covering(inner, chunk_start)?;
        let span = (logical + run.len - chunk_start).min(BLOCK);
        Some((run.physical + (chunk_start - logical), span))
    }
}

/// Reject a mutation of a removed blob (unspecified by the trait): its
/// extents are already queued for reuse (see `unlink`), so a fresh
/// allocation would leak until restart and a COW would later double-free
/// the replaced block. Reads stay served (extents are gated on the open
/// handles).
pub(super) fn check_not_removed(blob: &BlobCore) -> Result<(), Error> {
    if blob.inner.lock().removed {
        return Err(Error::BlobMissing(blob.partition.clone(), hex(&blob.name)));
    }
    Ok(())
}

/// Reject an operation reaching below the pruned floor: those bytes were
/// dropped, and serving or mutating them would silently resurrect a
/// discarded prefix.
pub(super) fn check_floor(blob: &BlobCore, offset: u64) -> Result<(), Error> {
    let floor = blob.inner.lock().floor();
    if offset < floor {
        return Err(Error::OffsetPruned(
            blob.partition.clone(),
            hex(&blob.name),
            floor,
        ));
    }
    Ok(())
}

/// Record and report `chunk`'s corruption: every mismatch of a chunk's
/// expected CRC counts in the corruption metric and raises this loud
/// error — fused so no report can forget the counter.
pub(super) fn chunk_mismatch<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    chunk: u64,
) -> Error {
    ready.metrics.corruptions.inc();
    Error::BlobCorrupt(
        blob.partition.clone(),
        hex(&blob.name),
        format!("chunk {chunk} checksum mismatch"),
    )
}
