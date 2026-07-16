//! Volume state and data paths (write, read, resize).
//!
//! Locking:
//! - `State` and each blob's `BlobInner` sit behind synchronous mutexes,
//!   never held across an await.
//! - Each blob has an async `write_lock` serializing its mutations (and the
//!   commit snapshotter) across inner I/O — this keeps chunk CRC state
//!   coherent with issued bytes. Under it, writers interleave brief
//!   state-lock sections with I/O freely.
//! - Readers take no locks across I/O: they snapshot backing + CRC state and
//!   a relocation `generation`, read, verify, and retry if the generation
//!   moved. Extent reuse under an in-flight read causes a retry, never a
//!   false corruption report.
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
    layout::Entry,
    BLOCK,
};
use crate::{Blob as _, BufferPool, Error, IoBuf};
use bytes::{BufMut as _, Bytes};
use commonware_cryptography::Crc32;
use commonware_formatting::hex;
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

/// The chunk index containing logical byte `offset`. Chunks and blocks
/// coincide in this format (checksum granularity == tearing granularity).
pub(super) const fn chunk_of(offset: u64) -> u64 {
    offset / BLOCK
}

/// Write `bytes` at block-aligned `offset`, zero-padded to a whole number of
/// blocks in a pool-allocated (alignment-honoring) buffer.
///
/// Every inner write the volume issues goes through here so the inner file
/// can run direct I/O: whole blocks, block-aligned offsets, aligned buffer
/// memory. Padding bytes land only inside the target extent, beyond any
/// referenced span, so they are never read back.
pub(super) async fn write_blocks<B: crate::Blob>(
    file: &B,
    pool: &BufferPool,
    offset: u64,
    bytes: &[u8],
) -> Result<(), Error> {
    debug_assert!(
        offset.is_multiple_of(BLOCK),
        "unaligned volume write at {offset}"
    );
    debug_assert!(!bytes.is_empty(), "empty volume write at {offset}");
    let padded = block_align(bytes.len() as u64) as usize;
    let mut buf = pool.alloc(padded);
    buf.put_slice(bytes);
    buf.put_bytes(0, padded - bytes.len());
    file.write_at(offset, buf.freeze()).await
}

/// Read exactly `len` bytes at block-aligned `offset`, rounding the inner
/// read up to whole blocks (bytes beyond `len` in the final block are
/// discarded).
///
/// Every inner read the volume issues goes through here so the inner file
/// can run direct I/O. Rounding never reads past the file end: every write
/// lands whole blocks, so any block holding referenced bytes exists in full.
pub(super) async fn read_blocks<B: crate::Blob>(
    file: &B,
    offset: u64,
    len: usize,
) -> Result<IoBuf, Error> {
    debug_assert!(
        offset.is_multiple_of(BLOCK),
        "unaligned volume read at {offset}"
    );
    let rounded = block_align(len as u64) as usize;
    let buf = file.read_at(offset, rounded).await?.coalesce();
    Ok(buf.freeze().slice(0..len))
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

/// Per-blob mutable state.
#[derive(Debug, Default)]
pub(super) struct BlobInner {
    /// Current logical size (includes uncommitted writes).
    pub size: u64,
    /// Freeze boundary: bytes below are covered by the last confirmed table
    /// or the in-flight snapshot.
    pub freeze_size: u64,
    /// Written runs keyed by logical start; gaps are holes (zeros).
    pub runs: BTreeMap<u64, RunMeta>,
    /// CRC32C per backed chunk, over the chunk's written span.
    pub crcs: BTreeMap<u64, u32>,
    /// Bytes of the frontier chunk's written span (from its chunk base),
    /// kept in memory so append CRCs and commit shadows never read back.
    /// Meaningful only when `frontier_chunk` is backed.
    pub tail: Vec<u8>,
    /// Chunk `tail` describes.
    pub tail_chunk: u64,
    /// Chunks whose content changed since the last snapshot.
    pub dirty_chunks: BTreeSet<u64>,
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
    /// a hole. Every chunk is covered by at most one run.
    pub fn chunk_span(&self, chunk: u64) -> Option<(u64, u64)> {
        let chunk_start = chunk * BLOCK;
        let (logical, run) = self.covering(chunk_start)?;
        let span = (logical + run.len - chunk_start).min(BLOCK);
        Some((run.physical + (chunk_start - logical), span))
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
    pub committed_meta: BTreeMap<u64, Vec<Extent>>,
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

/// The volume once recovery has run.
pub(super) struct Ready<S: crate::Storage> {
    /// The single inner blob backing the volume.
    pub file: S::Blob,
    pub state: Mutex<State>,
    /// Serializes commits.
    pub commit_lock: AsyncMutex<()>,
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
    let target = block_align(end.div_ceil(ready.growth_quantum) * ready.growth_quantum);
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
    /// Staged chunk CRCs.
    pub crcs: BTreeMap<u64, u32>,
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
        let chunk_start = chunk * BLOCK;
        let (logical, run, _) = self.covering(inner, chunk_start)?;
        let span = (logical + run.len - chunk_start).min(BLOCK);
        Some((run.physical + (chunk_start - logical), span))
    }
}

/// One planned stretch: a single inner write plus its state updates,
/// published only after the write completes (a failed write publishes
/// nothing; its bytes land in space no table references).
struct Stretch {
    /// First logical byte NOT covered by this stretch.
    end: u64,
    /// Block-aligned physical write position.
    physical: u64,
    /// Write payload covering whole affected chunks from their block base
    /// (padded to whole blocks at write time).
    bytes: Vec<u8>,
    /// Run insert/replace: (logical start, run).
    run: (u64, RunMeta),
    /// Chunk CRC updates.
    crcs: Vec<(u64, u32)>,
    /// Bytes of the final affected chunk's written span (chunk, span bytes),
    /// used to refresh the tail buffer when this stretch reaches the blob's
    /// write frontier.
    last_span: (u64, Vec<u8>),
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
        let write_end = stretch.physical + block_align(stretch.bytes.len() as u64);
        ensure_provisioned(ready, write_end).await?;
        write_blocks(&ready.file, &ready.pool, stretch.physical, &stretch.bytes).await?;
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
        let write_end = stretch.physical + block_align(stretch.bytes.len() as u64);
        ensure_provisioned(ready, write_end).await?;
        write_blocks(&ready.file, &ready.pool, stretch.physical, &stretch.bytes).await?;
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
async fn plan_stretch<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    cursor: u64,
    end: u64,
    data: &IoBuf,
    data_base: u64,
) -> Result<Stretch, Error> {
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
        },
    }

    let plan = {
        let mut state = ready.state.lock();
        let inner = blob.inner.lock();
        let chunk = chunk_of(cursor);
        let chunk_start = chunk * BLOCK;

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
                    let extent = state.alloc.allocate(BLOCK);
                    Plan::Cow {
                        span_physical,
                        span_len,
                        extent,
                        seq: state.seq,
                    }
                } else {
                    // In place. The write may start beyond the backed end
                    // (a gap inside this run's frontier chunk): zero-fill
                    // from the backed end. It may extend past the backing
                    // but only within the extent's capacity.
                    let fill_from = cursor.min(backed_end);
                    let stretch_end = end.min(run_logical + run.capacity);
                    debug_assert!(stretch_end > cursor);
                    Plan::InPlace {
                        stretch_end,
                        run_logical,
                        run,
                        fill_from,
                        private,
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
                let len = block_align(stretch_end - chunk_start);
                let extent = state.alloc.allocate(len);
                Plan::Fresh {
                    stretch_end,
                    extent,
                    chunk_base: chunk_start,
                    seq: state.seq,
                }
            }
        }
    };

    match plan {
        Plan::InPlace {
            stretch_end,
            run_logical,
            run,
            fill_from,
            private,
        } => {
            // Assemble the full written span of every affected chunk,
            // [base, suffix_end): the first chunk's existing prefix, zeros
            // over the gap, the data slice, and the final chunk's existing
            // suffix. The whole assembly is the write — the first chunk's
            // committed prefix is rewritten in place with identical bytes so
            // the write starts at a block boundary (the shadow block covers
            // the shared tail chunk's frozen prefix against tearing; every
            // other in-place chunk holds only uncommitted bytes).
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let first_chunk = chunk_of(fill_from);
            let last_chunk = chunk_of(stretch_end - 1);
            let base = first_chunk * BLOCK;

            let mut assembled =
                read_span_prefix(ready, blob, staged, &run, run_logical, base, fill_from).await?;
            assembled.resize((cursor - base) as usize, 0);
            assembled.extend_from_slice(data.slice(d0..d1).as_ref());

            // The final chunk may have existing bytes beyond the write (an
            // in-place overwrite inside a longer span): source them from the
            // chunk's block.
            let span_end = (run_logical + run.len).max(stretch_end);
            let chunk_cap = (last_chunk + 1) * BLOCK;
            let suffix_end = span_end.min(chunk_cap);
            if suffix_end > stretch_end {
                let last_base = last_chunk * BLOCK;
                let phys = run.physical + (last_base - run_logical);
                let span =
                    read_blocks(&ready.file, phys, (suffix_end - last_base) as usize).await?;
                assembled.extend_from_slice(&span.as_ref()[(stretch_end - last_base) as usize..]);
            }

            let mut crcs = Vec::new();
            let mut last_span = (last_chunk, Vec::new());
            for chunk in first_chunk..=last_chunk {
                let s = ((chunk - first_chunk) * BLOCK) as usize;
                let e = assembled.len().min(s + BLOCK as usize);
                crcs.push((chunk, Crc32::checksum(&assembled[s..e])));
                if chunk == last_chunk {
                    last_span = (chunk, assembled[s..e].to_vec());
                }
            }

            let new_len = (stretch_end - run_logical).max(run.len);
            Ok(Stretch {
                end: stretch_end,
                physical: run.physical + (base - run_logical),
                bytes: assembled,
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
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let mut bytes = vec![0u8; (cursor - chunk_base) as usize];
            bytes.extend_from_slice(data.slice(d0..d1).as_ref());

            let first_chunk = chunk_of(chunk_base);
            let last_chunk = chunk_of(stretch_end - 1);
            let mut crcs = Vec::new();
            let mut last_span = (last_chunk, Vec::new());
            for chunk in first_chunk..=last_chunk {
                let s = ((chunk - first_chunk) * BLOCK) as usize;
                let e = bytes.len().min(s + BLOCK as usize);
                crcs.push((chunk, Crc32::checksum(&bytes[s..e])));
                if chunk == last_chunk {
                    last_span = (chunk, bytes[s..e].to_vec());
                }
            }

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
        } => {
            let chunk = chunk_of(cursor);
            let chunk_start = chunk * BLOCK;
            let stretch_end = end.min(chunk_start + BLOCK);
            // Read the old span (stable: frozen extents are never rewritten,
            // and deferred frees keep them allocated until the next commit
            // confirms).
            let old = read_blocks(&ready.file, span_physical, span_len as usize).await?;
            let w0 = (cursor - chunk_start) as usize;
            let w1 = (stretch_end - chunk_start) as usize;
            let mut bytes = old.as_ref().to_vec();
            if bytes.len() < w1 {
                bytes.resize(w1, 0);
            }
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            bytes[w0..w1].copy_from_slice(data.slice(d0..d1).as_ref());

            Ok(Stretch {
                end: stretch_end,
                physical: extent.offset,
                run: (
                    chunk_start,
                    RunMeta {
                        physical: extent.offset,
                        len: bytes.len() as u64,
                        capacity: extent.len,
                        born: seq,
                    },
                ),
                crcs: vec![(chunk, Crc32::checksum(&bytes))],
                last_span: (chunk, bytes.clone()),
                bytes,
                replaced: Some(Extent {
                    offset: span_physical - (span_physical % BLOCK),
                    len: BLOCK,
                }),
                allocated: Some(extent),
                private: true,
            })
        }
    }
}

/// Source the first affected chunk's committed prefix `[base, fill_from)`:
/// from an in-memory tail buffer when one describes this chunk, otherwise a
/// read-back (rare: mid-run in-place overwrites of unfrozen chunks).
async fn read_span_prefix<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    staged: Option<&StagedBlob>,
    run: &RunMeta,
    run_logical: u64,
    base: u64,
    fill_from: u64,
) -> Result<Vec<u8>, Error> {
    let prefix_len = (fill_from - base) as usize;
    if prefix_len == 0 {
        return Ok(Vec::new());
    }
    let chunk = chunk_of(base);
    {
        let inner = blob.inner.lock();
        match staged {
            Some(st) => {
                // The staged tail wins for chunks the batch touched; the
                // published tail is valid only for untouched chunks.
                if let Some((tail_chunk, tail)) = &st.tail {
                    if *tail_chunk == chunk && tail.len() >= prefix_len {
                        return Ok(tail[..prefix_len].to_vec());
                    }
                }
                if !st.crcs.contains_key(&chunk)
                    && inner.tail_chunk == chunk
                    && inner.tail.len() >= prefix_len
                {
                    return Ok(inner.tail[..prefix_len].to_vec());
                }
            }
            None => {
                if inner.tail_chunk == chunk && inner.tail.len() >= prefix_len {
                    return Ok(inner.tail[..prefix_len].to_vec());
                }
            }
        }
    }
    let phys = run.physical + (base - run_logical);
    Ok(read_blocks(&ready.file, phys, prefix_len)
        .await?
        .as_ref()
        .to_vec())
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

    for (chunk, crc) in stretch.crcs {
        inner.crcs.insert(chunk, crc);
        inner.dirty_chunks.insert(chunk);
    }
    // Refresh the tail buffer if this stretch reaches the write frontier.
    let (chunk, span) = stretch.last_span;
    if stretch.end >= inner.size || chunk >= inner.tail_chunk {
        inner.tail_chunk = chunk;
        inner.tail = span;
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

    for (chunk, crc) in stretch.crcs {
        staged.crcs.insert(chunk, crc);
    }
    // Refresh the staged tail if this stretch reaches the staged frontier.
    let (chunk, span) = stretch.last_span;
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
    let chunk_end = chunk_start + BLOCK;

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
    let chunk_end = chunk_start + BLOCK;

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

/// Verified read of `[offset, offset + len)`.
pub(super) async fn read_verified<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, Error> {
    ready.check_poisoned()?;
    let end = offset
        .checked_add(len as u64)
        .ok_or(Error::OffsetOverflow)?;

    'retry: loop {
        struct Seg {
            chunk_start: u64,
            /// (physical span base, span len, expected crc); None = hole.
            source: Option<(u64, u64, u32)>,
        }
        let (generation, segs) = {
            let inner = blob.inner.lock();
            if end > inner.size {
                return Err(Error::BlobInsufficientLength);
            }
            if len == 0 {
                return Ok(Vec::new());
            }
            let mut segs = Vec::new();
            for chunk in chunk_of(offset)..=chunk_of(end - 1) {
                let source = inner.chunk_span(chunk).map(|(phys, span)| {
                    (
                        phys,
                        span,
                        *inner.crcs.get(&chunk).expect("backed chunk has crc"),
                    )
                });
                segs.push(Seg {
                    chunk_start: chunk * BLOCK,
                    source,
                });
            }
            (inner.generation, segs)
        };

        let mut out = vec![0u8; len];
        for seg in &segs {
            let Some((phys, span, crc)) = seg.source else {
                continue; // hole: zeros already in place
            };
            let bytes = read_blocks(&ready.file, phys, span as usize).await?;
            if Crc32::checksum(bytes.as_ref()) != crc {
                let inner = blob.inner.lock();
                if inner.generation != generation {
                    continue 'retry;
                }
                return Err(Error::BlobCorrupt(
                    blob.partition.clone(),
                    hex(&blob.name),
                    format!("chunk {} checksum mismatch", chunk_of(seg.chunk_start)),
                ));
            }
            // Copy the requested slice of this chunk's span; bytes past the
            // span within the chunk are holes (zeros).
            let r_start = offset.max(seg.chunk_start);
            let copy_end = end.min(seg.chunk_start + span);
            if copy_end > r_start {
                out[(r_start - offset) as usize..(copy_end - offset) as usize].copy_from_slice(
                    &bytes.as_ref()[(r_start - seg.chunk_start) as usize
                        ..(copy_end - seg.chunk_start) as usize],
                );
            }
        }
        return Ok(out);
    }
}

/// Resize to `len`. The blob's `write_lock` MUST be held.
pub(super) async fn resize_locked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    len: u64,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    let old_size = blob.inner.lock().size;

    if len >= old_size {
        // Zero extension: physically zero the backed portion of the
        // boundary chunk in [old_size, len) through the normal write path
        // (the residue there is arbitrary and the table would otherwise
        // vouch for zeros it never wrote); unbacked regions become holes.
        let zero_to = {
            let inner = blob.inner.lock();
            let boundary = chunk_of(old_size);
            match inner.chunk_span(boundary) {
                Some(_) if !old_size.is_multiple_of(BLOCK) => ((boundary + 1) * BLOCK).min(len),
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
                let keep = block_align(run.len);
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
            let boundary = chunk_of(len - 1);
            inner.crcs.retain(|&c, _| c <= boundary);
            inner.dirty_chunks.retain(|&c| c <= boundary);
            inner.dirty_chunks.insert(boundary);
        }
        inner.generation += 1;
        inner.size = len;
        state.dirty.insert(blob.id);
    }

    // Recompute the boundary chunk's CRC/tail from its (unchanged) bytes.
    if len > 0 {
        let boundary = chunk_of(len - 1);
        let span = {
            let inner = blob.inner.lock();
            inner.chunk_span(boundary)
        };
        if let Some((phys, span_len)) = span {
            let bytes = read_blocks(&ready.file, phys, span_len as usize).await?;
            let mut inner = blob.inner.lock();
            inner.crcs.insert(boundary, Crc32::checksum(bytes.as_ref()));
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
