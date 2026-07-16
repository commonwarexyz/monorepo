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
    /// first committed with content). Used verbatim for clean blobs at
    /// table assembly — never derived from live state, which may already
    /// contain post-snapshot writes.
    pub committed_entry: Option<Entry>,
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
    /// Committed entries for blobs NOT opened this run, served verbatim into
    /// every table and hydrated into `open` on first open.
    pub dormant: BTreeMap<u64, Entry>,
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
}

impl State {
    /// Queue an extent for reuse once `free_at` confirms (and, for removed
    /// blobs' extents, once the last handle drops).
    pub fn defer_free(&mut self, extent: Extent, free_at: u64, gate: Option<u64>) {
        self.pending_free.push((extent, free_at, gate));
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
}

impl<S: crate::Storage> Ready<S> {
    pub fn check_poisoned(&self) -> Result<(), Error> {
        self.poisoned.get().map_or(Ok(()), |e| Err(e.clone()))
    }
}

/// One planned stretch: a single inner write plus its state updates,
/// published only after the write completes (a failed write publishes
/// nothing; its bytes land in space no table references).
struct Stretch {
    /// First logical byte NOT covered by this stretch.
    end: u64,
    physical: u64,
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
        let stretch = plan_stretch(ready, blob, cursor, end, &data, offset).await?;
        ready
            .file
            .write_at(stretch.physical, IoBuf::copy_from_slice(&stretch.bytes))
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

/// Plan the next stretch starting at `cursor` (performing any COW/CRC
/// read-backs needed to make the plan self-contained).
async fn plan_stretch<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
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
        },
        /// Fresh extent for `[chunk_base, stretch_end)` (zero-lead below the
        /// write; the chunk base is unbacked).
        Fresh {
            stretch_end: u64,
            extent: Extent,
            chunk_base: u64,
            seq: u64,
        },
        /// The cursor's chunk is frozen: COW its backed span.
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

        match inner.covering(chunk_start) {
            Some((run_logical, run)) => {
                let backed_end = run_logical + run.len;
                let writable = run.born > state.snapshot_seq || cursor >= inner.freeze_size;
                if !writable {
                    let (span_physical, span_len) =
                        inner.chunk_span(chunk).expect("covered chunk has a span");
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
                    }
                }
            }
            None => {
                // Unbacked chunk: fresh extent from this chunk's base to the
                // end of the write (or the next backed run, which must not
                // be overlapped).
                let next_backed = inner
                    .runs
                    .range(chunk_start..)
                    .next()
                    .map(|(&l, _)| l)
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
        } => {
            // Assemble the write: zeros over the gap, then the data slice.
            let d0 = (cursor - data_base) as usize;
            let d1 = (stretch_end - data_base) as usize;
            let mut bytes = vec![0u8; (cursor - fill_from) as usize];
            bytes.extend_from_slice(data.slice(d0..d1).as_ref());

            // CRC recomputation needs the full written span of each affected
            // chunk. The first chunk may have a prefix below `fill_from`;
            // the last chunk may have a suffix beyond `stretch_end` (an
            // in-place overwrite inside a longer span).
            let first_chunk = chunk_of(fill_from);
            let last_chunk = chunk_of(stretch_end - 1);
            let base = first_chunk * BLOCK;

            let prefix = read_span_prefix(ready, blob, &run, run_logical, base, fill_from).await?;
            let span_end = (run_logical + run.len).max(stretch_end);
            let chunk_cap = (last_chunk + 1) * BLOCK;
            let suffix_end = span_end.min(chunk_cap);
            let suffix: Vec<u8> = if suffix_end > stretch_end {
                let phys = run.physical + (stretch_end - run_logical);
                ready
                    .file
                    .read_at(phys, (suffix_end - stretch_end) as usize)
                    .await?
                    .coalesce()
                    .as_ref()
                    .to_vec()
            } else {
                Vec::new()
            };

            // assembled covers [base, suffix_end).
            let mut assembled = prefix;
            assembled.extend_from_slice(&bytes);
            assembled.extend_from_slice(&suffix);

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
            let old = ready
                .file
                .read_at(span_physical, span_len as usize)
                .await?
                .coalesce();
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
            })
        }
    }
}

/// Source the first affected chunk's committed prefix `[base, fill_from)`:
/// from the in-memory tail buffer when it describes this chunk, otherwise a
/// read-back (rare: mid-run in-place overwrites of unfrozen chunks).
async fn read_span_prefix<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    run: &RunMeta,
    run_logical: u64,
    base: u64,
    fill_from: u64,
) -> Result<Vec<u8>, Error> {
    let prefix_len = (fill_from - base) as usize;
    if prefix_len == 0 {
        return Ok(Vec::new());
    }
    {
        let inner = blob.inner.lock();
        if inner.tail_chunk == chunk_of(base) && inner.tail.len() >= prefix_len {
            return Ok(inner.tail[..prefix_len].to_vec());
        }
    }
    let phys = run.physical + (base - run_logical);
    Ok(ready
        .file
        .read_at(phys, prefix_len)
        .await?
        .coalesce()
        .as_ref()
        .to_vec())
}

/// Publish a completed stretch. Caller holds the blob write lock.
fn publish_stretch<S: crate::Storage>(ready: &Ready<S>, blob: &BlobCore, stretch: Stretch) {
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();
    let (logical, run) = stretch.run;

    if let Some(replaced) = stretch.replaced {
        let seq = state.seq;
        cow_remap(&mut inner, logical, run);
        state.defer_free(replaced, seq, None);
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
            let bytes = ready.file.read_at(phys, span as usize).await?.coalesce();
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
    // the boundary chunk's CRC + tail buffer.
    {
        let mut state = ready.state.lock();
        let mut inner = blob.inner.lock();
        let seq = state.seq;

        let dropped: Vec<u64> = inner.runs.range(len..).map(|(&l, _)| l).collect();
        for l in dropped {
            let run = inner.runs.remove(&l).unwrap();
            state.defer_free(
                Extent {
                    offset: run.physical,
                    len: run.capacity,
                },
                seq,
                None,
            );
        }
        if let Some((l, _)) = inner.covering(len.saturating_sub(1)).filter(|_| len > 0) {
            let run = inner.runs.get_mut(&l).unwrap();
            if l + run.len > len {
                run.len = len - l;
                let keep = block_align(run.len);
                if run.capacity > keep {
                    state.defer_free(
                        Extent {
                            offset: run.physical + keep,
                            len: run.capacity - keep,
                        },
                        seq,
                        None,
                    );
                    run.capacity = keep;
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
            let bytes = ready
                .file
                .read_at(phys, span_len as usize)
                .await?
                .coalesce();
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
