//! The commit: snapshot -> write -> fsync -> finalize.
//!
//! Commits serialize on `Ready::commit_lock` and are SELECTIVE: a commit
//! captures only the blobs it is rooted at (the synced blob — pooled with
//! every concurrently queued sync's blob by [`commit`]'s coalescing — a
//! batch's blobs, a removal's ids), expanded across applied-batch groups so
//! an applied batch is never split across commits. Every other blob's table
//! entry is served verbatim from its cached committed encoding; uncaptured
//! dirty state (dirty marks, manifest chunks, content frees) stays pending
//! for a later commit that captures the blob.
//!
//! The snapshot briefly takes each captured blob's write lock (in id order)
//! to capture a coherent entry and raise its freeze boundary; writers never
//! block on the fsync itself. A clean sync returns immediately. Any failure
//! during the write or fsync phase permanently poisons the volume (see
//! `Ready::poisoned`): a failed fsync is a volume-wide (physical) event, so
//! the latch covers every blob, captured or not.

use super::{
    alloc::{block_align, Extent},
    core::{chunk_of, merge_frozen_runs, BlobCore, ChunkCrc, CommittedMeta, Ready},
    layout::{ChecksumRef, Entry, Run, Superblock, Table},
    BLOCK,
};
use crate::{Blob as _, Error, IoBuf};
use bytes::Bytes;
use commonware_cryptography::Crc32;
use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

/// Cap on a blob's checksum refs: an append-shaped commit that would exceed
/// it rewrites the full array as one ref instead (compaction). Bounds the
/// table entry's ref list and the block-alignment slack of small delta
/// extents, while amortizing full-array rewrites to at most one per this
/// many append-shaped commits.
pub(super) const MAX_CHECKSUM_REFS: usize = 16;

/// A planned write for the commit's WRITE phase.
struct MetaWrite {
    physical: u64,
    bytes: Vec<u8>,
}

/// Everything captured by the SNAPSHOT phase.
struct Snapshot {
    seq: u64,
    table_extent: Extent,
    writes: Vec<MetaWrite>,
    /// (blob core, its new committed entry) for every captured dirty blob.
    committed: Vec<(Arc<BlobCore>, Entry)>,
    /// The capture set (groups it covers are cleared at finalize).
    capture: BTreeSet<u64>,
    /// The previous confirmed table extent (freed on confirmation).
    old_table: Option<Extent>,
}

/// Commit the dirty state of the blobs rooted at `roots` (expanded across
/// applied-batch groups), coalescing with concurrent syncs: callers pool
/// their roots, and whichever queued caller acquires the commit lock first
/// drains the pool and commits the UNION, so one fsync acknowledges every
/// pooled caller. Each caller's durability promise is met exactly — the
/// union's snapshot begins after every pooled registration — and a failed
/// union commit fails every pooled caller (they were promised durability,
/// and the poison latch stands for everyone). Returns without I/O when the
/// captured state is clean.
///
/// Coalescing is keyed off the commit-lock queue alone (no timers): under
/// the deterministic runtime, identical schedules produce identical commit
/// grouping.
pub(super) async fn commit<S: crate::Storage>(
    ready: &Ready<S>,
    roots: &[u64],
) -> Result<(), Error> {
    // Register under the CURRENT ticket before queueing: the first leader
    // to drain the pool after this point covers these roots.
    let ticket = {
        let mut pending = ready.pending.lock();
        pending.roots.extend(roots.iter().copied());
        pending.ticket.clone()
    };
    let _commit = ready.commit_lock.lock().await;
    // Resolved while queued: a leader's commit already covered our roots.
    if let Some(result) = ticket.get() {
        return result.clone();
    }
    // Leader: drain the pool (these roots plus everything registered since
    // the previous drain) and commit the union.
    let (union, ticket) = {
        let mut pending = ready.pending.lock();
        let union: Vec<u64> = std::mem::take(&mut pending.roots).into_iter().collect();
        let ticket = std::mem::replace(&mut pending.ticket, Arc::new(OnceLock::new()));
        (union, ticket)
    };
    let result = commit_locked(ready, &union).await;
    ticket
        .set(result.clone())
        .expect("only the draining leader resolves a ticket");
    result
}

/// [`commit`] with `Ready::commit_lock` already held by the caller.
pub(super) async fn commit_locked<S: crate::Storage>(
    ready: &Ready<S>,
    roots: &[u64],
) -> Result<(), Error> {
    ready.check_poisoned()?;

    let capture = {
        let state = ready.state.lock();
        let capture = state.expand_capture(roots);
        if !state.meta_dirty && state.dirty.iter().all(|id| !capture.contains(id)) {
            return Ok(());
        }
        capture
    };

    let snapshot = match take_snapshot(ready, capture).await {
        Ok(s) => s,
        Err(e) => {
            // Snapshot allocates extents and mutates freeze/dirty state; a
            // failure mid-way leaves the volume inconsistent with its
            // bookkeeping. Poison (consistent with the workspace rule that
            // mutable storage-op failures are fatal).
            let _ = ready.poisoned.set(e.clone());
            return Err(e);
        }
    };

    for write in &snapshot.writes {
        let end = write.physical + write.bytes.len() as u64;
        if let Err(e) = super::core::ensure_provisioned(ready, end).await {
            let _ = ready.poisoned.set(e.clone());
            return Err(e);
        }
        if let Err(e) = ready
            .file
            .write_at(write.physical, IoBuf::copy_from_slice(&write.bytes))
            .await
        {
            let _ = ready.poisoned.set(e.clone());
            return Err(e);
        }
    }

    if let Err(e) = ready.file.sync().await {
        let _ = ready.poisoned.set(e.clone());
        return Err(e);
    }

    finalize(ready, snapshot);
    Ok(())
}

/// Capture the commit's content and allocate/encode its metadata writes.
async fn take_snapshot<S: crate::Storage>(
    ready: &Ready<S>,
    capture: BTreeSet<u64>,
) -> Result<Snapshot, Error> {
    // Assign the seq and advance the freeze epoch before touching blobs:
    // writes racing the snapshot land with `born > snapshot_seq` and are
    // exempt from freezing only until their blob's capture below, which
    // re-stamps every run it references (a racing run captured by this
    // commit is NOT invisible to it — only runs created after the capture
    // are). Uncaptured dirty blobs lose the exemption entirely (their young
    // extents are not referenced by any table): conservatively over-frozen,
    // which costs an extra COW on a later in-place rewrite but is always
    // safe.
    let (seq, dirty_ids) = {
        let mut state = ready.state.lock();
        let seq = state.seq;
        state.seq += 1;
        state.snapshot_seq = seq;
        let dirty_ids: Vec<u64> = state
            .dirty
            .iter()
            .copied()
            .filter(|id| capture.contains(id))
            .collect();
        (seq, dirty_ids)
    };

    let mut writes = Vec::new();
    let mut committed = Vec::new();
    let mut manifest = Vec::new();

    for id in dirty_ids {
        let Some(blob) = ready.state.lock().open.get(&id).cloned() else {
            continue; // removed with no handles: nothing to snapshot
        };
        // Serialize against writers so the captured entry is coherent with
        // issued bytes; released before any I/O below (the capture is a
        // value snapshot, and the freeze boundary protects it thereafter).
        let write_guard = blob.write_lock.lock().await;
        let (entry, dirty_chunks, array_start, cksum_bytes, shadow_bytes, retained, superseded) = {
            let mut state = ready.state.lock();
            let mut inner = blob.inner.lock();
            if inner.removed {
                state.dirty.remove(&id);
                continue;
            }

            // Raise the freeze boundary: nothing this snapshot covers may be
            // rewritten in place until it is confirmed (or rolled back).
            inner.freeze_size = inner.freeze_size.max(inner.size);

            // Finalize deferred chunk CRCs from their overlay entries (the
            // write lock quiesces the writer): the checksum array, tail
            // CRC, and delta manifest below must carry exact values.
            inner.overlay_finalize();

            // Freeze the captured runs atomically with the capture (the
            // model freezes per-run coverage at snapshot time): this entry,
            // its checksum extents, and its manifest reference every run
            // below, so the young-extent exemption must not apply to any of
            // them — an in-place rewrite after capture would invalidate a
            // manifested chunk and roll back this commit at recovery. Runs
            // created after this point keep `born > snapshot_seq` and stay
            // exempt: they are genuinely absent from this commit's table.
            for run in inner.runs.values_mut() {
                run.born = run.born.min(seq);
            }

            // With every run frozen as of this capture, coalesce contiguous
            // neighbors: the entry encodes fewer runs and every later
            // runs-map descent walks a shallower map. Skipped while a batch
            // holds staged state for this blob, whose overlay references
            // base runs by key (merging would move keys under it).
            if inner.staged_batches == 0 {
                merge_frozen_runs(&mut inner.runs);
            }
            let dirty_chunks: Vec<u64> = std::mem::take(&mut inner.dirty_chunks)
                .into_iter()
                .collect();
            state.dirty.remove(&id);

            // Content frees of a captured blob resolve when this commit
            // confirms: its new entry stops referencing them.
            let pending = std::mem::take(&mut inner.pending_frees);
            for extent in pending {
                state.defer_free(extent, seq, None);
            }

            let last_backed = inner
                .runs
                .iter()
                .next_back()
                .map(|(&l, r)| chunk_of(l + r.len - 1));

            // Chunk coverage the checksum refs must provide: every backed
            // chunk below the frontier, plus the frontier itself when it is
            // a FULL chunk (a partial frontier is served by `tail_crc`, so
            // coverage stops below it). Hole positions inside the covered
            // range are never consulted (holes are identified from the
            // runs, not the array).
            let covered_end = last_backed.map_or(0, |last| {
                let (_, span) = inner.chunk_span(last).expect("backed chunk");
                if span == BLOCK {
                    last + 1
                } else {
                    last
                }
            });

            // Append-shaped dirt leaves every previously covered chunk's
            // CRC valid: extend coverage with one NEW delta ref and keep
            // the prior refs (and their extents) untouched, so a bulk-load
            // sync stops rewriting the blob's whole array. Anything else —
            // dirt below the covered frontier (overwrite, COW, shrink),
            // coverage shrinking (rewind), or a full ref list — rewrites
            // the array as a single ref, which also keeps refs disjoint
            // and contiguous from chunk 0 (compaction).
            let prev_refs = inner
                .committed_entry
                .as_ref()
                .map_or(&[][..], |e| &e.checksums[..]);
            let prev_end = prev_refs
                .last()
                .map_or(0, |r| r.first_chunk + r.count as u64);
            let delta = covered_end >= prev_end
                && prev_refs.len() < MAX_CHECKSUM_REFS
                && dirty_chunks.first().is_none_or(|&c| c >= prev_end);
            let (array_start, checksums) = if delta {
                (prev_end, prev_refs.to_vec())
            } else {
                (0, Vec::new())
            };
            let cksum_bytes: Vec<u8> = {
                let mut bytes = Vec::with_capacity(((covered_end - array_start) * 4) as usize);
                for c in array_start..covered_end {
                    let crc = inner.crcs.get(&c).map_or(0, |s| match s.crc {
                        ChunkCrc::Ready(crc) => crc,
                        // Finalized above (every pending chunk is resident).
                        ChunkCrc::Pending => unreachable!("pending CRC at capture"),
                    });
                    bytes.extend_from_slice(&crc.to_be_bytes());
                }
                bytes
            };

            // Shadow: the frontier chunk's span, when partial (post-commit
            // appends will write into its block in place; recovery restores
            // the frozen span from the shadow).
            let shadow_bytes = last_backed.and_then(|last| {
                let (_, span) = inner.chunk_span(last).expect("backed chunk");
                (span < BLOCK).then(|| {
                    debug_assert_eq!(inner.tail_chunk, last);
                    debug_assert_eq!(inner.tail.len() as u64, span);
                    inner.tail.clone()
                })
            });

            let tail_crc =
                last_backed
                    .and_then(|last| inner.crcs.get(&last))
                    .map_or(0, |s| match s.crc {
                        ChunkCrc::Ready(crc) => crc,
                        ChunkCrc::Pending => unreachable!("pending CRC at capture"),
                    });

            let runs: Vec<Run> = inner
                .runs
                .iter()
                .map(|(&logical, r)| Run {
                    logical,
                    physical: r.physical,
                    len: r.len,
                })
                .collect();

            // Extents the new entry stops referencing, freed once this
            // commit confirms: the previous shadow always (each commit that
            // needs one writes a fresh block), the previous checksum
            // extents only on a full rewrite (a delta commit keeps
            // referencing them).
            let mut prev_meta = state.committed_meta.remove(&id).unwrap_or_default();
            debug_assert_eq!(
                prev_meta.checksums.len(),
                prev_refs.len(),
                "committed_meta out of sync with the committed entry"
            );
            let mut superseded: Vec<Extent> = Vec::new();
            superseded.extend(prev_meta.shadow.take());
            let retained = if delta {
                std::mem::take(&mut prev_meta.checksums)
            } else {
                superseded.append(&mut prev_meta.checksums);
                Vec::new()
            };

            let entry = Entry {
                id,
                partition: 0, // resolved during table assembly
                name: blob.name.clone(),
                version: blob.version,
                size: inner.size,
                runs,
                checksums, // retained refs (a new delta/full ref is pushed below)
                tail_crc,
                shadow: None, // filled after allocation below
            };
            (
                entry,
                dirty_chunks,
                array_start,
                cksum_bytes,
                shadow_bytes,
                retained,
                superseded,
            )
        };
        drop(write_guard);

        // Allocate + stage checksum/shadow writes.
        let mut entry = entry;
        let mut meta = CommittedMeta {
            checksums: retained,
            shadow: None,
        };
        if !cksum_bytes.is_empty() {
            let extent = {
                let mut state = ready.state.lock();
                state.alloc.allocate(block_align(cksum_bytes.len() as u64))
            };
            entry.checksums.push(ChecksumRef {
                first_chunk: array_start,
                count: (cksum_bytes.len() / 4) as u32,
                offset: extent.offset,
                crc: Crc32::checksum(&cksum_bytes),
            });
            writes.push(MetaWrite {
                physical: extent.offset,
                bytes: cksum_bytes,
            });
            meta.checksums.push(extent);
        }
        if let Some(shadow) = shadow_bytes {
            let extent = {
                let mut state = ready.state.lock();
                state.alloc.allocate(BLOCK)
            };
            entry.shadow = Some(extent.offset);
            writes.push(MetaWrite {
                physical: extent.offset,
                bytes: shadow,
            });
            meta.shadow = Some(extent);
        }
        for chunk in dirty_chunks {
            manifest.push((id, chunk));
        }
        {
            let mut state = ready.state.lock();
            for extent in superseded {
                state.defer_free(extent, seq, None);
            }
            state.committed_meta.insert(id, meta);
        }
        committed.push((blob, entry));
    }

    // Assemble the table: captured blobs re-encode; everything else is
    // served from its cached encoded entry (encoded lazily on first use),
    // so assembly is O(captured + concatenation).
    let (old_table, table_extent) = {
        let mut state = ready.state.lock();
        state.meta_dirty = false;

        // Encodings embed partition indexes: a changed partition LIST
        // invalidates every cached encoding.
        if state.encoded_epoch != state.partition_epoch {
            state.encoded.clear();
            state.encoded_epoch = state.partition_epoch;
        }

        let partitions: Vec<String> = state.partitions.keys().cloned().collect();
        let pindex = |p: &str, partitions: &[String]| {
            partitions
                .iter()
                .position(|x| x == p)
                .expect("known partition") as u32
        };

        // Fresh encodings for captured blobs.
        for (blob, entry) in &mut committed {
            entry.partition = pindex(&blob.partition, &partitions);
            state.encoded.insert(entry.id, Bytes::from(entry.encode()));
        }
        // Cache misses among served blobs (first commit after recovery or
        // an epoch change).
        let mut missing: Vec<(u64, Bytes)> = Vec::new();
        for (&id, (partition, entry)) in &state.dormant {
            if state.encoded.contains_key(&id) {
                continue;
            }
            let mut entry = entry.clone();
            entry.partition = pindex(partition, &partitions);
            missing.push((id, Bytes::from(entry.encode())));
        }
        for (&id, core) in &state.open {
            if state.encoded.contains_key(&id) {
                continue;
            }
            // Served open blob: its cached committed entry (set by the last
            // commit that captured it), or a fresh empty entry (created but
            // never captured). Never derived from live state, which may
            // hold uncommitted writes.
            let inner = core.inner.lock();
            if inner.removed {
                continue;
            }
            let mut entry = inner.committed_entry.clone().unwrap_or_else(|| Entry {
                id: core.id,
                partition: 0,
                name: core.name.clone(),
                version: core.version,
                size: 0,
                runs: Vec::new(),
                checksums: Vec::new(),
                tail_crc: 0,
                shadow: None,
            });
            entry.partition = pindex(&core.partition, &partitions);
            missing.push((id, Bytes::from(entry.encode())));
        }
        for (id, bytes) in missing {
            state.encoded.insert(id, bytes);
        }
        manifest.sort_unstable();
        debug_assert_eq!(
            state.encoded.len(),
            state.dormant.len()
                + state
                    .open
                    .values()
                    .filter(|core| !core.inner.lock().removed)
                    .count(),
            "encoded-entry cache out of sync with the namespace"
        );

        let entries: Vec<Bytes> = state.encoded.values().cloned().collect();
        let bytes = Table::assemble(seq, state.next_id, &partitions, entries, &manifest);
        let extent = state.alloc.allocate(block_align(bytes.len() as u64));
        let superblock_offset = Superblock::slot_offset(1 - state.sacred_slot);
        let sb = Superblock {
            seq,
            table_offset: extent.offset,
            table_len: bytes.len() as u32,
            table_crc: Crc32::checksum(&bytes),
        };
        writes.push(MetaWrite {
            physical: extent.offset,
            bytes,
        });
        writes.push(MetaWrite {
            physical: superblock_offset,
            bytes: sb.encode(),
        });
        (state.table_extent, extent)
    };

    Ok(Snapshot {
        seq,
        table_extent,
        writes,
        committed,
        capture,
        old_table,
    })
}

/// Publish a confirmed commit.
fn finalize<S: crate::Storage>(ready: &Ready<S>, snapshot: Snapshot) {
    let mut state = ready.state.lock();
    state.sacred_slot = 1 - state.sacred_slot;
    state.confirmed_seq = snapshot.seq;
    if let Some(old) = snapshot.old_table {
        let seq = snapshot.seq;
        state.defer_free(old, seq, None);
    }
    state.table_extent = Some(snapshot.table_extent);
    // Applied-batch groups covered by this capture are committed. Capture
    // expansion guarantees all-or-nothing coverage (never-split).
    state.groups.retain(|group| {
        let covered = group.iter().any(|id| snapshot.capture.contains(id));
        debug_assert!(
            !covered || group.iter().all(|id| snapshot.capture.contains(id)),
            "commit split an applied batch group"
        );
        !covered
    });
    state.apply_frees();
    drop(state);

    for (blob, entry) in snapshot.committed {
        let mut inner = blob.inner.lock();
        // The confirmed size is now the exact freeze boundary (a rewind
        // below the old boundary takes effect here).
        inner.freeze_size = entry.size;
        inner.shadow = entry.shadow;
        inner.committed_entry = Some(entry);
    }
}
