//! The group commit: snapshot -> write -> fsync -> finalize.
//!
//! Commits serialize on `Ready::commit_lock`. The snapshot briefly takes
//! each dirty blob's write lock (in id order) to capture a coherent entry
//! and raise its freeze boundary; writers never block on the fsync itself.
//! A clean sync returns immediately. Any failure during the write or fsync
//! phase permanently poisons the volume (see `Ready::poisoned`).

use super::{
    alloc::{block_align, Extent},
    core::{chunk_of, BlobCore, Ready},
    layout::{ChecksumRef, Entry, Run, Superblock, Table},
    BLOCK,
};
use crate::{Blob as _, Error, IoBuf};
use commonware_cryptography::Crc32;
use std::sync::Arc;

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
    /// (blob core, its new committed entry) for every dirty blob.
    committed: Vec<(Arc<BlobCore>, Entry)>,
    /// The previous confirmed table extent (freed on confirmation).
    old_table: Option<Extent>,
}

/// Commit all dirty state. Returns without I/O when clean.
pub(super) async fn commit<S: crate::Storage>(ready: &Ready<S>) -> Result<(), Error> {
    let _commit = ready.commit_lock.lock().await;
    ready.check_poisoned()?;

    {
        let state = ready.state.lock();
        if state.dirty.is_empty() && !state.meta_dirty {
            return Ok(());
        }
    }

    let snapshot = match take_snapshot(ready).await {
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
async fn take_snapshot<S: crate::Storage>(ready: &Ready<S>) -> Result<Snapshot, Error> {
    // Assign the seq and advance the freeze epoch before touching blobs:
    // writes racing the snapshot land with `born > snapshot_seq` and are
    // exempt from freezing (their extents are invisible to this commit).
    let (seq, dirty_ids) = {
        let mut state = ready.state.lock();
        let seq = state.seq;
        state.seq += 1;
        state.snapshot_seq = seq;
        (seq, state.dirty.iter().copied().collect::<Vec<_>>())
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
        let (entry, dirty_chunks, cksum_bytes, shadow_bytes, superseded) = {
            let mut state = ready.state.lock();
            let mut inner = blob.inner.lock();
            if inner.removed {
                state.dirty.remove(&id);
                continue;
            }

            // Raise the freeze boundary: nothing this snapshot covers may be
            // rewritten in place until it is confirmed (or rolled back).
            inner.freeze_size = inner.freeze_size.max(inner.size);
            let dirty_chunks: Vec<u64> = std::mem::take(&mut inner.dirty_chunks)
                .into_iter()
                .collect();
            state.dirty.remove(&id);

            // Dense chunk CRC array over [0, last backed chunk]; hole
            // positions are never consulted (holes are identified from the
            // runs, not the array).
            let last_backed = inner
                .runs
                .iter()
                .next_back()
                .map(|(&l, r)| chunk_of(l + r.len - 1));
            let cksum_bytes: Vec<u8> = last_backed.map_or_else(Vec::new, |last| {
                let mut bytes = Vec::with_capacity(((last + 1) * 4) as usize);
                for c in 0..=last {
                    bytes
                        .extend_from_slice(&inner.crcs.get(&c).copied().unwrap_or(0).to_be_bytes());
                }
                bytes
            });

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

            let tail_crc = last_backed
                .and_then(|last| inner.crcs.get(&last).copied())
                .unwrap_or(0);

            let runs: Vec<Run> = inner
                .runs
                .iter()
                .map(|(&logical, r)| Run {
                    logical,
                    physical: r.physical,
                    len: r.len,
                })
                .collect();

            // Extents referenced by the PREVIOUS entry for this blob are
            // superseded once this commit confirms.
            let superseded = state.committed_meta.remove(&id).unwrap_or_default();

            let entry = Entry {
                id,
                partition: 0, // resolved during table assembly
                name: blob.name.clone(),
                version: blob.version,
                size: inner.size,
                runs,
                checksums: Vec::new(), // filled after allocation below
                tail_crc,
                shadow: None, // filled after allocation below
            };
            (entry, dirty_chunks, cksum_bytes, shadow_bytes, superseded)
        };
        drop(write_guard);

        // Allocate + stage checksum/shadow writes.
        let mut entry = entry;
        let mut meta_extents = Vec::new();
        if !cksum_bytes.is_empty() {
            let extent = {
                let mut state = ready.state.lock();
                state.alloc.allocate(block_align(cksum_bytes.len() as u64))
            };
            entry.checksums.push(ChecksumRef {
                first_chunk: 0,
                count: (cksum_bytes.len() / 4) as u32,
                offset: extent.offset,
                crc: Crc32::checksum(&cksum_bytes),
            });
            writes.push(MetaWrite {
                physical: extent.offset,
                bytes: cksum_bytes,
            });
            meta_extents.push(extent);
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
            meta_extents.push(extent);
        }
        for chunk in dirty_chunks {
            manifest.push((id, chunk));
        }
        {
            let mut state = ready.state.lock();
            for extent in superseded {
                state.defer_free(extent, seq, None);
            }
            state.committed_meta.insert(id, meta_extents);
        }
        committed.push((blob, entry));
    }

    // Assemble the table: dormant entries verbatim, open blobs' committed
    // entries (cached for clean blobs, fresh for dirty ones).
    let (old_table, table_extent) = {
        let mut state = ready.state.lock();
        state.meta_dirty = false;

        let partitions: Vec<String> = state.partitions.keys().cloned().collect();
        let pindex = |p: &str, partitions: &[String]| {
            partitions
                .iter()
                .position(|x| x == p)
                .expect("known partition") as u32
        };

        let mut blobs: Vec<Entry> = state.dormant.values().cloned().collect();
        for (blob, entry) in &mut committed {
            entry.partition = pindex(&blob.partition, &partitions);
            blobs.push(entry.clone());
        }
        for (id, core) in &state.open {
            if committed.iter().any(|(b, _)| b.id == *id) {
                continue;
            }
            // Clean open blob: its cached committed entry (set by the last
            // commit that covered it), or a fresh empty entry (created but
            // never written).
            let inner = core.inner.lock();
            if inner.removed {
                continue;
            }
            let mut entry = inner.committed_entry.clone().unwrap_or_else(|| Entry {
                id: core.id,
                partition: 0,
                name: core.name.clone(),
                version: core.version,
                size: inner.size,
                runs: Vec::new(),
                checksums: Vec::new(),
                tail_crc: 0,
                shadow: None,
            });
            entry.partition = pindex(&core.partition, &partitions);
            blobs.push(entry);
        }
        blobs.sort_by_key(|e| e.id);
        manifest.sort_unstable();

        let table = Table {
            seq,
            next_id: state.next_id,
            partitions,
            blobs,
            manifest,
        };
        let bytes = table.encode();
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
