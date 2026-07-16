//! Cross-blob write batches: stage now, publish (and commit) atomically.
//!
//! Staging is two-phase and efficiency-first:
//!
//! 1. STAGE: [`Batch::write_at`] / [`Batch::resize`] plan and write through
//!    to the volume file immediately — one inner write per contiguous
//!    stretch with a streaming CRC pass, the identical I/O profile of
//!    unbatched writes. All resulting state (run splices, chunk CRCs, the
//!    staged size and tail) accumulates in the batch's per-blob overlays,
//!    NOT in the blobs' published state: readers, commits, and snapshots
//!    cannot observe staged bytes. Placement follows the batch rule proven
//!    by the model: in place only where no snapshot can capture the bytes
//!    (batch-private extents, or at/beyond BOTH the blob's published size
//!    and its freeze boundary — the shared tail block's committed bytes
//!    stay covered by the shadow mechanism); staged overwrites of any
//!    published byte relocate to fresh extents nothing references yet.
//! 2. PUBLISH: [`Batch::apply`] swings sizes, runs, CRCs, and dirty marks
//!    under the commit lock — pure RAM, O(ops), no I/O — and records the
//!    blobs as one applied-batch group. From then on any commit capturing
//!    one of them captures all of them (never-split), until a commit
//!    resolves the group. [`Batch::apply_sync`] additionally commits the
//!    group immediately.
//!
//! A batch dropped without apply never happened: its bytes live in extents
//! no table references, returned through the ordinary deferred-free path.
//! A crash before apply likewise discards the batch wholesale.
//!
//! # Writer exclusivity
//!
//! While a batch holds staged content for a blob, the batch is that blob's
//! ONE writer: mutating the blob outside the batch before apply rewrites
//! bytes whose staged expected content the overlay already recorded (found
//! by the model). This is the [`crate::Blob`] contract's writer exclusivity
//! applied to the batch as a deferred writer.
//!
//! # Removals and creations
//!
//! [`Batch::remove`] stages namespace removals and [`Batch::create`] stages
//! blob creations. Both land atomically with the publish and require
//! [`Batch::apply_sync`]. A removal published without an immediate commit
//! could be committed by an unrelated sync while the batch's writes stay
//! uncommitted (an entry drop is global, so the never-split group cannot
//! defer it), and a creation is symmetric: table assembly emits an entry
//! for every live blob, so a published-but-uncommitted creation would be
//! persisted by any unrelated commit without the batch's other members.
//! [`Batch::apply_sync`] publishes and commits under one hold of the commit
//! lock, so no such commit can interleave.

use super::{
    alloc::Extent,
    commit,
    core::{
        chunk_of, stage_write, BlobCore, BlobInner, ChunkCrc, ChunkState, Ready, RunMeta,
        StagedBlob, StagedRun,
    },
    unlink, Blob, HandleTracker, Shared, BLOCK,
};
use crate::{Blob as _, Error, IoBuf, IoBufs, DEFAULT_BLOB_VERSION};
use commonware_cryptography::Crc32;
use commonware_formatting::hex;
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// One blob's staged state within a batch.
struct Staged {
    core: Arc<BlobCore>,
    overlay: StagedBlob,
    /// Batch-allocated extents no longer referenced by the overlay (staged
    /// shrink): freed at apply, or at drop with the rest.
    discarded: Vec<Extent>,
    /// Whether the blob was staged for membership only ([`Batch::sync`]).
    touched_only: bool,
}

/// A staged blob creation: the namespace entry publishes at apply.
struct Creation {
    partition: String,
    name: Vec<u8>,
    core: Arc<BlobCore>,
}

/// A batch of writes spanning multiple blobs of one volume, staged
/// write-through and published atomically. See the module docs.
pub struct Batch<S: crate::Storage> {
    shared: Arc<Shared<S>>,
    ready: Arc<Ready<S>>,
    staged: BTreeMap<u64, Staged>,
    removals: Vec<(String, Option<Vec<u8>>)>,
    creations: Vec<Creation>,
    applied: bool,
}

impl<S: crate::Storage> Batch<S> {
    pub(super) const fn new(shared: Arc<Shared<S>>, ready: Arc<Ready<S>>) -> Self {
        Self {
            shared,
            ready,
            staged: BTreeMap::new(),
            removals: Vec::new(),
            creations: Vec::new(),
            applied: false,
        }
    }

    /// The staged entry for `blob`, created (at the blob's published size)
    /// on first touch.
    fn staged_mut(&mut self, blob: &Blob<S>) -> &mut Staged {
        self.staged.entry(blob.core.id).or_insert_with(|| Staged {
            core: blob.core.clone(),
            overlay: StagedBlob::new(blob.core.inner.lock().size),
            discarded: Vec::new(),
            touched_only: true,
        })
    }

    /// Stage a write of `bufs` at `offset`, writing through to disk.
    pub async fn write_at(
        &mut self,
        blob: &Blob<S>,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let data = bufs.into().coalesce();
        if data.is_empty() {
            return Ok(());
        }
        let ready = self.ready.clone();
        let core = blob.core.clone();
        let staged = self.staged_mut(blob);
        staged.touched_only = false;
        let _guard = core.write_lock.lock().await;
        stage_write(&ready, &core, &mut staged.overlay, offset, data).await
    }

    /// Stage a resize to `len`.
    pub async fn resize(&mut self, blob: &Blob<S>, len: u64) -> Result<(), Error> {
        self.ready.check_poisoned()?;
        let ready = self.ready.clone();
        let core = blob.core.clone();
        let staged = self.staged_mut(blob);
        staged.touched_only = false;
        let _guard = core.write_lock.lock().await;

        if len >= staged.overlay.size {
            // Zero extension: physically zero the backed portion of the
            // boundary chunk (merged view) through the staged write path;
            // unbacked regions become holes.
            let size = staged.overlay.size;
            let zero_to = {
                let inner = core.inner.lock();
                let boundary = chunk_of(size);
                match staged.overlay.chunk_span(&inner, boundary) {
                    Some(_) if !size.is_multiple_of(BLOCK) => ((boundary + 1) * BLOCK).min(len),
                    _ => size,
                }
            };
            if zero_to > size {
                let zeros = IoBuf::copy_from_slice(&vec![0u8; (zero_to - size) as usize]);
                stage_write(&ready, &core, &mut staged.overlay, size, zeros).await?;
            }
            staged.overlay.size = staged.overlay.size.max(len);
            return Ok(());
        }

        // Staged shrink: trim the overlay so apply publishes the truncated
        // view; base extents dropped from coverage are replaced at apply.
        {
            let inner = core.inner.lock();
            let overlay = &mut staged.overlay;

            let dropped: Vec<u64> = overlay.runs.range(len..).map(|(&l, _)| l).collect();
            for l in dropped {
                let sr = overlay.runs.remove(&l).expect("listed key");
                let extent = Extent {
                    offset: sr.meta.physical,
                    len: sr.meta.capacity,
                };
                if sr.private {
                    // Batch-allocated: nothing will ever reference it.
                    overlay.fresh.retain(|e| e.offset != extent.offset);
                    staged.discarded.push(extent);
                } else {
                    // The base run underneath drops with the overlay.
                    overlay.removed.insert(l);
                    overlay.replaced.push(extent);
                }
            }
            for (&l, r) in inner.runs.range(len..) {
                if overlay.removed.contains(&l) {
                    continue;
                }
                overlay.removed.insert(l);
                overlay.replaced.push(Extent {
                    offset: r.physical,
                    len: r.capacity,
                });
            }
            // Trim the boundary run in the overlay (capacity kept: staged
            // shrink never trims extent capacity; a later capture of the
            // published state reclaims nothing it still owns).
            if len > 0 {
                if let Some((l, run, private)) = overlay.covering(&inner, len - 1) {
                    if l + run.len > len {
                        overlay.runs.insert(
                            l,
                            StagedRun {
                                meta: RunMeta {
                                    len: len - l,
                                    ..run
                                },
                                private,
                            },
                        );
                    }
                }
            }
            if len == 0 {
                overlay.crcs.clear();
                overlay.tail = Some((0, Vec::new()));
            } else {
                let boundary = chunk_of(len - 1);
                overlay.crcs.retain(|&c, _| c <= boundary);
            }
            overlay.relocated = true;
            overlay.size = len;
        }

        // Recompute the boundary chunk's CRC/tail from its (unchanged)
        // bytes in the merged view.
        if len > 0 {
            let boundary = chunk_of(len - 1);
            let span = {
                let inner = core.inner.lock();
                staged.overlay.chunk_span(&inner, boundary)
            };
            if let Some((phys, span_len)) = span {
                let bytes = ready
                    .file
                    .read_at(phys, span_len as usize)
                    .await?
                    .coalesce();
                // Recomputed from an unchecked read-back: the boundary chunk
                // stays unverified (see `ChunkState`).
                let state = ChunkState {
                    crc: ChunkCrc::Ready(Crc32::checksum(bytes.as_ref())),
                    verified: false,
                };
                staged.overlay.crcs.insert(boundary, state);
                staged.overlay.tail = Some((boundary, bytes.as_ref().to_vec()));
            }
        }
        Ok(())
    }

    /// Include `blob` in the batch's atomic group without staging content:
    /// its (directly written) dirty state commits with the batch.
    pub fn sync(&mut self, blob: &Blob<S>) {
        self.staged_mut(blob);
    }

    /// Stage a namespace removal (a blob, or a whole partition when `name`
    /// is `None`), validated and applied atomically at [`Self::apply_sync`].
    pub fn remove(&mut self, partition: &str, name: Option<&[u8]>) {
        self.removals
            .push((partition.into(), name.map(<[u8]>::to_vec)));
    }

    /// Stage the creation of a NEW (empty) blob, returning a handle to it.
    /// The name is validated at [`Self::apply_sync`], where the namespace
    /// entry publishes and commits atomically with the rest of the batch.
    /// Until then the blob is invisible to opens, scans, and commits, and
    /// the returned handle must not be used.
    pub fn create(&mut self, partition: &str, name: &[u8]) -> Result<Blob<S>, Error> {
        super::super::validate_partition_name(partition)?;
        self.ready.check_poisoned()?;
        let (id, core) = {
            let mut state = self.ready.state.lock();
            let id = state.next_id;
            state.next_id += 1;
            // Register the handle count now so the returned handle's tracker
            // works whether or not the batch ever applies.
            *state.handles.entry(id).or_insert(0) += 1;
            let core = Arc::new(BlobCore {
                id,
                partition: partition.into(),
                name: name.to_vec(),
                version: DEFAULT_BLOB_VERSION,
                write_lock: AsyncMutex::new(()),
                inner: Mutex::new(BlobInner {
                    committed_entry: None,
                    ..Default::default()
                }),
            });
            (id, core)
        };
        self.creations.push(Creation {
            partition: partition.into(),
            name: name.to_vec(),
            core: core.clone(),
        });
        Ok(Blob {
            ready: self.ready.clone(),
            core,
            _tracker: Arc::new(HandleTracker {
                ready: self.ready.clone(),
                id,
            }),
        })
    }

    /// Publish the staged state: pure RAM, under the commit lock, O(ops).
    /// The touched blobs form one applied-batch group that later commits
    /// capture all-or-nothing. A crash before the group commits discards
    /// the batch wholesale.
    ///
    /// # Panics
    ///
    /// Panics if removals or creations were staged (they require
    /// [`Self::apply_sync`]).
    pub async fn apply(mut self) -> Result<(), Error> {
        assert!(
            self.removals.is_empty(),
            "staged removals require apply_sync"
        );
        assert!(
            self.creations.is_empty(),
            "staged creations require apply_sync"
        );
        self.apply_inner(false).await
    }

    /// [`Self::apply`] plus an immediate commit of the batch's group (one
    /// selective commit covering exactly the touched blobs and removals).
    pub async fn apply_sync(mut self) -> Result<(), Error> {
        self.apply_inner(true).await
    }

    async fn apply_inner(&mut self, sync: bool) -> Result<(), Error> {
        self.ready.check_poisoned()?;
        // Namespace changes serialize on the same lock (and in the same
        // order relative to the commit lock) as open/remove.
        let _ns = if self.removals.is_empty() && self.creations.is_empty() {
            None
        } else {
            Some(self.shared.ns_lock.lock().await)
        };
        let _commit = self.ready.commit_lock.lock().await;
        self.ready.check_poisoned()?;

        // Validate every staged removal and creation against a simulation of
        // the namespace BEFORE publishing anything: an invalid batch applies
        // nothing (Drop returns its extents). Removals simulate first, so a
        // batch may remove a name and recreate it.
        if !self.removals.is_empty() || !self.creations.is_empty() {
            let state = self.ready.state.lock();
            let mut sim: BTreeMap<&String, BTreeSet<&Vec<u8>>> = state
                .partitions
                .iter()
                .map(|(partition, blobs)| (partition, blobs.keys().collect()))
                .collect();
            for (partition, name) in &self.removals {
                match name {
                    Some(name) => {
                        let blobs = sim
                            .get_mut(partition)
                            .ok_or_else(|| Error::PartitionMissing(partition.clone()))?;
                        if !blobs.remove(name) {
                            return Err(Error::BlobMissing(partition.clone(), hex(name)));
                        }
                    }
                    None => {
                        sim.remove(partition)
                            .ok_or_else(|| Error::PartitionMissing(partition.clone()))?;
                    }
                }
            }
            for creation in &self.creations {
                if !sim
                    .entry(&creation.partition)
                    .or_default()
                    .insert(&creation.name)
                {
                    return Err(Error::BlobExists(
                        creation.partition.clone(),
                        hex(&creation.name),
                    ));
                }
            }
        }

        // Publish staged creations first (their namespace entries must exist
        // before any staged overlay against them publishes), then each
        // blob's overlay (blob-id order; the commit lock keeps any snapshot
        // from observing a partial publish).
        let staged = std::mem::take(&mut self.staged);
        let mut roots: Vec<u64> = Vec::with_capacity(self.creations.len() + staged.len());
        if !self.creations.is_empty() {
            let mut state = self.ready.state.lock();
            for creation in std::mem::take(&mut self.creations) {
                let id = creation.core.id;
                if !state.partitions.contains_key(&creation.partition) {
                    state.partition_epoch += 1;
                }
                state
                    .partitions
                    .entry(creation.partition)
                    .or_default()
                    .insert(creation.name, id);
                state.open.insert(id, creation.core);
                state.meta_dirty = true;
                roots.push(id);
            }
        }
        for (id, st) in staged {
            roots.push(id);
            let _guard = st.core.write_lock.lock().await;
            let mut state = self.ready.state.lock();
            let seq = state.seq;
            for extent in st.discarded {
                state.defer_free(extent, seq, None);
            }
            if !st.touched_only {
                let mut inner = st.core.inner.lock();
                publish_overlay(&mut inner, st.overlay);
                state.dirty.insert(id);
            }
        }
        {
            let mut state = self.ready.state.lock();
            state.merge_group(roots.iter().copied());
        }
        self.applied = true;

        // Namespace removals (validated above; cannot fail).
        if !self.removals.is_empty() {
            let mut state = self.ready.state.lock();
            for (partition, name) in std::mem::take(&mut self.removals) {
                let blobs = state.partitions.get(&partition).expect("validated");
                let ids: Vec<u64> = name.as_ref().map_or_else(
                    || blobs.values().copied().collect(),
                    |name| vec![*blobs.get(name).expect("validated")],
                );
                for &id in &ids {
                    unlink(&mut state, id);
                }
                roots.extend(ids);
                match name {
                    Some(name) => {
                        state
                            .partitions
                            .get_mut(&partition)
                            .expect("validated")
                            .remove(&name);
                    }
                    None => {
                        state.partitions.remove(&partition);
                        state.partition_epoch += 1;
                    }
                }
                state.meta_dirty = true;
            }
        }

        if sync {
            commit::commit_locked(&self.ready, &roots).await
        } else {
            Ok(())
        }
    }
}

/// Swing a blob's published state to the staged overlay. Caller holds the
/// commit lock, the blob's write lock, and the blob's state lock.
fn publish_overlay(inner: &mut BlobInner, overlay: StagedBlob) {
    if overlay.size < inner.size {
        // Staged shrink: mirror the published resize bookkeeping.
        if overlay.size == 0 {
            inner.crcs.clear();
            inner.dirty_chunks.clear();
        } else {
            let boundary = chunk_of(overlay.size - 1);
            inner.crcs.retain(|&c, _| c <= boundary);
            inner.dirty_chunks.retain(|&c| c <= boundary);
            inner.dirty_chunks.insert(boundary);
        }
    }
    for l in &overlay.removed {
        inner.runs.remove(l);
    }
    for (l, sr) in overlay.runs {
        inner.runs.insert(l, sr.meta);
    }
    for (&chunk, &state) in &overlay.crcs {
        inner.crcs.insert(chunk, state);
        inner.dirty_chunks.insert(chunk);
    }
    inner.size = overlay.size;
    if let Some((chunk, bytes)) = overlay.tail {
        inner.tail_chunk = chunk;
        inner.tail = bytes;
    }
    if overlay.relocated {
        inner.generation += 1;
    }
    inner.pending_frees.extend(overlay.replaced);

    // Staged state supersedes the blob's overlay bytes for every chunk it
    // touched (and a staged shrink may have moved spans): keep only entries
    // that still back a pending CRC.
    let BlobInner {
        crcs,
        overlay: blob_overlay,
        ..
    } = inner;
    blob_overlay.retain(|chunk, _| crcs.get(chunk).is_some_and(|s| s.crc == ChunkCrc::Pending));
}

impl<S: crate::Storage> Drop for Batch<S> {
    fn drop(&mut self) {
        if self.applied {
            return;
        }
        // Dropped without apply: nothing references the staged extents;
        // return them through the ordinary deferred-free path.
        let mut state = self.ready.state.lock();
        let seq = state.seq;
        for st in self.staged.values_mut() {
            for extent in st.overlay.fresh.drain(..) {
                state.defer_free(extent, seq, None);
            }
            for extent in st.discarded.drain(..) {
                state.defer_free(extent, seq, None);
            }
        }
    }
}
