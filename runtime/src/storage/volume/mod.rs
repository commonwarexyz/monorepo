//! A single-file storage backend with atomic group commit.
//!
//! `volume` packs every blob of a [`crate::Storage`] workload into ONE inner
//! blob (the "volume file") and provides a strictly stronger crash contract
//! than the trait requires:
//!
//! > After a crash and reopen, every blob's readable state is exactly the
//! > state captured by one commit: the last confirmed commit (whose sync
//! > returned), or a newer fully-landed one (legal roll-forward). A commit
//! > happens on any [`crate::Blob::sync`] / [`crate::Blob::write_at_sync`]
//! > and on blob creation/removal, and atomically covers ALL dirty state
//! > across ALL blobs of the volume (group commit). Every read verifies a
//! > CRC32C; a mismatch is loud corruption, never silent truncation.
//!
//! Storage structures above a volume can therefore delete their own
//! torn-write detection and recovery machinery: torn tails, partial frames,
//! and cross-blob ordering skew are impossible by construction, and the
//! deterministic runtime's crash model becomes the production model.
//!
//! Group commit may make MORE data durable than a caller explicitly synced
//! (equivalent to the OS persisting write-back cache early, which is always
//! permitted). A failed commit permanently poisons the volume: a failed
//! fsync leaves the page cache undefined, so no later commit may vouch for
//! bytes it can no longer prove will land.
//!
//! # Formal model
//!
//! The commit protocol (freeze-rule copy-on-write, deferred frees, sacred
//! superblock slot, shadowed frontier chunks, content-bound tables, poison
//! latch) is specified and exhaustively model-checked under crash and power
//! loss in [`model`]; the implementation follows the model's decisions
//! exactly. Read the model docs before changing anything here.

mod alloc;
mod commit;
mod core;
mod layout;
#[cfg(test)]
mod model;
mod recover;
#[cfg(test)]
mod tests;

use crate::{BufferPool, Error, Handle, IoBufs, IoBufsMut};
use alloc::{block_align, Extent};
use commonware_formatting::hex;
use commonware_utils::sync::AsyncMutex;
use core::{BlobCore, Ready};
use std::{
    ops::RangeInclusive,
    sync::{Arc, OnceLock},
};

/// Alignment unit and checksum granularity: writes tear at (at most) this
/// granularity, and every read is verified per this granularity.
pub(crate) const BLOCK: u64 = 4096;

/// Location of the volume file within the inner storage.
#[derive(Clone, Debug)]
pub struct Config {
    /// Inner partition holding the volume file.
    pub partition: String,
    /// Inner blob name of the volume file.
    pub name: Vec<u8>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            partition: "volume".into(),
            name: b"volume".to_vec(),
        }
    }
}

/// A single-file storage backend with atomic group commit over an inner
/// [`crate::Storage`].
pub struct Storage<S: crate::Storage> {
    shared: Arc<Shared<S>>,
}

impl<S: crate::Storage> Clone for Storage<S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

struct Shared<S: crate::Storage> {
    inner: S,
    pool: BufferPool,
    cfg: Config,
    /// Set once recovery has completed (fast path).
    ready: OnceLock<Arc<Ready<S>>>,
    /// Serializes recovery (single-flight) and namespace changes.
    ns_lock: AsyncMutex<()>,
}

impl<S: crate::Storage> Storage<S> {
    /// Create a volume over `inner`. Recovery runs lazily on the first
    /// operation (or eagerly via [`Self::init`]).
    pub fn new(inner: S, pool: BufferPool, cfg: Config) -> Self {
        Self {
            shared: Arc::new(Shared {
                inner,
                pool,
                cfg,
                ready: OnceLock::new(),
                ns_lock: AsyncMutex::new(()),
            }),
        }
    }

    /// Create a volume and run recovery immediately.
    pub async fn init(inner: S, pool: BufferPool, cfg: Config) -> Result<Self, Error> {
        let storage = Self::new(inner, pool, cfg);
        storage.ensure().await?;
        Ok(storage)
    }

    /// The inner storage holding the volume file.
    pub fn inner(&self) -> &S {
        &self.shared.inner
    }

    /// The volume file's location.
    pub fn config(&self) -> &Config {
        &self.shared.cfg
    }

    /// Recovery, single-flight, before any operation.
    async fn ensure(&self) -> Result<Arc<Ready<S>>, Error> {
        if let Some(ready) = self.shared.ready.get() {
            return Ok(ready.clone());
        }
        let _guard = self.shared.ns_lock.lock().await;
        if let Some(ready) = self.shared.ready.get() {
            return Ok(ready.clone());
        }
        let ready = Arc::new(
            recover::recover(&self.shared.inner, &self.shared.pool, &self.shared.cfg).await?,
        );
        let _ = self.shared.ready.set(ready.clone());
        Ok(ready)
    }
}

/// Tracks one open handle (shared by clones); the drop of the last clone
/// releases removal-gated extents.
struct HandleTracker<S: crate::Storage> {
    ready: Arc<Ready<S>>,
    id: u64,
}

impl<S: crate::Storage> Drop for HandleTracker<S> {
    fn drop(&mut self) {
        let mut state = self.ready.state.lock();
        let count = state.handles.entry(self.id).or_insert(1);
        *count = count.saturating_sub(1);
        if *count == 0 {
            state.handles.remove(&self.id);
            // Drop the blob entirely if it was removed (no name references
            // it and no handle can reach it anymore).
            let removed = state
                .open
                .get(&self.id)
                .is_some_and(|b| b.inner.lock().removed);
            if removed {
                state.open.remove(&self.id);
            }
            state.apply_frees();
        }
    }
}

/// A handle to a blob stored in a volume.
pub struct Blob<S: crate::Storage> {
    ready: Arc<Ready<S>>,
    core: Arc<BlobCore>,
    _tracker: Arc<HandleTracker<S>>,
}

impl<S: crate::Storage> Clone for Blob<S> {
    fn clone(&self) -> Self {
        Self {
            ready: self.ready.clone(),
            core: self.core.clone(),
            _tracker: self._tracker.clone(),
        }
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;
        let ready = self.ensure().await?;
        let _ns = self.shared.ns_lock.lock().await;
        ready.check_poisoned()?;

        // Fast path: already known (open or dormant).
        let known = {
            let state = ready.state.lock();
            state
                .partitions
                .get(partition)
                .and_then(|blobs| blobs.get(name))
                .copied()
        };

        if let Some(id) = known {
            // Hydrate a dormant entry if this blob is not open yet.
            let hydrated = {
                let state = ready.state.lock();
                if state.open.contains_key(&id) {
                    None
                } else {
                    Some(state.dormant.get(&id).cloned().expect("known blob"))
                }
            };
            if let Some(entry) = hydrated {
                let inner = recover::hydrate(&ready, &entry, partition).await?;
                let mut state = ready.state.lock();
                state.dormant.remove(&id);
                state.open.insert(
                    id,
                    Arc::new(BlobCore {
                        id,
                        partition: partition.into(),
                        name: name.to_vec(),
                        version: entry.version,
                        write_lock: AsyncMutex::new(()),
                        inner: commonware_utils::sync::Mutex::new(inner),
                    }),
                );
            }

            let (core, size) = {
                let mut state = ready.state.lock();
                let core = state.open.get(&id).expect("hydrated").clone();
                *state.handles.entry(id).or_insert(0) += 1;
                let size = core.inner.lock().size;
                (core, size)
            };
            if !versions.contains(&core.version) {
                // Not a match: release the handle we just took.
                drop(HandleTracker {
                    ready: ready.clone(),
                    id,
                });
                return Err(Error::BlobVersionMismatch {
                    expected: versions,
                    found: core.version,
                });
            }
            let version = core.version;
            let tracker = Arc::new(HandleTracker {
                ready: ready.clone(),
                id,
            });
            return Ok((
                Blob {
                    ready: ready.clone(),
                    core,
                    _tracker: tracker,
                },
                size,
                version,
            ));
        }

        // Create: new id, empty blob, durable via group commit.
        let version = *versions.end();
        let (id, core) = {
            let mut state = ready.state.lock();
            let id = state.next_id;
            state.next_id += 1;
            let core = Arc::new(BlobCore {
                id,
                partition: partition.into(),
                name: name.to_vec(),
                version,
                write_lock: AsyncMutex::new(()),
                inner: commonware_utils::sync::Mutex::new(core::BlobInner {
                    committed_entry: None,
                    ..Default::default()
                }),
            });
            state
                .partitions
                .entry(partition.into())
                .or_default()
                .insert(name.to_vec(), id);
            state.open.insert(id, core.clone());
            *state.handles.entry(id).or_insert(0) += 1;
            state.meta_dirty = true;
            (id, core)
        };
        // "An Ok result indicates the blob is durably created."
        commit::commit(&ready).await?;
        let tracker = Arc::new(HandleTracker {
            ready: ready.clone(),
            id,
        });
        Ok((
            Blob {
                ready: ready.clone(),
                core,
                _tracker: tracker,
            },
            0,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;
        let ready = self.ensure().await?;
        let _ns = self.shared.ns_lock.lock().await;
        ready.check_poisoned()?;

        {
            let mut state = ready.state.lock();
            let Some(blobs) = state.partitions.get(partition) else {
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

            for id in ids {
                unlink(&mut state, id);
            }
            match name {
                Some(name) => {
                    state
                        .partitions
                        .get_mut(partition)
                        .expect("checked")
                        .remove(name);
                }
                None => {
                    state.partitions.remove(partition);
                }
            }
            state.meta_dirty = true;
        }
        // "An Ok result indicates the blob is durably removed."
        commit::commit(&ready).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;
        let ready = self.ensure().await?;
        ready.check_poisoned()?;
        let state = ready.state.lock();
        let Some(blobs) = state.partitions.get(partition) else {
            return Err(Error::PartitionMissing(partition.into()));
        };
        Ok(blobs.keys().cloned().collect())
    }
}

/// Unlink one blob id: mark removed, queue every extent it references for
/// reuse once the removal commits (and its last handle drops).
fn unlink(state: &mut core::State, id: u64) {
    let seq = state.seq;
    let gate = Some(id);
    if let Some(core) = state.open.get(&id).cloned() {
        let mut inner = core.inner.lock();
        inner.removed = true;
        inner.generation += 1;
        for run in inner.runs.values() {
            state.pending_free.push((
                Extent {
                    offset: run.physical,
                    len: run.capacity,
                },
                seq,
                gate,
            ));
        }
        state.dirty.remove(&id);
        // Committed metadata extents (checksums + shadow).
        if let Some(meta) = state.committed_meta.remove(&id) {
            for extent in meta {
                state.pending_free.push((extent, seq, gate));
            }
        }
        // No handles: nothing can read it; drop immediately.
        if state.handles.get(&id).copied().unwrap_or(0) == 0 {
            drop(inner);
            state.open.remove(&id);
        }
    } else if let Some(entry) = state.dormant.remove(&id) {
        for r in &entry.runs {
            state.pending_free.push((
                Extent {
                    offset: r.physical,
                    len: block_align(r.len),
                },
                seq,
                None,
            ));
        }
        if let Some(meta) = state.committed_meta.remove(&id) {
            for extent in meta {
                state.pending_free.push((extent, seq, None));
            }
        }
    }
}

impl<S: crate::Storage> crate::Blob for Blob<S> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, self.ready.pool.alloc(len))
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut bufs = bufs.into();
        let data = core::read_verified(&self.ready, &self.core, offset, len).await?;
        // SAFETY: `len` bytes are filled via copy_from_slice below.
        unsafe { bufs.set_len(len) };
        bufs.copy_from_slice(&data);
        Ok(bufs)
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let data = bufs.into().coalesce();
        let _guard = self.core.write_lock.lock().await;
        core::write_locked(&self.ready, &self.core, offset, data).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        if !bytes::Buf::has_remaining(&bufs) {
            return Ok(());
        }
        self.write_at(offset, bufs).await?;
        self.sync().await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let _guard = self.core.write_lock.lock().await;
        core::resize_locked(&self.ready, &self.core, len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        commit::commit(&self.ready).await
    }

    async fn start_sync(&self) -> Handle<()> {
        Handle::ready(self.sync().await)
    }
}
