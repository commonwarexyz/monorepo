//! A single-file storage backend with atomic commit.
//!
//! `volume` packs every blob of a [`crate::Storage`] workload into ONE inner
//! blob (the "volume file") and provides a strictly stronger crash contract
//! than the trait requires:
//!
//! > After a crash and reopen, every blob's readable state is exactly the
//! > state captured by one commit: the last confirmed commit (whose sync
//! > returned), or a newer fully-landed one (legal roll-forward). A commit
//! > happens on any [`crate::Blob::sync`] / [`crate::Blob::write_at_sync`],
//! > on [`crate::Storage`] blob creation/removal, on
//! > [`Batch::apply_sync`], and when a commit registered by
//! > [`crate::Blob::start_sync`] / [`Batch::apply_start_sync`] lands
//! > (driven by its handle, or coalesced into any later commit). It atomically
//! > covers the CAPTURED blobs: the synced blob (pooled with every
//! > concurrently queued sync's blob, see Concurrency below) or the
//! > applying batch's blobs, expanded across applied-batch groups so an
//! > applied [`Batch`] is never split across commits. Reads are
//! > CRC32C-verified: each chunk
//! > is checked once per process lifetime — on its first read, by
//! > construction for chunks written this process, or by recovery's own
//! > manifest verification — and a mismatch is loud corruption, never
//! > silent truncation.
//!
//! Every runtime serves ALL storage through a volume over its platform
//! backend, so this is the crash contract of every runtime context.
//! Storage structures can therefore delete their own torn-write detection,
//! recovery machinery, and cross-blob sync-ordering discipline: torn
//! tails, partial frames, and (through [`Batch`]) cross-blob skew are
//! impossible by construction, and the deterministic runtime's crash model
//! is the production model.
//!
//! Corruption loudness has ONE bounded exception: media corruption (bit
//! rot) that lands inside the NEWEST commit's table or in the extents its
//! manifest verification reads — the delta-manifested chunks, the shadow
//! extents of manifested frontier chunks, the checksum extents covering
//! manifested chunks, plus each manifested blob's LAST checksum extent
//! (loaded unconditionally, even when an older commit wrote it) — is
//! indistinguishable from a torn commit at recovery, which then falls back
//! to the previous confirmed commit and emits a warn-level event instead
//! of returning an error (see `recover`). The silent fallback additionally
//! requires the previous table's extent to be unrecycled (it is freed at
//! confirmation, so a post-confirmation write may legally reuse it): rot
//! in the newest table can otherwise surface as a loud
//! [`crate::Error::PartitionCorrupt`] instead of the one-commit rollback.
//! Corruption anywhere else — committed data, metadata the manifest does
//! not consult — is always a loud [`crate::Error::BlobCorrupt`]. The crash
//! contract itself is model-checked under crash and power loss, not under
//! media corruption.
//!
//! A commit may make MORE data durable than a caller explicitly synced (the
//! single inner fsync covers every pending write of the volume file, which
//! is equivalent to the OS persisting write-back cache early — always
//! permitted). It never makes UNCAPTURED state readable after a crash:
//! blobs outside the capture set keep their last-captured table entry. A
//! failed commit permanently poisons the volume — every blob, captured or
//! not: a failed fsync leaves the page cache of the shared volume file
//! undefined (fsyncgate is physical), so no later commit may vouch for
//! bytes it can no longer prove will land.
//!
//! # Batches
//!
//! [`Storage::batch`] stages writes across MULTIPLE blobs and publishes
//! them atomically: staging writes through to disk immediately (same I/O
//! profile as unbatched writes), placed so that no snapshot can capture
//! staged bytes; [`Batch::apply`] publishes in RAM under the commit lock,
//! and [`Batch::apply_sync`] additionally commits. Batches also stage
//! namespace changes — [`Batch::remove`] and [`Batch::create`] — which
//! publish and commit with the batch. Removals (and creations staged
//! alongside anything else) require [`Batch::apply_sync`]. A batch staging
//! ONLY creations publishes with plain [`Batch::apply`], its creations
//! becoming durable together at the next commit — or erased together by a
//! crash before one. A batch dropped without apply (or lost to a crash)
//! never happened.
//!
//! # Concurrency
//!
//! Data paths parallelize, commits serialize, and commit COALESCING keeps
//! the serialization from becoming a bottleneck:
//!
//! - Writes to different blobs run concurrently. Each blob has its own
//!   async write lock, and a writer touches the volume-wide state mutex
//!   only for microsecond-scale planning and publish sections per stretch
//!   (measured uncontended at 16 concurrent appenders: ~50ns waits, ~2us
//!   holds). Reads take no locks across I/O at all (generation-validated
//!   retry). File growth serializes on a provision lock but is rare (once
//!   per growth quantum).
//! - Commits serialize on ONE commit lock, and every commit ends in an
//!   fsync of the ONE volume file. Concurrent syncs therefore COALESCE:
//!   syncs arriving while a commit is in flight pool their blobs, and
//!   whichever queued sync acquires the lock first commits the pooled
//!   UNION under a single fsync, acknowledging every pooled sync at once
//!   (see `commit::commit`). Callers see only their own `sync` return.
//!   Coalescing is keyed off the lock queue alone — no timers — so the
//!   deterministic runtime stays deterministic, and a serial caller (no
//!   overlap) commits exactly as without coalescing. With 16 concurrent
//!   appenders syncing distinct blobs this measured ~5.6x the throughput
//!   of unpooled serialized commits and lower sync latency than one file
//!   per blob (each pooled fsync covers many syncs, where per-file
//!   backends pay one flush each).
//!
//! ## Why two superblock slots suffice
//!
//! An alternative to coalescing is more superblock slots (A/B -> A..G),
//! pipelining commit N+1's snapshot and metadata writes under commit N's
//! in-flight fsync, each commit targeting its own slot. Measured phase
//! attribution rules this out: all commits fsync the SAME file, and
//! same-file fsyncs serialize at the kernel/device, so extra slots can
//! only overlap a commit's CPU and pagecache phases (snapshot + metadata
//! writes, measured 0.2-0.4ms) with the previous fsync (measured ~3.7ms)
//! — a <10% ceiling that shrinks further under coalescing (the union
//! snapshot amortizes over every pooled sync) and does not reduce the
//! per-sync latency floor of one full fsync. Against that ceiling, K>2
//! slots cost a superblock format change and a harder recovery protocol:
//! candidate CHAINS with fallback across multiple torn commits, a
//! generalized sacred-slot rule ("newest confirmed slot is never
//! written"), and losing-slot zeroing of all-but-adopted — all new model
//! workloads and mutations. Two slots (newest confirmed + one in-flight)
//! are exactly the states a serialized commit protocol can occupy, so the
//! extra slots would buy nothing until the physics change (a backend with
//! sub-file fsync domains, where same-file flushes could overlap).
//!
//! # Scale envelope
//!
//! Costs that grow with namespace or blob size (the `storage_volume`
//! metrics expose the live values):
//!
//! - Every commit writes the ENTIRE blob table to a fresh extent. At
//!   ~55-111 bytes per small blob, 10k blobs cost ~1 MiB and 100k blobs
//!   ~5-11 MiB of table write + CRC per commit (several ms against the
//!   fsync budget), and creating N blobs one at a time commits N tables —
//!   use [`Batch::create`] for bulk creation. Table assembly also rescans
//!   the namespace for encode-cache misses on each commit (~0.2 ms at 10k
//!   blobs, under the state mutex).
//! - A capture whose dirt falls below the covered frontier (any overwrite,
//!   COW, or shrink — and every 16th append-shaped commit, see
//!   `MAX_CHECKSUM_REFS`) rewrites the blob's whole checksum array:
//!   O(size/1024) bytes read and written per such commit (~10 MiB for a
//!   10 GiB blob, ~1 GiB for 1 TiB), with the array re-encode running
//!   under the volume-wide state mutex.
//! - Uncommitted dirt costs ~20 B/chunk of RAM and 16 B/chunk of manifest
//!   in the next table, and recovery re-reads every manifested byte before
//!   the volume serves its first operation — on every open until a later
//!   commit supersedes that manifest. A 100 GiB write burst before one
//!   sync holds ~0.5 GB of dirty-chunk RAM, writes a ~420 MB manifest, and
//!   costs a 100 GiB verification read at the next open: sync bulk loads
//!   incrementally.
//! - Allocation is first-fit over the in-memory free list: O(free ranges)
//!   under the state mutex per allocation (~70 us at 100k fragments — the
//!   `free_bytes` gauge plus monotonic `file_end_bytes` growth signal
//!   fragmentation). Splice-rewrite working sets beyond 1024 chunks per
//!   blob pay an O(1024) overlay-eviction scan per further insert
//!   (~0.8 us under the blob lock).
//!
//! # Formal model
//!
//! The commit protocol (freeze-rule copy-on-write, capture-gated deferred
//! frees, sacred superblock slot, shadowed frontier chunks, content-bound
//! tables, poison latch, selective capture, coalesced union capture, and
//! batch staging/publish with
//! the never-split rule) is specified and exhaustively model-checked under
//! crash and power loss in the `model` module (compiled with tests), and
//! the `conformance` module CHECKS that this implementation refines it:
//! bounded workloads run against the real volume in lockstep with the
//! model, power loss is materialized at every step (each pending write
//! independently lands, vanishes, or tears) with the recovered state
//! required to be one the model allows for that history, and commit
//! futures are cancelled at every await point (the class below the
//! model). See the model docs' trust story. Read the model docs before
//! changing anything here.

mod alloc;
mod batch;
mod commit;
#[cfg(test)]
mod conformance;
mod core;
mod layout;
mod metrics;
#[cfg(test)]
mod model;
mod recover;
#[cfg(test)]
mod tests;

use crate::{BufferPool, Error, Handle, IoBufs, IoBufsMut};
use alloc::{block_align, Extent};
pub use batch::Batch;
use commonware_formatting::hex;
use commonware_utils::sync::AsyncMutex;
use core::{BlobCore, Ready};
use std::{
    ops::RangeInclusive,
    sync::{Arc, OnceLock},
};

/// Alignment unit for all extents, checksum granularity, and the assumed
/// physical tearing granularity of the inner blob: writes tear at (at
/// most) this granularity, reads are verified per this granularity (once
/// per chunk per process lifetime), and an uncommitted write never lands
/// in a block that holds committed bytes of a DIFFERENT extent — so a torn
/// write can only damage data that the adopted table does not reference.
pub(crate) const BLOCK: u64 = 4096;

/// Location and growth policy of the volume file within the inner storage.
#[derive(Clone, Debug)]
pub struct Config {
    /// Inner partition holding the volume file.
    pub partition: String,
    /// Inner blob name of the volume file.
    pub name: Vec<u8>,
    /// Grow the volume file in steps of this many bytes (rounded up to a
    /// whole number of blocks) instead of implicitly on every write.
    ///
    /// Zero disables provisioning: the file grows exactly as written. On
    /// file-backed storage a coarse quantum (tens of MiB) avoids extending
    /// the file a few blocks at a time, which churns filesystem extent
    /// metadata and fragments the file. Growth is always automatic; this
    /// only sets the step size. Shrinking is never performed — space freed
    /// by removed blobs is reused for new extents, not returned to the
    /// filesystem.
    pub growth_quantum: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            partition: "volume".into(),
            name: b"volume".to_vec(),
            growth_quantum: 0,
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
    metrics: Arc<metrics::Metrics>,
    /// Set once recovery has completed (fast path).
    ready: OnceLock<Arc<Ready<S>>>,
    /// Serializes recovery (single-flight) and namespace changes.
    ns_lock: AsyncMutex<()>,
}

impl<S: crate::Storage> Storage<S> {
    /// Create a volume over `inner`. Recovery runs lazily on the first
    /// operation (or eagerly via [`Self::init`]).
    ///
    /// A volume created this way keeps its operational metrics
    /// unregistered; the runtime contexts construct their volumes with a
    /// registry so operators see them.
    pub fn new(inner: S, pool: BufferPool, cfg: Config) -> Self {
        Self::with_metrics(inner, pool, cfg, metrics::Metrics::unregistered())
    }

    /// [`Self::new`] with metrics registered under `registry`.
    pub(crate) fn new_registered(
        inner: S,
        pool: BufferPool,
        cfg: Config,
        registry: &mut impl crate::telemetry::metrics::Register,
    ) -> Self {
        Self::with_metrics(inner, pool, cfg, metrics::Metrics::new(registry))
    }

    fn with_metrics(inner: S, pool: BufferPool, cfg: Config, metrics: metrics::Metrics) -> Self {
        Self {
            shared: Arc::new(Shared {
                inner,
                pool,
                cfg,
                metrics: Arc::new(metrics),
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

    /// Start a [`Batch`]: cross-blob writes staged now, published (and
    /// optionally committed) atomically later.
    pub async fn batch(&self) -> Result<Batch<S>, Error> {
        let ready = self.ensure().await?;
        ready.check_poisoned()?;
        Ok(Batch::new(self.shared.clone(), ready))
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
            recover::recover(
                &self.shared.inner,
                &self.shared.pool,
                &self.shared.cfg,
                self.shared.metrics.clone(),
            )
            .await?,
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
            self.ready.metrics.observe_state(&state);
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

impl<S: crate::Storage> crate::Batchable for Storage<S> {
    type Batch = Batch<S>;

    async fn batch(&self) -> Result<Batch<S>, Error> {
        Self::batch(self).await
    }
}

impl<S: crate::Storage> crate::WriteBatch for Batch<S> {
    type Blob = Blob<S>;

    async fn write_at(
        &mut self,
        blob: &Blob<S>,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        Self::write_at(self, blob, offset, bufs).await
    }

    async fn resize(&mut self, blob: &Blob<S>, len: u64) -> Result<(), Error> {
        Self::resize(self, blob, len).await
    }

    fn sync(&mut self, blob: &Blob<S>) {
        Self::sync(self, blob);
    }

    fn remove(&mut self, partition: &str, name: Option<&[u8]>) {
        Self::remove(self, partition, name);
    }

    async fn create(&mut self, partition: &str, name: &[u8]) -> Result<Blob<S>, Error> {
        Self::create(self, partition, name)
    }

    async fn apply(self) -> Result<(), Error> {
        Self::apply(self).await
    }

    async fn apply_sync(self) -> Result<(), Error> {
        Self::apply_sync(self).await
    }

    async fn apply_start_sync(self) -> Result<Handle<()>, Error> {
        Self::apply_start_sync(self).await
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
                    Some(state.dormant.get(&id).cloned().expect("known blob").1)
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
            if !state.partitions.contains_key(partition) {
                state.partition_epoch += 1;
            }
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
        // "An Ok result indicates the blob is durably created." The new
        // blob is clean (its empty entry is served by assembly), so the
        // commit captures just the namespace change.
        commit::commit(&ready, &[id]).await?;
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
        // Hold the commit lock across unlink-plus-commit (exactly as staged
        // batch removals do): an entry drop is global, so a commit racing
        // the window between the namespace edit and the removal's own
        // commit would resolve the removal without capturing its
        // applied-batch group, splitting the group (never-split).
        let _commit = ready.commit_lock.lock().await;
        ready.check_poisoned()?;

        let removed = {
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

            for &id in &ids {
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
                    state.partition_epoch += 1;
                }
            }
            state.meta_dirty = true;
            ids
        };
        // "An Ok result indicates the blob is durably removed." The removed
        // ids root the commit so their applied-batch groups (if any) are
        // captured with the removal (never-split).
        commit::commit_locked(&ready, &removed).await
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
///
/// The very next commit — whatever it captures — drops the entry from the
/// table, so removal frees gate only on that commit's seq (plus the handle
/// gate for extents still readable through open handles).
fn unlink(state: &mut core::State, id: u64) {
    let seq = state.seq;
    let gate = Some(id);
    state.encoded.remove(&id);
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
        // Capture-gated frees resolve with the removal commit: the entry
        // that referenced them is dropped (never readable via handles).
        for extent in std::mem::take(&mut inner.pending_frees) {
            state.pending_free.push((extent, seq, None));
        }
        state.dirty.remove(&id);
        // Committed metadata extents (checksums + shadow).
        if let Some(meta) = state.committed_meta.remove(&id) {
            for extent in meta.into_extents() {
                state.pending_free.push((extent, seq, gate));
            }
        }
        // No handles: nothing can read it; drop immediately.
        if state.handles.get(&id).copied().unwrap_or(0) == 0 {
            drop(inner);
            state.open.remove(&id);
        }
    } else if let Some((_, entry)) = state.dormant.remove(&id) {
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
            for extent in meta.into_extents() {
                state.pending_free.push((extent, seq, None));
            }
        }
    }
    state.recovery_verified.remove(&id);
}

impl<S: crate::Storage> crate::Blob for Blob<S> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        core::read_verified(&self.ready, &self.core, offset, len, None).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        core::read_verified(&self.ready, &self.core, offset, len, Some(bufs.into())).await
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
        commit::commit(&self.ready, &[self.core.id]).await
    }

    async fn start_sync(&self) -> Handle<()> {
        // Register under the current ticket now: any commit that drains the
        // pool after this point covers this blob and resolves the handle.
        // The handle itself lead-drives a covering commit when awaited (see
        // `commit::drive`), so its progress never depends on unrelated
        // traffic — but it must be awaited: a never-polled handle leaves
        // the registered root for the next commit, and a commit failure is
        // reported only through the handle (the poison latch also fails
        // every later operation). A handle polled at least once must be
        // driven to completion or dropped: parked (alive, unpolled) it can
        // hold the commit lock and block every later commit, and dropped
        // mid-commit it poisons the volume (see `commit::CancelGuard`).
        let ticket = commit::register(&self.ready, &[self.core.id]);
        let ready = self.ready.clone();
        Handle::from_future(async move { commit::drive(&ready, ticket).await })
    }
}
