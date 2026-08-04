//! A [crate::Storage] backend that keeps all blobs of a partition inside one physical file.
//!
//! Each partition becomes a single "volume" file, stored as one blob of an inner
//! [crate::Storage] backend. Blobs are rows in an in-memory catalog rebuilt at open from
//! a record journal inside the volume; blob creation, deletion, and sync are journal
//! records rather than filesystem operations, and any number of concurrent operations in
//! one partition group-commit under a single barrier (the inner blob's `sync`).
//!
//! # Why
//!
//! The per-file backends pay directory fsyncs per blob creation and removal and one
//! fdatasync per synced blob. Structures that keep many small blobs per partition
//! (journals with one blob per section, for example) pay that per blob. A volume turns
//! namespace changes into cheap records and collapses each partition's concurrent sync
//! width to one barrier, while inheriting the inner backend's platform I/O, directory
//! durability, and torn-creation handling for the volume file itself.
//!
//! # Crash model and invariants
//!
//! The inner blob's `sync` is the only barrier; between barriers any subset of issued
//! writes may survive, torn at arbitrary byte granularity. Four invariants carry the
//! correctness argument:
//!
//! - Payload writes complete before the barrier their record rides, so an acknowledged
//!   sync has durable payload and metadata with no recovery-time verification.
//! - Blobs are only ever mapped to chunks that were durably zero under a completed
//!   barrier, so a surviving record whose payload was lost reads zeros, never another
//!   blob's bytes.
//! - A freed chunk is reused only after the record that freed it is durable, no live
//!   handle can reach it, and no in-flight I/O resolved it through an older map.
//! - Journal extents are durably zeroed before the root that names them is written, so
//!   replay's end-of-log detection is exact.
//!
//! See `format` for the on-disk layout and `volume` for creation and recovery.
//!
//! # Durability assumptions, inherited from the inner backend
//!
//! `Blob::sync` is a real barrier (fdatasync semantics) for writes previously completed
//! through any clone of the handle, and unwritten file regions (holes, space past the
//! last write) read as zeros.

mod blob;
mod committer;
mod format;
mod state;
#[allow(clippy::module_inception)]
mod volume;

pub use blob::Blob;
use commonware_formatting::hex;
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use futures::future::BoxFuture;
use state::Core;
use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    sync::{Arc, atomic::Ordering},
};
use volume::{VOLUME_NAME, Volume};

/// Spawns the committer task of each opened volume. Runtime-owning code supplies this
/// from whatever executor it has (any context's spawner works).
pub type Spawn = Arc<dyn Fn(BoxFuture<'static, ()>) + Send + Sync>;

/// Configuration for a volume storage.
#[derive(Clone, Debug)]
pub struct Config {
    /// Chunk size in bytes for newly created volumes: a power of two in
    /// `[64 KiB, 1 GiB]`. Existing volumes keep the size they were created with.
    ///
    /// Smaller chunks waste less space per blob (about half a chunk each) but cost more
    /// map memory per unit of data (4-48 bytes per mapped chunk).
    pub chunk_size: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chunk_size: 1 << 20,
        }
    }
}

/// A volume-backed storage: every partition lives in one file of the inner backend.
pub struct Storage<S: crate::Storage> {
    inner: S,
    spawn: Spawn,
    chunk_size: u32,
    partitions: Arc<Mutex<BTreeMap<String, Slot<S>>>>,
}

impl<S: crate::Storage> Clone for Storage<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            spawn: self.spawn.clone(),
            chunk_size: self.chunk_size,
            partitions: self.partitions.clone(),
        }
    }
}

/// Registry state of one partition.
enum Slot<S: crate::Storage> {
    /// Being opened (or removed) by one task; waiters are notified with the outcome.
    /// `Ok(None)` means the partition does not exist (or was just removed).
    Busy(Vec<oneshot::Sender<Result<Option<Volume<S>>, crate::Error>>>),
    Open(Volume<S>),
}

/// Removes a `Busy` slot if its owner is dropped mid-operation, waking waiters to retry.
struct BusyGuard<'a, S: crate::Storage> {
    partitions: &'a Mutex<BTreeMap<String, Slot<S>>>,
    partition: &'a str,
    armed: bool,
}

impl<S: crate::Storage> Drop for BusyGuard<'_, S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Dropping the slot drops the waiters' senders; their receivers error and the
        // waiters retry from scratch.
        self.partitions.lock().remove(self.partition);
    }
}

impl<S: crate::Storage> BusyGuard<'_, S> {
    /// Publishes the operation's outcome: registers the volume (if any) and notifies
    /// every waiter.
    fn finish(mut self, result: &Result<Option<Volume<S>>, crate::Error>) {
        self.armed = false;
        let mut partitions = self.partitions.lock();
        let Some(Slot::Busy(waiters)) = partitions.remove(self.partition) else {
            unreachable!("busy slot owned by this guard");
        };
        if let Ok(Some(volume)) = result {
            partitions.insert(self.partition.to_string(), Slot::Open(volume.clone()));
        }
        drop(partitions);
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }
}

impl<S: crate::Storage> Storage<S> {
    /// Wraps `inner` so that every partition is stored as a single volume file.
    ///
    /// # Panics
    ///
    /// Panics if `cfg.chunk_size` is not a power of two in `[64 KiB, 1 GiB]`.
    pub fn new(inner: S, spawn: Spawn, cfg: Config) -> Self {
        assert!(
            (format::MIN_CHUNK_SIZE..=format::MAX_CHUNK_SIZE).contains(&cfg.chunk_size)
                && cfg.chunk_size.is_power_of_two(),
            "invalid chunk size {}",
            cfg.chunk_size
        );
        Self {
            inner,
            spawn,
            chunk_size: cfg.chunk_size,
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Returns the partition's volume, opening it if needed. With `create`, a missing
    /// partition is created; without, `Ok(None)` is returned.
    async fn volume(
        &self,
        partition: &str,
        create: bool,
    ) -> Result<Option<Volume<S>>, crate::Error> {
        loop {
            enum Plan<S: crate::Storage> {
                Ready(Volume<S>),
                Wait(oneshot::Receiver<Result<Option<Volume<S>>, crate::Error>>),
                Open,
            }
            let plan = {
                let mut partitions = self.partitions.lock();
                match partitions.get_mut(partition) {
                    Some(Slot::Open(volume)) => Plan::Ready(volume.clone()),
                    Some(Slot::Busy(waiters)) => {
                        let (sender, receiver) = oneshot::channel();
                        waiters.push(sender);
                        Plan::Wait(receiver)
                    }
                    None => {
                        partitions.insert(partition.to_string(), Slot::Busy(Vec::new()));
                        Plan::Open
                    }
                }
            };
            match plan {
                Plan::Ready(volume) => return Ok(Some(volume)),
                Plan::Wait(receiver) => match receiver.await {
                    // A "does not exist" outcome is final for probes but means retry
                    // for creators (the concurrent operation was a probe or removal).
                    Ok(Ok(None)) if create => continue,
                    Ok(result) => return result,
                    // The owner was dropped mid-operation; retry.
                    Err(_) => continue,
                },
                Plan::Open => {
                    let guard = BusyGuard {
                        partitions: &self.partitions,
                        partition,
                        armed: true,
                    };
                    let result = self.open_volume(partition, create).await;
                    guard.finish(&result);
                    return result;
                }
            }
        }
    }

    /// Opens the volume file for `partition`, creating it only when `create`.
    async fn open_volume(
        &self,
        partition: &str,
        create: bool,
    ) -> Result<Option<Volume<S>>, crate::Error> {
        if !create {
            // Probe existence without creating anything. A partition directory with no
            // volume file can only be an interrupted creation's artifact; its creator
            // never observed the partition as existing.
            match self.inner.scan(partition).await {
                Err(crate::Error::PartitionMissing(_)) => return Ok(None),
                Err(error) => return Err(error),
                Ok(names) if names.is_empty() => return Ok(None),
                Ok(names) => {
                    if names != [VOLUME_NAME.to_vec()] {
                        return Err(crate::Error::PartitionCorrupt(partition.to_string()));
                    }
                }
            }
        }
        let (shared, journal) = volume::open(&self.inner, partition, self.chunk_size).await?;
        if create {
            // The volume must be the partition's only file: silently coexisting with a
            // foreign layout (for example per-file blobs from another backend) would
            // shadow that data.
            let names = self.inner.scan(partition).await?;
            if names != [VOLUME_NAME.to_vec()] {
                return Err(crate::Error::PartitionCorrupt(partition.to_string()));
            }
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        (self.spawn)(Box::pin(committer::run(shared.clone(), journal, receiver)));
        Ok(Some(Volume {
            shared,
            requests: sender,
        }))
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S>
where
    S: Clone,
{
    type Blob = Blob<S>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), crate::Error> {
        super::validate_partition_name(partition)?;
        // Reject names the record format cannot carry. Accepting one would journal a
        // create that replay refuses, making the whole partition unopenable.
        if name.len() > format::MAX_NAME_LEN {
            return Err(crate::Error::BlobOpenFailed(
                partition.to_string(),
                hex(name),
                Arc::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "blob name too long",
                )),
            ));
        }
        let volume = self
            .volume(partition, true)
            .await?
            .expect("creating volume lookups always return a volume");

        // Find or mint the row. The mint's create request is sent while the catalog
        // lock is still held (the channel send never blocks): journal order must equal
        // catalog order, or a concurrent recreate of the same name could journal its
        // create before this delete/create and make replay refuse the volume. Inserting
        // before the record is durable is what lets concurrent opens of the same name
        // share one row.
        let (core, len, receiver) = {
            let mut catalog = volume.shared.catalog.lock();
            match catalog.blobs.get(name) {
                Some(core) => {
                    if !versions.contains(&core.version) {
                        return Err(crate::Error::BlobVersionMismatch {
                            expected: versions,
                            found: core.version,
                        });
                    }
                    let len = core.state.lock().len;
                    (core.clone(), len, None)
                }
                None => {
                    let id = catalog.next_id;
                    catalog.next_id += 1;
                    let core = Arc::new(Core::new(id, *versions.end(), name.to_vec()));
                    catalog.blobs.insert(name.to_vec(), core.clone());
                    let (done, receiver) = oneshot::channel();
                    volume
                        .requests
                        .send(committer::Request::Create {
                            core: core.clone(),
                            done,
                        })
                        .map_err(|_| volume.shared.poisoned_error())?;
                    (core, 0, Some(receiver))
                }
            }
        };

        // "Ok means durably created". A minted row awaits its own create request. An
        // existing row's create was already sent (send and insert share a critical
        // section), so when it is not yet durable a bare barrier ride behind it in the
        // queue suffices.
        let receiver = match receiver {
            Some(receiver) => Some(receiver),
            None if core.created_batch.load(Ordering::Acquire)
                > volume.shared.durable_batch.load(Ordering::Acquire) =>
            {
                let (done, receiver) = oneshot::channel();
                volume
                    .requests
                    .send(committer::Request::Sync {
                        core: core.clone(),
                        done,
                    })
                    .map_err(|_| volume.shared.poisoned_error())?;
                Some(receiver)
            }
            None => None,
        };
        if let Some(receiver) = receiver {
            receiver
                .await
                .map_err(|_| volume.shared.poisoned_error())??;
        }

        let version = core.version;
        Ok((Blob::new(volume, core), len, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;

        let Some(name) = name else {
            // Remove the whole partition: own the registry slot (serializing against
            // concurrent opens and removes), unlink the volume file, then notify
            // waiters that the partition no longer exists. Existing handles keep
            // reading the unlinked file through the inner blob (read-after-remove),
            // and a subsequent open creates a fresh, independent volume.
            loop {
                let plan = {
                    let mut partitions = self.partitions.lock();
                    match partitions.get_mut(partition) {
                        Some(Slot::Busy(waiters)) => {
                            let (sender, receiver) = oneshot::channel();
                            waiters.push(sender);
                            Some(receiver)
                        }
                        // Take ownership whether the volume is open or was never
                        // opened; the inner removal decides whether it exists.
                        _ => {
                            partitions.insert(partition.to_string(), Slot::Busy(Vec::new()));
                            None
                        }
                    }
                };
                match plan {
                    Some(receiver) => {
                        // Whatever concluded (an open or another removal), retry from
                        // scratch; a second removal then reports PartitionMissing.
                        let _ = receiver.await;
                    }
                    None => {
                        let guard = BusyGuard {
                            partitions: &self.partitions,
                            partition,
                            armed: true,
                        };
                        let result = self.inner.remove(partition, None).await;
                        guard.finish(&result.clone().map(|()| None));
                        return result;
                    }
                }
            }
        };

        let Some(volume) = self.volume(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };

        // Remove one blob: take the row, freeze its chunk set (mutations fail once
        // `removed` is set, and both happen under the state lock), and journal the
        // delete, sending while the catalog lock is held so journal order equals
        // catalog order. Ok means the delete record's barrier completed.
        let receiver = {
            let mut catalog = volume.shared.catalog.lock();
            let core = catalog
                .blobs
                .remove(name)
                .ok_or_else(|| crate::Error::BlobMissing(partition.to_string(), hex(name)))?;
            let mut state = core.state.lock();
            state.removed = true;
            // A sync already queued for this blob drains after us; leave nothing for it
            // to journal (the delete record subsumes everything).
            let mut chunks: Vec<u32> = state.map.values().copied().collect();
            chunks.extend(state.snapshotted());
            drop(state);
            let (done, receiver) = oneshot::channel();
            volume
                .requests
                .send(committer::Request::Delete {
                    id: core.id,
                    chunks,
                    holder: Arc::downgrade(&core),
                    done,
                })
                .map_err(|_| volume.shared.poisoned_error())?;
            receiver
        };
        receiver.await.map_err(|_| volume.shared.poisoned_error())?
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, crate::Error> {
        super::validate_partition_name(partition)?;
        let Some(volume) = self.volume(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };
        let catalog = volume.shared.catalog.lock();
        Ok(catalog.blobs.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests;
