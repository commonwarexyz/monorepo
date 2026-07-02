//! Common blob management for segmented journals.
//!
//! This module provides `Manager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.

use crate::journal::Error;
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::{
        paged::{CacheRef, Writer},
        Write,
    },
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
    Blob, BufferPool, Error as RError, Handle, Metrics, Storage,
};
use futures::future::{join_all, try_join_all};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    mem::take,
    num::NonZeroUsize,
};
use tracing::debug;

/// A minimal [`Blob`] wrapper for [`Manager`].
pub trait SectionBuffer: Send + Sync {
    /// Returns the current logical size of the buffer including any buffered data.
    fn size(&self) -> u64;

    /// Ensure all data accepted by this buffer is durably persisted.
    fn sync(&mut self) -> impl Future<Output = Result<(), RError>> + Send;

    /// Start making data currently accepted by this buffer durable.
    ///
    /// The returned handle covers every write accepted before this call returns; later writes
    /// need a new sync. Implementations must wait for an outstanding sync before mutating the
    /// underlying blob and may reuse an in-flight handle when no newer writes need syncing.
    fn start_sync(&mut self) -> impl Future<Output = Handle<()>> + Send;

    /// Wait for any started sync to complete without starting a new sync.
    fn wait_for_sync(&mut self) -> impl Future<Output = Result<(), RError>> + Send;

    /// Resize the logical size of the buffer.
    fn resize(&mut self, len: u64) -> impl Future<Output = Result<(), RError>> + Send;
}

impl<B: Blob> SectionBuffer for Writer<B> {
    fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn sync(&mut self) -> Result<(), RError> {
        Self::sync(self).await
    }

    async fn start_sync(&mut self) -> Handle<()> {
        Self::start_sync(self).await
    }

    async fn wait_for_sync(&mut self) -> Result<(), RError> {
        Self::wait_for_sync(self).await
    }

    async fn resize(&mut self, len: u64) -> Result<(), RError> {
        Self::resize(self, len).await
    }
}

impl<B: Blob> SectionBuffer for Write<B> {
    fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn sync(&mut self) -> Result<(), RError> {
        Self::sync(self).await
    }

    async fn start_sync(&mut self) -> Handle<()> {
        Self::start_sync(self).await
    }

    async fn wait_for_sync(&mut self) -> Result<(), RError> {
        Self::wait_for_sync(self).await
    }

    async fn resize(&mut self, len: u64) -> Result<(), RError> {
        Self::resize(self, len).await
    }
}

/// Factory for creating section buffers from raw blobs.
pub trait BufferFactory<B: Blob>: Clone + Send + Sync {
    /// The buffer type produced by this factory.
    type Buffer: SectionBuffer;

    /// Create a new buffer wrapping the given blob with the specified size.
    fn create(
        &self,
        blob: B,
        size: u64,
    ) -> impl Future<Output = Result<Self::Buffer, RError>> + Send;
}

/// Factory for creating [`Writer`] buffers with page caching.
#[derive(Clone)]
pub struct AppendFactory {
    /// The size of the write buffer.
    pub write_buffer: NonZeroUsize,
    /// The page cache for read caching.
    pub page_cache_ref: CacheRef,
}

impl<B: Blob> BufferFactory<B> for AppendFactory {
    type Buffer = Writer<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Writer::new(
            blob,
            size,
            self.write_buffer.get(),
            self.page_cache_ref.clone(),
        )
        .await
    }
}

/// Factory for creating [`Write`] buffers without caching.
#[derive(Clone)]
pub struct WriteFactory {
    /// The capacity of the write buffer.
    pub capacity: NonZeroUsize,
    /// The buffer pool used by write buffers.
    pub pool: BufferPool,
}

impl<B: Blob> BufferFactory<B> for WriteFactory {
    type Buffer = Write<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Ok(Write::new(blob, size, self.capacity, self.pool.clone()))
    }
}

/// Configuration for blob management.
#[derive(Clone)]
pub struct Config<F> {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The factory for creating section buffers.
    pub factory: F,
}

/// Manages a collection of section-based blobs.
///
/// Each section is stored in a separate blob, named by its section number
/// (big-endian u64). This component handles initialization, pruning, syncing,
/// and metrics.
///
/// # In-flight syncs
///
/// Syncs started by [Manager::start_sync] complete in the background, so every path that
/// removes a blob from `blobs` (`prune`, `remove_section`, `rewind`, `clear`, `destroy`) must
/// call [SectionBuffer::wait_for_sync] before dropping it. This resolves the sync's shared
/// completion first, guaranteeing that caller-held sync handles always report the sync's true
/// result and that no buffer is dropped with I/O in flight. `destroy` waits for every blob
/// before surfacing an error for the same reason.
pub struct Manager<E: Storage + Metrics, F: BufferFactory<E::Blob>> {
    context: E,
    partition: String,
    factory: F,

    /// One blob per section.
    pub(crate) blobs: BTreeMap<u64, F::Buffer>,

    /// A section number before which all sections have been pruned during
    /// the current execution. Not persisted across restarts.
    oldest_retained_section: u64,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics, F: BufferFactory<E::Blob>> Manager<E, F> {
    /// Wait for all started syncs to complete, surfacing the first error only after every sync
    /// finishes (blobs must not be dropped with a sync in flight).
    async fn wait_for_syncs<'a>(
        blobs: impl IntoIterator<Item = &'a mut F::Buffer>,
    ) -> Result<(), Error>
    where
        F::Buffer: 'a,
    {
        join_all(blobs.into_iter().map(|blob| blob.wait_for_sync()))
            .await
            .into_iter()
            .collect::<Result<(), RError>>()
            .map_err(Error::Runtime)
    }

    /// Initialize a new `Manager`.
    ///
    /// Scans the partition for existing blobs and opens them.
    pub async fn init(context: E, cfg: Config<F>) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, size, "loaded section");
            let buffer = cfg.factory.create(blob, size).await?;
            blobs.insert(section, buffer);
        }

        // Initialize metrics
        let tracked = context.gauge("tracked", "Number of blobs");
        let synced = context.counter("synced", "Number of syncs");
        let pruned = context.counter("pruned", "Number of blobs pruned");
        let _ = tracked.try_set(blobs.len());

        Ok(Self {
            context,
            partition: cfg.partition,
            factory: cfg.factory,
            blobs,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
        })
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    pub const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Get a reference to a blob for a section, if it exists.
    pub fn get(&self, section: u64) -> Result<Option<&F::Buffer>, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section))
    }

    /// Get a mutable reference to a blob, creating it if it doesn't exist.
    pub async fn get_or_create(&mut self, section: u64) -> Result<&mut F::Buffer, Error> {
        self.prune_guard(section)?;

        if !self.blobs.contains_key(&section) {
            let name = section.to_be_bytes();
            let (blob, size) = self.context.open(&self.partition, &name).await?;
            let buffer = self.factory.create(blob, size).await?;
            self.tracked.inc();
            self.blobs.insert(section, buffer);
        }

        Ok(self.blobs.get_mut(&section).unwrap())
    }

    /// Sync the given `sections` to storage.
    pub async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        for &section in &sections {
            self.prune_guard(section)?;
        }
        let futures: Vec<_> = self
            .blobs
            .iter_mut()
            .filter(|(section, _)| sections.contains(section))
            .map(|(_, blob)| blob.sync())
            .collect();
        let count = futures.len() as u64;
        try_join_all(futures).await.map_err(Error::Runtime)?;
        self.synced.inc_by(count);
        Ok(())
    }

    /// Start syncing the given `sections` to storage.
    ///
    /// The returned handle completes once every selected section's sync completes, failing with
    /// the first error encountered. Sections with an in-flight sync and no newer writes reuse
    /// that sync's handle rather than starting a new one.
    ///
    /// The handle is a detached observer: dropping it does not cancel the sync, and a failure of
    /// the started sync resurfaces from the buffer on the section's next operation. A failure to
    /// flush buffered data while starting the sync, however, is reported only through the
    /// returned handle, so callers must observe the handle to detect it. The `synced` metric
    /// counts every selected section, including reused and clean no-op syncs, matching
    /// [Manager::sync] and [Manager::sync_all].
    pub async fn start_sync(
        &mut self,
        sections: impl crate::Sections,
    ) -> Result<Handle<()>, Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        for &section in &sections {
            self.prune_guard(section)?;
        }
        let futures: Vec<_> = self
            .blobs
            .iter_mut()
            .filter(|(section, _)| sections.contains(section))
            .map(|(_, blob)| blob.start_sync())
            .collect();
        self.synced.inc_by(futures.len() as u64);
        let handles = join_all(futures).await;
        Ok(Handle::from_future(async move {
            try_join_all(handles).await.map(|_| ())
        }))
    }

    /// Sync all sections to storage.
    pub async fn sync_all(&mut self) -> Result<(), Error> {
        let count = self.blobs.len() as u64;
        try_join_all(self.blobs.values_mut().map(|b| b.sync()))
            .await
            .map_err(Error::Runtime)?;
        self.synced.inc_by(count);
        Ok(())
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        // Prune any blobs that are smaller than the minimum
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            // Remove blob from map
            let mut blob = self.blobs.remove(&section).unwrap();
            blob.wait_for_sync().await?;
            let size = blob.size();
            drop(blob);

            // Remove blob from storage
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            pruned = true;

            debug!(section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if pruned {
            self.oldest_retained_section = min;
        }

        Ok(pruned)
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.blobs.first_key_value().map(|(&s, _)| s)
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.blobs.last_key_value().map(|(&s, _)| s)
    }

    /// Returns true if no blobs exist.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Returns the number of sections (blobs).
    pub fn num_sections(&self) -> usize {
        self.blobs.len()
    }

    /// Returns an iterator over all sections starting from `start_section`.
    pub fn sections_from(
        &mut self,
        start_section: u64,
    ) -> impl Iterator<Item = (&u64, &mut F::Buffer)> {
        self.blobs.range_mut(start_section..)
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.blobs.keys().copied()
    }

    /// Remove a specific section. Returns true if the section existed and was removed.
    pub async fn remove_section(&mut self, section: u64) -> Result<bool, Error> {
        self.prune_guard(section)?;

        if let Some(mut blob) = self.blobs.remove(&section) {
            blob.wait_for_sync().await?;
            let size = blob.size();
            drop(blob);
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section, size, "removed section");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove all underlying blobs.
    pub async fn destroy(mut self) -> Result<(), Error> {
        Self::wait_for_syncs(self.blobs.values_mut()).await?;
        for (section, blob) in self.blobs.into_iter() {
            let size = blob.size();
            drop(blob);
            debug!(section, size, "destroyed blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.partition, None).await {
            Ok(()) => {}
            // Partition already removed or never existed.
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }

    /// Clear all blobs, resetting the manager to an empty state.
    ///
    /// Unlike `destroy`, this keeps the manager alive so it can be reused.
    pub async fn clear(&mut self) -> Result<(), Error> {
        Self::wait_for_syncs(self.blobs.values_mut()).await?;
        let blobs = take(&mut self.blobs);
        for (section, blob) in blobs {
            let size = blob.size();
            drop(blob);
            debug!(section, size, "cleared blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        let _ = self.tracked.try_set(0);
        self.oldest_retained_section = 0;
        Ok(())
    }

    /// Rewind by removing all sections after `section` and resizing the target section.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Remove sections in descending order (newest first) to maintain a contiguous record
        // if a crash occurs during rewind. Section `u64::MAX` has no successor, so there are
        // no sections above it to remove.
        let sections_to_remove: Vec<u64> = match section.checked_add(1) {
            Some(next) => self.blobs.range(next..).rev().map(|(&s, _)| s).collect(),
            None => Vec::new(),
        };

        for s in sections_to_remove {
            // Remove the underlying blob from storage
            let mut blob = self.blobs.remove(&s).unwrap();
            blob.wait_for_sync().await?;
            drop(blob);
            self.context
                .remove(&self.partition, Some(&s.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section = s, "removed blob during rewind");
        }

        // If the section exists, truncate it to the given size
        if let Some(blob) = self.blobs.get_mut(&section) {
            let current_size = blob.size();
            if size < current_size {
                blob.resize(size).await?;
                debug!(
                    section,
                    old_size = current_size,
                    new_size = size,
                    "rewound blob"
                );
            }
        }

        Ok(())
    }

    /// Resize only the given section without affecting other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Get the blob at the given section
        if let Some(blob) = self.blobs.get_mut(&section) {
            // Truncate the blob to the given size
            let current = blob.size();
            if size < current {
                blob.resize(size).await?;
                debug!(section, from = current, to = size, "rewound section");
            }
        }

        Ok(())
    }

    /// Returns the byte size of the given section.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section).map_or(0, |blob| blob.size()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _, Spawner as _, Supervisor as _};
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use futures::{
        future::{BoxFuture, Shared},
        FutureExt as _,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    type SyncSender = oneshot::Sender<Result<(), RError>>;
    type PendingSyncs = Arc<Mutex<Vec<SyncSender>>>;

    /// A shared sync result, mirroring the runtime buffers' internal completion sharing.
    type SharedSync = Shared<BoxFuture<'static, Result<(), RError>>>;

    #[derive(Clone)]
    struct TestFactory {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
    }

    struct TestBuffer {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
        syncing: Option<SharedSync>,
    }

    impl Drop for TestBuffer {
        fn drop(&mut self) {
            assert!(
                self.syncing.is_none(),
                "dropped section buffer with in-flight sync"
            );
        }
    }

    impl SectionBuffer for TestBuffer {
        fn size(&self) -> u64 {
            0
        }

        async fn sync(&mut self) -> Result<(), RError> {
            Ok(())
        }

        async fn start_sync(&mut self) -> Handle<()> {
            if let Some(syncing) = &self.syncing {
                return Handle::from_future(syncing.clone());
            }
            let (sender, receiver) = oneshot::channel();
            self.pending.lock().push(sender);
            let sync = async move {
                receiver.await.map_err(|_| RError::Closed)??;
                Ok(())
            }
            .boxed()
            .shared();
            self.syncing = Some(sync.clone());
            Handle::from_future(sync)
        }

        async fn wait_for_sync(&mut self) -> Result<(), RError> {
            if let Some(syncing) = self.syncing.take() {
                self.wait_for_syncs.fetch_add(1, Ordering::Relaxed);
                syncing.await?;
            }
            Ok(())
        }

        async fn resize(&mut self, _len: u64) -> Result<(), RError> {
            Ok(())
        }
    }

    impl<B: Blob> BufferFactory<B> for TestFactory {
        type Buffer = TestBuffer;

        async fn create(&self, _blob: B, _size: u64) -> Result<Self::Buffer, RError> {
            Ok(TestBuffer {
                pending: self.pending.clone(),
                wait_for_syncs: self.wait_for_syncs.clone(),
                syncing: None,
            })
        }
    }

    fn test_config(pending: PendingSyncs, wait_for_syncs: Arc<AtomicUsize>) -> Config<TestFactory> {
        Config {
            partition: "test".into(),
            factory: TestFactory {
                pending,
                wait_for_syncs,
            },
        }
    }

    fn release_pending_syncs(pending: &PendingSyncs) {
        for sender in std::mem::take(&mut *pending.lock()) {
            let _ = sender.send(Ok(()));
        }
    }

    fn complete_next_pending_sync(pending: &PendingSyncs, result: Result<(), RError>) {
        let sender = {
            let mut pending = pending.lock();
            assert!(!pending.is_empty(), "no pending sync to complete");
            pending.remove(0)
        };
        let _ = sender.send(result);
    }

    #[test]
    fn test_start_sync_multiple_sections_returns_combined_handle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs);
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create first section");
            manager
                .get_or_create(2)
                .await
                .expect("failed to create second section");
            let handle = manager
                .start_sync([1, 2])
                .await
                .expect("failed to start sync");
            assert_eq!(pending.lock().len(), 2);
            futures::pin_mut!(handle);

            // Complete only the first section's sync: the combined handle must stay pending.
            complete_next_pending_sync(&pending, Ok(()));
            assert!(
                futures::poll!(handle.as_mut()).is_pending(),
                "combined sync handle must wait for every selected section"
            );

            complete_next_pending_sync(&pending, Ok(()));
            handle.await.expect("sync handle should complete");
            manager.destroy().await.expect("destroy failed");
        });
    }

    #[test]
    fn test_start_sync_reuses_in_flight_section_handle_without_waiting() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs);
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let first = manager.start_sync(1).await.expect("failed to start sync");
            assert_eq!(pending.lock().len(), 1);

            let second = manager
                .start_sync(1)
                .await
                .expect("failed to observe in-flight sync");
            assert_eq!(
                pending.lock().len(),
                1,
                "repeated start_sync should observe the in-flight section sync"
            );
            futures::pin_mut!(second);

            // The reused handle must remain tied to the in-flight sync.
            assert!(
                futures::poll!(second.as_mut()).is_pending(),
                "reused start_sync handle must wait for the in-flight sync"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            second.await.expect("reused sync handle should complete");
            manager.destroy().await.expect("destroy failed");
        });
    }

    #[test]
    fn test_prune_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs.clone());
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let handle = manager.start_sync(1).await.expect("failed to start sync");
            assert_eq!(pending.lock().len(), 1);

            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let waiter = context.child("prune").spawn(|_| async move {
                assert!(manager.prune(2).await.expect("prune failed"));
                completed_clone.fetch_add(1, Ordering::Relaxed);
                manager
            });

            while wait_for_syncs.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "prune must wait for the in-flight start_sync handle"
            );

            release_pending_syncs(&pending);
            handle.await.expect("sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let manager = waiter.await.expect("prune task failed");
            assert!(manager.is_empty());
        });
    }

    #[test]
    fn test_destroy_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs.clone());
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create section");
            let handle = manager.start_sync(1).await.expect("failed to start sync");
            assert_eq!(pending.lock().len(), 1);

            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let waiter = context.child("destroy").spawn(|_| async move {
                manager.destroy().await.expect("destroy failed");
                completed_clone.fetch_add(1, Ordering::Relaxed);
            });

            while wait_for_syncs.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "destroy must wait for the in-flight start_sync handle"
            );

            release_pending_syncs(&pending);
            handle.await.expect("sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            waiter.await.expect("destroy task failed");
        });
    }

    #[test]
    fn test_destroy_waits_for_all_in_flight_start_syncs_before_returning_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending.clone(), wait_for_syncs.clone());
            let mut manager = Manager::init(context.child("manager"), cfg)
                .await
                .expect("failed to initialize manager");

            manager
                .get_or_create(1)
                .await
                .expect("failed to create first section");
            manager
                .get_or_create(2)
                .await
                .expect("failed to create second section");
            let first = manager
                .start_sync(1)
                .await
                .expect("failed to start first sync");
            let second = manager
                .start_sync(2)
                .await
                .expect("failed to start second sync");
            assert_eq!(pending.lock().len(), 2);

            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let waiter = context.child("destroy").spawn(|_| async move {
                let result = manager.destroy().await;
                completed_clone.fetch_add(1, Ordering::Relaxed);
                result
            });

            while wait_for_syncs.load(Ordering::Relaxed) < 1 {
                commonware_runtime::reschedule().await;
            }
            complete_next_pending_sync(&pending, Err(RError::Closed));

            while wait_for_syncs.load(Ordering::Relaxed) < 2 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "destroy must wait for every in-flight sync before returning an error"
            );

            complete_next_pending_sync(&pending, Ok(()));
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let err = waiter
                .await
                .expect("destroy task failed")
                .expect_err("destroy should return the first sync error");
            assert!(matches!(err, Error::Runtime(RError::Closed)));
            assert!(matches!(
                first.await.expect_err("first sync handle should fail"),
                RError::Closed
            ));
            second.await.expect("second sync handle should complete");
        });
    }
}
