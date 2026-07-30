//! Common blob management for segmented journals.
//!
//! This module provides `Manager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.

use crate::journal::Error;
use commonware_formatting::hex;
use commonware_runtime::{
    BatchOperation, Blob, BufferPool, Error as RError, Handle, Metrics, RemoveTarget, Storage,
    buffer::{
        Write,
        paged::{CacheRef, Writer},
    },
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
};
use futures::future::{join_all, try_join_all};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    num::NonZeroUsize,
    ops::RangeBounds,
};
use tracing::debug;

/// A minimal [`Blob`] wrapper for [`Manager`].
pub trait SectionBuffer: Send + Sync {
    /// The wrapped blob type staged into atomic batches.
    type Blob: Blob;

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

    /// Stage a logical shrink in `batch`.
    fn resize_into(
        &mut self,
        len: u64,
        batch: &mut Vec<BatchOperation<Self::Blob>>,
    ) -> impl Future<Output = Result<(), RError>> + Send;
}

impl<B: Blob> SectionBuffer for Writer<B> {
    type Blob = B;

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

    async fn resize_into(
        &mut self,
        len: u64,
        batch: &mut Vec<BatchOperation<B>>,
    ) -> Result<(), RError> {
        Self::resize_into(self, len, batch).await
    }
}

impl<B: Blob> SectionBuffer for Write<B> {
    type Blob = B;

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

    async fn resize_into(
        &mut self,
        len: u64,
        batch: &mut Vec<BatchOperation<B>>,
    ) -> Result<(), RError> {
        Self::resize_into(self, len, batch).await
    }
}

/// Factory for creating section buffers from raw blobs.
pub trait BufferFactory<B: Blob>: Clone + Send + Sync {
    /// The buffer type produced by this factory.
    type Buffer: SectionBuffer<Blob = B>;

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
/// Syncs started by [Manager::start_sync] complete in the background, so mutations that remove
/// blobs (`prune`, `remove_section`, `rewind`, `clear`, `into_remove_targets`) call
/// [SectionBuffer::wait_for_sync] before dropping them. This resolves the sync's shared completion
/// first, guaranteeing that caller-held sync handles report the sync's true result.
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

/// A rewind whose batchable storage operations are staged but not yet finalized in memory.
pub(super) struct PreparedRewind {
    section: u64,
    size: u64,
    old_size: Option<u64>,
    remove_newer: bool,
}

impl<E: Storage + Metrics, F: BufferFactory<E::Blob>> Manager<E, F> {
    /// Wait for all started syncs to complete before their blobs are dropped.
    async fn wait_for_syncs<'a>(
        blobs: impl IntoIterator<Item = &'a mut F::Buffer>,
    ) -> Result<(), Error>
    where
        F::Buffer: 'a,
    {
        try_join_all(blobs.into_iter().map(|blob| blob.wait_for_sync()))
            .await
            .map(|_| ())
            .map_err(Error::Runtime)
    }

    /// Wait for selected section syncs, then return their exact removal targets.
    async fn remove_range_targets<R>(
        &mut self,
        range: R,
    ) -> Result<Vec<BatchOperation<E::Blob>>, Error>
    where
        R: RangeBounds<u64> + Clone,
    {
        let sections: Vec<_> = self
            .blobs
            .range(range.clone())
            .map(|(&section, _)| section)
            .collect();
        if sections.is_empty() {
            return Ok(Vec::new());
        }

        Self::wait_for_syncs(self.blobs.range_mut(range).map(|(_, blob)| blob)).await?;

        Ok(sections
            .into_iter()
            .map(|section| {
                RemoveTarget::Blob {
                    partition: self.partition.clone(),
                    name: section.to_be_bytes().to_vec(),
                }
                .into()
            })
            .collect())
    }

    /// Drop selected section handles after their removal succeeds.
    fn finalize_remove_range<R>(&mut self, range: R) -> Vec<(u64, u64)>
    where
        R: RangeBounds<u64>,
    {
        let sections: Vec<_> = self
            .blobs
            .range(range)
            .map(|(&section, _)| section)
            .collect();

        let mut removed = Vec::with_capacity(sections.len());
        for section in sections {
            let blob = self
                .blobs
                .remove(&section)
                .expect("selected section must exist");
            let size = blob.size();
            drop(blob);
            removed.push((section, size));
        }

        removed
    }

    /// Remove every section in `range` as one namespace operation.
    async fn remove_range<R>(&mut self, range: R) -> Result<Vec<(u64, u64)>, Error>
    where
        R: RangeBounds<u64> + Clone,
    {
        let targets = self.remove_range_targets(range.clone()).await?;
        self.apply_batch_operations(targets).await?;
        Ok(self.finalize_remove_range(range))
    }

    /// Apply exact storage mutations through this manager's storage context.
    pub(super) async fn apply_batch_operations(
        &self,
        operations: Vec<BatchOperation<E::Blob>>,
    ) -> Result<(), Error> {
        if operations.is_empty() {
            return Ok(());
        }
        self.context
            .apply_batch(operations)
            .await
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

    /// Get a mutable reference to a blob for a section, if it exists.
    ///
    /// Unlike [Self::get], skips the prune guard: the caller (an owned replay reader)
    /// holds the journal, so no prune can interleave.
    pub fn get_mut(&mut self, section: u64) -> Option<&mut F::Buffer> {
        self.blobs.get_mut(&section)
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
    /// returned handle, so callers must observe the handle to detect it.
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

        // Count every selected section, including reused and clean no-op syncs, matching
        // `sync` and `sync_all`.
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
        let targets = self.prune_targets(min).await?;
        self.apply_batch_operations(targets).await?;
        Ok(self.finalize_prune(min))
    }

    /// Wait for pruned section syncs, then return their exact removal targets.
    pub(super) async fn prune_targets(
        &mut self,
        min: u64,
    ) -> Result<Vec<BatchOperation<E::Blob>>, Error> {
        self.remove_range_targets(..min).await
    }

    /// Apply a successful prune to the in-memory state and metrics.
    pub(super) fn finalize_prune(&mut self, min: u64) -> bool {
        let removed = self.finalize_remove_range(..min);
        for (section, size) in &removed {
            debug!(section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if !removed.is_empty() {
            self.oldest_retained_section = min;
        }

        !removed.is_empty()
    }

    /// Returns true when `section` is below the prune floor.
    pub const fn pruned(&self, section: u64) -> bool {
        section < self.oldest_retained_section
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

    /// Remove selected sections as one namespace operation.
    pub(super) async fn remove_sections(
        &mut self,
        sections: impl crate::Sections,
    ) -> Result<usize, Error> {
        let sections = sections.sections().collect::<BTreeSet<_>>();
        for &section in &sections {
            self.prune_guard(section)?;
        }

        let mut targets = Vec::with_capacity(sections.len());
        for &section in &sections {
            let Some(blob) = self.blobs.get_mut(&section) else {
                continue;
            };
            blob.wait_for_sync().await?;
            targets.push(
                RemoveTarget::Blob {
                    partition: self.partition.clone(),
                    name: section.to_be_bytes().to_vec(),
                }
                .into(),
            );
        }
        self.apply_batch_operations(targets).await?;

        let mut removed = 0;
        for section in sections {
            let Some(blob) = self.blobs.remove(&section) else {
                continue;
            };
            let size = blob.size();
            drop(blob);
            self.tracked.dec();
            removed += 1;
            debug!(section, size, "removed section");
        }
        Ok(removed)
    }

    /// Remove a specific section. Returns true if the section existed and was removed.
    pub async fn remove_section(&mut self, section: u64) -> Result<bool, Error> {
        Ok(self.remove_sections(section).await? != 0)
    }

    /// Return a context capable of removing this manager's namespace entries.
    pub(crate) fn destroy_context(&self) -> E {
        self.context.child("destroy")
    }

    /// Wait for pending section syncs, then return the owned partition removal operation.
    pub(crate) async fn into_remove_targets(mut self) -> Result<Vec<RemoveTarget>, Error> {
        Self::wait_for_syncs(self.blobs.values_mut()).await?;
        Ok(vec![RemoveTarget::Partition(self.partition)])
    }

    /// Clear all blobs, resetting the manager to an empty state.
    ///
    /// Unlike `destroy`, this keeps the manager alive so it can be reused.
    pub async fn clear(&mut self) -> Result<(), Error> {
        let removed = self.remove_range(..).await?;
        for (section, size) in removed {
            debug!(section, size, "cleared blob");
        }
        let _ = self.tracked.try_set(0);
        self.oldest_retained_section = 0;
        Ok(())
    }

    /// Rewind by removing all sections after `section` and resizing the target section.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        let mut batch = Vec::new();
        let prepared = self.rewind_into(section, size, &mut batch).await?;
        self.apply_batch_operations(batch).await?;
        self.finalize_rewind(prepared);
        Ok(())
    }

    /// Resize only the given section without affecting other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        let mut batch = Vec::new();
        let prepared = self.rewind_section_into(section, size, &mut batch).await?;
        self.apply_batch_operations(batch).await?;
        self.finalize_rewind(prepared);
        Ok(())
    }

    /// Stage a rewind in `batch` without finalizing removed section handles.
    pub(super) async fn rewind_into(
        &mut self,
        section: u64,
        size: u64,
        batch: &mut Vec<BatchOperation<E::Blob>>,
    ) -> Result<PreparedRewind, Error> {
        self.prepare_rewind(section, size, true, batch).await
    }

    /// Stage a single-section rewind in `batch`.
    pub(super) async fn rewind_section_into(
        &mut self,
        section: u64,
        size: u64,
        batch: &mut Vec<BatchOperation<E::Blob>>,
    ) -> Result<PreparedRewind, Error> {
        self.prepare_rewind(section, size, false, batch).await
    }

    /// Stage the requested shrink and removals after validating the prune floor.
    async fn prepare_rewind(
        &mut self,
        section: u64,
        size: u64,
        remove_newer: bool,
        batch: &mut Vec<BatchOperation<E::Blob>>,
    ) -> Result<PreparedRewind, Error> {
        self.prune_guard(section)?;

        let old_size = if let Some(blob) = self.blobs.get_mut(&section) {
            let current_size = blob.size();
            if size < current_size {
                blob.resize_into(size, batch).await?;
                Some(current_size)
            } else {
                None
            }
        } else {
            None
        };

        if remove_newer && let Some(next) = section.checked_add(1) {
            batch.extend(self.remove_range_targets(next..).await?);
        }

        Ok(PreparedRewind {
            section,
            size,
            old_size,
            remove_newer,
        })
    }

    /// Finalize a successfully applied rewind in memory.
    pub(super) fn finalize_rewind(&mut self, prepared: PreparedRewind) {
        if prepared.remove_newer
            && let Some(next) = prepared.section.checked_add(1)
        {
            for (removed_section, _) in self.finalize_remove_range(next..) {
                self.tracked.dec();
                debug!(section = removed_section, "removed blob during rewind");
            }
        }

        if let Some(old_size) = prepared.old_size {
            debug!(
                section = prepared.section,
                old_size,
                new_size = prepared.size,
                "rewound blob"
            );
        }
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
    use commonware_runtime::{
        Name, Runner as _, Spawner as _, Supervisor, deterministic,
        telemetry::metrics::{Metric, Registered},
    };
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use futures::{
        FutureExt as _,
        future::{BoxFuture, Shared},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    type SyncSender = oneshot::Sender<Result<(), RError>>;
    type PendingSyncs = Arc<Mutex<Vec<SyncSender>>>;

    /// A shared sync result, mirroring the runtime buffers' internal completion sharing.
    type SharedSync = Shared<BoxFuture<'static, Result<(), RError>>>;

    #[derive(Debug, Eq, PartialEq)]
    enum RecordedOperation {
        Remove(RemoveTarget),
        Resize { len: u64 },
    }

    #[derive(Default)]
    struct RemoveCalls {
        batches: Vec<Vec<RecordedOperation>>,
    }

    #[derive(Clone)]
    struct RecordingContext<E> {
        inner: E,
        calls: Arc<Mutex<RemoveCalls>>,
    }

    impl<E: Supervisor> Supervisor for RecordingContext<E> {
        fn name(&self) -> Name {
            self.inner.name()
        }

        fn child(&self, label: &'static str) -> Self {
            Self {
                inner: self.inner.child(label),
                calls: self.calls.clone(),
            }
        }

        fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
            self.inner = self.inner.with_attribute(key, value);
            self
        }
    }

    impl<E: Metrics> Metrics for RecordingContext<E> {
        fn register<N: Into<String>, H: Into<String>, M: Metric>(
            &self,
            name: N,
            help: H,
            metric: M,
        ) -> Registered<M> {
            self.inner.register(name, help, metric)
        }

        fn encode(&self) -> String {
            self.inner.encode()
        }
    }

    impl<E: Storage> Storage for RecordingContext<E> {
        type Blob = E::Blob;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: std::ops::RangeInclusive<u16>,
        ) -> Result<(Self::Blob, u64, u16), RError> {
            self.inner.open_versioned(partition, name, versions).await
        }

        async fn apply_batch(
            &self,
            operations: Vec<BatchOperation<Self::Blob>>,
        ) -> Result<(), RError> {
            let recorded = operations
                .iter()
                .map(|operation| match operation {
                    BatchOperation::Remove(target) => RecordedOperation::Remove(target.clone()),
                    BatchOperation::Resize { len, .. } | BatchOperation::Update { len, .. } => {
                        RecordedOperation::Resize { len: *len }
                    }
                })
                .collect();
            self.calls.lock().batches.push(recorded);
            self.inner.apply_batch(operations).await
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, RError> {
            self.inner.scan(partition).await
        }
    }

    #[derive(Clone)]
    struct TestFactory {
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
    }

    struct TestBuffer<B: Blob> {
        blob: B,
        size: u64,
        pending: PendingSyncs,
        wait_for_syncs: Arc<AtomicUsize>,
        syncing: Option<SharedSync>,
    }

    impl<B: Blob> SectionBuffer for TestBuffer<B> {
        type Blob = B;

        fn size(&self) -> u64 {
            self.size
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

        async fn resize_into(
            &mut self,
            len: u64,
            batch: &mut Vec<BatchOperation<B>>,
        ) -> Result<(), RError> {
            if len < self.size {
                self.size = len;
                batch.push(BatchOperation::Resize {
                    blob: self.blob.clone(),
                    len,
                });
            }
            Ok(())
        }
    }

    impl<B: Blob> BufferFactory<B> for TestFactory {
        type Buffer = TestBuffer<B>;

        async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
            Ok(TestBuffer {
                blob,
                size,
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
    fn test_multi_section_removals_use_exact_batches() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let calls = Arc::new(Mutex::new(RemoveCalls::default()));
            let context = RecordingContext {
                inner: context.child("manager"),
                calls: calls.clone(),
            };
            let pending = Arc::new(Mutex::new(Vec::new()));
            let wait_for_syncs = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(pending, wait_for_syncs);
            let mut manager = Manager::init(context, cfg)
                .await
                .expect("failed to initialize manager");

            for section in 1..=4 {
                manager
                    .get_or_create(section)
                    .await
                    .expect("failed to create section");
            }
            assert!(manager.prune(3).await.expect("prune failed"));
            manager.clear().await.expect("clear failed");

            for section in 5..=7 {
                manager
                    .get_or_create(section)
                    .await
                    .expect("failed to create section");
            }
            manager.blobs.get_mut(&5).unwrap().size = 10;
            manager.rewind(5, 4).await.expect("rewind failed");

            let target = |section: u64| {
                RecordedOperation::Remove(RemoveTarget::Blob {
                    partition: "test".into(),
                    name: section.to_be_bytes().to_vec(),
                })
            };
            let calls = calls.lock();
            assert_eq!(
                calls.batches,
                vec![
                    vec![target(1), target(2)],
                    vec![target(3), target(4)],
                    vec![RecordedOperation::Resize { len: 4 }, target(6), target(7),],
                ]
            );
        });
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
            let destroy_context = manager.destroy_context();
            let targets = manager
                .into_remove_targets()
                .await
                .expect("failed to collect remove targets");
            destroy_context
                .apply_batch(targets.into_iter().map(Into::into).collect())
                .await
                .expect("destroy failed");
        });
    }

    // Reuse applies only when no new data was written since the sync started: a section with
    // newer writes flushes them (waiting on the in-flight sync) and starts a new sync, so
    // callers must call start_sync again to get a handle covering the new data.
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
            let destroy_context = manager.destroy_context();
            let targets = manager
                .into_remove_targets()
                .await
                .expect("failed to collect remove targets");
            destroy_context
                .apply_batch(targets.into_iter().map(Into::into).collect())
                .await
                .expect("destroy failed");
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
                let destroy_context = manager.destroy_context();
                let targets = manager
                    .into_remove_targets()
                    .await
                    .expect("failed to collect remove targets");
                destroy_context
                    .apply_batch(targets.into_iter().map(Into::into).collect())
                    .await
                    .expect("destroy failed");
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
    fn test_destroy_surfaces_failed_in_flight_start_sync() {
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
            let handle = manager.start_sync(1).await.expect("failed to start sync");
            complete_next_pending_sync(&pending, Err(RError::Closed));

            let err = manager
                .into_remove_targets()
                .await
                .expect_err("destroy should surface the sync failure");
            assert!(matches!(err, Error::Runtime(RError::Closed)));
            assert!(matches!(
                handle.await.expect_err("sync handle should fail"),
                RError::Closed
            ));
        });
    }
}
