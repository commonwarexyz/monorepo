use crate::{
    Buf, Error, Handle, IoBufs, IoBufsMut, WriteOptions,
    telemetry::{
        metrics::{Counter, Gauge, Register, raw},
        traces::TracedExt as _,
    },
};
commonware_macros::stability_scope!(ALPHA {
    use crate::{AtomicBlob, AtomicStorage, BatchOperation, BatchStorage};
});
use std::{
    ops::{Deref, RangeInclusive},
    sync::Arc,
};
use tracing::{Instrument as _, Span, field::Empty};

pub struct Metrics {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
    pub storage_syncs: Counter,
    pub storage_resizes: Counter,
}

impl Metrics {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    fn new(registry: &mut impl Register) -> Self {
        Self {
            open_blobs: registry.register(
                "open_blobs",
                "Number of open blobs",
                raw::Gauge::default(),
            ),
            storage_reads: registry.register(
                "storage_reads",
                "Total number of disk reads",
                raw::Counter::default(),
            ),
            storage_read_bytes: registry.register(
                "storage_read_bytes",
                "Total amount of data read from disk",
                raw::Counter::default(),
            ),
            storage_writes: registry.register(
                "storage_writes",
                "Total number of disk writes",
                raw::Counter::default(),
            ),
            storage_write_bytes: registry.register(
                "storage_write_bytes",
                "Total amount of data written to disk",
                raw::Counter::default(),
            ),
            storage_syncs: registry.register(
                "storage_syncs",
                "Total number of disk syncs",
                raw::Counter::default(),
            ),
            storage_resizes: registry.register(
                "storage_resizes",
                "Total number of disk resizes",
                raw::Counter::default(),
            ),
        }
    }
}

/// A wrapper around a `Storage` implementation that tracks metrics.
#[derive(Clone)]
pub struct Storage<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S> Storage<S> {
    pub(crate) fn new(inner: S, registry: &mut impl Register) -> Self {
        Self {
            inner,
            metrics: Metrics::new(registry).into(),
        }
    }

    /// Get a reference to the inner storage.
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (inner, len, blob_version) =
            self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            Blob {
                inner,
                partition: partition.into(),
                #[cfg(not(any(
                    commonware_stability_BETA,
                    commonware_stability_GAMMA,
                    commonware_stability_DELTA,
                    commonware_stability_EPSILON,
                    commonware_stability_RESERVED
                )))]
                name: Arc::from(name),
                metrics: Arc::new(MetricsHandle::new(self.metrics.clone())),
            },
            len,
            blob_version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

#[commonware_macros::stability(ALPHA)]
impl<S: AtomicStorage> AtomicStorage for Storage<S> {
    type AtomicBlob = Blob<S::AtomicBlob>;

    async fn migrate_atomic(&self, blob: Self::Blob) -> Result<(), Error> {
        self.inner.migrate_atomic(blob.inner).await
    }

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), Error> {
        let (inner, len, blob_version) = self
            .inner
            .open_atomic_versioned(partition, name, versions)
            .await?;
        Ok((
            Blob {
                inner,
                partition: partition.into(),
                name: Arc::from(name),
                metrics: Arc::new(MetricsHandle::new(self.metrics.clone())),
            },
            len,
            blob_version,
        ))
    }
}

#[commonware_macros::stability(ALPHA)]
impl<S: BatchStorage> BatchStorage for Storage<S> {
    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> Result<Handle<()>, Error> {
        let descriptors = crate::storage::batch::canonicalize_descriptors(&operations, |blob| {
            (blob.partition.to_string(), blob.name.to_vec())
        })?;
        let operations = crate::storage::batch::map_blobs(operations, |blob| blob.inner);
        let completion = self.inner.start_apply(operations).await?;

        for operation in descriptors {
            match operation {
                crate::storage::batch::Operation::Remove(_) => {}
                crate::storage::batch::Operation::Publish { .. } => {}
                crate::storage::batch::Operation::Rewind { .. } => {
                    self.metrics.storage_resizes.inc();
                }
            }
        }
        Ok(completion)
    }
}

/// A wrapper around a `Blob` implementation that tracks metrics
#[derive(Clone)]
pub struct Blob<B> {
    inner: B,
    partition: Arc<str>,
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    name: Arc<[u8]>,
    metrics: Arc<MetricsHandle>,
}

/// A wrapper around a `Metrics` implementation that updates
/// metrics when a blob (that may have been cloned multiple times)
/// is dropped.
struct MetricsHandle(Arc<Metrics>);

impl MetricsHandle {
    /// Counts the blob as open until this handle is dropped.
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.open_blobs.inc();
        Self(metrics)
    }
}

impl Deref for MetricsHandle {
    type Target = Metrics;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for MetricsHandle {
    fn drop(&mut self) {
        // Only decrement when the last reference to the blob is dropped
        self.0.open_blobs.dec();
    }
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(len as u64);
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(len as u64);
        self.inner.read_at_buf(offset, len, bufs).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.write_at",
        level = "info",
        skip_all,
        fields(
            partition = %self.partition,
            bytes = Empty,
            options = options.0.traced(),
        )
    )]
    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let bufs_len = bufs.remaining();
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(bufs_len as u64);
        if options.contains(WriteOptions::SYNC) {
            self.metrics.storage_syncs.inc();
        }
        Span::current().record("bytes", bufs_len as u64);
        self.inner.write_at(offset, bufs, options).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.resize",
        level = "info",
        skip_all,
        fields(partition = %self.partition, len = len)
    )]
    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.metrics.storage_resizes.inc();
        self.inner.resize(len).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.sync",
        level = "info",
        skip_all,
        fields(partition = %self.partition)
    )]
    async fn sync(&self) -> Result<(), Error> {
        self.metrics.storage_syncs.inc();
        self.inner.sync().await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.start_sync",
        level = "info",
        skip_all,
        fields(partition = %self.partition)
    )]
    #[allow(clippy::async_yields_async)]
    async fn start_sync(&self) -> Handle<()> {
        self.metrics.storage_syncs.inc();
        let handle = self.inner.start_sync().await;
        Handle::from_future(handle.instrument(tracing::info_span!(
            "runtime.storage.blob.sync",
            partition = %self.partition,
        )))
    }
}

#[commonware_macros::stability(ALPHA)]
impl<B: AtomicBlob> AtomicBlob for Blob<B> {
    async fn tag(&self) -> Result<[u8; crate::ATOMIC_BLOB_TAG_LEN], Error> {
        self.inner.tag().await
    }

    async fn set_tag(&self, tag: [u8; crate::ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        self.inner.set_tag(tag).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.append",
        level = "info",
        skip_all,
        fields(partition = %self.partition, bytes = Empty)
    )]
    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        let data = data.into();
        let data_len = data.remaining();
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(data_len as u64);
        Span::current().record("bytes", data_len as u64);
        self.inner.append(data).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.append_tagged",
        level = "info",
        skip_all,
        fields(partition = %self.partition, bytes = Empty)
    )]
    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        let data = data.into();
        let data_len = data.remaining();
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(data_len as u64);
        Span::current().record("bytes", data_len as u64);
        self.inner.append_tagged(data, tag).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.rewind",
        level = "info",
        skip_all,
        fields(partition = %self.partition, len = len)
    )]
    async fn rewind(&self, len: u64) -> Result<(), Error> {
        self.metrics.storage_resizes.inc();
        self.inner.rewind(len).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.rewind_tagged",
        level = "info",
        skip_all,
        fields(partition = %self.partition, len = len)
    )]
    async fn rewind_tagged(
        &self,
        len: u64,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<(), Error> {
        self.metrics.storage_resizes.inc();
        self.inner.rewind_tagged(len, tag).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob, BufferPool, BufferPoolConfig, Storage as _, WriteOptions,
        storage::{
            memory::Storage as MemoryStorage,
            tests::{
                run_atomic_blob_tests, run_atomic_storage_tests, run_batch_storage_tests,
                run_storage_foreign_handle_test, run_storage_tests,
            },
        },
        telemetry::metrics::Registry,
    };

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_storage(), scope)
    }

    #[tokio::test]
    async fn test_metered_storage() {
        let mut registry = crate::telemetry::metrics::Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));
        let tested = storage.clone();
        run_storage_tests(storage.clone()).await;
        run_atomic_storage_tests(storage.clone()).await;
        run_batch_storage_tests(storage.clone()).await;
        let (atomic, _) = storage
            .open_atomic("atomic_storage", b"blob")
            .await
            .unwrap();
        run_atomic_blob_tests(atomic).await;

        let mut foreign_registry = crate::telemetry::metrics::Registry::default();
        let foreign_inner = MemoryStorage::new(test_pool(
            &mut foreign_registry.sub_registry("foreign_pool"),
        ));
        let foreign = Storage::new(
            foreign_inner,
            &mut foreign_registry.sub_registry("foreign_storage"),
        );
        run_storage_foreign_handle_test(&tested, &foreign).await;
    }

    /// Test that a failed open does not count an open blob.
    #[tokio::test]
    async fn test_failed_open_does_not_count_open_blob() {
        let mut registry = crate::telemetry::metrics::Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        // Create a blob at the default version and release it
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        assert_eq!(storage.metrics.open_blobs.get(), 0);

        // Reopen with a disjoint version range
        let result = storage
            .open_versioned("partition", b"test_blob", 7..=7)
            .await;
        assert!(matches!(result, Err(Error::BlobVersionMismatch { .. })));
        assert_eq!(
            storage.metrics.open_blobs.get(),
            0,
            "failed open must not count an open blob"
        );
    }

    /// Test that metrics are updated correctly for basic operations.
    #[tokio::test]
    async fn test_metered_blob_metrics() {
        let mut registry = crate::telemetry::metrics::Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        // Open a blob
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Verify that the open_blobs metric is incremented
        let open_blobs = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs, 1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Write data to the blob
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();
        let writes = storage.metrics.storage_writes.get();
        let write_bytes = storage.metrics.storage_write_bytes.get();
        assert_eq!(
            writes, 1,
            "storage_writes metric was not incremented after write"
        );
        assert_eq!(
            write_bytes, 11,
            "storage_write_bytes metric was not updated correctly after write"
        );

        // Read data from the blob
        let read = blob.read_at(0, 11).await.unwrap();
        assert_eq!(read.coalesce(), b"hello world");
        let reads = storage.metrics.storage_reads.get();
        let read_bytes = storage.metrics.storage_read_bytes.get();
        assert_eq!(
            reads, 1,
            "storage_reads metric was not incremented after read"
        );
        assert_eq!(
            read_bytes, 11,
            "storage_read_bytes metric was not updated correctly after read"
        );

        // Sync the blob
        blob.sync().await.unwrap();
        let syncs = storage.metrics.storage_syncs.get();
        assert_eq!(
            syncs, 1,
            "storage_syncs metric was not incremented after sync"
        );

        // Write and sync in a single call
        blob.write_at(11, b" again", WriteOptions::SYNC)
            .await
            .unwrap();
        assert_eq!(
            storage.metrics.storage_writes.get(),
            2,
            "storage_writes metric was not incremented after write_at(SYNC)"
        );
        assert_eq!(
            storage.metrics.storage_syncs.get(),
            2,
            "storage_syncs metric was not incremented after write_at(SYNC)"
        );

        // Resize the blob
        blob.resize(11).await.unwrap();
        assert_eq!(
            storage.metrics.storage_resizes.get(),
            1,
            "storage_resizes metric was not incremented after resize"
        );

        // Drop the blob
        drop(blob);

        // Verify that the open_blobs metric is decremented
        let open_blobs_after_drop = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_drop, 0,
            "open_blobs metric was not decremented after dropping the blob"
        );
    }

    #[tokio::test]
    async fn test_metered_batch_and_atomic_mutation_metrics() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));
        let (first, _) = storage.open_atomic("partition", b"first").await.unwrap();
        let (second, _) = storage.open_atomic("partition", b"second").await.unwrap();
        let (updated, _) = storage.open_atomic("partition", b"updated").await.unwrap();
        first.append(b"first").await.unwrap();
        second.append(b"second").await.unwrap();
        updated.append(b"new").await.unwrap();

        storage
            .apply(vec![
                BatchOperation::Rewind {
                    blob: first.clone(),
                    len: 3,
                },
                BatchOperation::Rewind {
                    blob: first,
                    len: 3,
                },
                BatchOperation::Rewind {
                    blob: second,
                    len: 5,
                },
                BatchOperation::Publish(updated.clone()),
            ])
            .await
            .unwrap();

        assert_eq!(storage.metrics.storage_writes.get(), 3);
        assert_eq!(storage.metrics.storage_write_bytes.get(), 14);
        assert_eq!(storage.metrics.storage_resizes.get(), 2);

        assert_eq!(updated.read_at(0, 3).await.unwrap().coalesce(), b"new");
    }

    /// Test that `start_sync` increments the sync metric, matching `sync`.
    #[tokio::test]
    async fn test_metered_start_sync_increments_metric() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        blob.start_sync().await.await.unwrap();
        assert_eq!(
            storage.metrics.storage_syncs.get(),
            1,
            "storage_syncs metric was not incremented after start_sync"
        );
    }

    /// Test that metrics are updated correctly when multiple blobs are opened and dropped.
    #[tokio::test]
    async fn test_metered_blob_multiple_blobs() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        // Open multiple blobs
        let (blob1, _) = storage.open("partition", b"blob1").await.unwrap();
        let (blob2, _) = storage.open("partition", b"blob2").await.unwrap();

        // Verify that the open_blobs metric is incremented correctly
        let open_blobs = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs, 2,
            "open_blobs metric was not updated correctly after opening multiple blobs"
        );

        // Sync and drop one blob
        blob1.sync().await.unwrap();
        drop(blob1);

        // Verify that the open_blobs metric is decremented correctly
        let open_blobs_after_close_one = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_close_one, 1,
            "open_blobs metric was not decremented correctly after dropping one blob"
        );

        // Sync and drop the second blob
        blob2.sync().await.unwrap();
        drop(blob2);

        // Verify that the open_blobs metric is decremented to zero
        let open_blobs_after_drop_all = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_drop_all, 0,
            "open_blobs metric was not decremented to zero after dropping all blobs"
        );
    }

    /// Test that cloned blobs share the same metrics and only decrement when the last clone is dropped.
    #[tokio::test]
    async fn test_cloned_blobs_share_metrics() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        // Open a blob
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Verify that the open_blobs metric is incremented
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Clone the blob multiple times
        let clone1 = blob.clone();
        let clone2 = blob.clone();

        // Verify that cloning doesn't change the open_blobs metric
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric should not change when blobs are cloned"
        );

        // Use the clones for some operations to verify they share metrics
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        clone1
            .write_at(5, b"world", WriteOptions::default())
            .await
            .unwrap();
        let _ = clone1.read_at(0, 10).await.unwrap();
        let _ = clone2.read_at(0, 10).await.unwrap();

        // Verify that operations on clones update the shared metrics
        assert_eq!(
            storage.metrics.storage_writes.get(),
            2,
            "Operations on cloned blobs should update shared metrics"
        );

        assert_eq!(
            storage.metrics.storage_reads.get(),
            2,
            "Operations on cloned blobs should update shared metrics"
        );

        // Drop individual clones and verify the metric doesn't change
        drop(clone1);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric should not change when individual clones are dropped"
        );

        drop(clone2);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric should not change when individual clones are dropped"
        );

        // Sync and drop the original blob - this should finally decrement the counter
        drop(blob);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            0,
            "open_blobs metric should be decremented only when the last blob reference is dropped"
        );
    }
}
