use crate::{
    telemetry::metrics::{raw, Counter, Gauge, Register},
    Buf, Error, Handle, IoBufs, IoBufsMut,
};
use std::{
    ops::{Deref, RangeInclusive},
    sync::Arc,
};
use tracing::{field::Empty, Instrument as _, Span};

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

/// A wrapper around a `Blob` implementation that tracks metrics
#[derive(Clone)]
pub struct Blob<B> {
    inner: B,
    partition: Arc<str>,
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
        fields(partition = %self.partition, bytes = Empty)
    )]
    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        let bufs_len = bufs.remaining();
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(bufs_len as u64);
        Span::current().record("bytes", bufs_len as u64);
        self.inner.write_at(offset, bufs).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.write_at_sync",
        level = "info",
        skip_all,
        fields(partition = %self.partition, bytes = Empty)
    )]
    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let bufs_len = bufs.remaining();
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(bufs_len as u64);
        self.metrics.storage_syncs.inc();
        Span::current().record("bytes", bufs_len as u64);
        self.inner.write_at_sync(offset, bufs).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{memory::Storage as MemoryStorage, tests::run_storage_tests},
        telemetry::metrics::Registry,
        Blob, BufferPool, BufferPoolConfig, Storage as _,
    };

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_storage(), scope)
    }

    #[tokio::test]
    async fn test_metered_storage() {
        let mut registry = crate::telemetry::metrics::Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        run_storage_tests(storage).await;
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
        blob.write_at(0, b"hello world").await.unwrap();
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
        blob.write_at_sync(11, b" again").await.unwrap();
        assert_eq!(
            storage.metrics.storage_writes.get(),
            2,
            "storage_writes metric was not incremented after write_at_sync"
        );
        assert_eq!(
            storage.metrics.storage_syncs.get(),
            2,
            "storage_syncs metric was not incremented after write_at_sync"
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

    /// Test that `start_sync` increments the sync metric, matching `sync`.
    #[tokio::test]
    async fn test_metered_start_sync_increments_metric() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world").await.unwrap();

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
        blob.write_at(0, b"hello").await.unwrap();
        clone1.write_at(5, b"world").await.unwrap();
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
