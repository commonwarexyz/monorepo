use crate::Error;
use commonware_utils::StableBuf;
use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use std::{ops::Deref, sync::Arc};

pub struct Metrics {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
}

impl Metrics {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bytes: Counter::default(),
            storage_writes: Counter::default(),
            storage_write_bytes: Counter::default(),
        };

        registry.register(
            "open_blobs",
            "Number of open blobs",
            metrics.open_blobs.clone(),
        );
        registry.register(
            "storage_reads",
            "Total number of disk reads",
            metrics.storage_reads.clone(),
        );
        registry.register(
            "storage_read_bytes",
            "Total amount of data read from disk",
            metrics.storage_read_bytes.clone(),
        );
        registry.register(
            "storage_writes",
            "Total number of disk writes",
            metrics.storage_writes.clone(),
        );
        registry.register(
            "storage_write_bytes",
            "Total amount of data written to disk",
            metrics.storage_write_bytes.clone(),
        );

        metrics
    }
}

/// A wrapper around a `Storage` implementation that tracks metrics.
#[derive(Clone)]
pub struct Storage<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S> Storage<S> {
    pub fn new(inner: S, registry: &mut Registry) -> Self {
        Self {
            inner,
            metrics: Metrics::new(registry).into(),
        }
    }
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S::Blob>;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), Error> {
        self.metrics.open_blobs.inc();
        let (inner, len) = self.inner.open(partition, name).await?;
        Ok((
            Blob {
                inner,
                metrics: Arc::new(MetricsHandle(self.metrics.clone())),
            },
            len,
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
    metrics: Arc<MetricsHandle>,
}

/// A wrapper around a `Metrics` implementation that updates
/// metrics when a blob (that may have been cloned multiple times)
/// is dropped.
struct MetricsHandle(Arc<Metrics>);

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
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        let read = self.inner.read_at(buf, offset).await?;
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(read.len() as u64);
        Ok(read)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        let buf = buf.into();
        let buf_len = buf.len();
        self.inner.write_at(buf, offset).await?;
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf_len as u64);
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{memory::Storage as MemoryStorage, tests::run_storage_tests},
        Blob, Storage as _,
    };
    use prometheus_client::registry::Registry;

    #[tokio::test]
    async fn test_metered_storage() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry);

        run_storage_tests(storage).await;
    }

    /// Test that metrics are updated correctly for basic operations.
    #[tokio::test]
    async fn test_metered_blob_metrics() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry);

        // Open a blob
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Verify that the open_blobs metric is incremented
        let open_blobs = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs, 1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Write data to the blob
        blob.write_at(b"hello world".to_vec(), 0).await.unwrap();
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
        let read = blob.read_at(vec![0; 11], 0).await.unwrap();
        assert_eq!(read.as_ref(), b"hello world");
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

        // Sync and drop the blob
        blob.sync().await.unwrap();
        drop(blob);

        // Verify that the open_blobs metric is decremented
        let open_blobs_after_drop = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_drop, 0,
            "open_blobs metric was not decremented after dropping the blob"
        );
    }

    /// Test that metrics are updated correctly when multiple blobs are opened and dropped.
    #[tokio::test]
    async fn test_metered_blob_multiple_blobs() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry);

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
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry);

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
        blob.write_at(b"hello".to_vec(), 0).await.unwrap();
        clone1.write_at(b"world".to_vec(), 5).await.unwrap();
        let _ = clone1.read_at(vec![0; 10], 0).await.unwrap();
        let _ = clone2.read_at(vec![0; 10], 0).await.unwrap();

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
