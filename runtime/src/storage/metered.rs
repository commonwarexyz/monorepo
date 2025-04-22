use crate::Error;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;
use std::sync::Arc;

pub struct Metrics {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
}

impl Metrics {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    pub(crate) fn new(registry: &mut Registry) -> Self {
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

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.metrics.open_blobs.inc();
        let inner = self.inner.open(partition, name).await?;
        Ok(Blob {
            inner,
            metrics: self.metrics.clone(),
        })
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
    metrics: Arc<Metrics>,
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn len(&self) -> Result<u64, Error> {
        self.inner.len().await
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.inner.read_at(buf, offset).await?;
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        self.inner.write_at(buf, offset).await?;
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.inner.truncate(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    // TODO danlaine: This is error-prone because the metrics will be
    // incorrect if the blob is dropped before it's closed. We should
    // consider using a `Drop` implementation to decrement the metric.
    // https://github.com/commonwarexyz/monorepo/issues/754
    async fn close(self) -> Result<(), Error> {
        self.metrics.open_blobs.dec();
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::Storage as MemoryStorage;
    use crate::storage::tests::run_storage_tests;
    use crate::{Blob, Storage as _};
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
        let blob = storage.open("partition", b"test_blob").await.unwrap();

        // Verify that the open_blobs metric is incremented
        let open_blobs = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs, 1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Write data to the blob
        blob.write_at(b"hello world", 0).await.unwrap();
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
        let mut buffer = vec![0; 11];
        blob.read_at(&mut buffer, 0).await.unwrap();
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

        // Close the blob
        blob.close().await.unwrap();

        // Verify that the open_blobs metric is decremented
        let open_blobs_after_close = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_close, 0,
            "open_blobs metric was not decremented after closing the blob"
        );
    }

    /// Test that metrics are updated correctly when multiple blobs are opened and closed.
    #[tokio::test]
    async fn test_metered_blob_multiple_blobs() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry);

        // Open multiple blobs
        let blob1 = storage.open("partition", b"blob1").await.unwrap();
        let blob2 = storage.open("partition", b"blob2").await.unwrap();

        // Verify that the open_blobs metric is incremented correctly
        let open_blobs = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs, 2,
            "open_blobs metric was not updated correctly after opening multiple blobs"
        );

        // Close one blob
        blob1.close().await.unwrap();

        // Verify that the open_blobs metric is decremented correctly
        let open_blobs_after_close_one = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_close_one, 1,
            "open_blobs metric was not decremented correctly after closing one blob"
        );

        // Close the second blob
        blob2.close().await.unwrap();

        // Verify that the open_blobs metric is decremented to zero
        let open_blobs_after_close_all = storage.metrics.open_blobs.get();
        assert_eq!(
            open_blobs_after_close_all, 0,
            "open_blobs metric was not decremented to zero after closing all blobs"
        );
    }
}
