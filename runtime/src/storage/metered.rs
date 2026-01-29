use crate::{
    telemetry::metrics::histogram::{Buckets, Timed},
    Buf, Error, IoBufs, IoBufsMut, RawClock,
};
use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use std::{
    ops::{Deref, RangeInclusive},
    sync::Arc,
};

pub struct Metrics<C: RawClock> {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_read_latency: Timed<C>,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
    pub storage_write_latency: Timed<C>,
    pub storage_resize_latency: Timed<C>,
    pub storage_sync_latency: Timed<C>,
}

impl<C: RawClock> Metrics<C> {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    fn new(clock: Arc<C>, registry: &mut Registry) -> Self {
        let storage_read_latency = Histogram::new(Buckets::LOCAL);
        let storage_write_latency = Histogram::new(Buckets::LOCAL);
        let storage_resize_latency = Histogram::new(Buckets::LOCAL);
        let storage_sync_latency = Histogram::new(Buckets::LOCAL);

        let metrics = Self {
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bytes: Counter::default(),
            storage_read_latency: Timed::new(storage_read_latency.clone(), clock.clone()),
            storage_writes: Counter::default(),
            storage_write_bytes: Counter::default(),
            storage_write_latency: Timed::new(storage_write_latency.clone(), clock.clone()),
            storage_resize_latency: Timed::new(storage_resize_latency.clone(), clock.clone()),
            storage_sync_latency: Timed::new(storage_sync_latency.clone(), clock),
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
            "storage_read_latency",
            "Latency of disk reads in seconds",
            storage_read_latency,
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
        registry.register(
            "storage_write_latency",
            "Latency of disk writes in seconds",
            storage_write_latency,
        );
        registry.register(
            "storage_resize_latency",
            "Latency of blob resize operations in seconds",
            storage_resize_latency,
        );
        registry.register(
            "storage_sync_latency",
            "Latency of blob sync operations in seconds",
            storage_sync_latency,
        );

        metrics
    }
}

/// A wrapper around a `Storage` implementation that tracks metrics.
#[derive(Clone)]
pub struct Storage<C: RawClock, S> {
    inner: S,
    metrics: Arc<Metrics<C>>,
}

impl<C: RawClock, S> Storage<C, S> {
    pub fn new(clock: C, inner: S, registry: &mut Registry) -> Self {
        Self {
            inner,
            metrics: Metrics::new(Arc::new(clock), registry).into(),
        }
    }

    /// Get a reference to the inner storage.
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<C: RawClock, S: crate::Storage> crate::Storage for Storage<C, S> {
    type Blob = Blob<C, S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        self.metrics.open_blobs.inc();
        let (inner, len, blob_version) =
            self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            Blob {
                inner,
                metrics: Arc::new(MetricsHandle(self.metrics.clone())),
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
pub struct Blob<C: RawClock, B> {
    inner: B,
    metrics: Arc<MetricsHandle<C>>,
}

/// A wrapper around a `Metrics` implementation that updates
/// metrics when a blob (that may have been cloned multiple times)
/// is dropped.
struct MetricsHandle<C: RawClock>(Arc<Metrics<C>>);

impl<C: RawClock> Deref for MetricsHandle<C> {
    type Target = Metrics<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: RawClock> Drop for MetricsHandle<C> {
    fn drop(&mut self) {
        // Only decrement when the last reference to the blob is dropped
        self.0.open_blobs.dec();
    }
}

impl<C: RawClock, B: crate::Blob> crate::Blob for Blob<C, B> {
    async fn read_at(
        &self,
        offset: u64,
        buf: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let buf = buf.into();
        let _timer = self.metrics.storage_read_latency.timer();
        let read = self.inner.read_at(offset, buf).await?;
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(read.len() as u64);
        Ok(read)
    }

    async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let buf = buf.into();
        let buf_len = buf.remaining();
        let _timer = self.metrics.storage_write_latency.timer();
        self.inner.write_at(offset, buf).await?;
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf_len as u64);
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let _timer = self.metrics.storage_resize_latency.timer();
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        let _timer = self.metrics.storage_sync_latency.timer();
        self.inner.sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deterministic,
        storage::{memory::Storage as MemoryStorage, tests::run_storage_tests},
        tokio as tokio_runtime, Blob, Clock, IoBufMut, Runner, Storage as _,
    };
    use prometheus_client::registry::Registry;

    #[test]
    fn test_metered_storage_deterministic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut registry = Registry::default();
            let inner = MemoryStorage::default();
            let storage = Storage::new(context, inner, &mut registry);

            test_metered_blob_metrics(&storage).await;
            test_metered_blob_multiple_blobs(&storage).await;
            test_cloned_blobs_share_metrics(&storage).await;
        });
    }

    #[test]
    fn test_metered_storage_tokio() {
        let cfg = tokio_runtime::Config::default()
            .with_storage_directory(std::env::temp_dir().join("metered_storage_tokio_test"));
        let runner = tokio_runtime::Runner::new(cfg);
        runner.start(|context| async move {
            let mut registry = Registry::default();
            let inner = MemoryStorage::default();
            let storage = Storage::new(context, inner, &mut registry);

            run_storage_tests(storage.clone()).await;
            test_metered_blob_metrics(&storage).await;
        });
    }

    async fn test_metered_blob_metrics<C: Clock, S: crate::Storage>(storage: &Storage<C, S>)
    where
        S::Blob: Send + Sync,
    {
        let initial_open_blobs = storage.metrics.open_blobs.get();
        let initial_writes = storage.metrics.storage_writes.get();
        let initial_write_bytes = storage.metrics.storage_write_bytes.get();
        let initial_reads = storage.metrics.storage_reads.get();
        let initial_read_bytes = storage.metrics.storage_read_bytes.get();

        // Open a blob
        let (blob, _) = storage.open("metered_test", b"test_blob").await.unwrap();

        // Verify that the open_blobs metric is incremented
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Write data to the blob
        blob.write_at(0, b"hello world").await.unwrap();
        assert_eq!(
            storage.metrics.storage_writes.get() - initial_writes,
            1,
            "storage_writes metric was not incremented after write"
        );
        assert_eq!(
            storage.metrics.storage_write_bytes.get() - initial_write_bytes,
            11,
            "storage_write_bytes metric was not updated correctly after write"
        );

        // Read data from the blob
        let read = blob.read_at(0, IoBufMut::zeroed(11)).await.unwrap();
        assert_eq!(read.coalesce(), b"hello world");
        assert_eq!(
            storage.metrics.storage_reads.get() - initial_reads,
            1,
            "storage_reads metric was not incremented after read"
        );
        assert_eq!(
            storage.metrics.storage_read_bytes.get() - initial_read_bytes,
            11,
            "storage_read_bytes metric was not updated correctly after read"
        );

        // Sync and drop the blob
        blob.sync().await.unwrap();
        drop(blob);

        // Verify that the open_blobs metric is decremented
        assert_eq!(
            storage.metrics.open_blobs.get(),
            initial_open_blobs,
            "open_blobs metric was not decremented after dropping the blob"
        );
    }

    async fn test_metered_blob_multiple_blobs<C: Clock, S: crate::Storage>(storage: &Storage<C, S>)
    where
        S::Blob: Send + Sync,
    {
        let initial_open_blobs = storage.metrics.open_blobs.get();

        // Open multiple blobs
        let (blob1, _) = storage.open("metered_test", b"blob1").await.unwrap();
        let (blob2, _) = storage.open("metered_test", b"blob2").await.unwrap();

        // Verify that the open_blobs metric is incremented correctly
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            2,
            "open_blobs metric was not updated correctly after opening multiple blobs"
        );

        // Sync and drop one blob
        blob1.sync().await.unwrap();
        drop(blob1);

        // Verify that the open_blobs metric is decremented correctly
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            1,
            "open_blobs metric was not decremented correctly after dropping one blob"
        );

        // Sync and drop the second blob
        blob2.sync().await.unwrap();
        drop(blob2);

        // Verify that the open_blobs metric is decremented to initial value
        assert_eq!(
            storage.metrics.open_blobs.get(),
            initial_open_blobs,
            "open_blobs metric was not decremented correctly after dropping all blobs"
        );
    }

    async fn test_cloned_blobs_share_metrics<C: Clock, S: crate::Storage>(storage: &Storage<C, S>)
    where
        S::Blob: Send + Sync,
    {
        let initial_open_blobs = storage.metrics.open_blobs.get();
        let initial_writes = storage.metrics.storage_writes.get();
        let initial_reads = storage.metrics.storage_reads.get();

        // Open a blob
        let (blob, _) = storage.open("metered_test", b"clone_blob").await.unwrap();

        // Verify that the open_blobs metric is incremented
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Clone the blob multiple times
        let clone1 = blob.clone();
        let clone2 = blob.clone();

        // Verify that cloning doesn't change the open_blobs metric
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            1,
            "open_blobs metric should not change when blobs are cloned"
        );

        // Use the clones for some operations to verify they share metrics
        blob.write_at(0, b"hello").await.unwrap();
        clone1.write_at(5, b"world").await.unwrap();
        let _ = clone1.read_at(0, IoBufMut::zeroed(10)).await.unwrap();
        let _ = clone2.read_at(0, IoBufMut::zeroed(10)).await.unwrap();

        // Verify that operations on clones update the shared metrics
        assert_eq!(
            storage.metrics.storage_writes.get() - initial_writes,
            2,
            "Operations on cloned blobs should update shared metrics"
        );

        assert_eq!(
            storage.metrics.storage_reads.get() - initial_reads,
            2,
            "Operations on cloned blobs should update shared metrics"
        );

        // Drop individual clones and verify the metric doesn't change
        drop(clone1);
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            1,
            "open_blobs metric should not change when individual clones are dropped"
        );

        drop(clone2);
        assert_eq!(
            storage.metrics.open_blobs.get() - initial_open_blobs,
            1,
            "open_blobs metric should not change when individual clones are dropped"
        );

        // Drop the original blob - this should finally decrement the counter
        drop(blob);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            initial_open_blobs,
            "open_blobs metric should be decremented only when the last blob reference is dropped"
        );
    }
}
