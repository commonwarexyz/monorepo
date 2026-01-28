use crate::{
    telemetry::metrics::histogram::{self, Buckets},
    Buf, Clock, Error, IoBufs, IoBufsMut,
};
use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use std::{
    ops::{Deref, RangeInclusive},
    sync::Arc,
};

pub struct Metrics<C: Clock> {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,

    pub read_at_duration: histogram::Timed<C>,
    pub write_at_duration: histogram::Timed<C>,
    pub resize_duration: histogram::Timed<C>,
    pub sync_duration: histogram::Timed<C>,
}

impl<C: Clock> Metrics<C> {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    fn new(registry: &mut Registry, clock: C) -> Self {
        let open_blobs = Gauge::default();
        let storage_reads = Counter::default();
        let storage_read_bytes = Counter::default();
        let storage_writes = Counter::default();
        let storage_write_bytes = Counter::default();

        let read_at_duration = Histogram::new(Buckets::LOCAL);
        let write_at_duration = Histogram::new(Buckets::LOCAL);
        let resize_duration = Histogram::new(Buckets::LOCAL);
        let sync_duration = Histogram::new(Buckets::LOCAL);

        registry.register("open_blobs", "Number of open blobs", open_blobs.clone());
        registry.register(
            "storage_reads",
            "Total number of disk reads",
            storage_reads.clone(),
        );
        registry.register(
            "storage_read_bytes",
            "Total amount of data read from disk",
            storage_read_bytes.clone(),
        );
        registry.register(
            "storage_writes",
            "Total number of disk writes",
            storage_writes.clone(),
        );
        registry.register(
            "storage_write_bytes",
            "Total amount of data written to disk",
            storage_write_bytes.clone(),
        );
        registry.register(
            "read_at_duration",
            "Histogram for the duration to execute a Blob::read_at operation",
            read_at_duration.clone(),
        );
        registry.register(
            "write_at_duration",
            "Histogram for the duration to execute a Blob::write_at operation",
            write_at_duration.clone(),
        );
        registry.register(
            "resize_duration",
            "Histogram for the duration to execute a Blob::resize operation",
            resize_duration.clone(),
        );
        registry.register(
            "sync_duration",
            "Histogram for the duration to execute a Blob::sync operation",
            sync_duration.clone(),
        );

        let clock = Arc::new(clock);
        let read_at_duration = histogram::Timed::new(read_at_duration, clock.clone());
        let write_at_duration = histogram::Timed::new(write_at_duration, clock.clone());
        let resize_duration = histogram::Timed::new(resize_duration, clock.clone());
        let sync_duration = histogram::Timed::new(sync_duration, clock.clone());
        Self {
            open_blobs,
            storage_reads,
            storage_read_bytes,
            storage_writes,
            storage_write_bytes,
            read_at_duration,
            write_at_duration,
            resize_duration,
            sync_duration,
        }
    }
}

/// A wrapper around a `Storage` implementation that tracks metrics.
#[derive(Clone)]
pub struct Storage<S, C: Clock> {
    inner: S,
    metrics: Arc<Metrics<C>>,
}

impl<S, C: Clock> Storage<S, C> {
    pub fn new(inner: S, registry: &mut Registry, clock: C) -> Self {
        Self {
            inner,
            metrics: Metrics::new(registry, clock).into(),
        }
    }

    /// Get a reference to the inner storage.
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: crate::Storage, C: Clock> crate::Storage for Storage<S, C> {
    type Blob = Blob<S::Blob, C>;

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
pub struct Blob<B, C: Clock> {
    inner: B,
    metrics: Arc<MetricsHandle<C>>,
}

/// A wrapper around a `Metrics` implementation that updates
/// metrics when a blob (that may have been cloned multiple times)
/// is dropped.
struct MetricsHandle<C: Clock>(Arc<Metrics<C>>);

impl<C: Clock> Deref for MetricsHandle<C> {
    type Target = Metrics<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: Clock> Drop for MetricsHandle<C> {
    fn drop(&mut self) {
        // Only decrement when the last reference to the blob is dropped
        self.0.open_blobs.dec();
    }
}

impl<B: crate::Blob, C: Clock> crate::Blob for Blob<B, C> {
    async fn read_at(
        &self,
        offset: u64,
        buf: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let _timer = self.metrics.read_at_duration.timer();
        let buf = buf.into();
        let read = self.inner.read_at(offset, buf).await?;
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(read.len() as u64);
        Ok(read)
    }

    async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let _timer = self.metrics.write_at_duration.timer();
        let buf = buf.into();
        let buf_len = buf.remaining();
        self.inner.write_at(offset, buf).await?;
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf_len as u64);
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let _timer = self.metrics.resize_duration.timer();
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        let _timer = self.metrics.sync_duration.timer();
        self.inner.sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{memory::Storage as MemoryStorage, tests::run_storage_tests},
        tokio::RuntimeClock,
        Blob, IoBufMut, Storage as _,
    };
    use prometheus_client::registry::Registry;

    #[tokio::test]
    async fn test_metered_storage() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry, RuntimeClock);

        run_storage_tests(storage).await;
    }

    /// Test that metrics are updated correctly for basic operations.
    #[tokio::test]
    async fn test_metered_blob_metrics() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::default();
        let storage = Storage::new(inner, &mut registry, RuntimeClock);

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
        let read = blob.read_at(0, IoBufMut::zeroed(11)).await.unwrap();
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
        let storage = Storage::new(inner, &mut registry, RuntimeClock);

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
        let storage = Storage::new(inner, &mut registry, RuntimeClock);

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
        let _ = clone1.read_at(0, IoBufMut::zeroed(10)).await.unwrap();
        let _ = clone2.read_at(0, IoBufMut::zeroed(10)).await.unwrap();

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
