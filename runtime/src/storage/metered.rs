use crate::{
    BlobVersion, Buf, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    telemetry::{
        metrics::{Counter, Gauge, Register, raw},
        traces::TracedExt as _,
    },
};
use std::{ops::RangeInclusive, sync::Arc};
use tracing::Instrument as _;

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
                "Total number of storage reads",
                raw::Counter::default(),
            ),
            storage_read_bytes: registry.register(
                "storage_read_bytes",
                "Total amount of data read from storage",
                raw::Counter::default(),
            ),
            storage_writes: registry.register(
                "storage_writes",
                "Total number of storage writes",
                raw::Counter::default(),
            ),
            storage_write_bytes: registry.register(
                "storage_write_bytes",
                "Total amount of data written to storage",
                raw::Counter::default(),
            ),
            storage_syncs: registry.register(
                "storage_syncs",
                "Total number of storage sync requests",
                raw::Counter::default(),
            ),
            storage_resizes: registry.register(
                "storage_resizes",
                "Total number of storage resizes",
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
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        let (inner, len, blob_version) =
            self.inner.open_versioned(partition, name, versions).await?;
        self.metrics.open_blobs.inc();
        Ok((
            Blob {
                inner,
                partition: partition.into(),
                metrics: self.metrics.clone(),
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
pub struct Blob<B> {
    inner: B,
    partition: String,
    metrics: Arc<Metrics>,
}

impl<B> Drop for Blob<B> {
    fn drop(&mut self) {
        self.metrics.open_blobs.dec();
    }
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(len as u64);
        self.inner.read_at(offset, len, options).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(len as u64);
        self.inner.read_at_buf(offset, len, bufs, options).await
    }

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
        self.inner
            .write_at(offset, bufs, options)
            .instrument(tracing::debug_span!(
                "runtime.storage.blob.write_at",
                partition = %self.partition,
                bytes = bufs_len as u64,
                options = options.0.traced(),
            ))
            .await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.resize",
        level = "debug",
        skip_all,
        fields(partition = %self.partition, len = len)
    )]
    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.metrics.storage_resizes.inc();
        self.inner.resize(len).await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.sync",
        level = "debug",
        skip_all,
        fields(partition = %self.partition)
    )]
    async fn sync(&self) -> Result<(), Error> {
        self.metrics.storage_syncs.inc();
        self.inner.sync().await
    }

    #[tracing::instrument(
        name = "runtime.storage.blob.start_sync",
        level = "debug",
        skip_all,
        fields(partition = %self.partition)
    )]
    #[allow(clippy::async_yields_async)]
    async fn start_sync(&self) -> Handle<()> {
        self.metrics.storage_syncs.inc();
        let handle = self.inner.start_sync().await;
        Handle::from_future(handle.instrument(tracing::debug_span!(
            "runtime.storage.blob.sync",
            partition = %self.partition,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob, BufferPool, BufferPoolConfig, IoBufMut, Runner, Spawner, Storage as _,
        mocks::RecordingContext,
        storage::{memory::Storage as MemoryStorage, tests::run_storage_tests},
        telemetry::metrics::Registry,
    };
    use commonware_utils::sync::Mutex;
    use rstest::rstest;
    use tracing::{Level, Subscriber, instrument::WithSubscriber as _, span};
    use tracing_subscriber::{
        Layer, filter::LevelFilter, layer::Context, prelude::*, registry::LookupSpan,
    };

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_storage(), scope)
    }

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(
        all(target_os = "linux", feature = "iouring"),
        case::iouring(crate::iouring::Runner::default())
    )]
    fn test_metered_storage<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let mut registry = crate::telemetry::metrics::Registry::default();
            let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
            let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

            run_storage_tests(context, storage).await;
        });
    }

    /// Records the blob spans a subscriber opens and rejects writes to a parent span.
    #[derive(Clone, Default)]
    struct Spans(Arc<Mutex<Vec<(&'static str, Level)>>>);

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Spans {
        fn on_record(&self, id: &span::Id, _: &span::Record<'_>, ctx: Context<'_, S>) {
            assert_ne!(
                ctx.span(id).unwrap().name(),
                "parent",
                "blob operations must not overwrite parent fields"
            );
        }

        fn on_new_span(&self, attrs: &span::Attributes<'_>, _: &span::Id, _: Context<'_, S>) {
            let metadata = attrs.metadata();
            if metadata.name().starts_with("runtime.storage.blob.") {
                self.0.lock().push((metadata.name(), *metadata.level()));
            }
        }
    }

    /// Runs blob operations under `filter` and checks which blob spans were opened.
    async fn assert_blob_span_levels(filter: LevelFilter, expect_spans: bool) {
        let spans = Spans::default();
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(spans.clone());
        async {
            let parent = tracing::info_span!("parent", bytes = 17_u64);
            async {
                let mut registry = Registry::default();
                let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
                let storage = Storage::new(inner, &mut registry.sub_registry("storage"));
                let (blob, len) = storage.open("partition", b"blob").await.unwrap();
                assert_eq!(len, 0);
                assert_eq!(storage.metrics.open_blobs.get(), 1);

                blob.write_at(0, b"data", WriteOptions::SYNC).await.unwrap();
                blob.resize(3).await.unwrap();
                blob.sync().await.unwrap();
                blob.start_sync().await.await.unwrap();
                assert_eq!(
                    blob.read_at(0, 3, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce(),
                    b"dat"
                );
                assert_eq!(storage.metrics.storage_writes.get(), 1);
                assert_eq!(storage.metrics.storage_write_bytes.get(), 4);
                assert_eq!(storage.metrics.storage_resizes.get(), 1);
                assert_eq!(storage.metrics.storage_syncs.get(), 3);
                assert_eq!(storage.metrics.storage_reads.get(), 1);
                assert_eq!(storage.metrics.storage_read_bytes.get(), 3);
                drop(blob);
                assert_eq!(storage.metrics.open_blobs.get(), 0);
            }
            .instrument(parent)
            .await;
        }
        .with_subscriber(subscriber)
        .await;

        let expected = if expect_spans {
            vec![
                ("runtime.storage.blob.write_at", Level::DEBUG),
                ("runtime.storage.blob.resize", Level::DEBUG),
                ("runtime.storage.blob.sync", Level::DEBUG),
                ("runtime.storage.blob.start_sync", Level::DEBUG),
                ("runtime.storage.blob.sync", Level::DEBUG),
            ]
        } else {
            vec![]
        };
        assert_eq!(*spans.0.lock(), expected);
    }

    #[tokio::test]
    async fn test_metered_blob_spans_hidden_at_info() {
        assert_blob_span_levels(LevelFilter::INFO, false).await;
    }

    #[tokio::test]
    async fn test_metered_blob_spans_emitted_at_debug() {
        assert_blob_span_levels(LevelFilter::DEBUG, true).await;
    }

    #[tokio::test]
    async fn test_metered_blob_forwards_read_options_and_counts_reads() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let (inner, recordings) = RecordingContext::new(inner);
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"data", WriteOptions::default())
            .await
            .unwrap();
        recordings.clear();

        // Both read entry points forward DONT_CACHE while contributing to the same metrics.
        let read = blob.read_at(0, 4, ReadOptions::DONT_CACHE).await.unwrap();
        assert_eq!(read.coalesce(), b"data");
        let read = blob
            .read_at_buf(0, 4, IoBufMut::with_capacity(4), ReadOptions::DONT_CACHE)
            .await
            .unwrap();
        assert_eq!(read.coalesce(), b"data");

        assert_eq!(
            recordings.snapshot().reads,
            vec![ReadOptions::DONT_CACHE, ReadOptions::DONT_CACHE]
        );
        assert_eq!(storage.metrics.storage_reads.get(), 2);
        assert_eq!(storage.metrics.storage_read_bytes.get(), 8);
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
            .open_versioned(
                "partition",
                b"test_blob",
                BlobVersion::new(7)..=BlobVersion::new(7),
            )
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
        let read = blob.read_at(0, 11, ReadOptions::default()).await.unwrap();
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

    /// Shared blob owners count as one open until the final owner drops.
    #[tokio::test]
    async fn test_shared_blob_owners_share_metrics() {
        let mut registry = Registry::default();
        let inner = MemoryStorage::new(test_pool(&mut registry.sub_registry("pool")));
        let storage = Storage::new(inner, &mut registry.sub_registry("storage"));

        // Open a blob
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        let blob = Arc::new(blob);

        // Verify that the open_blobs metric is incremented
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric was not incremented after opening a blob"
        );

        // Share one open blob across several owners.
        let owner1 = blob.clone();
        let owner2 = blob.clone();

        // Sharing the open does not change the open_blobs metric.
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric should not change when its owner is shared"
        );

        // Operations through every owner update the same metrics.
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        owner1
            .write_at(5, b"world", WriteOptions::default())
            .await
            .unwrap();
        let _ = owner1.read_at(0, 10, ReadOptions::default()).await.unwrap();
        let _ = owner2.read_at(0, 10, ReadOptions::default()).await.unwrap();

        // Verify that operations through shared owners update the metrics.
        assert_eq!(
            storage.metrics.storage_writes.get(),
            2,
            "Operations on shared blob owners should update shared metrics"
        );

        assert_eq!(
            storage.metrics.storage_reads.get(),
            2,
            "Operations on shared blob owners should update shared metrics"
        );

        // Dropping an owner leaves the open count unchanged while others remain.
        drop(owner1);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric should not change when other owners are dropped"
        );

        drop(owner2);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            1,
            "open_blobs metric should not change when other owners are dropped"
        );

        // Sync and drop the original blob - this should finally decrement the counter
        drop(blob);
        assert_eq!(
            storage.metrics.open_blobs.get(),
            0,
            "open_blobs metric should be decremented only when the last blob owner is dropped"
        );
    }
}
