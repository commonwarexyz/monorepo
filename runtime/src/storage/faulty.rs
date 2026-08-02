//! A storage wrapper that injects deterministic faults for testing crash recovery.

use crate::{
    AtomicBlob, AtomicStorage, BatchOperation, BatchStorage, Error, Handle, IoBufs, IoBufsMut,
    WriteOptions, deterministic::BoxDynRng,
};
use bytes::Buf;
use commonware_utils::sync::{Mutex, RwLock};
use rand::RngExt as _;
use std::{
    io::Error as IoError,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Operation types for fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Open,
    Read,
    Write,
    Sync,
    Resize,
    Remove,
    Batch,
    BatchPostCommit,
    Scan,
}

/// Configuration for deterministic storage fault injection.
///
/// Each rate is a probability from 0.0 (never fail) to 1.0 (always fail).
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Failure rate for `open_versioned` operations.
    pub open_rate: Option<f64>,

    /// Failure rate for `read_at` operations.
    pub read_rate: Option<f64>,

    /// Failure rate for `write_at` operations.
    pub write_rate: Option<f64>,

    /// Probability that a write failure is a partial write (some bytes written
    /// before failure) rather than a complete failure (no bytes written).
    /// Only applies when `write_rate` triggers a failure.
    /// Value from 0.0 (always complete failure) to 1.0 (always partial write).
    pub partial_write_rate: Option<f64>,

    /// Failure rate for `sync` operations.
    pub sync_rate: Option<f64>,

    /// Failure rate for `resize` operations.
    pub resize_rate: Option<f64>,

    /// Probability that a resize failure is partial (resized to an intermediate
    /// size before failure) rather than a complete failure (size unchanged).
    /// Only applies when `resize_rate` triggers a failure.
    /// Value from 0.0 (always complete failure) to 1.0 (always partial resize).
    pub partial_resize_rate: Option<f64>,

    /// Failure rate for `remove` operations.
    pub remove_rate: Option<f64>,

    /// Pre-commit failure rate for non-empty batch operations.
    pub batch_rate: Option<f64>,

    /// Failure rate reported after a non-empty batch commits successfully.
    pub batch_post_commit_rate: Option<f64>,

    /// Failure rate for `scan` operations.
    pub scan_rate: Option<f64>,
}

impl Config {
    /// Get the failure rate for an operation type.
    fn rate_for(&self, op: Op) -> f64 {
        match op {
            Op::Open => self.open_rate,
            Op::Read => self.read_rate,
            Op::Write => self.write_rate,
            Op::Sync => self.sync_rate,
            Op::Resize => self.resize_rate,
            Op::Remove => self.remove_rate,
            Op::Batch => self.batch_rate,
            Op::BatchPostCommit => self.batch_post_commit_rate,
            Op::Scan => self.scan_rate,
        }
        .unwrap_or(0.0)
    }

    /// Set the open failure rate.
    pub const fn open(mut self, rate: f64) -> Self {
        self.open_rate = Some(rate);
        self
    }

    /// Set the read failure rate.
    pub const fn read(mut self, rate: f64) -> Self {
        self.read_rate = Some(rate);
        self
    }

    /// Set the write failure rate.
    pub const fn write(mut self, rate: f64) -> Self {
        self.write_rate = Some(rate);
        self
    }

    /// Set the partial write rate (probability of partial vs complete write failure).
    pub const fn partial_write(mut self, rate: f64) -> Self {
        self.partial_write_rate = Some(rate);
        self
    }

    /// Set the sync failure rate.
    pub const fn sync(mut self, rate: f64) -> Self {
        self.sync_rate = Some(rate);
        self
    }

    /// Set the resize failure rate.
    pub const fn resize(mut self, rate: f64) -> Self {
        self.resize_rate = Some(rate);
        self
    }

    /// Set the partial resize rate (probability of partial vs complete resize failure).
    pub const fn partial_resize(mut self, rate: f64) -> Self {
        self.partial_resize_rate = Some(rate);
        self
    }

    /// Set the remove failure rate.
    pub const fn remove(mut self, rate: f64) -> Self {
        self.remove_rate = Some(rate);
        self
    }

    /// Set the pre-commit batch failure rate.
    pub const fn batch(mut self, rate: f64) -> Self {
        self.batch_rate = Some(rate);
        self
    }

    /// Set the failure rate reported after a batch commits.
    pub const fn batch_post_commit(mut self, rate: f64) -> Self {
        self.batch_post_commit_rate = Some(rate);
        self
    }

    /// Set the scan failure rate.
    pub const fn scan(mut self, rate: f64) -> Self {
        self.scan_rate = Some(rate);
        self
    }
}

/// Shared fault injection context.
#[derive(Clone)]
struct Oracle {
    rng: Arc<Mutex<BoxDynRng>>,
    config: Arc<RwLock<Config>>,
}

impl Oracle {
    /// Check if a fault should be injected for the given operation.
    fn should_fail(&self, op: Op) -> bool {
        self.roll(Some(self.config.read().rate_for(op)))
    }

    /// Check if a write fault should be injected. Returns (should_fail, partial_rate).
    /// Reads config once to avoid nested lock acquisition.
    fn check_write_fault(&self) -> (bool, Option<f64>) {
        let config = self.config.read();
        let fail = self.roll(Some(config.rate_for(Op::Write)));
        (fail, config.partial_write_rate)
    }

    /// Check if a resize fault should be injected. Returns (should_fail, partial_rate).
    /// Reads config once to avoid nested lock acquisition.
    fn check_resize_fault(&self) -> (bool, Option<f64>) {
        let config = self.config.read();
        let fail = self.roll(Some(config.rate_for(Op::Resize)));
        (fail, config.partial_resize_rate)
    }

    /// Check if an event should occur based on a probability rate.
    fn roll(&self, rate: Option<f64>) -> bool {
        let rate = rate.unwrap_or(0.0);
        if rate <= 0.0 {
            return false;
        }
        if rate >= 1.0 {
            return true;
        }
        self.rng.lock().random::<f64>() < rate
    }

    /// Generate a random value strictly between `from` and `to`, or None if not possible.
    fn random_between(&self, from: u64, to: u64) -> Option<u64> {
        if from == to {
            return None;
        }
        let (min, max) = if from < to { (from, to) } else { (to, from) };
        if max - min <= 1 {
            return None;
        }
        Some(self.rng.lock().random_range(min + 1..max))
    }

    /// Try to generate a partial operation target. Returns Some if both the rate
    /// check passes and an intermediate value exists between `from` and `to`.
    fn try_partial(&self, rate: Option<f64>, from: u64, to: u64) -> Option<u64> {
        if self.roll(rate) {
            self.random_between(from, to)
        } else {
            None
        }
    }
}

/// A storage wrapper that injects deterministic faults based on configuration.
///
/// Uses a shared RNG for determinism.
#[derive(Clone)]
pub struct Storage<S: crate::Storage> {
    inner: S,
    ctx: Oracle,
}

impl<S: crate::Storage> Storage<S> {
    /// Create a new faulty storage wrapper.
    pub fn new(inner: S, rng: Arc<Mutex<BoxDynRng>>, config: Arc<RwLock<Config>>) -> Self {
        Self {
            inner,
            ctx: Oracle { rng, config },
        }
    }

    /// Get a reference to the inner storage.
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Get access to the fault configuration for dynamic modification.
    pub fn config(&self) -> Arc<RwLock<Config>> {
        self.ctx.config.clone()
    }
}

/// Create an IoError for injected faults.
fn injected_io_error() -> IoError {
    IoError::other("injected storage fault")
}

impl<S: crate::Storage> crate::Storage for Storage<S> {
    type Blob = Blob<S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        if self.ctx.should_fail(Op::Open) {
            return Err(injected_io_error().into());
        }
        self.inner
            .open_versioned(partition, name, versions)
            .await
            .map(|(blob, len, blob_version)| {
                (
                    Blob::new(self.ctx.clone(), blob, partition.into(), name.to_vec(), len),
                    len,
                    blob_version,
                )
            })
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        if self.ctx.should_fail(Op::Remove) {
            return Err(injected_io_error().into());
        }
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        if self.ctx.should_fail(Op::Scan) {
            return Err(injected_io_error().into());
        }
        self.inner.scan(partition).await
    }
}

impl<S: AtomicStorage> AtomicStorage for Storage<S> {
    type AtomicBlob = Blob<S::AtomicBlob>;

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), Error> {
        if self.ctx.should_fail(Op::Open) {
            return Err(injected_io_error().into());
        }
        self.inner
            .open_atomic_versioned(partition, name, versions)
            .await
            .map(|(blob, len, blob_version)| {
                (
                    Blob::new(self.ctx.clone(), blob, partition.into(), name.to_vec(), len),
                    len,
                    blob_version,
                )
            })
    }
}

impl<S: BatchStorage> BatchStorage for Storage<S> {
    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> Result<Handle<()>, Error> {
        crate::storage::batch::canonicalize_descriptors(&operations, |blob| {
            (blob.partition.clone(), blob.name.clone())
        })?;
        if operations.is_empty() {
            return self.inner.start_apply(Vec::new()).await;
        }
        if self.ctx.should_fail(Op::Batch) {
            return Err(injected_io_error().into());
        }

        let mutated: Vec<_> = operations
            .iter()
            .filter_map(|operation| match operation {
                BatchOperation::Remove(_) | BatchOperation::Publish(_) => None,
                BatchOperation::Rewind { blob, len } => Some((blob.size.clone(), *len)),
            })
            .collect();
        let operations = crate::storage::batch::map_blobs(operations, |blob| blob.inner);
        let completion = self.inner.start_apply(operations).await?;
        for (size, len) in mutated {
            size.store(len, Ordering::Relaxed);
        }
        let fail_after_commit = self.ctx.should_fail(Op::BatchPostCommit);
        Ok(Handle::from_future(async move {
            completion.await?;
            if fail_after_commit {
                return Err(injected_io_error().into());
            }
            Ok(())
        }))
    }
}

/// A blob wrapper that injects deterministic faults based on configuration.
#[derive(Clone)]
pub struct Blob<B: crate::Blob> {
    inner: B,
    ctx: Oracle,
    partition: String,
    name: Vec<u8>,
    /// Tracked size for partial resize support.
    size: Arc<AtomicU64>,
}

impl<B: crate::Blob> Blob<B> {
    fn new(ctx: Oracle, inner: B, partition: String, name: Vec<u8>, size: u64) -> Self {
        Self {
            inner,
            ctx,
            partition,
            name,
            size: Arc::new(AtomicU64::new(size)),
        }
    }
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        if self.ctx.should_fail(Op::Read) {
            return Err(injected_io_error().into());
        }
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        if self.ctx.should_fail(Op::Read) {
            return Err(injected_io_error().into());
        }
        self.inner.read_at_buf(offset, len, bufs.into()).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let total_bytes = bufs.remaining() as u64;
        let sync = options.contains(WriteOptions::SYNC);
        if sync && total_bytes == 0 {
            return Ok(());
        }

        let (should_fail, partial_rate) = self.ctx.check_write_fault();
        if should_fail {
            if let Some(bytes) = self.ctx.try_partial(partial_rate, 0, total_bytes) {
                // Partial write: write some bytes, sync, then fail
                let bufs = bufs.coalesce().slice(..bytes as usize);
                self.inner.write_at(offset, bufs, options).await?;
                if !sync {
                    self.inner.sync().await?;
                }
                self.size
                    .fetch_max(offset.saturating_add(bytes), Ordering::Relaxed);
                return Err(injected_io_error().into());
            }
            return Err(injected_io_error().into());
        }

        if sync && self.ctx.should_fail(Op::Sync) {
            self.inner
                .write_at(offset, bufs, options.without(WriteOptions::SYNC))
                .await?;
            self.size
                .fetch_max(offset.saturating_add(total_bytes), Ordering::Relaxed);
            return Err(injected_io_error().into());
        }

        self.inner.write_at(offset, bufs, options).await?;
        self.size
            .fetch_max(offset.saturating_add(total_bytes), Ordering::Relaxed);
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let (should_fail, partial_rate) = self.ctx.check_resize_fault();
        if should_fail {
            let current = self.size.load(Ordering::Relaxed);
            if let Some(len) = self.ctx.try_partial(partial_rate, current, len) {
                // Partial resize: resize to intermediate size, sync, then fail
                self.inner.resize(len).await?;
                self.inner.sync().await?;
                self.size.store(len, Ordering::Relaxed);
                return Err(injected_io_error().into());
            }
            return Err(injected_io_error().into());
        }
        self.inner.resize(len).await?;
        self.size.store(len, Ordering::Relaxed);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.ctx.should_fail(Op::Sync) {
            return Err(injected_io_error().into());
        }
        self.inner.sync().await
    }

    async fn start_sync(&self) -> Handle<()> {
        if self.ctx.should_fail(Op::Sync) {
            return Handle::ready(Err(injected_io_error().into()));
        }
        self.inner.start_sync().await
    }
}

impl<B: AtomicBlob> AtomicBlob for Blob<B> {
    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        if self.ctx.should_fail(Op::Write) {
            return Err(injected_io_error().into());
        }
        let data = data.into();
        let data_len = u64::try_from(data.remaining()).map_err(|_| Error::OffsetOverflow)?;
        let offset = self.inner.append(data).await?;
        let len = offset.checked_add(data_len).ok_or(Error::OffsetOverflow)?;
        self.size.store(len, Ordering::Relaxed);
        Ok(offset)
    }

    async fn rewind(&self, len: u64) -> Result<(), Error> {
        if self.ctx.should_fail(Op::Resize) {
            return Err(injected_io_error().into());
        }
        self.inner.rewind(len).await?;
        self.size.store(len, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, BufferPool, BufferPoolConfig, IoBuf, Storage as _,
        storage::{
            memory::Storage as MemStorage,
            tests::{
                run_atomic_blob_tests, run_batch_storage_tests, run_storage_foreign_handle_test,
                run_storage_tests,
            },
        },
        telemetry::metrics::Registry,
    };
    use rand::{SeedableRng, rngs::StdRng};

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    /// Test harness with faulty storage wrapping memory storage.
    struct Harness {
        inner: MemStorage,
        storage: Storage<MemStorage>,
        config: Arc<RwLock<Config>>,
    }

    impl Harness {
        fn new(config: Config) -> Self {
            Self::with_seed(42, config)
        }

        fn with_seed(seed: u64, config: Config) -> Self {
            let inner = MemStorage::new(test_pool());
            let rng = Arc::new(Mutex::new(
                Box::new(StdRng::seed_from_u64(seed)) as BoxDynRng
            ));
            let config = Arc::new(RwLock::new(config));
            let storage = Storage::new(inner.clone(), rng, config.clone());
            Self {
                inner,
                storage,
                config,
            }
        }
    }

    #[tokio::test]
    async fn test_faulty_storage_no_faults() {
        let h = Harness::new(Config::default());
        let tested = h.storage.clone();
        run_storage_tests(h.storage.clone()).await;
        run_batch_storage_tests(h.storage.clone()).await;
        let (atomic, _) = h
            .storage
            .open_atomic("atomic_storage", b"blob")
            .await
            .unwrap();
        run_atomic_blob_tests(atomic).await;
        let foreign = Harness::new(Config::default());
        run_storage_foreign_handle_test(&tested, &foreign.storage).await;
    }

    #[tokio::test]
    async fn test_faulty_storage_sync_always_fails() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();

        assert!(matches!(blob.sync().await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_faulty_storage_start_sync_always_fails() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();

        let result = blob.start_sync().await.await;
        assert!(matches!(result, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_always_fails() {
        let h = Harness::new(Config::default().write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_with_sync_write_always_fails() {
        let h = Harness::new(Config::default().write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec(), WriteOptions::SYNC).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_with_sync_failure_is_not_durable() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec(), WriteOptions::SYNC).await,
            Err(Error::Io(_))
        ));

        let (_reopened, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_empty_write_with_sync_does_not_sync_prior_write() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();

        blob.write_at(4, Vec::<u8>::new(), WriteOptions::SYNC)
            .await
            .unwrap();

        let (_reopened, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_read_always_fails() {
        let h = Harness::new(Config::default());

        // Write some data first (no faults)
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Enable read faults
        h.config.write().read_rate = Some(1.0);

        assert!(matches!(blob.read_at(0, 4).await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_faulty_storage_open_always_fails() {
        let h = Harness::new(Config::default().open(1.0));

        assert!(matches!(
            h.storage.open("partition", b"test").await,
            Err(Error::Io(_))
        ));
        assert!(matches!(
            h.storage.open_atomic("partition", b"atomic").await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_remove_always_fails() {
        let h = Harness::new(Config::default());

        // Create a blob first
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // Enable remove faults
        h.config.write().remove_rate = Some(1.0);

        assert!(matches!(
            h.storage.remove("partition", Some(b"test")).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_batch_fault_phases_are_atomic() {
        let h = Harness::new(Config::default().batch(1.0));
        let mut targets = Vec::new();
        for partition in ["batch_a", "batch_b"] {
            let (blob, _) = h.storage.open_atomic(partition, b"name").await.unwrap();
            blob.append(partition.as_bytes()).await.unwrap();
            blob.sync().await.unwrap();
            targets.push(blob);
        }

        h.storage.apply(Vec::new()).await.unwrap();

        assert!(matches!(
            h.storage
                .apply(vec![
                    BatchOperation::Remove(targets[1].clone()),
                    BatchOperation::Remove(targets[0].clone()),
                    BatchOperation::Remove(targets[1].clone()),
                ])
                .await,
            Err(Error::Io(_))
        ));
        assert_eq!(
            h.inner.scan("batch_a").await.unwrap(),
            vec![b"name".to_vec()]
        );
        assert_eq!(
            h.inner.scan("batch_b").await.unwrap(),
            vec![b"name".to_vec()]
        );

        *h.config.write() = Config::default().batch_post_commit(1.0);
        assert!(matches!(
            h.storage
                .apply(targets.into_iter().map(BatchOperation::Remove).collect())
                .await,
            Err(Error::Io(_))
        ));
        assert!(h.inner.scan("batch_a").await.unwrap().is_empty());
        assert!(h.inner.scan("batch_b").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_faulty_storage_validates_mixed_batch_before_faulting() {
        let h = Harness::new(Config::default().batch(1.0));
        let (blob, _) = h.storage.open_atomic("partition", b"name").await.unwrap();

        let error = h
            .storage
            .apply(vec![
                BatchOperation::Remove(blob.clone()),
                BatchOperation::Rewind { blob, len: 0 },
            ])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Io(error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_batch_rewind_bypasses_resize_faults() {
        let h = Harness::new(Config::default());
        let (blob, _) = h.storage.open_atomic("partition", b"name").await.unwrap();
        blob.write_at(0, b"contents", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        *h.config.write() = Config::default().resize(1.0).partial_resize(1.0);

        h.storage
            .apply(vec![BatchOperation::Rewind { blob, len: 3 }])
            .await
            .unwrap();

        let (_, len) = h.inner.open("partition", b"name").await.unwrap();
        assert_eq!(len, 3);
    }

    #[tokio::test]
    async fn test_faulty_atomic_mutations_fault_before_apply() {
        for (config, append) in [
            (Config::default().write(1.0).partial_write(1.0), true),
            (Config::default().resize(1.0).partial_resize(1.0), false),
        ] {
            let h = Harness::new(Config::default());
            let (blob, _) = h.storage.open_atomic("partition", b"name").await.unwrap();
            blob.write_at(0, b"contents", WriteOptions::default())
                .await
                .unwrap();
            *h.config.write() = config;

            let result = if append {
                blob.append(b"new").await.map(|_| ())
            } else {
                blob.rewind(4).await
            };
            assert!(matches!(result, Err(Error::Io(_))));

            assert_eq!(blob.size.load(Ordering::Relaxed), 8);
            assert_eq!(blob.read_at(0, 8).await.unwrap().coalesce(), b"contents");
        }
    }

    #[tokio::test]
    async fn test_faulty_atomic_mutations_forward_data_and_track_size() {
        let h = Harness::new(Config::default());
        let (blob, _) = h.storage.open_atomic("partition", b"name").await.unwrap();
        blob.write_at(0, b"contents", WriteOptions::default())
            .await
            .unwrap();
        let data = IoBufs::from(vec![
            IoBuf::from(b"n".to_vec()),
            IoBuf::from(b"ew".to_vec()),
        ]);
        assert_eq!(blob.append(data).await.unwrap(), 8);

        assert_eq!(blob.size.load(Ordering::Relaxed), 11);
        assert_eq!(
            blob.read_at(0, 11).await.unwrap().coalesce(),
            b"contentsnew"
        );
        blob.rewind(4).await.unwrap();
        assert_eq!(blob.size.load(Ordering::Relaxed), 4);
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"cont");
    }

    #[tokio::test]
    async fn test_faulty_storage_scan_always_fails() {
        let h = Harness::new(Config::default());

        // Create some blobs first
        for i in 0..3 {
            let name = format!("blob{i}");
            let (blob, _) = h.storage.open("partition", name.as_bytes()).await.unwrap();
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
        }

        // Enable scan faults
        h.config.write().scan_rate = Some(1.0);

        assert!(matches!(
            h.storage.scan("partition").await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_determinism() {
        async fn run_ops(seed: u64, rate: f64) -> Vec<bool> {
            let h = Harness::with_seed(seed, Config::default().open(rate));
            let mut results = Vec::new();
            for i in 0..20 {
                let name = format!("blob{i}");
                results.push(h.storage.open("partition", name.as_bytes()).await.is_ok());
            }
            results
        }

        let results1 = run_ops(42, 0.5).await;
        let results2 = run_ops(42, 0.5).await;
        assert_eq!(results1, results2, "Same seed should produce same results");

        let results3 = run_ops(999, 0.5).await;
        assert_ne!(
            results1, results3,
            "Different seeds should produce different results"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_rate_for() {
        let config = Config::default().open(0.1).sync(0.9);

        assert!((config.rate_for(Op::Open) - 0.1).abs() < f64::EPSILON);
        assert!((config.rate_for(Op::Sync) - 0.9).abs() < f64::EPSILON);
        assert!(config.rate_for(Op::Write).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_faulty_storage_dynamic_config() {
        let h = Harness::new(Config::default());

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.sync().await.unwrap();

        h.config.write().sync_rate = Some(1.0);
        assert!(matches!(blob.sync().await, Err(Error::Io(_))));

        h.config.write().sync_rate = Some(0.0);
        blob.sync().await.unwrap();
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write() {
        let h = Harness::new(Config::default().write(1.0).partial_write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let data = b"hello world".to_vec();
        let result = blob
            .write_at(0, data.clone(), WriteOptions::default())
            .await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (inner_blob, size) = h.inner.open("partition", b"test").await.unwrap();
        let bytes_written = size as usize;
        assert!(
            bytes_written > 0 && bytes_written < data.len(),
            "Expected partial write: {bytes_written} bytes out of {}",
            data.len()
        );

        let read_result = inner_blob.read_at(0, bytes_written).await.unwrap();
        assert_eq!(read_result.coalesce().as_ref(), &data[..bytes_written]);
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write_disabled() {
        let h = Harness::new(Config::default().write(1.0).partial_write(0.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob
            .write_at(0, b"hello world".to_vec(), WriteOptions::default())
            .await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(
            size, 0,
            "Expected no bytes written when partial_write_rate is 0"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write_single_byte() {
        let h = Harness::new(Config::default().write(1.0).partial_write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob
            .write_at(0, b"x".to_vec(), WriteOptions::default())
            .await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "No partial write possible for single byte");
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_grow() {
        let h = Harness::new(Config::default().resize(1.0).partial_resize(1.0));

        let (blob, initial_size) = h.storage.open("partition", b"test").await.unwrap();
        assert_eq!(initial_size, 0);

        let target_size = 100u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, actual_size) = h.inner.open("partition", b"test").await.unwrap();
        assert!(
            actual_size > 0 && actual_size < target_size,
            "Expected partial resize: size {actual_size} should be between 0 and {target_size}"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_shrink() {
        let h = Harness::new(Config::default());

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.resize(100).await.unwrap();
        blob.sync().await.unwrap();

        {
            let mut cfg = h.config.write();
            cfg.resize_rate = Some(1.0);
            cfg.partial_resize_rate = Some(1.0);
        }

        let target_size = 10u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, actual_size) = h.inner.open("partition", b"test").await.unwrap();
        assert!(
            actual_size > target_size && actual_size < 100,
            "Expected partial shrink: size {actual_size} should be between {target_size} and 100"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_disabled() {
        let h = Harness::new(Config::default().resize(1.0).partial_resize(0.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob.resize(100).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "Expected no resize when partial_resize_rate is 0");
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_same_size() {
        let h = Harness::new(Config::default().resize(1.0).partial_resize(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob.resize(0).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_after_write_extends() {
        let h = Harness::new(Config::default());

        let (blob, initial_size) = h.storage.open("partition", b"test").await.unwrap();
        assert_eq!(initial_size, 0);

        blob.write_at(0, vec![0xABu8; 50], WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        let (_, size_after_write) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size_after_write, 50);

        {
            let mut cfg = h.config.write();
            cfg.resize_rate = Some(1.0);
            cfg.partial_resize_rate = Some(1.0);
        }

        let target_size = 10u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, actual_size) = h.inner.open("partition", b"test").await.unwrap();
        assert!(
            actual_size > target_size && actual_size < 50,
            "Expected partial shrink from 50: size {actual_size} should be between {target_size} and 50"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_one_byte_difference() {
        let h = Harness::new(Config::default().resize(1.0).partial_resize(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob.resize(1).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }
}
