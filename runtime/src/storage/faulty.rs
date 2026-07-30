//! A storage wrapper that injects deterministic faults for testing crash recovery.

use crate::{BatchOperation, Error, Handle, IoBuf, IoBufs, IoBufsMut, deterministic::BoxDynRng};
use bytes::Buf;
use commonware_utils::sync::{Mutex, RwLock};
use rand::RngExt as _;
use std::{
    io::Error as IoError,
    ops::Range,
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

    /// Probability that a write failure samples an arbitrary subset of bytes to persist rather
    /// than deterministically persisting none. The sampled subset may itself be empty or complete.
    /// Only applies when `write_rate` triggers a failure.
    /// Value from 0.0 (never sample) to 1.0 (always sample).
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

    /// Pre-commit failure rate for non-empty `apply_batch` operations.
    pub batch_rate: Option<f64>,

    /// Failure rate reported after a non-empty `apply_batch` commits successfully.
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

    /// Set the probability of sampling a sporadic byte subset on write failure.
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

fn selected_ranges(len: usize, mut next_mask: impl FnMut() -> u64) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut mask = 0u64;
    for index in 0..len {
        let bit = index % u64::BITS as usize;
        if bit == 0 {
            mask = next_mask();
        }
        if mask & (1 << bit) != 0 {
            start.get_or_insert(index);
        } else if let Some(start) = start.take() {
            ranges.push(start..index);
        }
    }
    if let Some(start) = start {
        ranges.push(start..len);
    }
    ranges
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

    /// Select an arbitrary subset of byte ranges for a failed write.
    fn try_partial_write(&self, rate: Option<f64>, len: usize) -> Option<Vec<Range<usize>>> {
        if len == 0 || !self.roll(rate) {
            return None;
        }

        let mut rng = self.rng.lock();
        Some(selected_ranges(len, || rng.random()))
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

    async fn apply_batch(&self, operations: Vec<BatchOperation<Self::Blob>>) -> Result<(), Error> {
        let descriptors = operations
            .iter()
            .map(|operation| match operation {
                BatchOperation::Remove(target) => {
                    crate::storage::batch::Operation::Remove(target.clone())
                }
                BatchOperation::Resize { blob, len } => crate::storage::batch::Operation::Resize {
                    partition: blob.partition.clone(),
                    name: blob.name.clone(),
                    len: *len,
                },
                BatchOperation::Update {
                    blob,
                    offset,
                    data,
                    len,
                } => crate::storage::batch::Operation::Update {
                    partition: blob.partition.clone(),
                    name: blob.name.clone(),
                    offset: *offset,
                    data: data.clone(),
                    len: *len,
                },
            })
            .collect();
        crate::storage::batch::canonicalize_operations(descriptors)?;
        if operations.is_empty() {
            return self.inner.apply_batch(Vec::new()).await;
        }
        if self.ctx.should_fail(Op::Batch) {
            return Err(injected_io_error().into());
        }

        let mut resized = Vec::new();
        let operations = operations
            .into_iter()
            .map(|operation| match operation {
                BatchOperation::Remove(target) => BatchOperation::Remove(target),
                BatchOperation::Resize { blob, len } => {
                    resized.push((blob.size.clone(), len));
                    BatchOperation::Resize {
                        blob: blob.inner,
                        len,
                    }
                }
                BatchOperation::Update {
                    blob,
                    offset,
                    data,
                    len,
                } => {
                    resized.push((blob.size.clone(), len));
                    BatchOperation::Update {
                        blob: blob.inner,
                        offset,
                        data,
                        len,
                    }
                }
            })
            .collect();
        self.inner.apply_batch(operations).await?;
        for (size, len) in resized {
            size.store(len, Ordering::Relaxed);
        }
        if self.ctx.should_fail(Op::BatchPostCommit) {
            return Err(injected_io_error().into());
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        if self.ctx.should_fail(Op::Scan) {
            return Err(injected_io_error().into());
        }
        self.inner.scan(partition).await
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

    async fn persist_partial_write(
        &self,
        offset: u64,
        buf: IoBuf,
        ranges: Vec<Range<usize>>,
    ) -> Result<(), Error> {
        for range in ranges {
            let range_offset = offset
                .checked_add(range.start as u64)
                .ok_or(Error::OffsetOverflow)?;
            let range_end = offset
                .checked_add(range.end as u64)
                .ok_or(Error::OffsetOverflow)?;
            self.inner
                .write_at_sync(range_offset, buf.slice(range))
                .await?;
            // A later range can be cancelled independently after this one is already durable.
            self.size.fetch_max(range_end, Ordering::Relaxed);
        }
        Ok(())
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

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        let total_bytes = bufs.remaining() as u64;
        let end = offset
            .checked_add(total_bytes)
            .ok_or(Error::OffsetOverflow)?;

        let (should_fail, partial_rate) = self.ctx.check_write_fault();
        if should_fail {
            if let Some(ranges) = self
                .ctx
                .try_partial_write(partial_rate, total_bytes as usize)
            {
                self.persist_partial_write(offset, bufs.coalesce(), ranges)
                    .await?;
                return Err(injected_io_error().into());
            }
            return Err(injected_io_error().into());
        }

        self.inner.write_at(offset, bufs).await?;
        self.size.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let total_bytes = bufs.remaining() as u64;
        let end = offset
            .checked_add(total_bytes)
            .ok_or(Error::OffsetOverflow)?;
        if total_bytes == 0 {
            return Ok(());
        }

        let (should_fail, partial_rate) = self.ctx.check_write_fault();
        if should_fail {
            if let Some(ranges) = self
                .ctx
                .try_partial_write(partial_rate, total_bytes as usize)
            {
                self.persist_partial_write(offset, bufs.coalesce(), ranges)
                    .await?;
                return Err(injected_io_error().into());
            }
            return Err(injected_io_error().into());
        }

        if self.ctx.should_fail(Op::Sync) {
            self.inner.write_at(offset, bufs).await?;
            self.size.fetch_max(end, Ordering::Relaxed);
            return Err(injected_io_error().into());
        }

        self.inner.write_at_sync(offset, bufs).await?;
        self.size.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let (should_fail, partial_rate) = self.ctx.check_resize_fault();
        if should_fail {
            let current = self.size.load(Ordering::Relaxed);
            if let Some(len) = self.ctx.try_partial(partial_rate, current, len) {
                self.inner.resize(len).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, BufferPool, BufferPoolConfig, RemoveTarget, Storage as _,
        storage::{memory::Storage as MemStorage, tests::run_storage_tests},
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

    #[test]
    fn test_selected_ranges_include_empty_and_complete_subsets() {
        assert!(selected_ranges(8, || 0).is_empty());
        assert_eq!(selected_ranges(8, || u64::MAX), vec![0..8]);
        assert_eq!(selected_ranges(8, || 0b1010_0110), vec![1..3, 5..6, 7..8]);
    }

    #[tokio::test]
    async fn test_faulty_storage_no_faults() {
        let h = Harness::new(Config::default());
        run_storage_tests(h.storage).await;
    }

    #[tokio::test]
    async fn test_faulty_storage_sync_always_fails() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec()).await.unwrap();

        assert!(matches!(blob.sync().await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_faulty_storage_start_sync_always_fails() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec()).await.unwrap();

        let result = blob.start_sync().await.await;
        assert!(matches!(result, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_always_fails() {
        let h = Harness::new(Config::default().write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec()).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_at_sync_write_always_fails() {
        let h = Harness::new(Config::default().write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at_sync(0, b"data".to_vec()).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_at_sync_sync_failure_is_not_durable() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at_sync(0, b"data".to_vec()).await,
            Err(Error::Io(_))
        ));

        drop(blob);
        h.inner.simulate_crash(|| 0);
        let (_reopened, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_empty_write_at_sync_does_not_sync_prior_write() {
        let h = Harness::new(Config::default().sync(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec()).await.unwrap();

        blob.write_at_sync(4, Vec::<u8>::new()).await.unwrap();

        drop(blob);
        h.inner.simulate_crash(|| 0);
        let (_reopened, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_read_always_fails() {
        let h = Harness::new(Config::default());

        // Write some data first (no faults)
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec()).await.unwrap();
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
    }

    #[tokio::test]
    async fn test_faulty_storage_remove_uses_batch_faults() {
        let h = Harness::new(Config::default());

        // Create a blob first
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // Enable pre-commit batch faults.
        h.config.write().batch_rate = Some(1.0);

        assert!(matches!(
            h.storage.remove("partition", Some(b"test")).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_batch_fault_phases_are_atomic() {
        let h = Harness::new(Config::default().batch(1.0));
        for partition in ["batch_a", "batch_b"] {
            let (blob, _) = h.storage.open(partition, b"name").await.unwrap();
            blob.write_at(0, partition.as_bytes()).await.unwrap();
            blob.sync().await.unwrap();
        }

        assert!(matches!(
            h.storage
                .apply_batch(vec![RemoveTarget::Partition("invalid/name".into()).into()])
                .await,
            Err(Error::PartitionNameInvalid(_))
        ));
        h.storage.apply_batch(Vec::new()).await.unwrap();

        let targets = vec![
            RemoveTarget::Blob {
                partition: "batch_b".into(),
                name: b"name".to_vec(),
            },
            RemoveTarget::Blob {
                partition: "batch_a".into(),
                name: b"name".to_vec(),
            },
            RemoveTarget::Blob {
                partition: "batch_b".into(),
                name: b"name".to_vec(),
            },
        ];
        assert!(matches!(
            h.storage
                .apply_batch(targets.iter().cloned().map(BatchOperation::from).collect())
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
                .apply_batch(targets.into_iter().map(BatchOperation::from).collect())
                .await,
            Err(Error::Io(_))
        ));
        assert!(h.inner.scan("batch_a").await.unwrap().is_empty());
        assert!(h.inner.scan("batch_b").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_faulty_storage_validates_mixed_batch_before_faulting() {
        let h = Harness::new(Config::default().batch(1.0));
        let (blob, _) = h.storage.open("partition", b"name").await.unwrap();

        let error = h
            .storage
            .apply_batch(vec![
                BatchOperation::Remove(RemoveTarget::Blob {
                    partition: "partition".into(),
                    name: b"name".to_vec(),
                }),
                BatchOperation::Resize { blob, len: 0 },
            ])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Io(error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_batch_resize_bypasses_resize_faults() {
        let h = Harness::new(Config::default());
        let (blob, _) = h.storage.open("partition", b"name").await.unwrap();
        blob.write_at(0, b"contents").await.unwrap();
        blob.sync().await.unwrap();
        *h.config.write() = Config::default().resize(1.0).partial_resize(1.0);

        h.storage
            .apply_batch(vec![BatchOperation::Resize { blob, len: 3 }])
            .await
            .unwrap();

        let (_, len) = h.inner.open("partition", b"name").await.unwrap();
        assert_eq!(len, 3);
    }

    #[tokio::test]
    async fn test_faulty_storage_batch_update_post_commit_tracks_size() {
        let h = Harness::new(Config::default());
        let (blob, _) = h.storage.open("partition", b"name").await.unwrap();
        blob.write_at(0, b"contents").await.unwrap();
        blob.sync().await.unwrap();
        *h.config.write() = Config::default()
            .write(1.0)
            .partial_write(1.0)
            .resize(1.0)
            .partial_resize(1.0)
            .batch_post_commit(1.0);

        assert!(matches!(
            h.storage
                .apply_batch(vec![BatchOperation::Update {
                    blob: blob.clone(),
                    offset: 1,
                    data: b"new".into(),
                    len: 4,
                }])
                .await,
            Err(Error::Io(_))
        ));

        assert_eq!(blob.size.load(Ordering::Relaxed), 4);
        let (inner, len) = h.inner.open("partition", b"name").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(inner.read_at(0, 4).await.unwrap().coalesce(), b"cnew");
    }

    #[tokio::test]
    async fn test_faulty_storage_scan_always_fails() {
        let h = Harness::new(Config::default());

        // Create some blobs first
        for i in 0..3 {
            let name = format!("blob{i}");
            let (blob, _) = h.storage.open("partition", name.as_bytes()).await.unwrap();
            blob.write_at(0, b"data".to_vec()).await.unwrap();
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
        blob.resize(data.len() as u64).await.unwrap();
        blob.sync().await.unwrap();
        let result = blob.write_at(0, data.clone()).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (inner_blob, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, data.len() as u64);
        let persisted = inner_blob.read_at(0, data.len()).await.unwrap().coalesce();
        let persisted = persisted.as_ref();
        assert!(
            persisted
                .iter()
                .zip(&data)
                .any(|(actual, expected)| actual == expected)
        );
        assert!(persisted.contains(&0));
        assert!(
            persisted
                .iter()
                .zip(&data)
                .all(|(actual, expected)| *actual == 0 || actual == expected)
        );
        let first_omitted = persisted.iter().position(|byte| *byte == 0).unwrap();
        assert!(
            persisted[first_omitted + 1..]
                .iter()
                .zip(&data[first_omitted + 1..])
                .any(|(actual, expected)| actual == expected)
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write_at_sync() {
        let h = Harness::new(Config::default().write(1.0).partial_write(1.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let data = vec![0xA5; 64];
        blob.resize(data.len() as u64).await.unwrap();
        blob.sync().await.unwrap();

        assert!(matches!(
            blob.write_at_sync(0, data.clone()).await,
            Err(Error::Io(_))
        ));

        let (inner_blob, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, data.len() as u64);
        let persisted = inner_blob.read_at(0, data.len()).await.unwrap().coalesce();
        let persisted = persisted.as_ref();
        assert!(persisted.contains(&0xA5));
        assert!(persisted.contains(&0));
    }

    #[tokio::test]
    async fn test_partial_write_does_not_promote_earlier_dirty_bytes() {
        let h = Harness::new(Config::default());
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.resize(32).await.unwrap();
        blob.sync().await.unwrap();
        blob.write_at(0, b"dirty".to_vec()).await.unwrap();

        *h.config.write() = Config::default().write(1.0).partial_write(1.0);
        assert!(matches!(
            blob.write_at(16, vec![0xA5; 16]).await,
            Err(Error::Io(_))
        ));
        drop(blob);

        let (inner, _) = h.inner.open("partition", b"test").await.unwrap();
        let selected = inner.read_at(16, 16).await.unwrap().coalesce();
        assert!(selected.as_ref().contains(&0xA5));
        assert!(selected.as_ref().contains(&0));
        drop(inner);

        // Lose the earlier ordinary write. The sparse ranges persisted by the failed write remain
        // durable without pulling the unrelated dirty bytes through a full sync.
        h.inner.simulate_crash(|| 0);
        let (inner, _) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(
            inner.read_at(0, 5).await.unwrap().coalesce().as_ref(),
            &[0; 5]
        );
        assert_eq!(
            inner.read_at(16, 16).await.unwrap().coalesce().as_ref(),
            selected.as_ref()
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write_disabled() {
        let h = Harness::new(Config::default().write(1.0).partial_write(0.0));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob.write_at(0, b"hello world".to_vec()).await;

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
        let result = blob.write_at(0, b"x".to_vec()).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (inner, size) = h.inner.open("partition", b"test").await.unwrap();
        assert!(size <= 1);
        if size == 1 {
            assert_eq!(inner.read_at(0, 1).await.unwrap().coalesce(), b"x");
        }
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_grow() {
        let h = Harness::new(Config::default().resize(1.0).partial_resize(1.0));

        let (blob, initial_size) = h.storage.open("partition", b"test").await.unwrap();
        assert_eq!(initial_size, 0);

        let target_size = 100u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let actual_size = blob.size.load(Ordering::Relaxed);
        assert!(
            actual_size > 0 && actual_size < target_size,
            "Expected partial resize: size {actual_size} should be between 0 and {target_size}"
        );

        drop(blob);
        h.inner.simulate_crash(|| 1);
        let (_, recovered_size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(recovered_size, actual_size);
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

        let actual_size = blob.size.load(Ordering::Relaxed);
        assert!(
            actual_size > target_size && actual_size < 100,
            "Expected partial shrink: size {actual_size} should be between {target_size} and 100"
        );

        drop(blob);
        h.inner.simulate_crash(|| 1);
        let (_, recovered_size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(recovered_size, actual_size);
    }

    #[tokio::test]
    async fn test_partial_resize_does_not_sync_prior_write() {
        let h = Harness::new(Config::default());
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.resize(32).await.unwrap();
        blob.sync().await.unwrap();
        blob.write_at(0, b"dirty").await.unwrap();

        *h.config.write() = Config::default().resize(1.0).partial_resize(1.0);
        assert!(matches!(blob.resize(64).await, Err(Error::Io(_))));
        let partial_size = blob.size.load(Ordering::Relaxed);
        assert!(partial_size > 32 && partial_size < 64);
        drop(blob);

        // Lose the earlier write while retaining the failed resize. The partial resize must not
        // implicitly make unrelated dirty bytes durable.
        let mut decisions = [0, 1].into_iter();
        h.inner.simulate_crash(|| decisions.next().unwrap());
        let (recovered, recovered_size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(recovered_size, partial_size);
        assert_eq!(
            recovered.read_at(0, 5).await.unwrap().coalesce().as_ref(),
            &[0; 5]
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

        blob.write_at(0, vec![0xABu8; 50]).await.unwrap();
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

        let actual_size = blob.size.load(Ordering::Relaxed);
        assert!(
            actual_size > target_size && actual_size < 50,
            "Expected partial shrink from 50: size {actual_size} should be between {target_size} and 50"
        );

        drop(blob);
        h.inner.simulate_crash(|| 1);
        let (_, recovered_size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(recovered_size, actual_size);
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
