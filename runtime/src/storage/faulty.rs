//! A storage wrapper that injects deterministic faults for testing crash recovery.

use crate::{
    Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions, deterministic::BoxDynRng,
};
use bytes::Buf;
use commonware_utils::{
    Probability, probability,
    sync::{AsyncMutex, Mutex, RwLock},
};
use futures::{FutureExt as _, future::Shared};
use rand::RngExt as _;
use std::{
    collections::{BTreeMap, HashSet},
    io::Error as IoError,
    sync::{
        Arc, OnceLock, Weak,
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
    Scan,
}

/// Selects how submitted bytes are retained from a write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartialWriteMode {
    /// Retain bytes from the beginning of the write until the first omitted byte.
    Prefix,

    /// Independently select each submitted byte for retention.
    Subset,
}

/// Fault configuration for `write_at` operations and byte retention from failed writes or
/// successful unsynchronized writes when a crash is simulated.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WriteConfig {
    /// Probability that `write_at` returns an injected failure.
    pub failure_rate: Probability,

    /// Probability used by the selected mode when retaining submitted bytes.
    pub retention_rate: Probability,

    /// Arrangement of bytes retained by the simulated storage device.
    pub mode: PartialWriteMode,
}

#[cfg(feature = "arbitrary")]
const WRITE_CONFIG_RATE_STEPS: u16 = 101;
#[cfg(feature = "arbitrary")]
const WRITE_CONFIG_RATE_PAIRS: u16 = WRITE_CONFIG_RATE_STEPS * WRITE_CONFIG_RATE_STEPS;
#[cfg(feature = "arbitrary")]
const WRITE_CONFIG_CELLS: u16 = WRITE_CONFIG_RATE_PAIRS * 2;

#[cfg(feature = "arbitrary")]
fn write_config_from_cell(cell: u16) -> WriteConfig {
    let rates = cell % WRITE_CONFIG_RATE_PAIRS;
    let failure = rates % WRITE_CONFIG_RATE_STEPS;
    let retention = rates / WRITE_CONFIG_RATE_STEPS;
    WriteConfig {
        failure_rate: Probability::new(u64::from(failure), 100).unwrap(),
        retention_rate: Probability::new(u64::from(retention), 100).unwrap(),
        mode: if cell < WRITE_CONFIG_RATE_PAIRS {
            PartialWriteMode::Prefix
        } else {
            PartialWriteMode::Subset
        },
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for WriteConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(write_config_from_cell(
            u.int_in_range(0..=WRITE_CONFIG_CELLS - 1)?,
        ))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (2, Some(2))
    }
}

/// Fault configuration for `resize` operations and partial failure behavior.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResizeConfig {
    /// Probability that `resize` returns an injected failure, also used independently as the
    /// probability that a successful unsynchronized resize survives a simulated crash.
    pub failure_rate: Probability,

    /// Probability that an injected failure resizes to an intermediate size rather than leaving
    /// the size unchanged.
    pub partial_rate: Probability,
}

/// Configuration for deterministic storage fault injection.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Failure rate for `open_versioned` operations.
    pub open_rate: Option<Probability>,

    /// Failure rate for `read_at` operations.
    pub read_rate: Option<Probability>,

    /// Failure and byte-retention configuration for `write_at` operations.
    pub write_rate: Option<WriteConfig>,

    /// Failure rate for `sync` operations.
    pub sync_rate: Option<Probability>,

    /// Failure and partial-failure configuration for `resize` operations.
    pub resize_rate: Option<ResizeConfig>,

    /// Failure rate for `remove` operations.
    pub remove_rate: Option<Probability>,

    /// Failure rate for `scan` operations.
    pub scan_rate: Option<Probability>,
}

impl Config {
    /// Get the failure rate for an operation type.
    fn rate_for(&self, op: Op) -> Probability {
        match op {
            Op::Open => self.open_rate,
            Op::Read => self.read_rate,
            Op::Write => self.write_rate.map(|config| config.failure_rate),
            Op::Sync => self.sync_rate,
            Op::Resize => self.resize_rate.map(|config| config.failure_rate),
            Op::Remove => self.remove_rate,
            Op::Scan => self.scan_rate,
        }
        .unwrap_or(probability!(0.0))
    }

    /// Set the open failure rate.
    pub const fn open(mut self, rate: Probability) -> Self {
        self.open_rate = Some(rate);
        self
    }

    /// Set the read failure rate.
    pub const fn read(mut self, rate: Probability) -> Self {
        self.read_rate = Some(rate);
        self
    }

    /// Set the write fault configuration.
    pub const fn write(mut self, config: WriteConfig) -> Self {
        self.write_rate = Some(config);
        self
    }

    /// Set the sync failure rate.
    pub const fn sync(mut self, rate: Probability) -> Self {
        self.sync_rate = Some(rate);
        self
    }

    /// Set the resize fault configuration.
    pub const fn resize(mut self, config: ResizeConfig) -> Self {
        self.resize_rate = Some(config);
        self
    }

    /// Set the remove failure rate.
    pub const fn remove(mut self, rate: Probability) -> Self {
        self.remove_rate = Some(rate);
        self
    }

    /// Set the scan failure rate.
    pub const fn scan(mut self, rate: Probability) -> Self {
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

/// An issued mutation or durability cut whose crash outcome remains unresolved.
enum PendingMutation<B> {
    /// A write fragment whose `selection_offset` maps it into one issued write's shared byte
    /// selection.
    Write {
        generation: Arc<FileGeneration>,
        blob: B,
        offset: u64,
        bufs: IoBufs,
        retention: Arc<PendingWriteRetention>,
        selection_offset: usize,
    },
    /// A successful resize already selected to survive a simulated crash.
    Resize {
        generation: Arc<FileGeneration>,
        blob: B,
        len: u64,
    },
    /// A full-sync cut whose completion determines whether earlier mutations remain pending.
    Sync { sync: Arc<PendingSync> },
}

/// One initiated full sync owns its durability cut and is observed by both its caller and crash
/// replay bookkeeping.
struct PendingSync {
    generation: Arc<FileGeneration>,
    completion: Shared<Handle<()>>,
}

impl PendingSync {
    fn completed_successfully(&self) -> bool {
        matches!(self.completion.clone().now_or_never(), Some(Ok(())))
    }
}

/// Retention choices belong to the issued write and are shared by fragments created by later
/// durability barriers.
struct PendingWriteRetention {
    policy: (PartialWriteMode, Probability),
    len: usize,
    selected: OnceLock<Vec<bool>>,
}

impl PendingWriteRetention {
    const fn new(policy: (PartialWriteMode, Probability), len: usize) -> Self {
        Self {
            policy,
            len,
            selected: OnceLock::new(),
        }
    }
}

impl<B> PendingMutation<B> {
    fn generation(&self) -> &Arc<FileGeneration> {
        match self {
            Self::Write { generation, .. } | Self::Resize { generation, .. } => generation,
            Self::Sync { sync } => &sync.generation,
        }
    }
}

/// Unresolved entries in issue order within each file generation.
type PendingMutations<B> = Arc<Mutex<Vec<PendingMutation<B>>>>;

/// Identifies a file by partition and name.
type FileKey = (String, Vec<u8>);

/// Identifies one live file generation and serializes its mutations across handles.
struct FileGeneration {
    mutation: AsyncMutex<()>,
}

impl FileGeneration {
    fn new() -> Self {
        Self {
            mutation: AsyncMutex::new(()),
        }
    }
}

/// Tracks the generation shared by existing handles and unresolved mutations for each file.
type FileGenerations = Arc<Mutex<BTreeMap<FileKey, Weak<FileGeneration>>>>;

fn clear_pending<B>(pending: &PendingMutations<B>, generation: &Arc<FileGeneration>) {
    pending
        .lock()
        .retain(|mutation| !Arc::ptr_eq(mutation.generation(), generation));
}

/// A successful full sync retires mutations issued before it while preserving later crash debt.
fn resolve_pending_sync<B>(
    pending: &PendingMutations<B>,
    sync: &Arc<PendingSync>,
    succeeded: bool,
) {
    let mut pending = pending.lock();
    let Some(cut) = pending.iter().position(
        |mutation| matches!(mutation, PendingMutation::Sync { sync: candidate, .. } if Arc::ptr_eq(candidate, sync)),
    ) else {
        return;
    };
    let mut index = 0;
    pending.retain(|mutation| {
        let is_target = matches!(mutation, PendingMutation::Sync { sync: candidate, .. } if Arc::ptr_eq(candidate, sync));
        let retire = is_target
            || (succeeded
                && index < cut
                && Arc::ptr_eq(mutation.generation(), &sync.generation));
        index += 1;
        !retire
    });
}

impl Oracle {
    /// Check if a fault should be injected for the given operation.
    fn should_fail(&self, op: Op) -> bool {
        self.roll(self.config.read().rate_for(op))
    }

    /// Check if a write fault should be injected.
    /// Reads config once to avoid nested lock acquisition.
    fn check_write_fault(&self) -> (bool, Option<(PartialWriteMode, Probability)>) {
        let config = self.config.read();
        let fail = self.roll(config.rate_for(Op::Write));
        let retention = config
            .write_rate
            .map(|config| (config.mode, config.retention_rate))
            .filter(|(_, retention_rate)| !retention_rate.is_zero());
        (fail, retention)
    }

    /// Check if a resize fault should be injected and snapshot its crash outcome.
    /// Reads config once to avoid nested lock acquisition.
    fn check_resize_fault(&self) -> (bool, Probability, bool) {
        let config = self.config.read();
        let Some(resize_config) = config.resize_rate else {
            return (false, probability!(0.0), false);
        };
        let failure_rate = config.rate_for(Op::Resize);
        let fail = self.roll(failure_rate);
        let retain = !fail && self.roll(failure_rate);
        (fail, resize_config.partial_rate, retain)
    }

    /// Check if an event should occur based on a probability rate.
    fn roll(&self, rate: Probability) -> bool {
        rate.sample(&mut **self.rng.lock())
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

    /// Select retained byte positions according to a snapshotted write policy.
    fn retained_bytes(
        &self,
        len: usize,
        (mode, retention_rate): (PartialWriteMode, Probability),
    ) -> Vec<bool> {
        let mut rng = self.rng.lock();
        match mode {
            PartialWriteMode::Prefix => {
                let mut positions = vec![false; len];
                let retained = (0..len)
                    .take_while(|_| retention_rate.sample(&mut **rng))
                    .count();
                positions[..retained].fill(true);
                positions
            }
            PartialWriteMode::Subset => (0..len)
                .map(|_| retention_rate.sample(&mut **rng))
                .collect(),
        }
    }

    /// Try to generate a partial operation target. Returns Some if both the rate
    /// check passes and an intermediate value exists between `from` and `to`.
    fn try_partial(&self, rate: Probability, from: u64, to: u64) -> Option<u64> {
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
    pending: PendingMutations<S::Blob>,
    generations: FileGenerations,
}

impl<S: crate::Storage> Storage<S> {
    /// Create a new faulty storage wrapper.
    pub fn new(inner: S, rng: Arc<Mutex<BoxDynRng>>, config: Arc<RwLock<Config>>) -> Self {
        Self {
            inner,
            ctx: Oracle { rng, config },
            pending: Arc::new(Mutex::new(Vec::new())),
            generations: Arc::new(Mutex::new(BTreeMap::new())),
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

    /// Associates an open blob with the current generation for its file.
    fn wrap_blob(&self, partition: &str, name: &[u8], inner: S::Blob, size: u64) -> Blob<S::Blob> {
        let key = (partition.to_string(), name.to_vec());
        let generation = {
            let mut generations = self.generations.lock();
            generations
                .get(&key)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| {
                    let generation = Arc::new(FileGeneration::new());
                    generations.insert(key.clone(), Arc::downgrade(&generation));
                    generation
                })
        };
        Blob::new(
            self.ctx.clone(),
            self.pending.clone(),
            generation,
            inner,
            size,
        )
    }

    /// Retires generations and pending mutations for one file or an entire partition.
    fn retire_names(&self, partition: &str, name: Option<&[u8]>) {
        let retired = {
            let mut generations = self.generations.lock();
            match name {
                Some(name) => generations
                    .remove(&(partition.to_string(), name.to_vec()))
                    .and_then(|generation| generation.upgrade())
                    .into_iter()
                    .collect::<Vec<_>>(),
                None => {
                    let keys = generations
                        .keys()
                        .filter(|(candidate, _)| candidate == partition)
                        .cloned()
                        .collect::<Vec<_>>();
                    keys.into_iter()
                        .filter_map(|key| generations.remove(&key)?.upgrade())
                        .collect()
                }
            }
        };
        for generation in retired {
            clear_pending(&self.pending, &generation);
        }
    }
}

impl Storage<crate::storage::memory::Storage> {
    /// Replay selected crash outcomes in issue order.
    pub(crate) fn crash(&self) -> Result<(), Error> {
        let pending = std::mem::take(&mut *self.pending.lock());
        let mut synced = HashSet::new();
        let mut replay = Vec::with_capacity(pending.len());
        for mutation in pending.into_iter().rev() {
            match mutation {
                PendingMutation::Sync { sync } => {
                    if sync.completed_successfully() {
                        synced.insert(Arc::as_ptr(&sync.generation));
                    }
                }
                mutation => {
                    if !synced.contains(&Arc::as_ptr(mutation.generation())) {
                        replay.push(mutation);
                    }
                }
            }
        }
        for mutation in replay.into_iter().rev() {
            match mutation {
                PendingMutation::Write {
                    blob,
                    offset,
                    bufs,
                    retention,
                    selection_offset,
                    ..
                } => {
                    let selected = retention
                        .selected
                        .get_or_init(|| self.ctx.retained_bytes(retention.len, retention.policy));
                    let selection_end = selection_offset
                        .checked_add(bufs.remaining())
                        .expect("a pending-write fragment stays within its selection");
                    let mut retained = selected[selection_offset..selection_end].iter().copied();
                    blob.retain_crash_write(offset, bufs, || {
                        retained
                            .next()
                            .expect("the retention policy covers every submitted byte")
                    })?;
                }
                PendingMutation::Resize { blob, len, .. } => {
                    blob.retain_crash_resize(len)?;
                }
                PendingMutation::Sync { .. } => unreachable!("sync markers are not replayed"),
            }
        }
        Ok(())
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
        let (blob, len, blob_version) =
            self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            self.wrap_blob(partition, name, blob, len),
            len,
            blob_version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        if self.ctx.should_fail(Op::Remove) {
            return Err(injected_io_error().into());
        }
        self.inner.remove(partition, name).await?;
        self.retire_names(partition, name);
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
    pending: PendingMutations<B>,
    generation: Arc<FileGeneration>,
    /// Tracked size for partial resize support.
    size: Arc<AtomicU64>,
}

impl<B: crate::Blob> Blob<B> {
    fn new(
        ctx: Oracle,
        pending: PendingMutations<B>,
        generation: Arc<FileGeneration>,
        inner: B,
        size: u64,
    ) -> Self {
        Self {
            inner,
            ctx,
            pending,
            generation,
            size: Arc::new(AtomicU64::new(size)),
        }
    }

    fn record_pending(
        &self,
        offset: u64,
        bufs: IoBufs,
        retention: (PartialWriteMode, Probability),
    ) {
        if bufs.is_empty() {
            return;
        }
        let retention = Arc::new(PendingWriteRetention::new(retention, bufs.remaining()));
        self.pending.lock().push(PendingMutation::Write {
            generation: self.generation.clone(),
            blob: self.inner.clone(),
            offset,
            bufs,
            retention,
            selection_offset: 0,
        });
    }

    fn record_pending_resize(&self, len: u64) {
        self.pending.lock().push(PendingMutation::Resize {
            generation: self.generation.clone(),
            blob: self.inner.clone(),
            len,
        });
    }

    /// Retire covered write debt and replay the durable range after any earlier resize debt.
    fn record_durable_range(&self, offset: u64, durable: IoBufs) {
        let len = durable.remaining() as u64;
        if len == 0 {
            return;
        }
        let end = offset
            .checked_add(len)
            .expect("submitted write range was validated before mutation");
        let mut pending = self.pending.lock();
        let mutations = std::mem::take(&mut *pending);
        let mut retained = Vec::with_capacity(mutations.len() + 1);
        let mut follows_resize = false;
        for mutation in mutations {
            if !Arc::ptr_eq(mutation.generation(), &self.generation) {
                retained.push(mutation);
                continue;
            }
            let (write_generation, write_blob, write_offset, bufs, retention, selection_offset) =
                match mutation {
                    PendingMutation::Write {
                        generation,
                        blob,
                        offset,
                        bufs,
                        retention,
                        selection_offset,
                    } => (generation, blob, offset, bufs, retention, selection_offset),
                    resize @ PendingMutation::Resize { .. } => {
                        follows_resize = true;
                        retained.push(resize);
                        continue;
                    }
                    sync @ PendingMutation::Sync { .. } => {
                        retained.push(sync);
                        continue;
                    }
                };
            let write_len = bufs.remaining() as u64;
            let write_end = write_offset
                .checked_add(write_len)
                .expect("pending write ranges are validated before recording");
            let overlap_start = write_offset.max(offset);
            let overlap_end = write_end.min(end);
            if overlap_start >= overlap_end {
                retained.push(PendingMutation::Write {
                    generation: write_generation,
                    blob: write_blob,
                    offset: write_offset,
                    bufs,
                    retention,
                    selection_offset,
                });
                continue;
            }

            let bytes = bufs.coalesce();
            if write_offset < overlap_start {
                let prefix_len = usize::try_from(overlap_start - write_offset)
                    .expect("a pending-write subrange fits its source buffer");
                retained.push(PendingMutation::Write {
                    generation: write_generation.clone(),
                    blob: write_blob.clone(),
                    offset: write_offset,
                    bufs: bytes.slice(..prefix_len).into(),
                    retention: retention.clone(),
                    selection_offset,
                });
            }
            if overlap_end < write_end {
                let suffix_start = usize::try_from(overlap_end - write_offset)
                    .expect("a pending-write subrange fits its source buffer");
                retained.push(PendingMutation::Write {
                    generation: write_generation,
                    blob: write_blob,
                    offset: overlap_end,
                    bufs: bytes.slice(suffix_start..).into(),
                    retention,
                    selection_offset: selection_offset
                        .checked_add(suffix_start)
                        .expect("a pending-write fragment stays within its selection"),
                });
            }
        }
        if follows_resize {
            let retention = Arc::new(PendingWriteRetention::new(
                (PartialWriteMode::Prefix, probability!(1.0)),
                durable.remaining(),
            ));
            retained.push(PendingMutation::Write {
                generation: self.generation.clone(),
                blob: self.inner.clone(),
                offset,
                bufs: durable,
                retention,
                selection_offset: 0,
            });
        }
        *pending = retained;
    }
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        if self.ctx.should_fail(Op::Read) {
            return Err(injected_io_error().into());
        }
        self.inner.read_at(offset, len, options).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        if self.ctx.should_fail(Op::Read) {
            return Err(injected_io_error().into());
        }
        self.inner
            .read_at_buf(offset, len, bufs.into(), options)
            .await
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
        offset
            .checked_add(total_bytes)
            .ok_or(Error::OffsetOverflow)?;
        let (should_fail, write_retention) = self.ctx.check_write_fault();
        let _mutation = self.generation.mutation.lock().await;
        if should_fail {
            if let Some(retention) = write_retention {
                let len = bufs.remaining();
                let retained = self.ctx.retained_bytes(len, retention);
                let bufs = bufs.coalesce();
                let mut position = 0;
                while position < len {
                    if !retained[position] {
                        position += 1;
                        continue;
                    }

                    let start = position;
                    while position < len && retained[position] {
                        position += 1;
                    }
                    let end = position;
                    let run_offset = offset
                        .checked_add(start as u64)
                        .ok_or(Error::OffsetOverflow)?;
                    let run = bufs.slice(start..end);
                    let durable = run.clone().into();
                    self.inner
                        .write_at(run_offset, run, options | WriteOptions::SYNC)
                        .await?;
                    self.record_durable_range(run_offset, durable);
                    self.size.fetch_max(
                        run_offset.saturating_add((end - start) as u64),
                        Ordering::Relaxed,
                    );
                }
            }
            return Err(injected_io_error().into());
        }

        if sync && self.ctx.should_fail(Op::Sync) {
            let pending = write_retention.map(|retention| (bufs.clone(), retention));
            self.inner
                .write_at(offset, bufs, options.without(WriteOptions::SYNC))
                .await?;
            self.size
                .fetch_max(offset.saturating_add(total_bytes), Ordering::Relaxed);
            if let Some((bufs, retention)) = pending {
                self.record_pending(offset, bufs, retention);
            }
            return Err(injected_io_error().into());
        }

        let pending = match (sync, write_retention) {
            (false, Some(retention)) => Some((bufs.clone(), retention)),
            _ => None,
        };
        let durable = sync.then(|| bufs.clone());
        self.inner.write_at(offset, bufs, options).await?;
        self.size
            .fetch_max(offset.saturating_add(total_bytes), Ordering::Relaxed);
        if let Some(durable) = durable {
            self.record_durable_range(offset, durable);
        } else if let Some((bufs, retention)) = pending {
            self.record_pending(offset, bufs, retention);
        }
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let (should_fail, partial_rate, retain) = self.ctx.check_resize_fault();
        let _mutation = self.generation.mutation.lock().await;
        if should_fail {
            let current = self.size.load(Ordering::Relaxed);
            if let Some(len) = self.ctx.try_partial(partial_rate, current, len) {
                self.inner.resize(len).await?;
                self.record_pending_resize(len);
                self.size.store(len, Ordering::Relaxed);
                return Err(injected_io_error().into());
            }
            return Err(injected_io_error().into());
        }
        self.inner.resize(len).await?;
        if retain {
            self.record_pending_resize(len);
        }
        self.size.store(len, Ordering::Relaxed);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.ctx.should_fail(Op::Sync) {
            return Err(injected_io_error().into());
        }
        let _mutation = self.generation.mutation.lock().await;
        self.inner.sync().await?;
        clear_pending(&self.pending, &self.generation);
        Ok(())
    }

    async fn start_sync(&self) -> Handle<()> {
        if self.ctx.should_fail(Op::Sync) {
            return Handle::ready(Err(injected_io_error().into()));
        }
        let _mutation = self.generation.mutation.lock().await;
        let sync = Arc::new(PendingSync {
            generation: self.generation.clone(),
            completion: self.inner.start_sync().await.shared(),
        });
        self.pending
            .lock()
            .push(PendingMutation::Sync { sync: sync.clone() });

        let pending = self.pending.clone();
        let completion = sync.completion.clone();
        Handle::from_future(async move {
            let result = completion.await;
            resolve_pending_sync(&pending, &sync, result.is_ok());
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, BufferPool, BufferPoolConfig, IoBufMut, Storage as _,
        mocks::RecordingContext,
        storage::{memory::Storage as MemStorage, tests::run_storage_tests},
        telemetry::metrics::Registry,
    };
    use commonware_utils::ScriptedRng;
    use futures::task::noop_waker;
    use rand::{SeedableRng, rngs::StdRng};
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::AtomicBool,
        task::{Context, Poll},
    };

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_write_config_arbitrary_is_compact_and_covers_grid() {
        use arbitrary::{Arbitrary as _, Unstructured};

        assert_eq!(WriteConfig::size_hint(0), (2, Some(2)));
        let mut input = Unstructured::new(&[0, 0, 0]);
        WriteConfig::arbitrary(&mut input).unwrap();
        assert_eq!(input.len(), 1);

        for cell in 0..WRITE_CONFIG_CELLS {
            let config = write_config_from_cell(cell);
            let rates = cell % WRITE_CONFIG_RATE_PAIRS;
            assert_eq!(
                config.failure_rate,
                Probability::new(u64::from(rates % WRITE_CONFIG_RATE_STEPS), 100).unwrap()
            );
            assert_eq!(
                config.retention_rate,
                Probability::new(u64::from(rates / WRITE_CONFIG_RATE_STEPS), 100).unwrap()
            );
            assert_eq!(
                config.mode,
                if cell < WRITE_CONFIG_RATE_PAIRS {
                    PartialWriteMode::Prefix
                } else {
                    PartialWriteMode::Subset
                }
            );
        }
    }

    #[derive(Clone)]
    struct OperationGate<B> {
        inner: B,
        pause_after_write: bool,
        armed: Arc<AtomicBool>,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl<B> OperationGate<B> {
        async fn pause(&self, after_write: bool) {
            if self.pause_after_write == after_write && self.armed.swap(false, Ordering::Relaxed) {
                self.started.notify_one();
                self.release.notified().await;
            }
        }
    }

    impl<B: crate::Blob> crate::Blob for OperationGate<B> {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len, options).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            self.inner.write_at(offset, bufs, options).await?;
            self.pause(true).await;
            Ok(())
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await?;
            self.pause(false).await;
            Ok(())
        }

        async fn start_sync(&self) -> Handle<()> {
            let gate = self.clone();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            drop(tokio::spawn(async move {
                let _ = sender.send(gate.sync().await);
            }));
            Handle::from_receiver(receiver)
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let waker = noop_waker();
        future.poll(&mut Context::from_waker(&waker))
    }

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
            Self::with_rng(Box::new(StdRng::seed_from_u64(seed)), config)
        }

        fn with_rng(rng: BoxDynRng, config: Config) -> Self {
            let inner = MemStorage::new(test_pool());
            let rng = Arc::new(Mutex::new(rng));
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
    async fn test_start_sync_returns_before_backing_completion() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (inner, _) = h.inner.open("partition", b"start-sync").await.unwrap();
        inner
            .write_at(0, b"data", WriteOptions::SYNC)
            .await
            .unwrap();

        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let gated = OperationGate {
            inner,
            pause_after_write: false,
            armed: Arc::new(AtomicBool::new(true)),
            started: started.clone(),
            release: release.clone(),
        };
        let pending = Arc::new(Mutex::new(Vec::new()));
        let blob = Blob::new(
            h.storage.ctx.clone(),
            pending,
            Arc::new(FileGeneration::new()),
            gated,
            4,
        );

        let mut start = Box::pin(blob.start_sync());
        let Poll::Ready(mut completion) = poll_once(start.as_mut()) else {
            panic!("start_sync waited for backing durability");
        };
        started.notified().await;
        assert!(poll_once(Pin::new(&mut completion)).is_pending());
        release.notify_one();
        completion.await.unwrap();
    }

    async fn run_overlapping_barrier(start: bool) {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (inner, _) = h.inner.open("partition", b"overlap").await.unwrap();
        inner
            .write_at(0, b"base", WriteOptions::SYNC)
            .await
            .unwrap();

        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let gated = OperationGate {
            inner,
            pause_after_write: false,
            armed: Arc::new(AtomicBool::new(true)),
            started: started.clone(),
            release: release.clone(),
        };
        let pending = Arc::new(Mutex::new(Vec::new()));
        let blob = Blob::new(
            h.storage.ctx.clone(),
            pending.clone(),
            Arc::new(FileGeneration::new()),
            gated,
            4,
        );

        let barrier_blob = blob.clone();
        let barrier = tokio::spawn(async move {
            if start {
                drop(barrier_blob.start_sync().await);
            } else {
                barrier_blob.sync().await.unwrap();
            }
        });
        started.notified().await;

        let mut late = Box::pin(blob.write_at(0, b"late", WriteOptions::default()));
        if start {
            let Poll::Ready(result) = poll_once(late.as_mut()) else {
                panic!("a started sync blocked a later write");
            };
            result.unwrap();
            release.notify_one();
            barrier.await.unwrap();
            tokio::task::yield_now().await;
        } else {
            assert!(poll_once(late.as_mut()).is_pending());
            release.notify_one();
            barrier.await.unwrap();
            late.await.unwrap();
        }

        for mutation in std::mem::take(&mut *pending.lock()) {
            match mutation {
                PendingMutation::Write {
                    blob,
                    offset,
                    bufs,
                    retention,
                    ..
                } => {
                    assert_eq!(
                        retention.policy,
                        (PartialWriteMode::Prefix, probability!(1.0))
                    );
                    blob.inner
                        .retain_crash_write(offset, bufs, || true)
                        .unwrap();
                }
                PendingMutation::Sync { .. } => {}
                PendingMutation::Resize { .. } => panic!("write test recorded a resize"),
            }
        }
        let (durable, len) = h.inner.open("partition", b"overlap").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(
            durable
                .read_at(0, 4, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"late"
        );
    }

    #[tokio::test]
    async fn test_completed_backing_write_cannot_record_after_later_full_sync() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (inner, _) = h.inner.open("partition", b"late-record").await.unwrap();
        inner
            .write_at(0, b"base!", WriteOptions::SYNC)
            .await
            .unwrap();

        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let gated = OperationGate {
            inner,
            pause_after_write: true,
            armed: Arc::new(AtomicBool::new(true)),
            started: started.clone(),
            release: release.clone(),
        };
        let pending = Arc::new(Mutex::new(Vec::new()));
        let blob = Blob::new(
            h.storage.ctx.clone(),
            pending.clone(),
            Arc::new(FileGeneration::new()),
            gated,
            5,
        );

        let mut stale = Box::pin(blob.write_at(0, b"stale", WriteOptions::default()));
        assert!(poll_once(stale.as_mut()).is_pending());
        started.notified().await;

        *h.config.write() = Config::default();
        let fresh_blob = blob.clone();
        let mut fresh = Box::pin(async move {
            fresh_blob
                .write_at(0, b"fresh", WriteOptions::default())
                .await?;
            fresh_blob.sync().await
        });
        assert!(poll_once(fresh.as_mut()).is_pending());

        release.notify_one();
        stale.await.unwrap();
        fresh.await.unwrap();

        for mutation in std::mem::take(&mut *pending.lock()) {
            let PendingMutation::Write {
                blob,
                offset,
                bufs,
                retention,
                ..
            } = mutation
            else {
                panic!("write test recorded a resize");
            };
            assert_eq!(
                retention.policy,
                (PartialWriteMode::Prefix, probability!(1.0))
            );
            blob.inner
                .retain_crash_write(offset, bufs, || true)
                .unwrap();
        }
        let (durable, len) = h.inner.open("partition", b"late-record").await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(
            durable
                .read_at(0, 5, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"fresh"
        );
    }

    async fn run_subset_overwrite(seed: u64, original: &[u8], replacement: &[u8]) -> Vec<u8> {
        assert_eq!(original.len(), replacement.len());

        let h = Harness::with_seed(
            seed,
            Config::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(0.5),
                mode: PartialWriteMode::Subset,
            }),
        );
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, original.to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        {
            let mut config = h.config.write();
            config.write_rate = Some(WriteConfig {
                failure_rate: probability!(1.0),
                retention_rate: probability!(0.5),
                mode: PartialWriteMode::Subset,
            });
        }

        let result = blob
            .write_at(0, replacement.to_vec(), WriteOptions::default())
            .await;
        assert!(matches!(result, Err(Error::Io(_))));

        let (inner_blob, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, original.len() as u64);
        inner_blob
            .read_at(0, original.len(), ReadOptions::default())
            .await
            .unwrap()
            .coalesce()
            .as_ref()
            .to_vec()
    }

    async fn run_random_crash(seed: u64, len: usize) -> Vec<u8> {
        let h = Harness::with_seed(
            seed,
            Config::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(0.5),
                mode: PartialWriteMode::Subset,
            }),
        );
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, vec![0; len], WriteOptions::SYNC)
            .await
            .unwrap();
        blob.write_at(0, vec![1; len], WriteOptions::default())
            .await
            .unwrap();

        // The retention policy is part of the completed write, not a global crash-time choice.
        h.config.write().write_rate = None;
        h.storage.crash().unwrap();

        let (blob, durable_len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(durable_len, len as u64);
        blob.read_at(0, len, ReadOptions::default())
            .await
            .unwrap()
            .coalesce()
            .as_ref()
            .to_vec()
    }

    #[tokio::test]
    async fn test_reopened_sync_clears_prior_handle_crash_writes() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"stale", WriteOptions::default())
            .await
            .unwrap();
        drop(blob);

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"fresh", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        h.storage.crash().unwrap();
        let (blob, len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(
            blob.read_at(0, 5, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"fresh"
        );
    }

    #[tokio::test]
    async fn test_dropped_completed_start_sync_clears_the_crash_epoch() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"stale", WriteOptions::default())
            .await
            .unwrap();
        h.config.write().write_rate = None;
        blob.write_at(0, b"fresh", WriteOptions::default())
            .await
            .unwrap();

        let completion = blob.start_sync().await;
        drop(completion);

        h.config.write().write_rate = Some(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        });
        blob.write_at(5, b"later", WriteOptions::default())
            .await
            .unwrap();
        h.storage.crash().unwrap();

        let (blob, len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(len, 10);
        assert_eq!(
            blob.read_at(0, 10, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"freshlater"
        );
    }

    #[tokio::test]
    async fn test_sync_write_does_not_barrier_disjoint_pending_write() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"........", WriteOptions::SYNC)
            .await
            .unwrap();

        blob.write_at(0, b"A", WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(7, b"Z", WriteOptions::SYNC).await.unwrap();
        h.storage.crash().unwrap();

        let (durable, len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(len, 8);
        assert_eq!(
            durable
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"A......Z"
        );
    }

    #[tokio::test]
    async fn test_sync_write_retires_only_overlapping_pending_bytes() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let (other, _) = h.storage.open("partition", b"other").await.unwrap();
        for candidate in [&blob, &other] {
            candidate
                .write_at(0, b"........", WriteOptions::SYNC)
                .await
                .unwrap();
        }

        blob.write_at(0, b"ABCDEFGH", WriteOptions::default())
            .await
            .unwrap();
        other
            .write_at(0, b"12345678", WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(3, b"xy", WriteOptions::SYNC).await.unwrap();
        h.storage.crash().unwrap();

        let (durable, _) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(
            durable
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"ABCxyFGH"
        );
        let (durable, _) = h.inner.open("partition", b"other").await.unwrap();
        assert_eq!(
            durable
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"12345678"
        );
    }

    #[tokio::test]
    async fn test_range_sync_preserves_prefix_retention_across_pending_fragments() {
        let mut exercised = false;
        for seed in 0..64 {
            let h = Harness::with_seed(
                seed,
                Config::default().write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate: probability!(0.5),
                    mode: PartialWriteMode::Prefix,
                }),
            );
            let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
            blob.write_at(0, b"........", WriteOptions::SYNC)
                .await
                .unwrap();
            blob.write_at(0, b"ABCDEFGH", WriteOptions::default())
                .await
                .unwrap();
            blob.write_at(3, b"xy", WriteOptions::SYNC).await.unwrap();

            h.storage.crash().unwrap();
            let (durable, _) = h.inner.open("partition", b"test").await.unwrap();
            let durable = durable
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            if durable.as_ref()[..3].contains(&b'.') {
                exercised = true;
                assert_eq!(&durable.as_ref()[5..], b"...");
            }
        }
        assert!(exercised, "seed sweep must exercise a partial prefix");
    }

    #[tokio::test]
    async fn test_crash_replays_writes_and_resizes_in_issue_order() {
        let retained_resizes = [u64::MAX, 0].repeat(3);
        let h = Harness::with_rng(
            Box::new(ScriptedRng::new(retained_resizes)),
            Config::default()
                .write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate: probability!(1.0),
                    mode: PartialWriteMode::Prefix,
                })
                .resize(ResizeConfig {
                    failure_rate: probability!(0.5),
                    partial_rate: probability!(0.0),
                }),
        );
        let (write_then_resize, _) = h.storage.open("partition", b"first").await.unwrap();
        write_then_resize
            .write_at(0, b"abcdef", WriteOptions::default())
            .await
            .unwrap();
        write_then_resize.resize(3).await.unwrap();
        write_then_resize.resize(5).await.unwrap();

        let (resize_then_write, _) = h.storage.open("partition", b"second").await.unwrap();
        resize_then_write
            .write_at(0, b"abcdef", WriteOptions::SYNC)
            .await
            .unwrap();
        resize_then_write.resize(3).await.unwrap();
        resize_then_write
            .write_at(5, b"X", WriteOptions::default())
            .await
            .unwrap();

        h.storage.crash().unwrap();

        let (first, len) = h.inner.open("partition", b"first").await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(
            first
                .read_at(0, 5, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"abc\0\0"
        );
        let (second, len) = h.inner.open("partition", b"second").await.unwrap();
        assert_eq!(len, 6);
        assert_eq!(
            second
                .read_at(0, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"abc\0\0X"
        );
    }

    #[tokio::test]
    async fn test_partial_sync_write_replays_after_retained_resize() {
        let retained_resize = [u64::MAX, 0];
        let retained_write_bytes = [0, u64::MAX, 0, u64::MAX];
        let h = Harness::with_rng(
            Box::new(ScriptedRng::new(
                retained_resize.into_iter().chain(retained_write_bytes),
            )),
            Config::default().resize(ResizeConfig {
                failure_rate: probability!(0.5),
                partial_rate: probability!(0.0),
            }),
        );
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"abcdefghij", WriteOptions::SYNC)
            .await
            .unwrap();
        blob.resize(3).await.unwrap();
        {
            let mut config = h.config.write();
            config.write_rate = Some(WriteConfig {
                failure_rate: probability!(1.0),
                retention_rate: probability!(0.5),
                mode: PartialWriteMode::Subset,
            });
        }

        assert!(blob.write_at(6, b"WXYZ", WriteOptions::SYNC).await.is_err());
        let (before, _) = h.inner.open("partition", b"test").await.unwrap();
        let before = before
            .read_at(0, 10, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        let mut expected = b"abc".to_vec();
        for (index, replacement) in b"WXYZ".iter().copied().enumerate() {
            let index = index + 6;
            if before.as_ref()[index] != replacement {
                continue;
            }
            expected.resize(index + 1, 0);
            expected[index] = replacement;
        }
        assert!(expected.len() > 3);

        h.storage.crash().unwrap();

        let (durable, len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(len, expected.len() as u64);
        assert_eq!(
            durable
                .read_at(0, expected.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            expected
        );
    }

    #[tokio::test]
    async fn test_preissued_sync_write_survives_failed_partial_resize() {
        let h = Harness::new(Config::default().resize(ResizeConfig {
            failure_rate: probability!(1.0),
            partial_rate: probability!(1.0),
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"abcdefghij", WriteOptions::SYNC)
            .await
            .unwrap();

        let resize_blob = blob.clone();
        let (resize, write) = tokio::join!(biased;
            resize_blob.resize(0),
            blob.write_at(10, b"X", WriteOptions::SYNC),
        );
        assert!(resize.is_err());
        write.unwrap();

        let retained_len = h
            .storage
            .pending
            .lock()
            .iter()
            .find_map(|mutation| match mutation {
                PendingMutation::Resize { len, .. } => Some(*len),
                PendingMutation::Write { .. } | PendingMutation::Sync { .. } => None,
            })
            .unwrap();
        h.storage.crash().unwrap();

        let (durable, len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(len, 11);
        let mut expected = b"abcdefghij".to_vec();
        expected.truncate(retained_len as usize);
        expected.resize(10, 0);
        expected.push(b'X');
        assert_eq!(
            durable
                .read_at(0, 11, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            expected
        );
    }

    #[tokio::test]
    async fn test_partial_sync_write_retires_each_persisted_range() {
        for partial_write_mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
            let h = Harness::new(Config::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(1.0),
                mode: PartialWriteMode::Prefix,
            }));
            let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
            blob.write_at(0, b"........", WriteOptions::SYNC)
                .await
                .unwrap();
            blob.write_at(0, b"ABCDEFGH", WriteOptions::default())
                .await
                .unwrap();
            {
                let mut config = h.config.write();
                config.write_rate = Some(WriteConfig {
                    failure_rate: probability!(1.0),
                    retention_rate: probability!(0.5),
                    mode: partial_write_mode,
                });
            }

            assert!(blob.write_at(2, b"wxyz", WriteOptions::SYNC).await.is_err());
            let (before, _) = h.inner.open("partition", b"test").await.unwrap();
            let before = before
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            h.storage.crash().unwrap();
            let (after, _) = h.inner.open("partition", b"test").await.unwrap();
            let after = after
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            for (index, (&before, &after)) in before
                .as_ref()
                .iter()
                .zip(after.as_ref().iter())
                .enumerate()
            {
                let expected = if before == b'.' {
                    b'A' + index as u8
                } else {
                    before
                };
                assert_eq!(
                    after, expected,
                    "mode={partial_write_mode:?}, index={index}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_full_sync_epoch_is_linearized_with_overlapping_write() {
        run_overlapping_barrier(false).await;
    }

    #[tokio::test]
    async fn test_dropped_start_sync_epoch_is_linearized_with_overlapping_write() {
        run_overlapping_barrier(true).await;
    }

    #[tokio::test]
    async fn test_faulty_storage_no_faults() {
        let h = Harness::new(Config::default());
        run_storage_tests(h.storage).await;
    }

    #[test]
    fn test_probability_endpoints_do_not_consume_randomness() {
        let expected = Harness::with_seed(0, Config::default());
        let expected = expected.storage.ctx.rng.lock().random::<u64>();

        let h = Harness::with_seed(0, Config::default());
        for (probability, outcome) in [(probability!(0.0), false), (probability!(1.0), true)] {
            assert_eq!(h.storage.ctx.roll(probability), outcome);
            for mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
                assert_eq!(
                    h.storage.ctx.retained_bytes(4, (mode, probability)),
                    [outcome; 4]
                );
            }
        }

        assert_eq!(h.storage.ctx.rng.lock().random::<u64>(), expected);
    }

    #[test]
    fn test_prefix_retention_rate_selects_inclusive_prefix() {
        let h = Harness::new(Config::default());
        let mut observed = [false; 5];
        for seed in 0..512 {
            let h = Harness::with_seed(seed, Config::default());
            let retained = h
                .storage
                .ctx
                .retained_bytes(4, (PartialWriteMode::Prefix, probability!(0.5)));
            let prefix_len = retained.iter().take_while(|&&keep| keep).count();
            assert!(retained[prefix_len..].iter().all(|&keep| !keep));
            observed[prefix_len] = true;
        }
        assert!(observed.iter().all(|&seen| seen));

        assert!(
            h.storage
                .ctx
                .retained_bytes(0, (PartialWriteMode::Prefix, probability!(0.5)))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_write_rejects_offset_overflow_before_retention() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(1.0),
            retention_rate: probability!(0.5),
            mode: PartialWriteMode::Subset,
        }));
        let (blob, _) = h.storage.open("partition", b"blob").await.unwrap();
        assert!(matches!(
            blob.write_at(u64::MAX, vec![1, 2], WriteOptions::default())
                .await,
            Err(Error::OffsetOverflow)
        ));
        let (_, len) = h.inner.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 0);
    }

    #[tokio::test]
    async fn test_failed_write_can_retain_every_byte() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(1.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"blob").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"x", WriteOptions::default()).await,
            Err(Error::Io(_))
        ));
        let (durable, len) = h.inner.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 1);
        assert_eq!(
            durable
                .read_at(0, 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"x"
        );
    }

    #[tokio::test]
    async fn test_faulty_blob_forwards_read_options_without_faults() {
        let (inner, recordings) = RecordingContext::new(MemStorage::new(test_pool()));
        let rng = Arc::new(Mutex::new(Box::new(StdRng::seed_from_u64(42)) as BoxDynRng));
        let storage = Storage::new(inner, rng, Arc::new(RwLock::new(Config::default())));
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"data", WriteOptions::default())
            .await
            .unwrap();
        recordings.clear();

        // With fault rates disabled, both read entry points must preserve DONT_CACHE.
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
    }

    #[tokio::test]
    async fn test_faulty_storage_sync_always_fails() {
        let h = Harness::new(Config::default().sync(probability!(1.0)));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();

        assert!(matches!(blob.sync().await, Err(Error::Io(_))));
    }

    #[tokio::test]
    async fn test_faulty_storage_start_sync_always_fails() {
        let h = Harness::new(
            Config::default()
                .write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate: probability!(1.0),
                    mode: PartialWriteMode::Prefix,
                })
                .sync(probability!(1.0)),
        );

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();

        let result = blob.start_sync().await.await;
        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(h.storage.pending.lock().len(), 1);
    }

    #[tokio::test]
    async fn test_faulty_storage_write_always_fails() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(1.0),
            retention_rate: probability!(0.0),
            mode: PartialWriteMode::Prefix,
        }));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_at_sync_write_always_fails() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(1.0),
            retention_rate: probability!(0.0),
            mode: PartialWriteMode::Prefix,
        }));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec(), WriteOptions::SYNC).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_write_at_sync_failure_is_not_durable() {
        let h = Harness::new(Config::default().sync(probability!(1.0)));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        assert!(matches!(
            blob.write_at(0, b"data".to_vec(), WriteOptions::SYNC).await,
            Err(Error::Io(_))
        ));

        let (_reopened, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_empty_write_at_sync_does_not_sync_prior_write() {
        let h = Harness::new(Config::default().sync(probability!(1.0)));

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
    async fn test_empty_unsynced_write_does_not_create_crash_debt() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, Vec::<u8>::new(), WriteOptions::default())
            .await
            .unwrap();
        assert!(h.storage.pending.lock().is_empty());
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
        h.config.write().read_rate = Some(probability!(1.0));

        assert!(matches!(
            blob.read_at(0, 4, ReadOptions::default()).await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_open_always_fails() {
        let h = Harness::new(Config::default().open(probability!(1.0)));

        assert!(matches!(
            h.storage.open("partition", b"test").await,
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
        h.config.write().remove_rate = Some(probability!(1.0));

        assert!(matches!(
            h.storage.remove("partition", Some(b"test")).await,
            Err(Error::Io(_))
        ));
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
        h.config.write().scan_rate = Some(probability!(1.0));

        assert!(matches!(
            h.storage.scan("partition").await,
            Err(Error::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_faulty_storage_determinism() {
        async fn run_ops(seed: u64, rate: Probability) -> Vec<bool> {
            let h = Harness::with_seed(seed, Config::default().open(rate));
            let mut results = Vec::new();
            for i in 0..20 {
                let name = format!("blob{i}");
                results.push(h.storage.open("partition", name.as_bytes()).await.is_ok());
            }
            results
        }

        let results1 = run_ops(42, probability!(0.5)).await;
        let results2 = run_ops(42, probability!(0.5)).await;
        assert_eq!(results1, results2, "Same seed should produce same results");

        let results3 = run_ops(999, probability!(0.5)).await;
        assert_ne!(
            results1, results3,
            "Different seeds should produce different results"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_rate_for() {
        let config = Config::default()
            .open(probability!(0.1))
            .write(WriteConfig {
                failure_rate: probability!(0.3),
                retention_rate: probability!(0.4),
                mode: PartialWriteMode::Subset,
            })
            .resize(ResizeConfig {
                failure_rate: probability!(0.7),
                partial_rate: probability!(0.8),
            })
            .sync(probability!(0.9));

        assert_eq!(config.rate_for(Op::Open), probability!(0.1));
        assert_eq!(config.rate_for(Op::Write), probability!(0.3));
        assert_eq!(config.rate_for(Op::Resize), probability!(0.7));
        assert_eq!(config.rate_for(Op::Sync), probability!(0.9));
    }

    #[tokio::test]
    async fn test_faulty_storage_dynamic_config() {
        let h = Harness::new(Config::default());

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.sync().await.unwrap();

        h.config.write().sync_rate = Some(probability!(1.0));
        assert!(matches!(blob.sync().await, Err(Error::Io(_))));

        h.config.write().sync_rate = Some(probability!(0.0));
        blob.sync().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_retention_is_snapshotted_and_replayed_in_order() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        blob.write_at(0, b"........", WriteOptions::SYNC)
            .await
            .unwrap();

        blob.write_at(0, b"AB", WriteOptions::default())
            .await
            .unwrap();
        h.config.write().write_rate = None;
        blob.write_at(2, b"CD", WriteOptions::default())
            .await
            .unwrap();
        h.config.write().write_rate = Some(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        });
        blob.write_at(1, b"XY", WriteOptions::default())
            .await
            .unwrap();
        h.config.write().write_rate = None;

        h.storage.crash().unwrap();
        let (durable, _) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(
            durable
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"AXY....."
        );

        durable.write_at(0, b"Q", WriteOptions::SYNC).await.unwrap();
        h.storage.crash().unwrap();
        let (durable, _) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(
            durable
                .read_at(0, 8, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"QXY....."
        );
    }

    #[tokio::test]
    async fn test_random_crash_write_is_deterministic_and_inclusive() {
        let first = run_random_crash(12345, 64).await;
        let second = run_random_crash(12345, 64).await;
        let different = run_random_crash(54321, 64).await;
        assert_eq!(first, second);
        assert_ne!(first, different);
        assert!(first.contains(&0));
        assert!(first.contains(&1));

        let mut saw_empty = false;
        let mut saw_full = false;
        for seed in 0..64 {
            match run_random_crash(seed, 1).await.as_slice() {
                [0] => saw_empty = true,
                [1] => saw_full = true,
                other => panic!("unexpected one-byte crash result: {other:?}"),
            }
        }
        assert!(saw_empty && saw_full);
    }

    #[tokio::test]
    async fn failed_partial_write_does_not_barrier_prior_crash_writes() {
        for partial_write_mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
            let mut saw_old = false;
            let mut saw_new = false;
            for seed in 0..64 {
                let h = Harness::with_seed(
                    seed,
                    Config::default().write(WriteConfig {
                        failure_rate: probability!(0.0),
                        retention_rate: probability!(0.5),
                        mode: PartialWriteMode::Subset,
                    }),
                );
                let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
                blob.write_at(0, b"......", WriteOptions::SYNC)
                    .await
                    .unwrap();
                blob.write_at(0, b"AAAA", WriteOptions::default())
                    .await
                    .unwrap();
                {
                    let mut config = h.config.write();
                    config.write_rate = Some(WriteConfig {
                        failure_rate: probability!(1.0),
                        retention_rate: probability!(0.5),
                        mode: partial_write_mode,
                    });
                }

                assert!(
                    blob.write_at(4, b"XY", WriteOptions::default())
                        .await
                        .is_err()
                );
                h.storage.crash().unwrap();

                let (durable, _) = h.inner.open("partition", b"test").await.unwrap();
                let durable = durable
                    .read_at(0, 4, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce();
                saw_old |= durable.as_ref().contains(&b'.');
                saw_new |= durable.as_ref().contains(&b'A');
            }
            assert!(saw_old && saw_new);
        }
    }

    #[tokio::test]
    async fn failed_partial_resize_does_not_barrier_prior_crash_writes() {
        let mut saw_old = false;
        let mut saw_new = false;
        for seed in 0..64 {
            let h = Harness::with_seed(
                seed,
                Config::default().write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate: probability!(0.5),
                    mode: PartialWriteMode::Subset,
                }),
            );
            let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
            blob.write_at(0, b"......", WriteOptions::SYNC)
                .await
                .unwrap();
            blob.write_at(0, b"AAAA", WriteOptions::default())
                .await
                .unwrap();
            {
                let mut config = h.config.write();
                config.resize_rate = Some(ResizeConfig {
                    failure_rate: probability!(1.0),
                    partial_rate: probability!(1.0),
                });
            }

            assert!(blob.resize(8).await.is_err());
            h.storage.crash().unwrap();

            let (durable, len) = h.inner.open("partition", b"test").await.unwrap();
            assert_eq!(len, 7);
            let durable = durable
                .read_at(0, 4, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            saw_old |= durable.as_ref().contains(&b'.');
            saw_new |= durable.as_ref().contains(&b'A');
        }
        assert!(saw_old && saw_new);
    }

    #[tokio::test]
    async fn test_crash_journal_clears_only_after_completed_durability() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();

        blob.write_at(0, b"a", WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(h.storage.pending.lock().len(), 1);
        h.config.write().sync_rate = Some(probability!(1.0));
        assert!(matches!(blob.sync().await, Err(Error::Io(_))));
        assert_eq!(h.storage.pending.lock().len(), 1);

        h.config.write().sync_rate = None;
        blob.sync().await.unwrap();
        assert!(h.storage.pending.lock().is_empty());

        let (other, _) = h.storage.open("partition", b"other").await.unwrap();
        blob.write_at(0, b"b", WriteOptions::default())
            .await
            .unwrap();
        other
            .write_at(0, b"x", WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(h.storage.pending.lock().len(), 2);
        blob.sync().await.unwrap();
        assert_eq!(h.storage.pending.lock().len(), 1);
        other.sync().await.unwrap();
        assert!(h.storage.pending.lock().is_empty());

        blob.write_at(0, b"b", WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(h.storage.pending.lock().len(), 1);
        blob.start_sync().await.await.unwrap();
        assert!(h.storage.pending.lock().is_empty());

        blob.write_at(0, b"c", WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(h.storage.pending.lock().len(), 1);
        blob.write_at(0, b"d", WriteOptions::SYNC).await.unwrap();
        assert!(h.storage.pending.lock().is_empty());
    }

    #[tokio::test]
    async fn test_sync_failure_journals_the_successful_inner_write() {
        let h = Harness::new(
            Config::default()
                .write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate: probability!(1.0),
                    mode: PartialWriteMode::Prefix,
                })
                .sync(probability!(1.0)),
        );
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        assert!(matches!(
            blob.write_at(0, b"data", WriteOptions::SYNC).await,
            Err(Error::Io(_))
        ));
        assert_eq!(h.storage.pending.lock().len(), 1);

        h.storage.crash().unwrap();
        let (durable, len) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(
            durable
                .read_at(0, 4, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"data"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_zero_write_retention_preserves_nothing() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(1.0),
            retention_rate: probability!(0.0),
            mode: PartialWriteMode::Prefix,
        }));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let data = b"hello world".to_vec();
        let result = blob
            .write_at(0, data.clone(), WriteOptions::default())
            .await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write_subset_can_be_non_prefix() {
        let original = b"abcdefghijklmnop";
        let replacement = b"ABCDEFGHIJKLMNOP";
        let observed = run_subset_overwrite(42, original, replacement).await;

        let retained: Vec<_> = observed
            .iter()
            .zip(original)
            .zip(replacement)
            .map(|((&actual, &old), &new)| {
                assert!(actual == old || actual == new);
                actual == new
            })
            .collect();
        assert!(retained.iter().any(|&keep| keep));
        assert!(retained.iter().any(|&keep| !keep));

        let mut omitted = false;
        let non_prefix = retained.into_iter().any(|keep| {
            if keep {
                omitted
            } else {
                omitted = true;
                false
            }
        });
        assert!(non_prefix, "expected a retained byte after an omitted byte");
    }

    #[tokio::test]
    async fn test_faulty_storage_write_retention_rate_endpoints() {
        for (retention_rate, expected) in [
            (probability!(0.0), b"old".as_slice()),
            (probability!(1.0), b"new".as_slice()),
        ] {
            for mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
                let failed = Harness::new(Config::default().write(WriteConfig {
                    failure_rate: probability!(1.0),
                    retention_rate,
                    mode,
                }));
                let (blob, _) = failed.storage.open("partition", b"failed").await.unwrap();
                blob.write_at(0, b"new", WriteOptions::SYNC)
                    .await
                    .unwrap_err();
                let (durable, len) = failed.inner.open("partition", b"failed").await.unwrap();
                if retention_rate.is_one() {
                    assert_eq!(len, 3);
                    assert_eq!(
                        durable
                            .read_at(0, 3, ReadOptions::default())
                            .await
                            .unwrap()
                            .coalesce(),
                        expected
                    );
                } else {
                    assert_eq!(len, 0);
                }

                let crashed = Harness::new(Config::default().write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate,
                    mode,
                }));
                let (blob, _) = crashed.storage.open("partition", b"crashed").await.unwrap();
                blob.write_at(0, b"old", WriteOptions::SYNC).await.unwrap();
                blob.write_at(0, b"new", WriteOptions::default())
                    .await
                    .unwrap();
                crashed.storage.crash().unwrap();
                let (durable, len) = crashed.inner.open("partition", b"crashed").await.unwrap();
                assert_eq!(len, 3);
                assert_eq!(
                    durable
                        .read_at(0, 3, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce(),
                    expected
                );
            }
        }
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_write_subset_same_seed_is_deterministic() {
        let original = vec![0x11; 64];
        let replacement = vec![0xAA; 64];

        let first = run_subset_overwrite(12345, &original, &replacement).await;
        let second = run_subset_overwrite(12345, &original, &replacement).await;

        assert_eq!(first, second);
        assert!(first.contains(&0x11));
        assert!(first.contains(&0xAA));
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_grow() {
        let h = Harness::new(Config::default().resize(ResizeConfig {
            failure_rate: probability!(1.0),
            partial_rate: probability!(1.0),
        }));

        let (blob, initial_size) = h.storage.open("partition", b"test").await.unwrap();
        assert_eq!(initial_size, 0);

        let target_size = 100u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));
        h.storage.crash().unwrap();

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
            cfg.resize_rate = Some(ResizeConfig {
                failure_rate: probability!(1.0),
                partial_rate: probability!(1.0),
            });
        }

        let target_size = 10u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));
        h.storage.crash().unwrap();

        let (_, actual_size) = h.inner.open("partition", b"test").await.unwrap();
        assert!(
            actual_size > target_size && actual_size < 100,
            "Expected partial shrink: size {actual_size} should be between {target_size} and 100"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_disabled() {
        let h = Harness::new(Config::default().resize(ResizeConfig {
            failure_rate: probability!(1.0),
            partial_rate: probability!(0.0),
        }));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob.resize(100).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "Expected no resize when partial rate is 0");
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_same_size() {
        let h = Harness::new(Config::default().resize(ResizeConfig {
            failure_rate: probability!(1.0),
            partial_rate: probability!(1.0),
        }));

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
            cfg.resize_rate = Some(ResizeConfig {
                failure_rate: probability!(1.0),
                partial_rate: probability!(1.0),
            });
        }

        let target_size = 10u64;
        let result = blob.resize(target_size).await;

        assert!(matches!(result, Err(Error::Io(_))));
        h.storage.crash().unwrap();

        let (_, actual_size) = h.inner.open("partition", b"test").await.unwrap();
        assert!(
            actual_size > target_size && actual_size < 50,
            "Expected partial shrink from 50: size {actual_size} should be between {target_size} and 50"
        );
    }

    #[tokio::test]
    async fn test_faulty_storage_partial_resize_one_byte_difference() {
        let h = Harness::new(Config::default().resize(ResizeConfig {
            failure_rate: probability!(1.0),
            partial_rate: probability!(1.0),
        }));

        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let result = blob.resize(1).await;

        assert!(matches!(result, Err(Error::Io(_))));

        let (_, size) = h.inner.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0);
    }
}
