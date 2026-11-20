//! A storage wrapper that injects deterministic faults for testing crash recovery.

use super::memory;
use crate::{
    BlobVersion, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    deterministic::BoxDynRng,
};
use bytes::Buf;
use commonware_utils::{
    Probability, probability,
    sync::{AsyncMutex, Mutex, RwLock},
};
use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use rand::RngExt as _;
use std::{
    any::Any,
    collections::{BTreeMap, HashSet},
    future::poll_fn,
    io::Error as IoError,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
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
///
/// Per the [crate::Blob] durability contract, both modes leave bytes outside the written
/// range untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartialWriteMode {
    /// Retain bytes from the beginning of the write until the first omitted byte.
    Prefix,

    /// Independently select each submitted byte for retention.
    Subset,
}

/// Fault configuration for `write_at` operations and byte retention from failed writes or
/// successful unsynchronized writes when a crash is simulated. A successful reopen reads only
/// the blob's durable contents and retires its pending crash outcomes.
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
    /// probability that a successful unsynchronized resize survives a simulated crash. A
    /// successful reopen of the blob retires that outcome.
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

    /// Failure rate for nonempty reads. In the deterministic runner, invalid ranges still
    /// return [Error::OffsetOverflow]. A valid range may return an injected error instead of
    /// [Error::BlobInsufficientLength].
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

    /// Probability that a pending `write_at` or `resize` is passed over each time it could
    /// take effect.
    ///
    /// When set, a mutation is accepted on its first poll and then takes effect at a later
    /// point chosen from the shared RNG: a poll of its own future, or a later storage call that
    /// drives pending mutations. Mutations pending at the same time therefore take effect in any
    /// order, and dropping a mutation's future does not cancel it, so it may take effect after
    /// later operations complete, as on the io_uring and Tokio backends. A mutation's future
    /// completes only once it has taken effect, opening a blob first applies every mutation still
    /// pending on it, and a simulated crash discards mutations that have not taken effect. Unset
    /// or zero, mutations take effect when they are first polled, in call order.
    ///
    /// Must be less than one, or a pending mutation never takes effect. Opening a blob requires
    /// each of its pending mutations to finish in one poll, as the in-memory storage of the
    /// deterministic runtime does.
    pub reorder_rate: Option<Probability>,
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

    /// Set the rate at which pending mutations are passed over. See [`Self::reorder_rate`].
    pub const fn reorder(mut self, rate: Probability) -> Self {
        self.reorder_rate = Some(rate);
        self
    }

    /// The reorder rate, if mutations are deferred at all. Panics on a rate of one, which would
    /// leave every mutation pending forever.
    fn deferral(&self) -> Option<Probability> {
        let rate = self.reorder_rate.filter(|rate| !rate.is_zero())?;
        assert!(!rate.is_one(), "storage reorder rate must be less than one");
        Some(rate)
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
        blob: Arc<B>,
        offset: u64,
        bufs: IoBufs,
        retention: Arc<PendingWriteRetention>,
        selection_offset: usize,
    },
    /// A successful resize already selected to survive a simulated crash.
    Resize {
        generation: Arc<FileGeneration>,
        blob: Arc<B>,
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

/// Evidence detached by namespace operations or full syncs for disposal after unlocking.
pub(crate) struct Retired<B> {
    _mutations: Vec<PendingMutation<B>>,
}

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

/// A `write_at` or `resize` accepted on its first poll that may not have taken effect yet
/// (see [`Config::reorder_rate`]). It stays accepted when its future is dropped.
struct Accepted {
    /// File the mutation targets, so that opening it can apply the mutation first.
    key: FileKey,
    /// The mutation, absent once it has taken effect or while a driver polls it.
    work: Mutex<Option<BoxFuture<'static, Result<(), Error>>>>,
    /// The mutation's result, until its future takes it.
    result: Mutex<Option<Result<(), Error>>>,
    /// Whether the mutation has taken effect.
    done: AtomicBool,
}

impl Accepted {
    fn new(key: FileKey, work: BoxFuture<'static, Result<(), Error>>) -> Self {
        Self {
            key,
            work: Mutex::new(Some(work)),
            result: Mutex::new(None),
            done: AtomicBool::new(false),
        }
    }

    /// Poll the mutation once, returning whether it has taken effect.
    fn drive(&self) -> bool {
        // A missing mutation has taken effect, or another driver is polling it.
        let Some(mut work) = self.work.lock().take() else {
            return self.is_done();
        };
        match work.poll_unpin(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => {
                *self.result.lock() = Some(result);
                self.done.store(true, Ordering::Release);
                true
            }
            Poll::Pending => {
                *self.work.lock() = Some(work);
                false
            }
        }
    }

    /// Whether the mutation has taken effect.
    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

/// Mutations accepted but not yet applied, shared by every blob of one storage.
type AcceptedMutations = Arc<Mutex<Vec<Arc<Accepted>>>>;

/// Drive pending mutations: every one on `only`'s file when given, otherwise each with
/// probability one minus the reorder rate. Draws nothing from the RNG while none is pending.
fn settle(accepted: &AcceptedMutations, ctx: &Oracle, only: Option<&FileKey>) {
    // Drive a snapshot without holding the list, since a mutation may record crash evidence.
    let pending = accepted.lock().clone();
    if pending.is_empty() {
        return;
    }

    // Mutations left pending after reordering is disabled take effect at once.
    let rate = ctx.config.read().deferral();
    for mutation in &pending {
        let due = only.map_or_else(
            || rate.is_none_or(|rate| !ctx.roll(rate)),
            |key| mutation.key == *key,
        );
        if due {
            let applied = mutation.drive();
            assert!(
                applied || only.is_none(),
                "a pending mutation must apply before its blob opens again"
            );
        }
    }
    accepted.lock().retain(|mutation| !mutation.is_done());
}

fn clear_pending<B>(
    pending: &PendingMutations<B>,
    generations: &[Arc<FileGeneration>],
) -> Retired<B> {
    let mut pending = pending.lock();
    let retired = pending
        .extract_if(.., |mutation| {
            generations
                .iter()
                .any(|generation| Arc::ptr_eq(mutation.generation(), generation))
        })
        .collect();
    Retired {
        _mutations: retired,
    }
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
    let retired: Vec<_> = pending.extract_if(.., |mutation| {
        let is_target = matches!(mutation, PendingMutation::Sync { sync: candidate, .. } if Arc::ptr_eq(candidate, sync));
        let retire = is_target
            || (succeeded
                && index < cut
                && Arc::ptr_eq(mutation.generation(), &sync.generation));
        index += 1;
        retire
    }).collect();
    drop(pending);
    drop(retired);
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
/// Uses a shared RNG for determinism. With arbitrary backends, an injected fault can
/// take precedence over backend-specific range validation.
#[derive(Clone)]
pub struct Storage<S: crate::Storage> {
    inner: S,
    ctx: Oracle,
    pending: PendingMutations<S::Blob>,
    generations: FileGenerations,
    accepted: AcceptedMutations,
}

impl<S: crate::Storage> Storage<S> {
    /// Create a new faulty storage wrapper.
    pub fn new(inner: S, rng: Arc<Mutex<BoxDynRng>>, config: Arc<RwLock<Config>>) -> Self {
        Self {
            inner,
            ctx: Oracle { rng, config },
            pending: Arc::new(Mutex::new(Vec::new())),
            generations: Arc::new(Mutex::new(BTreeMap::new())),
            accepted: Arc::new(Mutex::new(Vec::new())),
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
        let mut blob = Blob::new(
            self.ctx.clone(),
            self.pending.clone(),
            generation,
            inner,
            size,
        );
        blob.accepted = self.accepted.clone();
        blob.key = key;
        blob
    }

    /// Retires generations and pending mutations for one file or an entire partition.
    fn retire_names(&self, partition: &str, name: Option<&[u8]>) -> Retired<S::Blob> {
        let retired = {
            let mut generations = self.generations.lock();
            match name {
                Some(name) => generations
                    .remove(&(partition.to_string(), name.to_vec()))
                    .and_then(|generation| generation.upgrade())
                    .into_iter()
                    .collect::<Vec<_>>(),
                None => generations
                    .extract_if(.., |(candidate, _), _| candidate == partition)
                    .filter_map(|(_, generation)| generation.upgrade())
                    .collect(),
            }
        };
        clear_pending(&self.pending, &retired)
    }

    /// Retire the removed file's crash evidence without destroying its byte owners.
    pub(crate) async fn remove_retired(
        &self,
        partition: &str,
        name: Option<&[u8]>,
    ) -> Result<Retired<S::Blob>, Error> {
        settle(&self.accepted, &self.ctx, None);
        if self.ctx.should_fail(Op::Remove) {
            return Err(injected_io_error().into());
        }
        self.inner.remove(partition, name).await?;
        Ok(self.retire_names(partition, name))
    }
}

impl Storage<memory::Storage> {
    /// Retire crash evidence excluded from the durable snapshot admitted by a successful open.
    /// The caller holds the logical namespace guard through admission and retirement.
    pub(crate) fn admit(
        &self,
        partition: &str,
        name: &[u8],
    ) -> Retired<crate::storage::memory::Blob> {
        let generation = self
            .generations
            .lock()
            .get(&(partition.to_owned(), name.to_vec()))
            .and_then(Weak::upgrade)
            .expect("an admitted blob retains its file generation");
        clear_pending(&self.pending, std::slice::from_ref(&generation))
    }

    /// Replay selected crash outcomes in issue order. Mutations that have not taken effect are
    /// discarded, as if the crash came first.
    pub(crate) fn crash(&self) -> Result<(), Error> {
        drop(std::mem::take(&mut *self.accepted.lock()));
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
        versions: std::ops::RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        // An earlier open's pending mutations take effect before the blob opens again.
        settle(
            &self.accepted,
            &self.ctx,
            Some(&(partition.to_string(), name.to_vec())),
        );
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
        drop(self.remove_retired(partition, name).await?);
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        settle(&self.accepted, &self.ctx, None);
        if self.ctx.should_fail(Op::Scan) {
            return Err(injected_io_error().into());
        }
        self.inner.scan(partition).await
    }
}

/// A blob wrapper that injects deterministic faults based on configuration.
pub struct Blob<B: crate::Blob> {
    inner: Arc<B>,
    ctx: Oracle,
    pending: PendingMutations<B>,
    generation: Arc<FileGeneration>,
    /// Tracked size for partial resize support.
    size: Arc<AtomicU64>,
    /// Mutations accepted but not yet applied, shared with the blob's storage.
    accepted: AcceptedMutations,
    /// File the blob opens.
    key: FileKey,
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
            inner: Arc::new(inner),
            ctx,
            pending,
            generation,
            size: Arc::new(AtomicU64::new(size)),
            accepted: Arc::new(Mutex::new(Vec::new())),
            key: (String::new(), Vec::new()),
        }
    }

    /// Another handle on this blob's state, for a mutation that can outlive its call. It leaves
    /// out the shared list of accepted mutations, which would otherwise keep the mutation that
    /// holds this handle alive through the list.
    fn handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            ctx: self.ctx.clone(),
            pending: self.pending.clone(),
            generation: self.generation.clone(),
            size: self.size.clone(),
            accepted: Arc::new(Mutex::new(Vec::new())),
            key: self.key.clone(),
        }
    }

    /// Drive mutations accepted earlier (see [`Config::reorder_rate`]).
    fn drive_pending(&self) {
        settle(&self.accepted, &self.ctx, None);
    }

    /// Apply `mutation` now, or accept it to take effect later when mutations are reordered
    /// (see [`Config::reorder_rate`]).
    async fn mutate(&self, mutation: BoxFuture<'static, Result<(), Error>>) -> Result<(), Error> {
        if self.ctx.config.read().deferral().is_none() {
            self.drive_pending();
            return mutation.await;
        }

        // From here on the mutation takes effect whether or not this future is polled again.
        let accepted = Arc::new(Accepted::new(self.key.clone(), mutation));
        self.accepted.lock().push(accepted.clone());
        poll_fn(|cx| {
            // Each poll drives the pending mutations, this one included, passing over each at
            // the reorder rate.
            self.drive_pending();
            if accepted.is_done() {
                return Poll::Ready(
                    accepted
                        .result
                        .lock()
                        .take()
                        .expect("an applied mutation keeps its result for its future"),
                );
            }

            // Only polls and later storage calls drive the mutation, so ask to be polled again.
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }

    fn memory_blob(&self) -> Option<&memory::Blob> {
        (self.inner.as_ref() as &dyn Any).downcast_ref()
    }

    /// Validate a nonempty write's range as the wrapped storage would, without sampling faults.
    fn write_range(&self, offset: u64, len: u64) -> Result<(), Error> {
        if let Some(blob) = self.memory_blob() {
            blob.write_range(offset, len)?;
        } else {
            offset.checked_add(len).ok_or(Error::OffsetOverflow)?;
        }
        Ok(())
    }

    fn preflight_read(&self, offset: u64, len: usize) -> Result<(), Error> {
        if len == 0 {
            return Ok(());
        }
        if let Some(blob) = self.memory_blob() {
            blob.read_offset(offset, len)?;
        }
        if self.ctx.should_fail(Op::Read) {
            return Err(injected_io_error().into());
        }
        Ok(())
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
        let mut retired = Vec::new();
        let mut follows_resize = false;
        for mutation in mutations {
            if !Arc::ptr_eq(mutation.generation(), &self.generation) {
                retained.push(mutation);
                continue;
            }
            let (write_generation, write_blob, write_offset, mut bufs, retention, selection) =
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
                    selection_offset: selection,
                });
                continue;
            }

            let prefix_len = usize::try_from(overlap_start - write_offset)
                .expect("a pending-write subrange fits its source buffer");
            let prefix = bufs.split_to(prefix_len);
            let overlap_len = usize::try_from(overlap_end - overlap_start)
                .expect("an overlapping subrange fits its source buffer");
            retired.push(bufs.split_to(overlap_len));
            if prefix_len != 0 {
                retained.push(PendingMutation::Write {
                    generation: write_generation.clone(),
                    blob: write_blob.clone(),
                    offset: write_offset,
                    bufs: prefix,
                    retention: retention.clone(),
                    selection_offset: selection,
                });
            }
            if overlap_end < write_end {
                let suffix_start = usize::try_from(overlap_end - write_offset)
                    .expect("a pending-write subrange fits its source buffer");
                retained.push(PendingMutation::Write {
                    generation: write_generation,
                    blob: write_blob,
                    offset: overlap_end,
                    bufs,
                    retention,
                    selection_offset: selection
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
        drop(pending);
        drop(retired);
    }

    /// Apply a `write_at`, injecting its faults and recording its crash evidence.
    async fn write_now(
        &self,
        offset: u64,
        bufs: IoBufs,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let total_bytes = bufs.remaining() as u64;
        if total_bytes == 0 {
            return self.inner.write_at(offset, bufs, options).await;
        }
        let sync = options.contains(WriteOptions::SYNC);
        self.write_range(offset, total_bytes)?;
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

    /// Apply a `resize`, injecting its faults and recording its crash evidence.
    async fn resize_now(&self, len: u64) -> Result<(), Error> {
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
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.drive_pending();
        self.preflight_read(offset, len)?;
        self.inner.read_at(offset, len, options).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        let bufs = bufs.into();
        assert!(
            len == 0 || len <= bufs.capacity(),
            "read length exceeds buffer capacity"
        );
        self.drive_pending();
        self.preflight_read(offset, len)?;
        self.inner.read_at_buf(offset, len, bufs, options).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        // Empty and invalid writes are settled at the call, so only real mutations are accepted.
        let bufs = bufs.into();
        let total_bytes = bufs.remaining() as u64;
        if total_bytes == 0 {
            return self.write_now(offset, bufs, options).await;
        }
        self.write_range(offset, total_bytes)?;
        let blob = self.handle();
        self.mutate(async move { blob.write_now(offset, bufs, options).await }.boxed())
            .await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        // An invalid length is settled at the call, so only real mutations are accepted.
        if let Some(blob) = self.memory_blob() {
            blob.resize_len(len)?;
        }
        let blob = self.handle();
        self.mutate(async move { blob.resize_now(len).await }.boxed())
            .await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.drive_pending();
        if self.ctx.should_fail(Op::Sync) {
            return Err(injected_io_error().into());
        }
        let mutation = self.generation.mutation.lock().await;
        self.inner.sync().await?;
        let retired = clear_pending(&self.pending, std::slice::from_ref(&self.generation));
        drop(mutation);
        drop(retired);
        Ok(())
    }

    async fn start_sync(&self) -> Handle<()> {
        self.drive_pending();
        if self.ctx.should_fail(Op::Sync) {
            return Handle::ready(Err(injected_io_error().into()));
        }
        let mutation = self.generation.mutation.lock().await;
        // Record the cut in mutation order. Later writes must remain pending even if
        // they arrive before we observe this sync's result.
        let sync = Arc::new(PendingSync {
            generation: self.generation.clone(),
            completion: self.inner.start_sync().await.shared(),
        });
        self.pending
            .lock()
            .push(PendingMutation::Sync { sync: sync.clone() });
        drop(mutation);

        let pending = self.pending.clone();
        let mut completion = sync.completion.clone().map(move |result| {
            resolve_pending_sync(&pending, &sync, result.is_ok());
            result
        });
        // Retire an already completed sync even if the caller discards its handle.
        // Polling and dropping a backing completion may run backend code.
        (&mut completion)
            .now_or_never()
            .map_or_else(|| Handle::from_future(completion), Handle::ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, IoBufMut, Runner, Spawner, Storage as _,
        mocks::RecordingContext,
        storage::{memory::Storage as MemStorage, tests::run_storage_tests},
    };
    use commonware_utils::ScriptedRng;
    use futures::task::noop_waker;
    use rand::{SeedableRng, rngs::StdRng};
    use rstest::rstest;
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

    struct OperationGate<B, C> {
        inner: Arc<B>,
        context: Arc<C>,
        pause_after_write: bool,
        armed: Arc<AtomicBool>,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        completed: Arc<tokio::sync::Notify>,
    }

    impl<B, C> Clone for OperationGate<B, C> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
                context: self.context.clone(),
                pause_after_write: self.pause_after_write,
                armed: self.armed.clone(),
                started: self.started.clone(),
                release: self.release.clone(),
                completed: self.completed.clone(),
            }
        }
    }

    impl<B, C> OperationGate<B, C> {
        async fn pause(&self, after_write: bool) {
            if self.pause_after_write == after_write && self.armed.swap(false, Ordering::Relaxed) {
                self.started.notify_one();
                self.release.notified().await;
            }
        }
    }

    impl<B: crate::Blob, C: Spawner> crate::Blob for OperationGate<B, C> {
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
            drop(self.context.child("sync").spawn(move |_| async move {
                let _ = sender.send(gate.sync().await);
                gate.completed.notify_one();
            }));
            Handle::from_receiver(receiver)
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let waker = noop_waker();
        future.poll(&mut Context::from_waker(&waker))
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
            let inner = MemStorage::new();
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

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(target_os = "linux", case::iouring(crate::iouring::Runner::default()))]
    fn test_start_sync_returns_before_backing_completion<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
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
                inner: Arc::new(inner),
                context: Arc::new(context),
                pause_after_write: false,
                armed: Arc::new(AtomicBool::new(true)),
                started: started.clone(),
                release: release.clone(),
                completed: Arc::new(tokio::sync::Notify::new()),
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
        });
    }

    async fn run_overlapping_barrier(context: impl Spawner, start: bool) {
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
        let completed = Arc::new(tokio::sync::Notify::new());
        let gated = OperationGate {
            inner: Arc::new(inner),
            context: Arc::new(context.child("gate")),
            pause_after_write: false,
            armed: Arc::new(AtomicBool::new(true)),
            started: started.clone(),
            release: release.clone(),
            completed: completed.clone(),
        };
        let pending = Arc::new(Mutex::new(Vec::new()));
        let blob = Blob::new(
            h.storage.ctx.clone(),
            pending.clone(),
            Arc::new(FileGeneration::new()),
            gated,
            4,
        );
        let blob = Arc::new(blob);

        let barrier_blob = blob.clone();
        let barrier = context.child("barrier").spawn(move |_| async move {
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
            // Wait for backing durability after dropping its completion handle.
            completed.notified().await;
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

    #[test]
    fn test_completed_backing_write_cannot_record_after_later_full_sync() {
        crate::tokio::Runner::default().start(|context| async move {
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
                inner: Arc::new(inner),
                context: Arc::new(context),
                pause_after_write: true,
                armed: Arc::new(AtomicBool::new(true)),
                started: started.clone(),
                release: release.clone(),
                completed: Arc::new(tokio::sync::Notify::new()),
            };
            let pending = Arc::new(Mutex::new(Vec::new()));
            let blob = Blob::new(
                h.storage.ctx.clone(),
                pending.clone(),
                Arc::new(FileGeneration::new()),
                gated,
                5,
            );
            let blob = Arc::new(blob);

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
        });
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
    async fn test_full_sync_releases_mutation_guard_before_retiring_buffers() {
        struct Owner(Arc<FileGeneration>, Arc<AtomicBool>);

        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                b"x"
            }
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                self.1
                    .store(self.0.mutation.try_lock().is_ok(), Ordering::Relaxed);
            }
        }

        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        for start in [true, false] {
            let unlocked = Arc::new(AtomicBool::new(false));
            let buf = bytes::Bytes::from_owner(Owner(blob.generation.clone(), unlocked.clone()));
            blob.write_at(0, buf, WriteOptions::default())
                .await
                .unwrap();
            if start {
                drop(blob.start_sync().await);
            } else {
                blob.sync().await.unwrap();
            }
            assert!(unlocked.load(Ordering::Relaxed), "start_sync = {start}");
        }
    }

    #[tokio::test]
    async fn test_start_sync_observes_the_backing_completion_without_the_mutation_lock() {
        let h = Harness::new(Config::default());
        let (inner, _) = h.storage.open("partition", b"test").await.unwrap();
        let generation = inner.generation.clone();
        let (delayed, gate) = crate::mocks::DelayedSyncBlob::new(inner);
        gate.unblock();
        let pending = Arc::new(Mutex::new(Vec::new()));
        let blob = Blob::new(
            h.storage.ctx.clone(),
            pending.clone(),
            generation,
            delayed,
            0,
        );

        // This backing completion takes the same mutation lock when polled. It can finish
        // during admission only after the wrapper releases that lock.
        drop(blob.start_sync().await);
        assert!(pending.lock().is_empty());
    }

    #[tokio::test]
    async fn test_dropped_ready_start_sync_resolves_at_admission() {
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let (other, _) = h.storage.open("partition", b"other").await.unwrap();
        other
            .write_at(0, b"x", WriteOptions::default())
            .await
            .unwrap();

        // A sync that completes during admission releases its cut and the writes it covers
        // without being observed.
        for round in 0..8u8 {
            blob.write_at(0, vec![round; 4], WriteOptions::default())
                .await
                .unwrap();
            drop(blob.start_sync().await);
            assert_eq!(h.storage.pending.lock().len(), 1);
        }

        // A sync that fails during admission leaves earlier writes pending without retaining
        // its cut.
        blob.write_at(0, b"lost", WriteOptions::default())
            .await
            .unwrap();
        h.inner.remove("partition", Some(b"test")).await.unwrap();
        let completion = blob.start_sync().await;
        let unresolved = |pending: &[PendingMutation<_>]| {
            pending
                .iter()
                .map(|mutation| matches!(mutation, PendingMutation::Write { .. }))
                .collect::<Vec<_>>()
        };
        assert_eq!(unresolved(&h.storage.pending.lock()), [true, true]);
        assert!(matches!(completion.await, Err(Error::BlobMissing(..))));
        assert_eq!(unresolved(&h.storage.pending.lock()), [true, true]);
    }

    #[test]
    fn test_dropped_pending_start_sync_keeps_its_crash_cut() {
        crate::tokio::Runner::default().start(|context| async move {
            let h = Harness::new(Config::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(1.0),
                mode: PartialWriteMode::Prefix,
            }));
            let (inner, _) = h.inner.open("partition", b"pending").await.unwrap();
            let started = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let completed = Arc::new(tokio::sync::Notify::new());
            let gated = OperationGate {
                inner: Arc::new(inner),
                context: Arc::new(context),
                pause_after_write: false,
                armed: Arc::new(AtomicBool::new(true)),
                started: started.clone(),
                release: release.clone(),
                completed: completed.clone(),
            };
            let pending = Arc::new(Mutex::new(Vec::new()));
            let blob = Blob::new(
                h.storage.ctx.clone(),
                pending.clone(),
                Arc::new(FileGeneration::new()),
                gated,
                0,
            );
            blob.write_at(0, b"data", WriteOptions::default())
                .await
                .unwrap();

            // Crash replay still owes the write while the unobserved sync is incomplete.
            drop(blob.start_sync().await);
            started.notified().await;
            let cut = {
                let pending = pending.lock();
                let [
                    PendingMutation::Write { .. },
                    PendingMutation::Sync { sync },
                ] = &pending[..]
                else {
                    panic!("an incomplete sync must retain its cut after the write it covers");
                };
                sync.clone()
            };
            assert!(!cut.completed_successfully());

            // Once the backing sync completes, the retained cut covers the write.
            release.notify_one();
            completed.notified().await;
            assert!(cut.completed_successfully());
            assert_eq!(pending.lock().len(), 2);
        });
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

        let (resize, write) = tokio::join!(biased;
            blob.resize(0),
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

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(target_os = "linux", case::iouring(crate::iouring::Runner::default()))]
    fn test_full_sync_epoch_is_linearized_with_overlapping_write<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            run_overlapping_barrier(context, false).await;
        });
    }

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(target_os = "linux", case::iouring(crate::iouring::Runner::default()))]
    fn test_dropped_start_sync_epoch_is_linearized_with_overlapping_write<R: Runner>(
        #[case] runner: R,
    ) where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            run_overlapping_barrier(context, true).await;
        });
    }

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(target_os = "linux", case::iouring(crate::iouring::Runner::default()))]
    fn test_faulty_storage_no_faults<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let h = Harness::new(Config::default());
            run_storage_tests(context, h.storage).await;
        });
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
        let (inner, recordings) = RecordingContext::new(MemStorage::new());
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
    async fn test_faulty_storage_empty_writes_skip_faults_and_bookkeeping() {
        let h = Harness::new(
            Config::default()
                .write(WriteConfig {
                    failure_rate: probability!(1.0),
                    retention_rate: probability!(1.0),
                    mode: PartialWriteMode::Prefix,
                })
                .sync(probability!(1.0)),
        );
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        for options in [WriteOptions::default(), WriteOptions::SYNC] {
            blob.write_at(8, Vec::<u8>::new(), options).await.unwrap();
            assert!(matches!(
                blob.write_at(u64::MAX, Vec::<u8>::new(), options).await,
                Err(Error::OffsetOverflow)
            ));
        }
        assert_eq!(blob.size.load(Ordering::Relaxed), 0);
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

        assert!(
            blob.read_at(5, 0, ReadOptions::default())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            blob.read_at(0, 4, ReadOptions::default()).await,
            Err(Error::Io(_))
        ));
        assert!(matches!(
            blob.read_at(i64::MAX as u64, 4, ReadOptions::default())
                .await,
            Err(Error::OffsetOverflow)
        ));
    }

    #[tokio::test]
    async fn test_opaque_storage_read_fault_can_precede_backing_range_validation() {
        let rng: BoxDynRng = Box::new(StdRng::seed_from_u64(42));
        let config = Arc::new(RwLock::new(Config::default().read(probability!(1.0))));
        let storage = Storage::new(
            crate::mocks::Storage::new(),
            Arc::new(Mutex::new(rng)),
            config.clone(),
        );
        let (blob, _) = storage.open("partition", b"test").await.unwrap();
        let offset = i64::MAX as u64;
        let options = ReadOptions::default();

        // Only directly wrapped memory blobs can preflight the backend's range.
        assert!(matches!(
            blob.read_at(offset, 4, options).await,
            Err(Error::Io(_))
        ));
        assert!(matches!(
            blob.read_at_buf(offset, 4, IoBufMut::with_capacity(4), options)
                .await,
            Err(Error::Io(_))
        ));
        config.write().read_rate = None;
        assert!(matches!(
            blob.read_at(offset, 4, options).await,
            Err(Error::OffsetOverflow)
        ));
    }

    #[tokio::test]
    #[should_panic(expected = "read length exceeds buffer capacity")]
    async fn test_read_fault_cannot_mask_insufficient_capacity() {
        let h = Harness::new(Config::default().read(probability!(1.0)));
        let (blob, _) = h.storage.open("partition", b"test").await.unwrap();
        let _ = blob
            .read_at_buf(u64::MAX, 1, IoBufMut::default(), ReadOptions::default())
            .await;
    }

    #[test]
    fn test_invalid_memory_reads_do_not_sample_faults() {
        crate::deterministic::Runner::default().start(|_| async {
            // The first sample lets a read through and the second injects a fault.
            let rng: BoxDynRng = ScriptedRng::new([u64::MAX, 0, 0]).into();
            let storage = Storage::new(
                MemStorage::new(),
                Arc::new(Mutex::new(rng)),
                Arc::new(RwLock::new(Config::default().read(probability!(0.5)))),
            );
            let (blob, _) = storage.open("partition", b"test").await.unwrap();
            blob.write_at(0, b"data", WriteOptions::default())
                .await
                .unwrap();

            let options = ReadOptions::default();
            // Empty reads still validate their start, but never consume a fault sample.
            assert!(blob.read_at(5, 0, options).await.unwrap().is_empty());
            assert!(matches!(
                blob.read_at(u64::MAX, 0, options).await,
                Err(Error::OffsetOverflow)
            ));
            assert!(
                blob.read_at_buf(5, 0, IoBufMut::with_capacity(4), options)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                blob.read_at_buf(u64::MAX, 0, IoBufMut::default(), options)
                    .await,
                Err(Error::OffsetOverflow)
            ));
            assert!(matches!(
                blob.read_at(u64::MAX, 4, options).await,
                Err(Error::OffsetOverflow)
            ));
            assert!(matches!(
                blob.read_at_buf(u64::MAX, 4, IoBufMut::with_capacity(4), options)
                    .await,
                Err(Error::OffsetOverflow)
            ));
            let read = blob.read_at(0, 4, options).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            assert!(matches!(
                blob.read_at_buf(0, 4, IoBufMut::with_capacity(4), options)
                    .await,
                Err(Error::Io(_))
            ));
        });
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
    async fn test_partition_removal_preserves_unrelated_crash_writes() {
        // Retain every unsynced write so crash replay exposes evidence lost during removal.
        let h = Harness::new(Config::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }));
        let (a, _) = h.storage.open("removed", b"a").await.unwrap();
        let (b, _) = h.storage.open("removed", b"b").await.unwrap();
        let (kept, _) = h.storage.open("kept", b"blob").await.unwrap();

        // Interleave both removed blobs with two distinct retained ranges.
        for (blob, offset, bytes) in [
            (&a, 0, b"one"),
            (&kept, 0, b"old"),
            (&b, 0, b"two"),
            (&kept, 3, b"new"),
        ] {
            blob.write_at(offset, bytes.as_slice(), WriteOptions::default())
                .await
                .unwrap();
        }
        drop((a, b, kept));

        // Retirement must remove both names' evidence and leave exactly the kept writes.
        h.storage.remove("removed", None).await.unwrap();
        assert_eq!(h.storage.pending.lock().len(), 2);
        h.storage.crash().unwrap();

        // Replay preserves both ranges in the surviving partition and cannot revive removed names.
        assert!(matches!(
            h.inner.scan("removed").await,
            Err(Error::PartitionMissing(_))
        ));
        let (kept, len) = h.inner.open("kept", b"blob").await.unwrap();
        assert_eq!(len, 6);
        assert_eq!(
            kept.read_at(0, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"oldnew"
        );
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

    /// Run `f` on the deterministic runtime with seed `seed` and mutations reordered at `rate`.
    fn run_reordered<F, Fut, T>(seed: u64, rate: Probability, f: F) -> T
    where
        F: FnOnce(crate::deterministic::Context) -> Fut,
        Fut: Future<Output = T>,
    {
        let cfg = crate::deterministic::Config::default()
            .with_seed(seed)
            .with_storage_fault_config(Config::default().reorder(rate));
        crate::deterministic::Runner::new(cfg).start(f)
    }

    #[test]
    fn test_reorder_lands_concurrent_writes_in_any_order() {
        // Two writes to one range pending at once. Without reordering the later call always
        // wins, and with it either may land last.
        let last_writer = |rate| {
            (0..32)
                .map(|seed| {
                    run_reordered(seed, rate, |context| async move {
                        let (blob, _) = context.open("partition", b"blob").await.unwrap();
                        let (first, second) = futures::join!(
                            blob.write_at(0, vec![1u8; 4], WriteOptions::default()),
                            blob.write_at(0, vec![2u8; 4], WriteOptions::default()),
                        );
                        first.unwrap();
                        second.unwrap();
                        let read = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
                        read.coalesce().as_ref()[0]
                    })
                })
                .collect::<HashSet<_>>()
        };
        assert_eq!(last_writer(probability!(0.0)), HashSet::from([2]));
        assert_eq!(last_writer(probability!(0.5)), HashSet::from([1, 2]));
    }

    #[test]
    fn test_reorder_lands_dropped_resize_after_later_sync() {
        // A resize polled once and dropped stays accepted. It may take effect before a later
        // write, or after that write and its sync have returned, truncating the synced bytes.
        let outcomes: HashSet<_> = (0..32)
            .map(|seed| {
                run_reordered(seed, probability!(0.5), |context| async move {
                    let (blob, _) = context.open("partition", b"blob").await.unwrap();
                    let mut resize = Box::pin(blob.resize(0));
                    let _ = futures::poll!(resize.as_mut());
                    drop(resize);

                    blob.write_at(0, vec![7u8; 4], WriteOptions::default())
                        .await
                        .unwrap();
                    blob.sync().await.unwrap();

                    // Later calls drive the resize until it has landed.
                    let mut truncated = false;
                    for _ in 0..64 {
                        if blob.read_at(0, 4, ReadOptions::default()).await.is_err() {
                            truncated = true;
                            break;
                        }
                    }
                    truncated
                })
            })
            .collect();
        assert_eq!(outcomes, HashSet::from([false, true]));
    }

    #[tokio::test]
    async fn test_reorder_open_applies_pending_mutations_first() {
        let h = Harness::new(Config::default().reorder(probability!(0.999)));
        let (blob, _) = h.storage.open("partition", b"blob").await.unwrap();
        let mut write = Box::pin(blob.write_at(0, b"lost", WriteOptions::default()));
        assert!(futures::poll!(write.as_mut()).is_pending());
        drop(write);
        drop(blob);
        assert_eq!(h.storage.accepted.lock().len(), 1);

        // The reopen applies the dropped write to its open first. That open was never synced,
        // so its write is discarded and no crash can replay it into the new open.
        let (blob, len) = h.storage.open("partition", b"blob").await.unwrap();
        assert!(h.storage.accepted.lock().is_empty());
        assert_eq!(len, 0);
        drop(blob);
    }

    #[tokio::test]
    async fn test_reorder_crash_discards_pending_mutations() {
        let h = Harness::new(
            Config::default()
                .reorder(probability!(0.999))
                .write(WriteConfig {
                    failure_rate: probability!(0.0),
                    retention_rate: probability!(1.0),
                    mode: PartialWriteMode::Prefix,
                }),
        );
        let (blob, _) = h.storage.open("partition", b"blob").await.unwrap();
        let mut write = Box::pin(blob.write_at(0, b"lost", WriteOptions::default()));
        assert!(futures::poll!(write.as_mut()).is_pending());
        drop(write);
        assert_eq!(h.storage.accepted.lock().len(), 1);

        // The write never took effect, so the crash has nothing of it to retain.
        h.storage.crash().unwrap();
        assert!(h.storage.accepted.lock().is_empty());
        let (_, len) = h.inner.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 0);
    }

    #[tokio::test]
    async fn test_reorder_pending_mutation_is_freed_with_its_storage() {
        let h = Harness::new(Config::default().reorder(probability!(0.999)));
        let (blob, _) = h.storage.open("partition", b"blob").await.unwrap();
        let mut write = Box::pin(blob.write_at(0, b"data", WriteOptions::default()));
        assert!(futures::poll!(write.as_mut()).is_pending());
        drop(write);
        drop(blob);

        // Without a crash or reopen the mutation stays pending, but nothing it holds keeps the
        // list of accepted mutations, and so the mutation itself, alive.
        let pending = Arc::downgrade(&h.storage.accepted.lock()[0]);
        drop(h);
        assert!(pending.upgrade().is_none());
    }

    #[test]
    #[should_panic(expected = "storage reorder rate must be less than one")]
    fn test_reorder_rate_of_one_is_rejected() {
        let h = Harness::new(Config::default().reorder(probability!(1.0)));
        let (blob, _) = futures::executor::block_on(h.storage.open("partition", b"blob")).unwrap();
        let _ = futures::executor::block_on(blob.resize(1));
    }
}
