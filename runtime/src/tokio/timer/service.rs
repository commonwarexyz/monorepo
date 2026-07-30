//! Native sharded timer service and concurrency protocols.

mod sync;

pub(super) use self::sync::EntryArc;
use self::sync::{AtomicWaker, Mutex};
use super::heap::{Heap, HeapItem};
#[cfg(target_os = "linux")]
use super::linux::NativeAlarm;
#[cfg(target_os = "macos")]
use super::macos::NativeAlarm;
use crate::utils::{Panicker, extract_panic_message, resume_reported_panic};
use commonware_macros::select;
use futures::FutureExt as _;
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering as AtomicOrdering};
#[cfg(not(feature = "loom"))]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering as AtomicOrdering};
use std::{
    any::Any,
    cell::RefCell,
    fmt,
    future::Future,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Weak, atomic::AtomicU64},
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tokio::{runtime::Builder, task::JoinHandle};

/// Maximum difference covered by an already armed slightly later alarm.
const REARM_TOLERANCE: Duration = Duration::from_nanos(50);

/// Maximum number of expired entries removed under one heap lock.
const WAKE_BATCH: usize = 32;

/// Expired entries processed before yielding when more are ready.
const EXPIRY_YIELD_BUDGET: usize = 512;

/// Entry state before its single terminal transition.
const ENTRY_WAITING: u8 = 0;

/// Entry state after its deadline expires.
const ENTRY_FIRED: u8 = 1;

/// Entry state after its sleep future is dropped.
const ENTRY_CANCELED: u8 = 2;

/// Entry state after timer infrastructure fails.
const ENTRY_FAILED: u8 = 3;

/// Entry state after orderly timer service shutdown.
const ENTRY_STOPPED: u8 = 4;

/// Heap index used by entries that are not resident.
pub(super) const NOT_IN_HEAP: usize = usize::MAX;

/// Allocates identities that distinguish runtimes sharing a thread.
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);

/// Claims one runtime identity without allowing the allocator to wrap.
fn allocate_runtime_id(counter: &AtomicU64) -> u64 {
    // Relaxed ordering is sufficient because the counter provides uniqueness only.
    counter
        .try_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |next| {
            next.checked_add(1)
        })
        .expect("timer runtime identity space exhausted")
}

thread_local! {
    /// Cached assignments for every timer runtime used by this thread.
    static THREAD_ASSIGNMENTS: RefCell<ThreadAssignments> = const {
        RefCell::new(ThreadAssignments::new())
    };
}

/// A monotonic deadline represented as time since the platform epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Deadline(Duration);

impl Deadline {
    /// Constructs a deadline from a duration since the monotonic epoch.
    pub(super) const fn from_duration(duration: Duration) -> Self {
        Self(duration)
    }

    /// Returns the duration since the monotonic epoch.
    pub(super) const fn as_duration(self) -> Duration {
        self.0
    }

    /// Adds a duration without exceeding the platform alarm limit.
    pub(super) fn saturating_add(self, duration: Duration, limit: Self) -> Self {
        match self.0.checked_add(duration) {
            Some(deadline) if deadline <= limit.0 => Self(deadline),
            _ => limit,
        }
    }

    /// Returns the nonnegative distance from an earlier deadline.
    const fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

/// Error raised while synchronously constructing a timer shard.
#[derive(Debug, Error)]
#[error("failed to initialize {platform} timer shard {shard} during {operation}: {source}")]
pub(crate) struct InitError {
    /// Operating system adapter being initialized.
    platform: &'static str,
    /// Zero-based shard index.
    shard: usize,
    /// Native or reactor operation that failed.
    operation: &'static str,
    /// Underlying I/O error.
    source: io::Error,
}

/// Error raised while constructing a native alarm object.
#[derive(Debug)]
pub(super) struct AlarmInitError {
    /// Native or reactor operation that failed.
    pub(super) operation: &'static str,
    /// Underlying I/O error.
    pub(super) source: io::Error,
}

impl AlarmInitError {
    /// Creates an initialization error with operation context.
    pub(super) const fn new(operation: &'static str, source: io::Error) -> Self {
        Self { operation, source }
    }
}

/// Statically dispatched boundary around a platform alarm.
pub(super) trait Alarm: Send + Sync + Sized + 'static {
    /// Human-readable platform name for fatal diagnostics.
    const PLATFORM: &'static str;

    /// Creates and registers one alarm with the active Tokio reactor.
    fn new(shard: usize) -> Result<Self, AlarmInitError>;

    /// Largest monotonic deadline that can be armed safely.
    fn max_deadline(&self) -> Deadline;

    /// Reads monotonic time without making a relative deadline early.
    fn now(&self) -> io::Result<Deadline>;

    /// Reads monotonic time without classifying a future deadline as expired.
    fn now_for_expiry(&self) -> io::Result<Deadline> {
        self.now()
    }

    /// Arms a one-shot alarm at an absolute monotonic deadline.
    fn arm(&self, deadline: Deadline) -> io::Result<()>;

    /// Disarms the alarm.
    fn disarm(&self) -> io::Result<()>;

    /// Waits for and fully consumes one readiness event.
    fn wait(&self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Configures worker shard affinity before the Tokio runtime is built.
pub(crate) struct Setup {
    /// Shared allocator used by callbacks and the eventual service.
    affinity: Arc<Affinity>,
}

impl Setup {
    /// Allocates a distinct runtime identity and its shard allocators.
    pub(crate) fn new(worker_threads: usize) -> Self {
        let runtime_id = allocate_runtime_id(&NEXT_RUNTIME_ID);
        Self {
            affinity: Arc::new(Affinity {
                runtime_id,
                lifetime: Arc::new(()),
                worker_threads,
                next_worker: AtomicUsize::new(0),
                next_fallback: AtomicUsize::new(0),
            }),
        }
    }

    /// Installs the worker-only callback that assigns stable shard indices.
    pub(crate) fn configure(&self, builder: &mut Builder) {
        let affinity = Arc::clone(&self.affinity);
        builder.on_thread_park(move || affinity.assign_worker());
    }
}

/// Owns the production native timer service.
pub(crate) struct Timer {
    /// Shards selected by worker or cached fallback affinity.
    shards: Vec<Arc<Shard<NativeAlarm>>>,
    /// Driver tasks, retained so teardown can abort them.
    drivers: Vec<JoinHandle<()>>,
    /// Per-runtime shard selection state.
    affinity: Arc<Affinity>,
}

/// Constructs and synchronously validates every alarm-backed shard.
fn initialize_shards<A, F>(
    worker_threads: usize,
    panicker: Panicker,
    mut create_alarm: F,
) -> Result<Vec<Arc<Shard<A>>>, InitError>
where
    A: Alarm,
    F: FnMut(usize) -> Result<A, AlarmInitError>,
{
    // Timer starts drivers only after every alarm completes this validation.
    // On error, Vec and local-value RAII drop all prior and current alarms.
    let mut shards = Vec::with_capacity(worker_threads);
    for index in 0..worker_threads {
        let alarm = create_alarm(index).map_err(|error| InitError {
            platform: A::PLATFORM,
            shard: index,
            operation: error.operation,
            source: error.source,
        })?;
        alarm.now().map_err(|source| InitError {
            platform: A::PLATFORM,
            shard: index,
            operation: "read monotonic clock",
            source,
        })?;
        alarm
            .arm(alarm.max_deadline())
            .map_err(|source| InitError {
                platform: A::PLATFORM,
                shard: index,
                operation: "validate initial arm",
                source,
            })?;
        alarm.disarm().map_err(|source| InitError {
            platform: A::PLATFORM,
            shard: index,
            operation: "validate initial disarm",
            source,
        })?;
        shards.push(Arc::new(Shard::new(index, alarm, panicker.clone())));
    }
    Ok(shards)
}

impl Timer {
    /// Synchronously validates shards and then starts their drivers.
    pub(crate) fn new(setup: Setup, panicker: Panicker) -> Result<Self, InitError> {
        let worker_threads = setup.affinity.worker_threads;
        let shards = initialize_shards(worker_threads, panicker, NativeAlarm::new)?;

        let drivers = shards
            .iter()
            .map(|shard| tokio::spawn(run_driver(Arc::clone(shard))))
            .collect();
        Ok(Self {
            shards,
            drivers,
            affinity: setup.affinity,
        })
    }

    /// Eagerly registers a sleep measured from this method call.
    pub(crate) fn sleep(&self, duration: Duration) -> Sleep {
        if duration.is_zero() {
            return Sleep::ready();
        }
        let index = self.affinity.select();
        Sleep::registered(self.shards[index].register_after(duration))
    }

    /// Eagerly converts one wall-clock deadline and registers its sleep.
    pub(crate) fn sleep_until(&self, deadline: SystemTime) -> Sleep {
        let remaining = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(remaining)
    }

    #[cfg(test)]
    /// Returns the current resident entry count for every shard.
    pub(crate) fn heap_lengths(&self) -> Vec<usize> {
        self.shards
            .iter()
            .map(|shard| shard.state.lock().entries.len())
            .collect()
    }

    #[cfg(test)]
    /// Returns the worker and fallback allocator claim counts.
    pub(crate) fn allocator_claims(&self) -> (usize, usize) {
        (
            self.affinity.next_worker.load(AtomicOrdering::Relaxed),
            self.affinity.next_fallback.load(AtomicOrdering::Relaxed),
        )
    }

    #[cfg(test)]
    /// Returns this runtime's assignment cached on the current thread.
    pub(crate) fn current_assignment(&self) -> Option<(usize, AssignmentKind)> {
        THREAD_ASSIGNMENTS.with(|assignments| assignments.borrow().get(self.affinity.runtime_id))
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        for shard in &self.shards {
            shard.stop();
        }
        for driver in &self.drivers {
            driver.abort();
        }
    }
}

/// Concrete future returned by the native timer facade.
pub(crate) struct Sleep {
    /// Ready or registered state owned by this future.
    inner: SleepInner,
}

impl Sleep {
    /// Constructs an immediately ready sleep.
    const fn ready() -> Self {
        Self {
            inner: SleepInner::Ready,
        }
    }

    /// Constructs a sleep tied to its originally selected shard.
    const fn registered(registered: RegisteredSleep<NativeAlarm>) -> Self {
        Self {
            inner: SleepInner::Registered(registered),
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match &self.get_mut().inner {
            SleepInner::Ready => poll_cooperative_ready(context),
            SleepInner::Registered(sleep) => sleep.entry.poll(context),
        }
    }
}

/// Consumes scheduler budget before completing an otherwise immediate sleep.
fn poll_cooperative_ready(context: &mut Context<'_>) -> Poll<()> {
    let mut budget = std::pin::pin!(tokio::task::coop::consume_budget());
    budget.as_mut().poll(context)
}

/// Storage variants for an immediately ready or registered sleep.
enum SleepInner {
    /// A zero-duration or past-deadline sleep.
    Ready,
    /// A sleep registered in one native shard.
    Registered(RegisteredSleep<NativeAlarm>),
}

/// Registered sleep state that remembers its original cancellation shard.
struct RegisteredSleep<A: Alarm> {
    /// Non-owning reference to the shard selected at construction.
    shard: Weak<Shard<A>>,
    /// Heap entry shared with the driver.
    entry: EntryArc<Entry>,
}

impl<A: Alarm> Drop for RegisteredSleep<A> {
    fn drop(&mut self) {
        if self.entry.transition(ENTRY_CANCELED) {
            // Task migration cannot change the shard that owns this entry.
            if let Some(shard) = self.shard.upgrade() {
                shard.cancel(&self.entry);
            }
        }
    }
}

/// Per-sleep state shared by its future and selected shard.
pub(super) struct Entry {
    /// Waiting or terminal lifecycle state.
    state: AtomicU8,
    /// Latest task waker registered by the future.
    waker: AtomicWaker,
    /// Exact heap array index or [`NOT_IN_HEAP`].
    pub(super) heap_index: AtomicUsize,
}

impl Entry {
    /// Creates one unregistered waiting entry.
    ///
    /// Loom's modeled atomic waker constructor is not const.
    #[allow(clippy::missing_const_for_fn)]
    pub(super) fn new() -> Self {
        Self {
            state: AtomicU8::new(ENTRY_WAITING),
            waker: AtomicWaker::new(),
            heap_index: AtomicUsize::new(NOT_IN_HEAP),
        }
    }

    /// Polls the terminal state while closing the registration race.
    fn poll(&self, context: &mut Context<'_>) -> Poll<()> {
        self.poll_after_first_check(context, || {})
    }

    /// Polls while optionally running work between the two state checks.
    fn poll_after_first_check<F>(&self, context: &mut Context<'_>, after_first_check: F) -> Poll<()>
    where
        F: FnOnce(),
    {
        // Acquire observes the terminal transition before returning its outcome.
        match self.state.load(AtomicOrdering::Acquire) {
            ENTRY_FIRED => return Poll::Ready(()),
            ENTRY_FAILED => resume_reported_panic("high-resolution timer service failed"),
            ENTRY_STOPPED => return Poll::Pending,
            _ => {}
        }

        after_first_check();
        self.waker.register(context.waker());

        // Completion may race with waker registration, so state is checked twice.
        // Acquire again pairs with the terminal transition that may have just won.
        match self.state.load(AtomicOrdering::Acquire) {
            ENTRY_FIRED => {
                self.waker.take();
                Poll::Ready(())
            }
            ENTRY_FAILED => {
                self.waker.take();
                resume_reported_panic("high-resolution timer service failed");
            }
            ENTRY_STOPPED => {
                self.waker.take();
                Poll::Pending
            }
            _ => Poll::Pending,
        }
    }

    /// Attempts the single transition from waiting to a terminal state.
    fn transition(&self, terminal: u8) -> bool {
        // AcqRel arbitrates one winner and publishes its preceding completion work.
        self.state
            .compare_exchange(
                ENTRY_WAITING,
                terminal,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            )
            .is_ok()
    }

    /// Takes the currently registered waker after a successful transition.
    fn take_waker(&self) -> Option<Waker> {
        self.waker.take()
    }
}

/// One timer shard and its authoritative heap state.
struct Shard<A: Alarm> {
    /// Zero-based diagnostic index.
    index: usize,
    /// Platform alarm used only by this shard's driver.
    alarm: A,
    /// Largest deadline accepted by this shard's platform alarm.
    max_deadline: Deadline,
    /// Coalesced producer-to-driver notification.
    signal: DriverSignal,
    /// Authoritative heap and lifecycle state.
    state: Mutex<ShardState>,
    /// Root runtime panic propagation handle.
    panicker: Panicker,
}

impl<A: Alarm> Shard<A> {
    /// Creates an empty running shard around one validated alarm.
    fn new(index: usize, alarm: A, panicker: Panicker) -> Self {
        let max_deadline = alarm.max_deadline();
        Self {
            index,
            alarm,
            max_deadline,
            signal: DriverSignal::new(),
            state: Mutex::new(ShardState::new()),
            panicker,
        }
    }

    /// Reads monotonic time and eagerly registers a relative sleep.
    fn register_after(self: &Arc<Self>, duration: Duration) -> RegisteredSleep<A> {
        // Establish the requested duration before allocator contention can
        // consume part of it.
        let now = self.alarm.now();
        let entry = EntryArc::new(Entry::new());
        let deadline = match now {
            Ok(now) => now.saturating_add(duration, self.max_deadline),
            Err(error) => {
                // This entry is not heap-resident, so fail it directly before shard cleanup.
                // Release publishes failure before the returned future can be polled.
                entry.state.store(ENTRY_FAILED, AtomicOrdering::Release);
                self.fail(DriverFailure::io(
                    "read monotonic clock during registration",
                    error,
                ));
                return RegisteredSleep {
                    shard: Arc::downgrade(self),
                    entry,
                };
            }
        };
        self.register(deadline, EntryArc::clone(&entry));
        RegisteredSleep {
            shard: Arc::downgrade(self),
            entry,
        }
    }

    /// Inserts an entry and signals only when the current arm is insufficient.
    fn register(&self, deadline: Deadline, entry: EntryArc<Entry>) {
        let notify = {
            let mut state = self.state.lock();
            match state.lifecycle {
                ShardLifecycle::Stopped => {
                    // Release makes orderly teardown visible to a later future poll.
                    entry.state.store(ENTRY_STOPPED, AtomicOrdering::Release);
                    false
                }
                ShardLifecycle::Failed => {
                    // Release makes fatal teardown visible to a later future poll.
                    entry.state.store(ENTRY_FAILED, AtomicOrdering::Release);
                    false
                }
                ShardLifecycle::Running => {
                    let previous = state.entries.peek().map(|item| item.deadline);
                    let sequence = state.sequence;
                    state.sequence = state.sequence.wrapping_add(1);
                    state.entries.push(HeapItem {
                        deadline,
                        sequence,
                        entry,
                    });
                    let desired = state.entries.peek().map(|item| item.deadline);
                    previous != desired && !arm_covers(state.armed_deadline, desired)
                }
            }
        };
        if notify {
            // The heap carries the payload, so the signal only requests recomputation.
            self.signal.notify();
        }
    }

    /// Removes a canceled entry from its original shard immediately.
    fn cancel(&self, entry: &EntryArc<Entry>) {
        let notify = {
            let mut state = self.state.lock();
            let index = entry.heap_index.load(AtomicOrdering::Relaxed);
            if index == NOT_IN_HEAP {
                return;
            }
            let previous = state.entries.peek().map(|item| item.deadline);
            state
                .entries
                .remove(index, entry)
                .expect("timer heap index does not reference its entry");
            let desired = state.entries.peek().map(|item| item.deadline);
            previous != desired && !arm_covers(state.armed_deadline, desired)
        };
        if notify {
            self.signal.notify();
        }
    }

    /// Converges the native alarm on the latest desired minimum.
    fn rearm(&self) -> Result<(), DriverFailure> {
        loop {
            let (armed, desired, stopped) = {
                let state = self.state.lock();
                (
                    state.armed_deadline,
                    state.entries.peek().map(|item| item.deadline),
                    state.lifecycle != ShardLifecycle::Running,
                )
            };
            if stopped || arm_covers(armed, desired) {
                return Ok(());
            }

            // Native operations stay outside the heap mutex so producers progress.
            match desired {
                Some(deadline) => self
                    .alarm
                    .arm(deadline)
                    .map_err(|error| DriverFailure::io("arm native alarm", error))?,
                None => self
                    .alarm
                    .disarm()
                    .map_err(|error| DriverFailure::io("disarm native alarm", error))?,
            }

            let mut state = self.state.lock();
            if state.lifecycle != ShardLifecycle::Running {
                drop(state);
                let _ = self.alarm.disarm();
                return Ok(());
            }
            state.armed_deadline = desired;
            let current = state.entries.peek().map(|item| item.deadline);
            if arm_covers(state.armed_deadline, current) {
                return Ok(());
            }
            // A producer changed the minimum during the syscall, so converge again.
        }
    }

    /// Pops one bounded batch of entries whose deadlines have elapsed.
    fn take_expired(&self, batch: &mut Batch) -> Result<bool, DriverFailure> {
        let now = self
            .alarm
            .now_for_expiry()
            .map_err(|error| DriverFailure::io("read monotonic clock during expiry", error))?;
        let mut state = self.state.lock();
        assert!(
            batch.entries.is_empty(),
            "timer driver started a batch before completing the previous batch"
        );
        // Consumed one-shot readiness makes the prior armed deadline non-authoritative.
        state.armed_deadline = None;
        while batch.entries.len() < WAKE_BATCH
            && state
                .entries
                .peek()
                .is_some_and(|item| item.deadline <= now)
        {
            let item = state.entries.pop().expect("timer heap minimum disappeared");
            // Commit expiry before teardown can observe the removed entry.
            // Cancellation may win the atomic transition, but not mutate the
            // heap concurrently. Callbacks and final release remain deferred.
            let _ = item.entry.transition(ENTRY_FIRED);
            batch.entries.push(item.entry);
        }
        Ok(state
            .entries
            .peek()
            .is_some_and(|item| item.deadline <= now))
    }

    /// Marks orderly teardown and releases every queued sleep without waking it.
    fn stop(&self) {
        let pending = {
            let mut state = self.state.lock();
            if state.lifecycle != ShardLifecycle::Running {
                return;
            }
            state.lifecycle = ShardLifecycle::Stopped;
            state.armed_deadline = None;
            drain_heap(&mut state.entries)
        };
        complete_entries(pending, ENTRY_STOPPED);
        self.signal.notify();
    }

    /// Captures failure state, drains the heap, and interrupts the root runtime.
    fn fail(&self, failure: DriverFailure) {
        self.fail_with_exposure_hook(failure, || {});
    }

    /// Runs failure cleanup with a hook after its state becomes observable.
    fn fail_with_exposure_hook<F>(&self, failure: DriverFailure, after_exposure: F)
    where
        F: FnOnce(),
    {
        let (snapshot, pending) = {
            let mut state = self.state.lock();
            if state.lifecycle != ShardLifecycle::Running {
                return;
            }
            let snapshot = ShardSnapshot {
                queued: state.entries.len(),
                desired: state.entries.peek().map(|item| item.deadline),
                armed: state.armed_deadline,
                notified: self.signal.is_notified(),
            };
            let message = format!(
                "{} timer shard {} failed during {}: {}; snapshot={snapshot:?}",
                A::PLATFORM,
                self.index,
                failure.operation,
                failure.cause
            );
            state.lifecycle = ShardLifecycle::Failed;
            state.armed_deadline = None;
            let pending = drain_heap(&mut state.entries);
            // Claim root interruption while the shard lock prevents a newly
            // failed sleep from racing this more detailed payload.
            let _ = self.panicker.notify_fatal(Box::new(message));
            (snapshot, pending)
        };

        // Every failed shard emits its own actionable diagnostic, even when
        // another panic already claimed or closed root interruption.
        tracing::error!(
            platform = A::PLATFORM,
            shard = self.index,
            operation = failure.operation,
            error = %failure.cause,
            error_kind = ?failure.cause.error_kind(),
            raw_os_error = ?failure.cause.raw_os_error(),
            ?snapshot,
            "timer infrastructure failed"
        );
        after_exposure();
        complete_entries(pending, ENTRY_FAILED);
        self.signal.notify();
    }

    /// Returns whether shutdown has made normal driver work invalid.
    fn is_stopped(&self) -> bool {
        self.state.lock().lifecycle != ShardLifecycle::Running
    }
}

/// Operating state for one timer shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShardLifecycle {
    /// Driver and producers may perform ordinary timer work.
    Running,
    /// The owning runtime is shutting down normally.
    Stopped,
    /// Native timer infrastructure failed while the runtime was live.
    Failed,
}

/// Heap contents and alarm intent protected by one shard mutex.
struct ShardState {
    /// Indexed 4-ary minimum heap.
    entries: Heap,
    /// Wrapping tie breaker for equal deadlines.
    sequence: u64,
    /// Deadline most recently confirmed armed by the driver.
    armed_deadline: Option<Deadline>,
    /// Whether the shard is running, stopped normally, or failed.
    lifecycle: ShardLifecycle,
}

impl ShardState {
    /// Creates empty running shard state.
    fn new() -> Self {
        Self {
            entries: Heap::default(),
            sequence: 0,
            armed_deadline: None,
            lifecycle: ShardLifecycle::Running,
        }
    }
}

/// Error context returned by the driver loop.
struct DriverFailure {
    /// Operation active when failure occurred.
    operation: &'static str,
    /// Original I/O error or classified panic payload.
    cause: DriverFailureCause,
}

/// Source retained by one fatal driver failure.
#[derive(Debug, Error)]
enum DriverFailureCause {
    /// Original operating-system or reactor error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Stable message extracted from a panic payload or invariant failure.
    #[error("{0}")]
    Message(String),
}

impl DriverFailureCause {
    /// Returns the structured I/O error kind when this failure came from I/O.
    fn error_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io(error) => Some(error.kind()),
            Self::Message(_) => None,
        }
    }

    /// Returns the raw operating-system error code when one is available.
    fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Io(error) => error.raw_os_error(),
            Self::Message(_) => None,
        }
    }
}

impl DriverFailure {
    /// Wraps an I/O error with stable operation context.
    const fn io(operation: &'static str, error: io::Error) -> Self {
        Self {
            operation,
            cause: DriverFailureCause::Io(error),
        }
    }

    /// Wraps an unwinding panic as a driver failure.
    fn panic(panic: &(dyn Any + Send)) -> Self {
        Self {
            operation: "driver panic",
            cause: DriverFailureCause::Message(extract_panic_message(panic)),
        }
    }
}

/// Pre-cleanup state attached to fatal infrastructure diagnostics.
struct ShardSnapshot {
    /// Entries still resident in the heap.
    queued: usize,
    /// Current desired heap minimum.
    desired: Option<Deadline>,
    /// Deadline last recorded as armed.
    armed: Option<Deadline>,
    /// Whether a producer notification is latched.
    notified: bool,
}

impl fmt::Debug for ShardSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShardSnapshot")
            .field("queued", &self.queued)
            .field("desired", &self.desired)
            .field("armed", &self.armed)
            .field("notified", &self.notified)
            .finish()
    }
}

/// Reusable driver scratch storage with unwind and abortion cleanup.
struct Batch {
    /// Entries removed from the heap but not yet fully completed.
    entries: Vec<EntryArc<Entry>>,
}

impl Batch {
    /// Allocates one reusable batch with the fixed lock-batch capacity.
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(WAKE_BATCH),
        }
    }

    /// Completes every entry and invokes all callbacks outside the heap lock.
    fn complete(&mut self, terminal: u8) -> Option<Box<dyn Any + Send>> {
        let mut first_panic = None;
        for entry in self.entries.drain(..) {
            // Waking or releasing the final user waker may unwind.
            let completion = catch_unwind(AssertUnwindSafe(move || {
                // Expiry commits FIRED while popping under the shard lock.
                // Other lifecycle paths transition their drained entries here.
                if (entry.state.load(AtomicOrdering::Acquire) == terminal
                    || entry.transition(terminal))
                    && let Some(waker) = entry.take_waker()
                {
                    if terminal == ENTRY_STOPPED {
                        drop(waker);
                    } else {
                        waker.wake();
                    }
                }
                drop(entry);
            }));
            if let Err(panic) = completion
                && first_panic.is_none()
            {
                first_panic = Some(panic);
            }
        }
        first_panic
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        // Abortion or unwind still delivers expiry committed during heap removal.
        let _ = self.complete(ENTRY_FIRED);
    }
}

/// Runs signal and native readiness handling until teardown.
async fn run_driver_loop<A: Alarm>(
    shard: &Arc<Shard<A>>,
    batch: &mut Batch,
) -> Result<(), DriverFailure> {
    shard.rearm()?;
    loop {
        if shard.is_stopped() {
            return Ok(());
        }
        select! {
            result = shard.alarm.wait() => {
                result.map_err(|error| DriverFailure::io("wait for native alarm", error))?;
                let mut processed = 0_usize;
                loop {
                    let more = shard.take_expired(batch)?;
                    processed = processed.saturating_add(batch.entries.len());
                    // Callbacks run after take_expired releases the shard mutex.
                    if let Some(panic) = batch.complete(ENTRY_FIRED) {
                        return Err(DriverFailure::panic(&*panic));
                    }
                    if !more {
                        break;
                    }
                    if processed >= EXPIRY_YIELD_BUDGET {
                        processed = 0;
                        tokio::task::yield_now().await;
                    }
                }
                shard.rearm()?;
            },
            _ = shard.signal.wait() => {
                shard.rearm()?;
            },
        }
    }
}

/// Runs one driver with panic capture and complete failure cleanup.
async fn run_driver<A: Alarm>(shard: Arc<Shard<A>>) {
    let mut batch = Batch::new();
    let outcome = AssertUnwindSafe(run_driver_loop(&shard, &mut batch))
        .catch_unwind()
        .await;
    let failure = match outcome {
        Ok(Ok(())) if shard.is_stopped() => return,
        Ok(Ok(())) => DriverFailure {
            operation: "driver exit",
            cause: DriverFailureCause::Message(
                "driver exited while its shard was running".to_string(),
            ),
        },
        Ok(Err(failure)) => failure,
        Err(panic) => DriverFailure::panic(&*panic),
    };
    shard.fail(failure);
    let _ = batch.complete(ENTRY_FIRED);
}

/// Durable coalesced notification from any producer to one driver.
struct DriverSignal {
    /// Whether at least one notification remains unconsumed.
    notified: AtomicBool,
    /// Driver waker for the single waiting task.
    waker: AtomicWaker,
}

impl DriverSignal {
    /// Creates an unnotified signal.
    ///
    /// Loom's modeled atomic waker constructor is not const.
    #[allow(clippy::missing_const_for_fn)]
    fn new() -> Self {
        Self {
            notified: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Latches a notification and wakes only on the false-to-true edge.
    fn notify(&self) {
        // Release publishes heap changes before the driver's acquire consume.
        if !self.notified.swap(true, AtomicOrdering::Release) {
            self.waker.wake();
        }
    }

    /// Waits with a consume-register-consume protocol that cannot lose a wake.
    async fn wait(&self) {
        futures::future::poll_fn(|context| {
            if self.notified.swap(false, AtomicOrdering::AcqRel) {
                self.waker.take();
                return Poll::Ready(());
            }
            self.waker.register(context.waker());
            if self.notified.swap(false, AtomicOrdering::AcqRel) {
                self.waker.take();
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Reports whether a notification is currently latched.
    fn is_notified(&self) -> bool {
        self.notified.load(AtomicOrdering::Acquire)
    }
}

/// Kind of shard assignment cached in thread-local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AssignmentKind {
    /// Temporary round-robin choice for a non-worker or pre-park worker.
    Provisional,
    /// Unique worker index claimed from the worker-only allocator.
    Worker,
}

/// Shard assignment scoped to one runtime identity.
#[derive(Debug)]
struct ThreadAssignment {
    /// Identity of the runtime that owns this assignment.
    runtime_id: u64,
    /// Weak token used to discard assignments after their runtime is dropped.
    lifetime: Weak<()>,
    /// Provisional or stable worker classification.
    kind: AssignmentKind,
    /// Selected shard index.
    index: usize,
}

impl ThreadAssignment {
    /// Returns the cached selection without cloning its liveness token.
    const fn selection(&self) -> (usize, AssignmentKind) {
        (self.index, self.kind)
    }

    /// Returns whether the runtime that owns this assignment is still alive.
    fn is_live(&self) -> bool {
        self.lifetime.strong_count() != 0
    }
}

/// Per-thread assignments with a fast path for the most recently used runtime.
struct ThreadAssignments {
    /// Assignment for the runtime used most recently on this thread.
    current: Option<ThreadAssignment>,
    /// Preserved assignments for other runtimes used by this thread.
    inactive: Vec<ThreadAssignment>,
}

impl ThreadAssignments {
    /// Creates an empty per-thread assignment cache.
    const fn new() -> Self {
        Self {
            current: None,
            inactive: Vec::new(),
        }
    }

    /// Returns a cached assignment without changing the fast-path runtime.
    #[cfg(test)]
    fn get(&self, runtime_id: u64) -> Option<(usize, AssignmentKind)> {
        self.current
            .as_ref()
            .filter(|assignment| assignment.runtime_id == runtime_id)
            .or_else(|| {
                self.inactive
                    .iter()
                    .find(|assignment| assignment.runtime_id == runtime_id)
            })
            .map(ThreadAssignment::selection)
    }

    /// Makes a cached runtime current and returns its assignment.
    fn activate(&mut self, runtime_id: u64) -> Option<(usize, AssignmentKind)> {
        if let Some(current) = self.current.as_ref()
            && current.runtime_id == runtime_id
        {
            return Some(current.selection());
        }
        // Cache misses are already the cold path, so retire assignments whose
        // runtimes have ended before searching the inactive set.
        self.inactive.retain(ThreadAssignment::is_live);
        let position = self
            .inactive
            .iter()
            .position(|assignment| assignment.runtime_id == runtime_id)?;
        let assignment = self.inactive.swap_remove(position);
        let selection = assignment.selection();
        if let Some(previous) = self.current.replace(assignment)
            && previous.is_live()
        {
            self.inactive.push(previous);
        }
        Some(selection)
    }

    /// Installs a new or upgraded assignment as the fast-path runtime.
    fn install(&mut self, assignment: ThreadAssignment) {
        let runtime_id = assignment.runtime_id;
        if let Some(previous) = self.current.replace(assignment)
            && previous.runtime_id != runtime_id
            && previous.is_live()
        {
            self.inactive.push(previous);
        }
    }
}

/// Separate worker and fallback allocators for one runtime.
struct Affinity {
    /// Identity checked by every thread-local lookup.
    runtime_id: u64,
    /// Token retained for exactly as long as this runtime's affinity exists.
    lifetime: Arc<()>,
    /// Number of native timer shards.
    worker_threads: usize,
    /// Allocator consumed only by worker park callbacks.
    next_worker: AtomicUsize,
    /// Allocator consumed only on uncached fallback lookup.
    next_fallback: AtomicUsize,
}

impl Affinity {
    /// Selects a cached shard or creates a provisional fallback assignment.
    fn select(&self) -> usize {
        THREAD_ASSIGNMENTS.with(|assignments| {
            let mut assignments = assignments.borrow_mut();
            if let Some((index, _)) = assignments.activate(self.runtime_id) {
                return index;
            }
            // Relaxed ordering is sufficient because this counter allocates unique claims only.
            let index =
                self.next_fallback.fetch_add(1, AtomicOrdering::Relaxed) % self.worker_threads;
            assignments.install(ThreadAssignment {
                runtime_id: self.runtime_id,
                lifetime: Arc::downgrade(&self.lifetime),
                kind: AssignmentKind::Provisional,
                index,
            });
            index
        })
    }

    /// Preserves a worker assignment or upgrades a provisional one.
    fn assign_worker(&self) {
        THREAD_ASSIGNMENTS.with(|assignments| {
            let mut assignments = assignments.borrow_mut();
            let existing = assignments.activate(self.runtime_id);
            if matches!(existing, Some((_, AssignmentKind::Worker))) {
                return;
            }

            // `block_in_place` may move one logical worker core to a temporary
            // blocking-pool thread. Such threads also invoke this park callback,
            // so only the configured number of callbacks may claim worker slots.
            // Relaxed ordering is sufficient because this counter allocates
            // unique claims only.
            //
            // Loom's atomic implementation does not provide `try_update`.
            #[allow(deprecated)]
            let Ok(index) = self.next_worker.fetch_update(
                AtomicOrdering::Relaxed,
                AtomicOrdering::Relaxed,
                |next| {
                    if next < self.worker_threads {
                        Some(next + 1)
                    } else {
                        None
                    }
                },
            ) else {
                if existing.is_some() {
                    return;
                }
                let index =
                    self.next_fallback.fetch_add(1, AtomicOrdering::Relaxed) % self.worker_threads;
                assignments.install(ThreadAssignment {
                    runtime_id: self.runtime_id,
                    lifetime: Arc::downgrade(&self.lifetime),
                    kind: AssignmentKind::Provisional,
                    index,
                });
                return;
            };
            assignments.install(ThreadAssignment {
                runtime_id: self.runtime_id,
                lifetime: Arc::downgrade(&self.lifetime),
                kind: AssignmentKind::Worker,
                index,
            });
        });
    }
}

/// Returns whether an existing alarm safely covers the current desired state.
fn arm_covers(armed: Option<Deadline>, desired: Option<Deadline>) -> bool {
    match (armed, desired) {
        (None, None) => true,
        (Some(armed), Some(desired)) if armed == desired => true,
        (Some(armed), Some(desired)) if desired < armed => {
            armed.saturating_duration_since(desired) <= REARM_TOLERANCE
        }
        _ => false,
    }
}

/// Removes every heap item and returns its shared entry.
fn drain_heap(heap: &mut Heap) -> Vec<EntryArc<Entry>> {
    let mut entries = Vec::with_capacity(heap.len());
    while let Some(item) = heap.pop() {
        entries.push(item.entry);
    }
    entries
}

/// Transitions entries and contains each individual callback unwind.
fn complete_entries(entries: Vec<EntryArc<Entry>>, terminal: u8) {
    let mut batch = Batch { entries };
    let _ = batch.complete(terminal);
}

#[cfg(test)]
mod tests;
