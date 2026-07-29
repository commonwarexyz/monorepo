//! Native sharded timer service and concurrency protocols.

use super::heap::{Heap, HeapItem};
#[cfg(target_os = "linux")]
use super::linux::NativeAlarm;
#[cfg(target_os = "macos")]
use super::macos::NativeAlarm;
use crate::utils::Panicker;
use commonware_macros::select;
use commonware_utils::sync::Mutex;
use futures::{FutureExt as _, task::AtomicWaker};
use std::{
    any::Any,
    cell::RefCell,
    fmt,
    future::Future,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
};
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

/// Entry state after timer infrastructure stops servicing it.
const ENTRY_FAILED: u8 = 3;

/// Heap index used by entries that are not resident.
pub(super) const NOT_IN_HEAP: usize = usize::MAX;

/// Allocates identities that distinguish runtimes sharing a thread.
static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);

/// Claims one runtime identity without allowing the allocator to wrap.
fn allocate_runtime_id(counter: &AtomicU64) -> u64 {
    // Relaxed ordering is sufficient because the counter provides uniqueness only.
    counter
        .fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |next| {
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

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to initialize {} timer shard {} during {}: {}",
            self.platform, self.shard, self.operation, self.source
        )
    }
}

impl fmt::Debug for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
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
        THREAD_ASSIGNMENTS.with(|assignments| {
            assignments
                .borrow()
                .get(self.affinity.runtime_id)
                .map(|current| (current.index, current.kind))
        })
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
            SleepInner::Ready => Poll::Ready(()),
            SleepInner::Registered(sleep) => sleep.entry.poll(context),
        }
    }
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
    entry: Arc<Entry>,
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
    pub(super) const fn new() -> Self {
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
            ENTRY_FAILED => panic!("high-resolution timer service failed"),
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
            ENTRY_FAILED => panic!("high-resolution timer service failed"),
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
        Self {
            index,
            alarm,
            signal: DriverSignal::new(),
            state: Mutex::new(ShardState::new()),
            panicker,
        }
    }

    /// Reads monotonic time and eagerly registers a relative sleep.
    fn register_after(self: &Arc<Self>, duration: Duration) -> RegisteredSleep<A> {
        let entry = Arc::new(Entry::new());
        let deadline = match self.alarm.now() {
            Ok(now) => now.saturating_add(duration, self.alarm.max_deadline()),
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
        self.register(deadline, Arc::clone(&entry));
        RegisteredSleep {
            shard: Arc::downgrade(self),
            entry,
        }
    }

    /// Inserts an entry and signals only when the current arm is insufficient.
    fn register(&self, deadline: Deadline, entry: Arc<Entry>) {
        let notify = {
            let mut state = self.state.lock();
            if state.stopped || state.failed {
                // Release makes teardown visible to a later future poll.
                entry.state.store(ENTRY_FAILED, AtomicOrdering::Release);
                false
            } else {
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
        };
        if notify {
            // The heap carries the payload, so the signal only requests recomputation.
            self.signal.notify();
        }
    }

    /// Removes a canceled entry from its original shard immediately.
    fn cancel(&self, entry: &Arc<Entry>) {
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
                    state.stopped,
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
            if state.stopped {
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
            state.in_flight.is_empty() && batch.entries.is_empty(),
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
            state.in_flight.push(Arc::clone(&item.entry));
            batch.entries.push(item.entry);
        }
        Ok(state
            .entries
            .peek()
            .is_some_and(|item| item.deadline <= now))
    }

    /// Completes one popped batch and then releases its shared teardown visibility.
    fn complete_batch(&self, batch: &mut Batch, terminal: u8) -> Option<Box<dyn Any + Send>> {
        let mut first_panic = batch.complete(terminal);
        let mut completed = {
            let mut state = self.state.lock();
            std::mem::take(&mut state.in_flight)
        };
        // Entry and user-waker destructors may re-enter the shard or unwind.
        while let Some(entry) = completed.pop() {
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| drop(entry)))
                && first_panic.is_none()
            {
                first_panic = Some(panic);
            }
        }
        let mut state = self.state.lock();
        if state.in_flight.is_empty() {
            std::mem::swap(&mut state.in_flight, &mut completed);
        }
        drop(state);
        // A concurrent lifecycle path may have installed another allocation.
        drop(completed);
        first_panic
    }

    /// Marks teardown state and fails every queued sleep without reporting fatal.
    fn stop(&self) {
        let pending = {
            let mut state = self.state.lock();
            if state.stopped {
                return;
            }
            state.stopped = true;
            state.armed_deadline = None;
            drain_pending(&mut state)
        };
        fail_entries(pending);
        self.signal.notify();
    }

    /// Captures failure state, drains the heap, and interrupts the root runtime.
    fn fail(&self, failure: DriverFailure) {
        let (snapshot, pending) = {
            let mut state = self.state.lock();
            if state.failed || state.stopped {
                return;
            }
            let snapshot = ShardSnapshot {
                queued: state.entries.len(),
                locally_batched: state.in_flight.len(),
                desired: state.entries.peek().map(|item| item.deadline),
                armed: state.armed_deadline,
                notified: self.signal.is_notified(),
            };
            state.failed = true;
            state.stopped = true;
            state.armed_deadline = None;
            (snapshot, drain_pending(&mut state))
        };
        fail_entries(pending);
        self.signal.notify();

        let message = format!(
            "{} timer shard {} failed during {}: {}; snapshot={snapshot:?}",
            A::PLATFORM,
            self.index,
            failure.operation,
            failure.cause
        );
        // Infrastructure failure bypasses the ordinary catch-panics policy.
        if self.panicker.notify_fatal(Box::new(message)) {
            tracing::error!(
                platform = A::PLATFORM,
                shard = self.index,
                operation = failure.operation,
                error = %failure.cause,
                ?snapshot,
                "timer infrastructure failed"
            );
        }
    }

    /// Returns whether shutdown has made normal driver work invalid.
    fn is_stopped(&self) -> bool {
        self.state.lock().stopped
    }
}

/// Heap contents and alarm intent protected by one shard mutex.
struct ShardState {
    /// Indexed 4-ary minimum heap.
    entries: Heap,
    /// Popped entries still exposed to synchronous teardown.
    in_flight: Vec<Arc<Entry>>,
    /// Wrapping tie breaker for equal deadlines.
    sequence: u64,
    /// Deadline most recently confirmed armed by the driver.
    armed_deadline: Option<Deadline>,
    /// Whether normal service teardown has started.
    stopped: bool,
    /// Whether a live infrastructure failure occurred.
    failed: bool,
}

impl ShardState {
    /// Creates empty running shard state.
    fn new() -> Self {
        Self {
            entries: Heap::default(),
            in_flight: Vec::with_capacity(WAKE_BATCH),
            sequence: 0,
            armed_deadline: None,
            stopped: false,
            failed: false,
        }
    }
}

/// Error context returned by the driver loop.
struct DriverFailure {
    /// Operation active when failure occurred.
    operation: &'static str,
    /// Displayable source or panic message.
    cause: String,
}

impl DriverFailure {
    /// Wraps an I/O error with stable operation context.
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self {
            operation,
            cause: error.to_string(),
        }
    }

    /// Wraps an unwinding panic as a driver failure.
    fn panic(panic: &(dyn Any + Send)) -> Self {
        let cause = panic
            .downcast_ref::<&str>()
            .map(|value| (*value).to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic".to_string());
        Self {
            operation: "driver panic",
            cause,
        }
    }
}

/// Pre-cleanup state attached to fatal infrastructure diagnostics.
struct ShardSnapshot {
    /// Entries still resident in the heap.
    queued: usize,
    /// Entries popped into driver scratch storage.
    locally_batched: usize,
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
            .field("locally_batched", &self.locally_batched)
            .field("desired", &self.desired)
            .field("armed", &self.armed)
            .field("notified", &self.notified)
            .finish()
    }
}

/// Reusable driver scratch storage with unwind and abortion cleanup.
struct Batch {
    /// Entries removed from the heap but not yet fully completed.
    entries: Vec<Arc<Entry>>,
}

impl Batch {
    /// Allocates one reusable batch with the fixed lock-batch capacity.
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(WAKE_BATCH),
        }
    }

    /// Transitions every entry and invokes all callbacks outside the heap lock.
    fn complete(&mut self, terminal: u8) -> Option<Box<dyn Any + Send>> {
        let mut first_panic = None;
        for entry in self.entries.drain(..) {
            // The final Entry owner may release a user waker whose destructor unwinds.
            let completion = catch_unwind(AssertUnwindSafe(move || {
                if entry.transition(terminal)
                    && let Some(waker) = entry.take_waker()
                {
                    waker.wake();
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
        // Abortion or unwind cannot strand popped entries in WAITING.
        let _ = self.complete(ENTRY_FAILED);
    }
}

/// Mutable state retained across all iterations of one driver.
struct DriverLoop {
    /// Scratch storage reused for every expiry batch.
    batch: Batch,
}

impl DriverLoop {
    /// Creates a driver loop with reusable scratch storage.
    fn new() -> Self {
        Self {
            batch: Batch::new(),
        }
    }

    /// Runs signal and native readiness handling until teardown.
    async fn run<A: Alarm>(&mut self, shard: &Arc<Shard<A>>) -> Result<(), DriverFailure> {
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
                        let more = shard.take_expired(&mut self.batch)?;
                        processed = processed.saturating_add(self.batch.entries.len());
                        // Callbacks run after take_expired releases the shard mutex.
                        if let Some(panic) = shard.complete_batch(&mut self.batch, ENTRY_FIRED) {
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
}

/// Runs one driver with panic capture and complete failure cleanup.
async fn run_driver<A: Alarm>(shard: Arc<Shard<A>>) {
    let mut driver = DriverLoop::new();
    let outcome = AssertUnwindSafe(driver.run(&shard)).catch_unwind().await;
    let failure = match outcome {
        Ok(Ok(())) if shard.is_stopped() => return,
        Ok(Ok(())) => DriverFailure {
            operation: "driver exit",
            cause: "driver exited while its shard was running".to_string(),
        },
        Ok(Err(failure)) => failure,
        Err(panic) => DriverFailure::panic(&*panic),
    };
    shard.fail(failure);
    let _ = driver.batch.complete(ENTRY_FAILED);
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
    const fn new() -> Self {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadAssignment {
    /// Identity of the runtime that owns this assignment.
    runtime_id: u64,
    /// Provisional or stable worker classification.
    kind: AssignmentKind,
    /// Selected shard index.
    index: usize,
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
    fn get(&self, runtime_id: u64) -> Option<ThreadAssignment> {
        self.current
            .filter(|assignment| assignment.runtime_id == runtime_id)
            .or_else(|| {
                self.inactive
                    .iter()
                    .find(|assignment| assignment.runtime_id == runtime_id)
                    .copied()
            })
    }

    /// Makes a cached runtime current and returns its assignment.
    fn activate(&mut self, runtime_id: u64) -> Option<ThreadAssignment> {
        if let Some(current) = self.current
            && current.runtime_id == runtime_id
        {
            return Some(current);
        }
        let position = self
            .inactive
            .iter()
            .position(|assignment| assignment.runtime_id == runtime_id)?;
        let assignment = self.inactive.swap_remove(position);
        if let Some(previous) = self.current.replace(assignment) {
            self.inactive.push(previous);
        }
        Some(assignment)
    }

    /// Installs a new or upgraded assignment as the fast-path runtime.
    fn install(&mut self, assignment: ThreadAssignment) {
        if let Some(previous) = self.current.replace(assignment)
            && previous.runtime_id != assignment.runtime_id
        {
            self.inactive.push(previous);
        }
    }
}

/// Separate worker and fallback allocators for one runtime.
struct Affinity {
    /// Identity checked by every thread-local lookup.
    runtime_id: u64,
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
            if let Some(current) = assignments.activate(self.runtime_id) {
                return current.index;
            }
            // Relaxed ordering is sufficient because this counter allocates unique claims only.
            let index =
                self.next_fallback.fetch_add(1, AtomicOrdering::Relaxed) % self.worker_threads;
            assignments.install(ThreadAssignment {
                runtime_id: self.runtime_id,
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
            if matches!(
                assignments.activate(self.runtime_id),
                Some(ThreadAssignment {
                    kind: AssignmentKind::Worker,
                    ..
                })
            ) {
                return;
            }
            // Relaxed ordering is sufficient because this counter allocates unique claims only.
            let index = self.next_worker.fetch_add(1, AtomicOrdering::Relaxed);
            assert!(
                index < self.worker_threads,
                "Tokio invoked the timer park callback on more workers than configured"
            );
            assignments.install(ThreadAssignment {
                runtime_id: self.runtime_id,
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
fn drain_heap(heap: &mut Heap) -> Vec<Arc<Entry>> {
    let mut entries = Vec::with_capacity(heap.len());
    while let Some(item) = heap.pop() {
        entries.push(item.entry);
    }
    entries
}

/// Removes every queued and popped entry while holding the shard mutex.
fn drain_pending(state: &mut ShardState) -> Vec<Arc<Entry>> {
    let mut entries = drain_heap(&mut state.entries);
    entries.append(&mut state.in_flight);
    entries
}

/// Fails entries and contains each individual callback unwind.
fn fail_entries(entries: Vec<Arc<Entry>>) {
    let mut batch = Batch { entries };
    let _ = batch.complete(ENTRY_FAILED);
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "loom"))]
mod loom_tests;
