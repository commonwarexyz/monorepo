//! Single-threaded executor that interleaves task polling with the io_uring
//! event loop.
//!
//! The thread that calls [crate::Runner::start] runs both the task executor
//! and the io_uring event loop: each iteration polls a bounded batch of ready
//! tasks, with a small initial quota for tasks woken by the prior event
//! delivery, then services the ring via [Driver::turn] so completions wake
//! tasks and staged submissions reach the kernel. When nothing is runnable,
//! the thread parks via [Driver::park] until a completion arrives, a timer
//! fires, a producer enqueues work, or another thread wakes a task.
//!
//! The owner thread repeats this scheduling cycle:
//!
//! ```text
//! normal ready FIFO ----\
//!                        +--> bounded task batch --> root poll
//! event ready FIFO  ----/                             |
//!                                                    v
//!                                      driver turn + due sleepers
//!                                                    |
//!                               ready work ----------+-- no work --> park
//! ```
//!
//! Driver completions and due sleepers enter the event FIFO. Other wakes enter
//! the normal FIFO. Each turn admits at most [`READY_TASKS_PER_TURN`] task
//! tokens, with at most [`EVENT_READY_TASKS_PER_TURN`] of the initial snapshot
//! reserved for event work. Either lane may use capacity the other lane leaves
//! idle, and the root and driver still receive a service point after the batch.
//!
//! ## Panic flow
//!
//! Task wrappers catch panics raised while polling. Dedicated worker wrappers
//! also catch the spawn closure. With [`Config::with_catch_panics`] enabled,
//! `Panicker` absorbs a panic that reaches either wrapper and the task handle
//! reports [`Error::Exited`]. Otherwise `Panicker` delivers the payload to the
//! root interrupt. When root completion wins the same poll, the interrupt
//! receiver closes before its final check so a concurrent sender either
//! becomes visible there or receives its payload back for the shared fallback.
//!
//! ```text
//! task catch -- catch_panics=true --------------------> Error::Exited
//!      |
//!      +-- false --> Panicker --> root interrupt
//!                            `--> retained fallback
//!
//! worker-loop catch ------\
//! cleanup panic isolation -+-> close -> ring drain -> resume
//!                           |
//! worker fallback ----------+-> opportunistic reap or final join
//!                           |
//! root unwind --------------+-> isolated output drop -> final resume
//! ```
//!
//! Worker teardown isolates cleanup callbacks, closes and drains the ring, and
//! resumes only after quiescence. A panic inside [`Driver::drain`] aborts
//! instead of unwinding ring state. [`crate::Runner::start`] joins every worker
//! before resuming a retained payload. Exact ordering between concurrently
//! observed failures is not guaranteed. Panic-capable output drops are
//! isolated, and secondary payloads are forgotten when dropping them could
//! interrupt the mandatory ring drain.
//!
//! Ordinary tasks run inline on the executor thread. Tasks spawned with
//! [crate::Spawner::dedicated] or [crate::Spawner::shared] with
//! `blocking == true` run as the root of a [Worker] on their own thread with
//! its own ring, so blocking work cannot starve the executor thread and the
//! task's context still submits IO thread-locally. Blocking shared tasks
//! currently run as dedicated workers, and a shared blocking pool may
//! replace this.
//! Resources created on one worker (blobs, sockets, listeners) are bound to
//! that worker's thread and must not be driven from another. Cross-thread
//! interactions that do not submit ring operations (waking a task from a
//! helper thread, registering a sleeper alarm, spawning a task through a
//! moved context, delivering a stop signal) remain supported through each
//! loop's latched wake state. A context refers to its origin worker: once
//! that worker has torn down, using the context from elsewhere fails loudly
//! instead of submitting work nothing will run.

use super::{
    RingConfig,
    driver::{Driver, validate_ring_config},
};
#[cfg(feature = "external")]
use crate::Pacer;
use crate::{
    BufferPool, BufferPoolConfig, Clock, Error, Execution, Handle, METRICS_PREFIX, Name, SinkOf,
    StreamOf, child_label,
    network::{
        iouring::{Config as NetworkConfig, Network as IoUringNetwork},
        metered::Network as MeteredNetwork,
    },
    prefixed_name,
    process::metered::Metrics as MeteredProcess,
    signal::Signal,
    storage::{iouring::Storage as IoUringStorage, metered::Storage as MeteredStorage},
    telemetry::metrics::{
        CounterFamily, GaugeFamily, Metric, Register, Registered, Registry, add_attribute, raw,
        task::Label, validate_label,
    },
    utils::{self, Panicker, signal::Stopper, supervision::Tree},
};
use commonware_macros::{select, stability};
#[stability(BETA)]
use commonware_parallel::Rayon;
use commonware_utils::{channel::oneshot, sync::Mutex, sys_rng};
use futures::{
    FutureExt as _,
    future::{AbortHandle, Abortable, Aborted},
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use rand_core::{Rng, TryCryptoRng, TryRng};
use rayon::ThreadPoolBuilder;
use std::{
    collections::BinaryHeap,
    convert::Infallible,
    env,
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self as std_task, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

mod task;
use self::task::{Erased, Tasks};

cfg_if::cfg_if! {
    if #[cfg(test)] {
        // Use a smaller ring in tests to reduce `io_uring_setup` failures
        // under parallel test load due to mlock/resource limits.
        const DEFAULT_RING_SIZE: u32 = 128;
    } else {
        const DEFAULT_RING_SIZE: u32 = 1024;
    }
}

/// Far-future cap for timer durations so conversions to [Instant] cannot
/// overflow (e.g. when sleeping until [SystemTime::limit]).
///
/// Sleep durations are clamped to this value, and [Config::validate] rejects
/// network timeouts above it for policy consistency with that clamp.
///
/// [SystemTime::limit]: commonware_utils::SystemTimeExt::limit
const MAX_TIMER_DURATION: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);

/// Maximum number of spawned-task ready tokens polled per worker turn.
const READY_TASKS_PER_TURN: usize = 64;

/// Initial event-ready share of each spawned-task batch.
///
/// Half the turn lets completion bursts drain without replaying the old
/// backlog delay, while the other half guarantees equal normal FIFO progress
/// whenever normal work was present at the snapshot.
const EVENT_READY_TASKS_PER_TURN: usize = READY_TASKS_PER_TURN / 2;

/// Type-erased payload retained while teardown completes.
type PanicPayload = Box<dyn std::any::Any + Send>;

/// Retain the earliest panic while teardown is still in progress.
fn retain_first_panic(first_panic: &mut Option<PanicPayload>, payload: PanicPayload) {
    if first_panic.is_none() {
        *first_panic = Some(payload);
    } else {
        // A secondary panic payload may itself panic when dropped. Leaking it
        // is preferable to unwinding past the mandatory ring drain.
        std::mem::forget(payload);
    }
}

/// Run one cleanup step and retain its panic unless an earlier step failed.
fn capture_cleanup_panic(first_panic: &mut Option<PanicPayload>, cleanup: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(cleanup)) {
        retain_first_panic(first_panic, payload);
    }
}

#[derive(Debug)]
struct Metrics {
    tasks_spawned: CounterFamily<Label>,
    tasks_running: GaugeFamily<Label>,
}

impl Metrics {
    pub fn init(registry: &mut impl Register) -> Self {
        Self {
            tasks_spawned: registry.register(
                "tasks_spawned",
                "Total number of tasks spawned",
                raw::Family::default(),
            ),
            tasks_running: registry.register(
                "tasks_running",
                "Number of tasks currently running",
                raw::Family::default(),
            ),
        }
    }
}

/// Configuration for the `iouring` runtime.
///
/// Worker-affinity rules (which resources may cross workers) are described
/// in the [module documentation](crate::iouring#worker-affinity).
#[derive(Clone)]
pub struct Config {
    /// Configuration for the runtime's io_uring instance.
    ///
    /// One ring serves all storage and network I/O, so its `size` bounds the
    /// number of waiter-backed logical operations. An admitted request keeps
    /// its slot while it is waiting in the submission backlog, in flight,
    /// awaiting cancellation, or holding an ordinary `Ready` result. A pending
    /// detached ticket also retains a slot. At terminal completion, a detached
    /// ticket's output moves to a separate completion arena and its waiter slot
    /// is recycled before its task waker runs. That output remains retained
    /// outside this bound until its ticket is polled or dropped.
    /// The driver always enables single-issuer and deferred task-run modes
    /// because the runtime thread creates the ring and is its only submitter.
    /// The timeout wheel horizon is derived from the maximum of
    /// `read_write_timeout` and `connect_timeout` so network deadlines are
    /// never clamped.
    ring: RingConfig,

    /// Whether or not to catch panics.
    catch_panics: bool,

    /// Base directory for all storage operations.
    storage_directory: PathBuf,

    /// Stack size to use for runtime-owned threads.
    ///
    /// Defaults to the system stack size when the current platform exposes it,
    /// and otherwise falls back to Rust's default spawned-thread stack size.
    ///
    /// See [utils::thread::system_thread_stack_size].
    thread_stack_size: usize,

    /// Network configuration.
    network_cfg: NetworkConfig,

    /// Buffer pool configuration for network I/O.
    network_buffer_pool_cfg: BufferPoolConfig,

    /// Buffer pool configuration for storage I/O.
    storage_buffer_pool_cfg: BufferPoolConfig,
}

impl Config {
    /// Returns a new [Config] with default values.
    pub fn new() -> Self {
        let rng = sys_rng().next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_iouring_runtime_{rng}"));
        Self {
            ring: RingConfig {
                size: DEFAULT_RING_SIZE,
                ..Default::default()
            },
            catch_panics: false,
            storage_directory,
            thread_stack_size: utils::thread::system_thread_stack_size(),
            network_cfg: NetworkConfig::default(),
            network_buffer_pool_cfg: BufferPoolConfig::for_network(),
            storage_buffer_pool_cfg: BufferPoolConfig::for_storage(),
        }
    }

    // Setters
    /// Sets the configuration for each worker's io_uring instance.
    ///
    /// The ring `size` bounds the number of waiter-backed logical operations
    /// per worker, including requests in the submission backlog, in flight,
    /// awaiting cancellation, and ordinary completed results that have not
    /// been consumed or dropped. Pending detached tickets also retain a slot.
    /// Their terminal outputs move to a separate completion arena and remain
    /// retained outside this bound until their tickets are polled or dropped.
    /// Defaults to a 1024-entry ring. The runtime derives the timeout wheel
    /// horizon from the configured network timeouts.
    pub const fn with_ring(mut self, ring: RingConfig) -> Self {
        self.ring = ring;
        self
    }
    /// Sets whether a task panic is caught and reported through the task's
    /// handle as [Error::Exited].
    ///
    /// With the default `false`, a task panic is forwarded to the root and
    /// unwinds [crate::Runner::start].
    pub const fn with_catch_panics(mut self, b: bool) -> Self {
        self.catch_panics = b;
        self
    }
    /// Sets the base directory for all storage operations.
    ///
    /// Defaults to a uniquely named directory under the system temporary
    /// directory. The directory's filesystem is flushed once at startup so
    /// data recovered from a prior process is crash-durable before it is
    /// read.
    pub fn with_storage_directory(mut self, p: impl Into<PathBuf>) -> Self {
        self.storage_directory = p.into();
        self
    }
    /// Sets the stack size in bytes for runtime-owned threads (dedicated and
    /// blocking workers).
    ///
    /// Defaults to the system stack size when the current platform exposes
    /// it, and otherwise to Rust's default spawned-thread stack size.
    pub const fn with_thread_stack_size(mut self, n: usize) -> Self {
        self.thread_stack_size = n;
        self
    }
    /// Sets the timeout applied to each network dial attempt.
    ///
    /// Defaults to 10 seconds. Zero and values above 30 years panic in
    /// [crate::Runner::start], a policy bound kept consistent with the
    /// runtime's sleep clamp. The timeout wheel horizon is the maximum of the
    /// configured network timeouts, so at the default
    /// [RingConfig::timeout_wheel_tick] the wheel's 1,048,576-slot cap
    /// (about 87 minutes of horizon) is what rejects oversized network
    /// timeouts at startup.
    pub const fn with_connect_timeout(mut self, d: Duration) -> Self {
        self.network_cfg.connect_timeout = d;
        self
    }
    /// Sets the timeout applied to each network send and receive operation
    /// and to each in-flight accept (which is transparently reissued on
    /// expiry).
    ///
    /// Defaults to 60 seconds. Zero and values above 30 years panic in
    /// [crate::Runner::start], a policy bound kept consistent with the
    /// runtime's sleep clamp. The timeout wheel horizon is the maximum of the
    /// configured network timeouts, so at the default
    /// [RingConfig::timeout_wheel_tick] the wheel's 1,048,576-slot cap
    /// (about 87 minutes of horizon) is what rejects oversized network
    /// timeouts at startup.
    pub const fn with_read_write_timeout(mut self, d: Duration) -> Self {
        self.network_cfg.read_write_timeout = d;
        self
    }
    /// Sets whether `TCP_NODELAY` is explicitly enabled or disabled on
    /// created sockets.
    ///
    /// `None` keeps the system default. Defaults to `Some(true)`.
    pub const fn with_tcp_nodelay(mut self, n: Option<bool>) -> Self {
        self.network_cfg.tcp_nodelay = n;
        self
    }
    /// Sets whether `SO_LINGER` is zeroed on created sockets, causing an
    /// immediate RST on close and skipping `TIME_WAIT`.
    ///
    /// Useful in adversarial environments to reclaim socket resources
    /// immediately when closing connections to misbehaving peers. Defaults
    /// to true.
    pub const fn with_zero_linger(mut self, l: bool) -> Self {
        self.network_cfg.zero_linger = l;
        self
    }
    /// Sets the per-connection read buffer size in bytes used to batch
    /// network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per
    /// call but uses more memory per connection. Defaults to 64 KiB.
    pub const fn with_read_buffer_size(mut self, n: usize) -> Self {
        self.network_cfg.read_buffer_size = n;
        self
    }
    /// Sets an explicit buffer pool configuration for network I/O.
    ///
    /// Defaults to [BufferPoolConfig::for_network].
    pub fn with_network_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.network_buffer_pool_cfg = cfg;
        self
    }
    /// Sets an explicit buffer pool configuration for storage I/O.
    ///
    /// Defaults to [BufferPoolConfig::for_storage].
    pub fn with_storage_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.storage_buffer_pool_cfg = cfg;
        self
    }

    // Getters
    /// Returns the configuration for each worker's io_uring instance (see
    /// [Self::with_ring]).
    pub const fn ring(&self) -> &RingConfig {
        &self.ring
    }
    /// Returns whether task panics are caught and reported through task
    /// handles (see [Self::with_catch_panics]).
    pub const fn catch_panics(&self) -> bool {
        self.catch_panics
    }
    /// Returns the base directory for all storage operations (see
    /// [Self::with_storage_directory]).
    pub const fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }
    /// Returns the stack size in bytes for runtime-owned threads (see
    /// [Self::with_thread_stack_size]).
    pub const fn thread_stack_size(&self) -> usize {
        self.thread_stack_size
    }
    /// Returns the timeout applied to each network dial attempt (see
    /// [Self::with_connect_timeout]).
    pub const fn connect_timeout(&self) -> Duration {
        self.network_cfg.connect_timeout
    }
    /// Returns the timeout applied to each network send, receive, and
    /// in-flight accept (see [Self::with_read_write_timeout]).
    pub const fn read_write_timeout(&self) -> Duration {
        self.network_cfg.read_write_timeout
    }
    /// Returns the explicit `TCP_NODELAY` setting for created sockets, or
    /// `None` for the system default (see [Self::with_tcp_nodelay]).
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.network_cfg.tcp_nodelay
    }
    /// Returns whether `SO_LINGER` is zeroed on created sockets (see
    /// [Self::with_zero_linger]).
    pub const fn zero_linger(&self) -> bool {
        self.network_cfg.zero_linger
    }
    /// Returns the per-connection read buffer size in bytes (see
    /// [Self::with_read_buffer_size]).
    pub const fn read_buffer_size(&self) -> usize {
        self.network_cfg.read_buffer_size
    }

    /// Rejects configurations the runtime must not start with.
    ///
    /// Called at the beginning of [crate::Runner::start], before any startup
    /// side effect. Panics when either network timeout violates policy, or
    /// when the ring configuration cannot construct its exact derived layout.
    fn validate(&self) {
        assert!(
            !self.network_cfg.connect_timeout.is_zero(),
            "connect_timeout must be non-zero"
        );
        assert!(
            !self.network_cfg.read_write_timeout.is_zero(),
            "read_write_timeout must be non-zero"
        );
        assert!(
            self.network_cfg.connect_timeout <= MAX_TIMER_DURATION,
            "connect_timeout must be at most 30 years"
        );
        assert!(
            self.network_cfg.read_write_timeout <= MAX_TIMER_DURATION,
            "read_write_timeout must be at most 30 years"
        );

        let max_request_timeout = self
            .network_cfg
            .connect_timeout
            .max(self.network_cfg.read_write_timeout);
        validate_ring_config(&self.ring, max_request_timeout);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// State shared by every worker thread of one runtime instance.
struct Shared {
    /// Configuration template used to construct workers.
    cfg: Config,
    registry: Registry,
    metrics: Metrics,
    shutdown: Mutex<Stopper>,
    panicker: Panicker,
    network_buffer_pool: BufferPool,
    storage_buffer_pool: BufferPool,
    /// Serializes filesystem-shape storage operations (open, remove, scan)
    /// across all workers sharing the runtime's storage directory.
    storage_lock: Arc<Mutex<()>>,
    /// Threads running dedicated workers, joined when the root worker exits.
    ///
    /// `None` once the root has joined every worker: a dedicated spawn racing
    /// final teardown from a non-worker thread must not create a thread
    /// nobody joins.
    workers: Mutex<Option<Vec<std::thread::JoinHandle<()>>>>,
    /// Panic payload from a worker joined by an opportunistic reap, resumed
    /// when the runtime shuts down (reaps must not swallow worker panics).
    worker_panic: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl Shared {
    /// Retain the first worker panic observed by a shared shutdown path.
    fn retain_worker_panic(&self, payload: PanicPayload) {
        retain_first_panic(&mut self.worker_panic.lock(), payload);
    }

    /// Join any finished worker threads, retaining live ones.
    ///
    /// Without reaping, every completed dedicated (or blocking shared) task
    /// would hold its exited thread's `JoinHandle` (and stack mapping) until
    /// shutdown. Called on every worker registration and on the process
    /// metrics collector's cadence, which bounds retention by the reap
    /// interval instead of the runtime's lifetime.
    fn reap_workers(&self) {
        let mut workers = self.workers.lock();
        let Some(list) = workers.as_mut() else {
            return;
        };
        let mut index = 0;
        while index < list.len() {
            if list[index].is_finished() {
                let worker = list.swap_remove(index);
                if let Err(payload) = worker.join() {
                    self.retain_worker_panic(payload);
                }
            } else {
                index += 1;
            }
        }
    }
}

/// The alarm queue of one worker's sleepers.
///
/// Wrapped in `Mutex<Option<Sleeping>>` on the [Executor]: the mutex is the
/// single synchronization point for every sleeper interaction (registration,
/// waker refresh, cancellation, and teardown), and `None` marks the worker as
/// torn down so late interactions fail loudly instead of parking state
/// nothing will ever drain.
///
/// Lock order: this mutex first, then any [Alarm] waker slot. Holding
/// the queue lock across a slot take and its tombstone accounting keeps
/// `cancelled` exact relative to draining and compaction.
struct Sleeping {
    alarms: BinaryHeap<Arc<Alarm>>,
    /// Alarms in the heap whose waker slot was emptied by cancellation.
    /// Tombstones hold no task resources and are dropped at their deadline
    /// or by compaction, whichever comes first.
    cancelled: usize,
}

impl Sleeping {
    /// Rebuild the heap without tombstones once they outnumber live alarms.
    ///
    /// Checked after every operation that changes the tombstone-to-live
    /// ratio (cancellation and firing), so the heap's size stays bounded by
    /// twice the live sleeper count.
    fn compact_if_needed(&mut self) {
        if self.cancelled * 2 > self.alarms.len() {
            self.alarms.retain(|alarm| alarm.waker.lock().is_some());
            self.cancelled = 0;
        }
    }
}

/// Runtime state shared by every [Context] on one worker thread.
pub struct Executor {
    shared: Arc<Shared>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<Option<Sleeping>>,
}

impl Executor {
    /// Register a sleeper alarm.
    ///
    /// If the alarm becomes the earliest deadline, the runtime thread is woken
    /// so a park in progress recomputes its timeout: without this, an alarm
    /// registered from another thread while the runtime is parked would not
    /// fire until the previous park deadline elapsed.
    ///
    /// Panics if this worker already tore down: an alarm registered after the
    /// queue closed would never fire, so the sleep fails loudly in the
    /// registering task instead of hanging it.
    fn register_alarm(&self, alarm: Arc<Alarm>) {
        let earliest = {
            let mut sleeping = self.sleeping.lock();
            let sleeping = sleeping
                .as_mut()
                .expect("sleep registered on a torn-down io_uring worker");
            let earliest = sleeping
                .alarms
                .peek()
                .is_none_or(|next| alarm.time < next.time);
            sleeping.alarms.push(alarm);
            earliest
        };
        if earliest {
            self.tasks.unpark_foreign();
        }
    }

    /// Store the current task's waker in a registered alarm, so the alarm
    /// always wakes the task that most recently polled its sleeper.
    ///
    /// Returns true when the alarm already fired: a foreign poll can pass its
    /// deadline check just before the deadline and lose the race to the
    /// origin worker popping the alarm, so an emptied slot under an open
    /// queue means the deadline elapsed and the sleep is complete
    /// (cancellation cannot produce it: dropping the sleeper consumes it).
    ///
    /// Panics if this worker already tore down: the alarm was discarded, so
    /// the sleep fails loudly in the polling task instead of hanging it.
    fn refresh_alarm(&self, alarm: &Alarm, waker: &Waker) -> bool {
        // Waker clone and drop callbacks are arbitrary user code. Clone the
        // incoming waker before acquiring either sleeper lock, then detach the
        // old one under the locks and release it afterward.
        let replacement = waker.clone();
        let (fired, detached) = {
            let sleeping = self.sleeping.lock();
            assert!(sleeping.is_some(), "sleep outlived its io_uring worker");
            let mut slot = alarm.waker.lock();
            if slot.is_some() {
                (false, slot.replace(replacement))
            } else {
                (true, Some(replacement))
            }
        };
        drop(detached);
        fired
    }

    /// Cancel a registered alarm: release its waker (and the task resources
    /// it retains) immediately, leaving a tombstone in the heap.
    ///
    /// Compaction rebuilds the heap once tombstones outnumber live alarms, so
    /// the heap's size stays proportional to live sleepers regardless of how
    /// many long-deadline sleeps are cancelled (e.g. by losing a `select!`).
    fn cancel_alarm(&self, alarm: &Alarm) {
        let detached = {
            let mut guard = self.sleeping.lock();
            // Worker already torn down: the heap (and this alarm) was
            // discarded.
            let Some(sleeping) = guard.as_mut() else {
                return;
            };
            // An already-empty slot means the alarm fired and left the heap.
            let detached = alarm.waker.lock().take();
            if detached.is_some() {
                sleeping.cancelled += 1;
                sleeping.compact_if_needed();
            }
            detached
        };
        drop(detached);
    }

    /// Wake any sleepers whose deadlines have elapsed.
    fn wake_ready_sleepers(&self, current: Instant) {
        let mut due = Vec::new();
        {
            let mut sleeping = self.sleeping.lock();
            let sleeping = sleeping
                .as_mut()
                .expect("alarm queue closed while the worker loop is running");
            // Reserve before detaching the first waker. A capacity panic must
            // not unwind a detached RawWaker while either sleeper lock is held.
            due.reserve(sleeping.alarms.len());
            while let Some(next) = sleeping.alarms.peek() {
                if next.time > current {
                    break;
                }
                let alarm = sleeping.alarms.pop().unwrap();
                match alarm.waker.lock().take() {
                    Some(waker) => due.push(waker),
                    // A tombstone reached its deadline before compaction.
                    None => sleeping.cancelled -= 1,
                }
            }
            // Popping live alarms can leave the heap tombstone-dominated
            // even though no cancellation ran: recheck so the size bound
            // holds at quiescence, not just at the last cancellation.
            sleeping.compact_if_needed();
        }
        let mut first_panic = None;
        for waker in due {
            capture_cleanup_panic(&mut first_panic, || waker.wake_by_ref());
            capture_cleanup_panic(&mut first_panic, move || drop(waker));
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
    }

    /// Return the delay until the next sleeper alarm, if any.
    ///
    /// Tombstones may report a deadline with no waker behind it, so the loop
    /// then wakes up only to discard them, which is harmless.
    fn next_alarm(&self) -> Option<Duration> {
        let sleeping = self.sleeping.lock();
        let sleeping = sleeping
            .as_ref()
            .expect("alarm queue closed while the worker loop is running");
        sleeping
            .alarms
            .peek()
            .map(|alarm| alarm.time.saturating_duration_since(Instant::now()))
    }
}

/// A single-threaded executor bound to a ring owned by its thread.
///
/// The thread calling [crate::Runner::start] runs one worker for the root
/// task, and every dedicated (or blocking shared) task runs on a worker of
/// its own thread. All op state a worker's tasks submit IO through is local
/// to its thread, so the driver's thread-affinity invariants hold per worker.
struct Worker {
    executor: Arc<Executor>,
    driver: Driver,
    storage: Storage,
    network: Network,
}

impl Worker {
    /// Create a worker on the current thread: the ring, driver, and all op
    /// state become owned by this thread.
    ///
    /// Every worker registers its metric families under the same names, so
    /// worker metrics aggregate into the runtime-wide families.
    ///
    /// Panics if the ring cannot be created.
    fn new(shared: Arc<Shared>) -> Self {
        let mut registry = shared.registry.clone();
        let mut runtime_registry = registry.sub_registry(METRICS_PREFIX);

        let max_request_timeout = shared
            .cfg
            .network_cfg
            .read_write_timeout
            .max(shared.cfg.network_cfg.connect_timeout);
        let (driver, handle) = Driver::new(
            shared.cfg.ring.clone(),
            max_request_timeout,
            &mut runtime_registry.sub_registry("iouring"),
        )
        .unwrap_or_else(|err| {
            panic!(
                "unable to create io_uring instance ({err}): this runtime requires Linux \
                         6.1+ (IORING_SETUP_SINGLE_ISSUER and IORING_SETUP_DEFER_TASKRUN)"
            )
        });

        // Initialize storage and network against this worker's driver.
        let storage = MeteredStorage::new(
            IoUringStorage::new(
                shared.cfg.storage_directory.clone(),
                handle.clone(),
                shared.storage_buffer_pool.clone(),
                Arc::clone(&shared.storage_lock),
            ),
            &mut runtime_registry,
        );
        let network = MeteredNetwork::new(
            IoUringNetwork::new(
                shared.cfg.network_cfg.clone(),
                handle,
                shared.network_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );

        let executor = Arc::new(Executor {
            tasks: Arc::new(Tasks::new(driver.waker())),
            sleeping: Mutex::new(Some(Sleeping {
                alarms: BinaryHeap::new(),
                cancelled: 0,
            })),
            shared,
        });
        Self {
            executor,
            driver,
            storage,
            network,
        }
    }

    /// Build a context rooted at `tree` for tasks on this worker.
    fn context(&self, name: String, attributes: Vec<(String, String)>, tree: Arc<Tree>) -> Context {
        Context {
            name,
            attributes,
            executor: Arc::downgrade(&self.executor),
            storage: self.storage.clone(),
            network: self.network.clone(),
            network_buffer_pool: self.executor.shared.network_buffer_pool.clone(),
            storage_buffer_pool: self.executor.shared.storage_buffer_pool.clone(),
            tree,
            execution: Execution::default(),
        }
    }

    /// Drive `root` to completion, interleaving task polling with the ring,
    /// then tear the worker down: abort `tree`, clear remaining tasks, and
    /// drain in-flight ring work before the ring is destroyed.
    ///
    /// A panic from the loop or teardown is resumed only after the ring is
    /// quiesced.
    fn run<F>(self, root: F, tree: Arc<Tree>) -> F::Output
    where
        F: Future,
    {
        let Self {
            executor,
            mut driver,
            storage,
            network,
        } = self;
        let mut root = Box::pin(root);

        // Build the root task's waker (the root starts ready).
        let root_waker = Tasks::root_waker(&executor.tasks);

        // Reusable ready-task buffer, local to this frame. Its capacity stays
        // at the batch high-water mark so a busy executor does not allocate
        // per iteration, and by teardown no task is parked in it.
        let mut scratch: Vec<Arc<dyn Erased>> = Vec::with_capacity(READY_TASKS_PER_TURN);

        // Process tasks until the root task completes.
        // Wrap the loop in catch_unwind to ensure task cleanup runs even if the loop or a task panics.
        let result = catch_unwind(AssertUnwindSafe(|| {
            loop {
                // Take one bounded batch. Event-delivered tokens receive the
                // initial quota, while a normal token present at the snapshot
                // is always reserved and either lane may fill unused capacity.
                // Wakes that arrive while a snapshot is being polled land in a
                // shared lane and may fill unused budget in this turn. Tokens
                // beyond the combined budget remain for a later turn. Every
                // moved token consumes budget, including a stale wake of an
                // already completed task. The lanes hold the tasks themselves,
                // so polling needs no registry lookup.
                //
                // Tasks run before the root so a task registered ahead of the
                // root's poll (e.g. the process-metrics collector) is polled
                // even if the root never yields.
                let mut remaining = READY_TASKS_PER_TURN;
                let mut event_quota = EVENT_READY_TASKS_PER_TURN;
                loop {
                    executor
                        .tasks
                        .drain_into(&mut scratch, remaining, event_quota);
                    // Event priority applies to the turn's initial snapshot.
                    // Refills preserve the shared lane order without granting
                    // a fresh event quota.
                    event_quota = 0;
                    let drained = scratch.len();
                    if drained == 0 {
                        break;
                    }
                    remaining -= drained;
                    for task in scratch.drain(..) {
                        if let Some(slot) = task.poll(&executor.tasks) {
                            executor.tasks.remove(slot);
                        }
                    }
                    if remaining == 0 {
                        break;
                    }
                }

                // The root future lives on this stack frame, not in the
                // arena, so its typed output is captured un-erased.
                if executor.tasks.take_root_ready() {
                    let mut cx = std_task::Context::from_waker(&root_waker);
                    if let Poll::Ready(result) = root.as_mut().poll(&mut cx) {
                        break result;
                    }
                }

                // Service the ring and deliver due sleepers under one event
                // phase. Only first task-wake transitions published by this
                // owner thread enter the event lane. Staged submissions also
                // reach the kernel before the executor considers parking.
                {
                    let _event_delivery = executor.tasks.event_delivery();
                    driver.turn();
                    executor.wake_ready_sleepers(Instant::now());
                }

                // If any task became ready, keep polling instead of parking.
                if executor.tasks.has_ready() {
                    continue;
                }

                // Park until a completion arrives, a wake is published, or the
                // next timer (ring timeout wheel or sleeper alarm) is due.
                driver.park(executor.next_alarm());

                // Fire sleepers that became due while parked as event wakes.
                {
                    let _event_delivery = executor.tasks.event_delivery();
                    executor.wake_ready_sleepers(Instant::now());
                }
            }
        }));

        let (output, mut first_panic) = match result {
            Ok(output) => (Some(output), None),
            Err(payload) => (None, Some(payload)),
        };

        // Close the alarm queue and detach every waker before invoking any
        // teardown callback. Registrations racing teardown now fail loudly
        // instead of landing in a heap nobody drains.
        let mut alarm_wakers = Vec::new();
        if let Some(sleeping) = executor.sleeping.lock().take() {
            alarm_wakers.reserve(sleeping.alarms.len());
            for alarm in sleeping.alarms {
                if let Some(waker) = alarm.waker.lock().take() {
                    alarm_wakers.push(waker);
                }
            }
        }

        // Abort every task spawned under this worker's root so registrations
        // racing teardown observe the abort. Each callback and resource drop
        // is isolated so later cleanup still runs.
        capture_cleanup_panic(&mut first_panic, || tree.abort());
        for waker in alarm_wakers {
            capture_cleanup_panic(&mut first_panic, || waker.wake_by_ref());
            capture_cleanup_panic(&mut first_panic, move || drop(waker));
        }

        // Task futures run arbitrary user drop code. Clearing all of them is
        // what orphans their driver observers before the ring drain.
        capture_cleanup_panic(&mut first_panic, || executor.tasks.clear());

        // Drop the root and every worker-owned handle before the executor.
        // Task and root destructors may still upgrade their executor weak
        // references during their isolated cleanup callbacks.
        capture_cleanup_panic(&mut first_panic, move || drop(root));
        capture_cleanup_panic(&mut first_panic, move || drop(storage));
        capture_cleanup_panic(&mut first_panic, move || drop(network));
        capture_cleanup_panic(&mut first_panic, move || drop(scratch));
        capture_cleanup_panic(&mut first_panic, move || drop(root_waker));
        capture_cleanup_panic(&mut first_panic, move || drop(tree));

        capture_cleanup_panic(&mut first_panic, move || drop(executor));

        // Close the driver so late admissions fail with their kind-specific
        // error, then drain in-flight ring work so kernel-owned buffers and
        // descriptors are released before the ring is destroyed. Dropping the
        // tasks above already orphaned abandoned operations (eagerly
        // requesting their cancellation), so e.g. an idle recv does not hold
        // its waiter slot until its deadline.
        //
        // Capacity wakers are arbitrary user code (any manually polled
        // future supplies its own waker): a waker panic must not skip the
        // drain, so it is retained and resumed only after the ring is
        // quiesced. A panic inside the drain itself aborts the process
        // before unwinding can free ring state (see [Driver::drain]).
        capture_cleanup_panic(&mut first_panic, || driver.close());
        driver.drain();

        if first_panic.is_some() {
            // A completed root may return a value with adversarial drop glue.
            // Dispose of it before resuming the retained payload so a second
            // panic cannot abort the process during unwind.
            capture_cleanup_panic(&mut first_panic, move || drop(output));
            resume_unwind(first_panic.expect("cleanup panic disappeared"));
        }
        output.expect("root output missing without a panic")
    }
}

/// Implementation of [crate::Runner] for the `iouring` runtime.
///
/// Unlike the tokio runtime, resources opened on one worker must not be used
/// from another: see the [worker affinity](crate::iouring#worker-affinity)
/// rules before spawning dedicated or blocking tasks.
pub struct Runner {
    cfg: Config,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Runner {
    /// Initialize a new `iouring` runtime with the given configuration.
    pub const fn new(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl crate::Runner for Runner {
    type Context = Context;

    fn start<F, Fut>(self, f: F) -> Fut::Output
    where
        F: FnOnce(Self::Context) -> Fut,
        Fut: Future,
    {
        // Reject dangerous configurations before any startup side effect.
        self.cfg.validate();

        // Create a new registry
        let registry = Registry::new();
        let mut root_registry = registry.clone();
        let mut runtime_registry = root_registry.sub_registry(METRICS_PREFIX);

        // Initialize metrics and panicker
        let metrics = Metrics::init(&mut runtime_registry);
        let (panicker, panicked) = Panicker::new(self.cfg.catch_panics);

        // Initialize buffer pools
        let network_buffer_pool = BufferPool::new(
            self.cfg.network_buffer_pool_cfg.clone(),
            &mut runtime_registry.sub_registry("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            self.cfg.storage_buffer_pool_cfg.clone(),
            &mut runtime_registry.sub_registry("storage_buffer_pool"),
        );

        // Make any storage a prior process left in the page cache crash-durable before we open it,
        // so the data read during init is durable.
        if let Err(e) = crate::storage::sync(&self.cfg.storage_directory) {
            panic!(
                "failed to sync storage filesystem at startup ({}): {e}",
                self.cfg.storage_directory.display()
            );
        }

        // Initialize the state shared by every worker and run the root task's
        // worker on this thread.
        let shared = Arc::new(Shared {
            cfg: self.cfg,
            registry,
            metrics,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            network_buffer_pool,
            storage_buffer_pool,
            storage_lock: Arc::new(Mutex::new(())),
            workers: Mutex::new(Some(Vec::new())),
            worker_panic: Mutex::new(None),
        });
        let worker = Worker::new(Arc::clone(&shared));

        // Collect process metrics.
        //
        // We prefer to collect process metrics outside of `Context` because
        // we are using `runtime_registry` rather than the one provided by `Context`.
        let process = MeteredProcess::init(&mut runtime_registry);
        let process_executor = Arc::downgrade(&worker.executor);
        let collector = process.collect(move |duration| {
            // Piggyback the collector's cadence: reap finished worker threads
            // so completed dedicated tasks don't retain exited threads until
            // shutdown even when nothing spawns again.
            if let Some(executor) = process_executor.upgrade() {
                executor.shared.reap_workers();
            }
            Sleeper {
                executor: process_executor.clone(),
                time: Instant::now() + duration.min(MAX_TIMER_DURATION),
                alarm: None,
            }
        });
        let _ = Tasks::register(&worker.executor.tasks, collector);

        // Get metrics
        let label = Label::root();
        shared.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = shared.metrics.tasks_running.get_or_create(&label).clone();
        gauge.inc();

        // Build the root context and drive the root task on this worker. A
        // panic (from the root task with `catch_panics` disabled, or from
        // `f` itself) must not unwind past the join loop below: dedicated
        // workers may still be draining their rings, and leaking their
        // threads past `start` would let ring work outlive the runtime.
        let root_tree = Tree::root();
        let output = catch_unwind(AssertUnwindSafe(|| {
            let context = worker.context(label.name(), Vec::new(), root_tree.clone());
            // Construct the user future inside the worker loop so a panic in
            // `f` follows the same driver cleanup path as a panic while
            // polling the future.
            let root = async move { panicked.interrupt(f(context)).await };
            worker.run(root, Arc::clone(&root_tree))
        }));

        // Close the registry and take every dedicated worker atomically.
        // `spawn_worker` holds this same mutex across its open check, thread
        // creation, and handle registration. A racing spawn is therefore in
        // this batch or observes the closed registry without starting a
        // thread. Panics are resumed only after every captured thread has
        // been joined.
        let mut worker_panic = None;
        let workers = shared
            .workers
            .lock()
            .take()
            .expect("worker registry already closed");
        for worker in workers {
            if let Err(payload) = worker.join() {
                retain_first_panic(&mut worker_panic, payload);
            }
        }

        // Prefer a root panic when present. Otherwise retain worker panics in
        // stash-then-join order.
        let mut first_panic = None;
        let output = match output {
            Ok(output) => Some(output),
            Err(payload) => {
                retain_first_panic(&mut first_panic, payload);
                None
            }
        };
        if let Some(payload) = shared.worker_panic.lock().take() {
            retain_first_panic(&mut first_panic, payload);
        }
        if let Some(payload) = worker_panic {
            retain_first_panic(&mut first_panic, payload);
        }
        gauge.dec();
        if first_panic.is_some() {
            capture_cleanup_panic(&mut first_panic, move || drop(output));
            resume_unwind(first_panic.expect("runner panic disappeared"));
        }

        output.expect("root output missing without a panic")
    }
}

type Storage = MeteredStorage<IoUringStorage>;
type Network = MeteredNetwork<IoUringNetwork>;

/// Implementation of [crate::Spawner], [crate::Clock],
/// [crate::Network], and [crate::Storage] for the `iouring`
/// runtime.
pub struct Context {
    name: String,
    attributes: Vec<(String, String)>,
    executor: Weak<Executor>,
    storage: Storage,
    network: Network,
    network_buffer_pool: BufferPool,
    storage_buffer_pool: BufferPool,
    tree: Arc<Tree>,
    execution: Execution,
}

impl Context {
    /// Upgrade the weak reference to the [Executor].
    fn executor(&self) -> Arc<Executor> {
        self.executor.upgrade().expect("executor already dropped")
    }

    /// Run `f` as the root task of a worker on its own thread.
    ///
    /// The handle is assembled from parts on the caller: the wrapper that
    /// owns the result sender only exists once the worker thread has built
    /// its ring. Panics on the worker thread outside the task itself (e.g.
    /// ring creation failure) resolve the handle with [Error::Closed] and
    /// are resumed when the runtime joins its workers at teardown.
    ///
    /// Mandatory supervision holds on every exit path: the [Publisher] guard
    /// aborts the consumed context's node before the handle can resolve, so
    /// contexts derived from it before the spawn cannot spawn afterwards
    /// (mirroring the inline path's [Handle::init] wrapper).
    fn spawn_worker<F, Fut, T>(
        self,
        f: F,
        metric: utils::MetricHandle,
        parent: Arc<Tree>,
    ) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Drop the parent-worker context pieces (storage, network, executor
        // reference): the task's context is rebuilt against its own worker.
        let Self {
            name,
            attributes,
            executor,
            tree,
            ..
        } = self;
        let shared = {
            let executor = executor.upgrade().expect("executor already dropped");
            Arc::clone(&executor.shared)
        };

        let (sender, receiver) = oneshot::channel();
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let handle = Handle::from_parts(receiver, abort_handle, metric.clone());
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }
        let publisher = Publisher {
            parent,
            sender: Some(sender),
        };

        // Run the worker until the task completes or teardown aborts it.
        let thread_shared = Arc::clone(&shared);
        let body = move || {
            let worker = Worker::new(Arc::clone(&thread_shared));
            let context = worker.context(name, attributes, Arc::clone(&tree));

            // Wrap the future with panic catching, abort support, and
            // cleanup, mirroring the wrapper [Handle::init] builds for
            // executor tasks. `f` itself runs inside the catch: a panic in
            // the closure is task failure (as on the inline path, where `f`
            // runs in the caller's task), not worker failure.
            let panicker = thread_shared.panicker.clone();
            let panic_shared = Arc::clone(&thread_shared);
            let wrapped = async move {
                let result = match catch_unwind(AssertUnwindSafe(|| f(context))) {
                    Ok(future) => {
                        Abortable::new(AssertUnwindSafe(future).catch_unwind(), abort_registration)
                            .await
                    }
                    Err(panic) => Ok(Err(panic)),
                };
                match result {
                    Ok(Ok(value)) => publisher.publish(Ok(value)),
                    Ok(Err(panic)) => {
                        // Deliver to the root's interrupt. If the root
                        // already finished (its receiver is gone), stash the
                        // payload: a poll panic racing root completion must
                        // still fail `start` through the join path's final
                        // take, not vanish because this worker exits cleanly.
                        if let Some(panic) = panicker.notify(panic) {
                            panic_shared.retain_worker_panic(panic);
                        }
                        publisher.publish(Err(Error::Exited));
                    }
                    // Dropping the publisher (at the end of this block)
                    // aborts the node and resolves the handle with
                    // [Error::Closed].
                    Err(Aborted) => {}
                }
                metric.finish();
            };
            worker.run(wrapped, tree);
        };

        // Reap finished workers so retention is bounded by spawn activity
        // rather than the runtime's lifetime.
        shared.reap_workers();

        // Register the thread while the registry is open: `start` joins every
        // registered worker before returning, so a spawn racing final
        // teardown from a non-worker thread must not create a thread nobody
        // joins. When the registry is already closed, dropping `body` (and
        // the publisher inside it) closes the node and resolves the handle
        // with [Error::Closed].
        let mut workers = shared.workers.lock();
        if let Some(list) = workers.as_mut() {
            list.push(utils::thread::spawn(shared.cfg.thread_stack_size, body));
        }
        drop(workers);

        handle
    }
}

/// Owns a dedicated task's result sender behind the mandatory-supervision
/// guarantee: the consumed context's node is aborted before the handle can
/// resolve, on every exit path.
///
/// [Self::publish] aborts and then sends. Dropping the guard instead (task
/// aborted, or a worker-infrastructure panic such as ring creation failure)
/// aborts in the drop body and only then releases the sender field, so the
/// handle resolves with [Error::Closed] strictly after the node closed.
struct Publisher<T> {
    /// The consumed context's supervision node.
    parent: Arc<Tree>,
    /// The handle's result channel, `None` once published.
    sender: Option<oneshot::Sender<Result<T, Error>>>,
}

impl<T> Publisher<T> {
    /// Abort the consumed node, then resolve the handle with `result`.
    fn publish(mut self, result: Result<T, Error>) {
        self.parent.abort();
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(result);
        }
    }
}

impl<T> Drop for Publisher<T> {
    fn drop(&mut self) {
        // Idempotent after `publish`. On unpublished paths this runs before
        // the sender field drops, preserving abort-before-resolution.
        self.parent.abort();
    }
}

impl crate::Spawner for Context {
    fn dedicated(mut self) -> Self {
        self.execution = Execution::Dedicated;
        self
    }

    fn shared(mut self, blocking: bool) -> Self {
        self.execution = Execution::Shared(blocking);
        self
    }

    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // A spawn can race its origin worker's full teardown (e.g. issued
        // from another worker through a moved context, after the tree-abort
        // cascade but also after the worker dropped its executor). Hold the
        // executor strong for the duration of the spawn. When it is already
        // gone, resolve with [Error::Closed] (the same outcome the
        // tree-aborted check below gives while the worker is still winding
        // down) instead of panicking on the dead reference.
        let Some(executor) = self.executor.upgrade() else {
            return Handle::ready(Err(Error::Closed));
        };

        // Get metrics
        let label = Label::task(self.name.clone(), self.execution);
        let (_, metric) = spawn_metrics!(label, @record &executor.shared.metrics);

        // Track supervision before resetting configuration
        let parent = Arc::clone(&self.tree);
        let past = self.execution;
        self.execution = Execution::default();
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;

        // Dedicated tasks (and, until a shared blocking pool lands, blocking
        // shared tasks) run as the root of a worker on their own thread: the
        // worker owns its own ring, so the task's context submits IO without
        // touching this thread's loop.
        if !matches!(past, Execution::Shared(false)) {
            return self.spawn_worker(f, metric, parent);
        }

        // Wrap the future with panic catching, abort support, and cleanup.
        let future = f(self);
        let panic_shared = Arc::clone(&executor.shared);
        let (task, handle) = Handle::init_with_fallback(
            future,
            metric.clone(),
            executor.shared.panicker.clone(),
            Arc::clone(&parent),
            move |panic| {
                panic_shared.retain_worker_panic(panic);
            },
        );

        // Register the task, unless the executor is already tearing down.
        if !Tasks::register(&executor.tasks, task) {
            return Handle::closed(metric);
        }

        // Register the task on the parent
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let stop_resolved = {
            let executor = self.executor();
            let mut shutdown = executor.shared.shutdown.lock();
            shutdown.stop(value)
        };

        // Wait for all tasks to complete or the timeout to fire
        let timeout_future = timeout.map_or_else(
            || futures::future::Either::Right(futures::future::pending()),
            |duration| futures::future::Either::Left(self.sleep(duration)),
        );
        select! {
            result = stop_resolved => {
                result.map_err(|_| Error::Closed)?;
                Ok(())
            },
            _ = timeout_future => Err(Error::Timeout),
        }
    }

    fn stopped(&self) -> Signal {
        self.executor().shared.shutdown.lock().stopped()
    }
}

/// Rayon workers execute compute-only work and never submit ring operations,
/// so the pool is backed by plain OS threads (one per unit of parallelism)
/// rather than dedicated runtime workers, which would each carry an io_uring
/// ring the compute work never uses. Pool completions wake awaiting tasks
/// through the loop's latched cross-thread wake state, and the detached pool
/// threads may briefly outlive [crate::Runner::start].
#[stability(BETA)]
impl crate::Strategizer for Context {
    fn strategy(&self, parallelism: NonZeroUsize) -> Rayon {
        let stack_size = self.executor().shared.cfg.thread_stack_size;
        let pool = ThreadPoolBuilder::new()
            .num_threads(parallelism.get())
            .spawn_handler(move |thread| {
                let stack_size = thread.stack_size().unwrap_or(stack_size);
                utils::thread::spawn(stack_size, move || thread.run());
                Ok(())
            })
            .build()
            .expect("failed to create io_uring Rayon thread pool");
        Rayon::with_pool(Arc::new(pool))
    }
}

impl crate::Supervisor for Context {
    fn child(&self, label: &'static str) -> Self {
        let (tree, _) = Tree::child(&self.tree);
        Self {
            name: child_label(&self.name, label),
            attributes: self.attributes.clone(),
            executor: self.executor.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),
            network_buffer_pool: self.network_buffer_pool.clone(),
            storage_buffer_pool: self.storage_buffer_pool.clone(),
            tree,
            execution: Execution::default(),
        }
    }

    fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        // Validate label format (must match [a-zA-Z][a-zA-Z0-9_]*)
        validate_label(key);

        // Add the attribute to the list of attributes
        add_attribute(&mut self.attributes, key, value);
        self
    }

    fn name(&self) -> Name {
        Name {
            label: self.name.clone(),
            attributes: self.attributes.clone(),
        }
    }
}

impl crate::Metrics for Context {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> Registered<M> {
        let name = name.into();
        let help = help.into();
        let metric = Arc::new(metric);
        self.executor().shared.registry.register(
            prefixed_name(&self.name, &name),
            help,
            self.attributes.clone(),
            metric,
        )
    }

    fn encode(&self) -> String {
        self.executor().shared.registry.encode()
    }
}

/// A future that resolves once a deadline has passed.
///
/// Deadlines are tracked on the monotonic clock: wall-clock inputs (e.g.
/// [Clock::sleep_until]) are converted once at creation, so a system clock
/// step can neither strand a sleeper nor fire it early.
struct Sleeper {
    executor: Weak<Executor>,
    time: Instant,
    /// Alarm shared with the heap, allocated on the first pending poll
    /// (an unpolled or immediately-ready sleep registers nothing).
    alarm: Option<Arc<Alarm>>,
}

struct Alarm {
    time: Instant,
    /// The waker of the task most recently seen polling the sleeper.
    ///
    /// Emptied exactly once: by firing, by cancellation ([Sleeper::drop]), or
    /// by worker teardown. Accessed only under the [Sleeping] queue lock (or
    /// with the heap already moved out of it at teardown).
    waker: Mutex<Option<Waker>>,
}

impl PartialEq for Alarm {
    fn eq(&self, other: &Self) -> bool {
        self.time.eq(&other.time)
    }
}

impl Eq for Alarm {}

impl PartialOrd for Alarm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Alarm {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the ordering for min-heap
        other.time.cmp(&self.time)
    }
}

impl Future for Sleeper {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.time {
            return Poll::Ready(());
        }
        let executor = self.executor.upgrade().expect("executor already dropped");
        match &self.alarm {
            None => {
                // First pending poll: share the alarm with the heap.
                let alarm = Arc::new(Alarm {
                    time: self.time,
                    waker: Mutex::new(Some(cx.waker().clone())),
                });
                executor.register_alarm(Arc::clone(&alarm));
                self.alarm = Some(alarm);
            }
            // A pending re-poll before the deadline: refresh the stored waker
            // so the alarm wakes whichever task holds the sleeper now. This
            // also fails loudly (instead of returning `Pending` with no alarm
            // left to fire) when the re-poll is the teardown wake of a worker
            // that discarded this sleeper's alarm.
            Some(alarm) => {
                // The alarm may fire between the deadline check above and the
                // refresh: the sleep is complete.
                if executor.refresh_alarm(alarm, cx.waker()) {
                    return Poll::Ready(());
                }
            }
        }
        Poll::Pending
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        // Cancelled before the deadline (e.g. by losing a `select!`): release
        // the registered waker so the heap does not retain the task's
        // resources until the deadline elapses.
        let Some(alarm) = self.alarm.take() else {
            return;
        };
        let Some(executor) = self.executor.upgrade() else {
            return;
        };
        executor.cancel_alarm(&alarm);
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        Sleeper {
            executor: self.executor.clone(),
            time: Instant::now() + duration.min(MAX_TIMER_DURATION),
            alarm: None,
        }
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        // Convert the wall-clock deadline to a monotonic one exactly once so
        // later system clock steps do not move the wakeup.
        let delay = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(delay)
    }
}

#[cfg(feature = "external")]
impl Pacer for Context {
    fn pace<'a, F, T>(
        &'a self,
        _latency: Duration,
        future: F,
    ) -> impl Future<Output = T> + Send + 'a
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        // Execute the future immediately
        future
    }
}

impl GClock for Context {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl ReasonablyRealtime for Context {}

impl crate::Network for Context {
    type Listener = <Network as crate::Network>::Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.network.bind(socket).await
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        self.network.dial(socket).await
    }
}

impl crate::Resolver for Context {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        // Uses the host's DNS configuration via the system's libc resolver.
        // `getaddrinfo` is blocking, so resolution runs on a short-lived
        // helper thread. The helper is detached: joining it at shutdown could
        // stall `Runner::start` for a full resolver timeout, so if the
        // awaiting task is aborted the thread may briefly outlive the
        // runtime (bounded by `getaddrinfo` itself), holding only its owned
        // string and a dead oneshot sender.
        //
        // The `:0` port is required by `to_socket_addrs` but is not used for
        // DNS resolution.
        let host_port = format!("{host}:0");
        let (tx, rx) = oneshot::channel();
        utils::thread::spawn(self.executor().shared.cfg.thread_stack_size, move || {
            let result = std::net::ToSocketAddrs::to_socket_addrs(host_port.as_str())
                .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
                .map_err(|e| Error::ResolveFailed(e.to_string()));
            let _ = tx.send(result);
        });
        rx.await
            .map_err(|_| Error::ResolveFailed("resolver thread exited".into()))?
    }
}

impl TryRng for Context {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(sys_rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(sys_rng().next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        sys_rng().fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for Context {}

impl crate::Storage for Context {
    type Blob = <Storage as crate::Storage>::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        self.storage.open_versioned(partition, name, versions).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.storage.scan(partition).await
    }
}

impl crate::BufferPooler for Context {
    fn network_buffer_pool(&self) -> &BufferPool {
        &self.network_buffer_pool
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        &self.storage_buffer_pool
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
