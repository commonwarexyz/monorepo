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

use super::{Driver, RingConfig};
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
    mem::take,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
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
    /// number of concurrently in-flight logical operations (each in-flight
    /// send, recv, accept, connect, read, write, or sync consumes one slot).
    /// `single_issuer` is always enabled by the runtime because the runtime
    /// thread creates the ring and is its only submitter, and
    /// `max_request_timeout` is raised to at least `read_write_timeout` and
    /// `connect_timeout` so network deadlines are never clamped.
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

    /// Explicit buffer pool configuration for network I/O, if provided.
    network_buffer_pool_cfg: Option<BufferPoolConfig>,

    /// Explicit buffer pool configuration for storage I/O, if provided.
    storage_buffer_pool_cfg: Option<BufferPoolConfig>,
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
            network_buffer_pool_cfg: None,
            storage_buffer_pool_cfg: None,
        }
    }

    // Setters
    /// Sets the configuration for each worker's io_uring instance.
    ///
    /// The ring `size` bounds the number of concurrently in-flight logical
    /// operations per worker. Defaults to a 1024-entry ring. Regardless of
    /// the provided value, the runtime always enables `single_issuer` and
    /// raises `max_request_timeout` to cover both network timeouts.
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
    /// Defaults to 10 seconds. Values above 30 years panic in
    /// [crate::Runner::start], a policy bound kept consistent with the
    /// runtime's sleep clamp. The runtime raises the ring's timeout wheel
    /// horizon to cover both network timeouts, so at the default
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
    /// Defaults to 60 seconds. Values above 30 years panic in
    /// [crate::Runner::start], a policy bound kept consistent with the
    /// runtime's sleep clamp. The runtime raises the ring's timeout wheel
    /// horizon to cover both network timeouts, so at the default
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
    /// Defaults to [BufferPoolConfig::for_network] when unset.
    pub fn with_network_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.network_buffer_pool_cfg = Some(cfg);
        self
    }
    /// Sets an explicit buffer pool configuration for storage I/O.
    ///
    /// Defaults to [BufferPoolConfig::for_storage] when unset.
    pub fn with_storage_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.storage_buffer_pool_cfg = Some(cfg);
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

    /// Returns the network buffer pool config, using the network default when
    /// not explicitly configured.
    fn resolved_network_buffer_pool_config(&self) -> BufferPoolConfig {
        self.network_buffer_pool_cfg
            .clone()
            .unwrap_or_else(BufferPoolConfig::for_network)
    }

    /// Returns the storage buffer pool config, using the storage default when
    /// not explicitly configured.
    fn resolved_storage_buffer_pool_config(&self) -> BufferPoolConfig {
        self.storage_buffer_pool_cfg
            .clone()
            .unwrap_or_else(BufferPoolConfig::for_storage)
    }

    /// Rejects configurations the runtime must not start with.
    ///
    /// Called at the beginning of [crate::Runner::start], before any startup
    /// side effect. Panics when either network timeout exceeds
    /// [MAX_TIMER_DURATION], keeping timeout policy consistent with the
    /// runtime's sleep clamp.
    fn validate(&self) {
        assert!(
            self.network_cfg.connect_timeout <= MAX_TIMER_DURATION,
            "connect_timeout must be at most 30 years"
        );
        assert!(
            self.network_cfg.read_write_timeout <= MAX_TIMER_DURATION,
            "read_write_timeout must be at most 30 years"
        );
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
    metrics: Arc<Metrics>,
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
    /// Whether this runtime ever spawned a worker thread. Monotone: set (for
    /// an accepted spawn) before the worker thread is launched, never
    /// cleared, so any worker observing its own teardown sees it set.
    spawned_workers: AtomicBool,
    /// Panic payload from a worker joined by an opportunistic reap, resumed
    /// when the runtime shuts down (reaps must not swallow worker panics).
    worker_panic: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl Shared {
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
                    let _ = self.worker_panic.lock().get_or_insert(payload);
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
/// Lock order: this mutex first, then any [AlarmState] waker slot. Holding
/// the queue lock across a slot take and its tombstone accounting keeps
/// `cancelled` exact relative to draining and compaction.
struct Sleeping {
    alarms: BinaryHeap<Alarm>,
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
            self.alarms
                .retain(|alarm| alarm.state.waker.lock().is_some());
            self.cancelled = 0;
        }
    }
}

/// State shared between a heap [Alarm] and its [Sleeper].
struct AlarmState {
    /// The waker of the task most recently seen polling the sleeper.
    ///
    /// Emptied exactly once: by firing, by cancellation ([Sleeper::drop]), or
    /// by worker teardown. Accessed only under the [Sleeping] queue lock (or
    /// with the heap already moved out of it at teardown).
    waker: Mutex<Option<Waker>>,
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
    fn register_alarm(&self, alarm: Alarm) {
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
    fn refresh_alarm(&self, state: &AlarmState, waker: &Waker) -> bool {
        let sleeping = self.sleeping.lock();
        assert!(sleeping.is_some(), "sleep outlived its io_uring worker");
        let mut slot = state.waker.lock();
        let Some(current) = slot.as_mut() else {
            return true;
        };
        current.clone_from(waker);
        false
    }

    /// Cancel a registered alarm: release its waker (and the task resources
    /// it retains) immediately, leaving a tombstone in the heap.
    ///
    /// Compaction rebuilds the heap once tombstones outnumber live alarms, so
    /// the heap's size stays proportional to live sleepers regardless of how
    /// many long-deadline sleeps are cancelled (e.g. by losing a `select!`).
    fn cancel_alarm(&self, state: &AlarmState) {
        let mut guard = self.sleeping.lock();
        // Worker already torn down: the heap (and this alarm) was discarded.
        let Some(sleeping) = guard.as_mut() else {
            return;
        };
        // An already-empty slot means the alarm fired and left the heap.
        if state.waker.lock().take().is_none() {
            return;
        }
        sleeping.cancelled += 1;
        sleeping.compact_if_needed();
    }

    /// Wake any sleepers whose deadlines have elapsed.
    fn wake_ready_sleepers(&self, current: Instant) {
        let mut due = Vec::new();
        {
            let mut sleeping = self.sleeping.lock();
            let sleeping = sleeping
                .as_mut()
                .expect("alarm queue closed while the worker loop is running");
            while let Some(next) = sleeping.alarms.peek() {
                if next.time > current {
                    break;
                }
                let alarm = sleeping.alarms.pop().unwrap();
                match alarm.state.waker.lock().take() {
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
        for waker in due {
            waker.wake();
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

        // The worker thread creates the ring and is its only submitter, so
        // single issuer mode is always sound here.
        let mut ring_cfg = shared.cfg.ring.clone();
        ring_cfg.single_issuer = true;
        ring_cfg.max_request_timeout = ring_cfg
            .max_request_timeout
            .max(shared.cfg.network_cfg.read_write_timeout)
            .max(shared.cfg.network_cfg.connect_timeout);
        let (driver, handle) = Driver::new(ring_cfg, &mut runtime_registry.sub_registry("iouring"))
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
                        let slot = task.slot();
                        if task.poll() {
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

        // Abort every task spawned under this worker's root so registrations
        // racing teardown observe the abort.
        tree.abort();

        // Clear remaining tasks and the root: task futures run arbitrary user
        // drop code, and a panic here must not skip the drain below while the
        // waiter slab still owns kernel-referenced buffers, so capture it and
        // resume after the ring is quiesced.
        //
        // It is critical that we wait to drop the strong reference to executor
        // until after we have dropped all tasks (as they may attempt to
        // upgrade their weak reference to the executor during drop).
        let teardown = catch_unwind(AssertUnwindSafe(|| {
            // Close the alarm queue (registrations racing teardown now fail
            // loudly instead of landing in a heap nobody drains), then wake
            // the discarded alarms outside the lock: a woken foreign waiter
            // re-polls, observes the closed queue, and panics in its own
            // task rather than hanging on a wake that will never arrive.
            let sleeping = executor
                .sleeping
                .lock()
                .take()
                .expect("alarm queue closed twice");
            for alarm in sleeping.alarms {
                if let Some(waker) = alarm.state.waker.lock().take() {
                    waker.wake();
                }
            }
            for task in executor.tasks.clear() {
                task.clear();
            }

            // Drop the root task (and the worker's own handles) to release
            // any Context references still held.
            drop(root);
            drop(storage);
            drop(network);
        }));

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
        let close_wakers = catch_unwind(AssertUnwindSafe(|| driver.close()));
        driver.drain();

        // Assert no context escaped the runtime. The check is meaningful only
        // for runtimes that never spawned another worker: once one exists,
        // the count legitimately races (another worker's tasks may hold this
        // worker's contexts or sleep futures and drop them only when their
        // own teardown observes the abort cascade, possibly after the join
        // loop has already drained the registry), so a monotone flag gates
        // the check rather than any point-in-time registry state. It runs
        // only when no caught payload is pending: an escape observed then is
        // usually a consequence of the pending panic (the root died before
        // releasing or joining whatever holds the reference), and this
        // diagnostic must not replace the payload that explains it.
        if result.is_ok() && teardown.is_ok() && close_wakers.is_ok() {
            let multi_worker = executor.shared.spawned_workers.load(Ordering::Relaxed);
            assert!(
                multi_worker || Arc::weak_count(&executor) == 0,
                "executor still has weak references"
            );
        }

        // Handle the result: resume the original panic after cleanup if one
        // was caught, preferring it over a panic from task teardown, and
        // either over a close-waker panic.
        match (result, teardown, close_wakers) {
            (Err(payload), _, _) | (Ok(_), Err(payload), _) | (Ok(_), Ok(()), Err(payload)) => {
                resume_unwind(payload)
            }
            (Ok(output), Ok(()), Ok(())) => output,
        }
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
        let metrics = Arc::new(Metrics::init(&mut runtime_registry));
        let (panicker, panicked) = Panicker::new(self.cfg.catch_panics);

        // Initialize buffer pools
        let network_buffer_pool = BufferPool::new(
            self.cfg.resolved_network_buffer_pool_config(),
            &mut runtime_registry.sub_registry("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            self.cfg.resolved_storage_buffer_pool_config(),
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
            spawned_workers: AtomicBool::new(false),
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
                state: None,
            }
        });
        let _ = Tasks::register(&worker.executor.tasks, collector);

        // Get metrics
        let label = Label::root();
        shared.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = shared.metrics.tasks_running.get_or_create(&label).clone();

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

        // Snapshot reap-stashed panics before triggering any further
        // teardown: a payload present at this point was captured while the
        // root still ran, so it predates (and usually causes) any root
        // panic. Taking it after the abort below would let a worker panicked
        // BY that cascade (and reaped by a racing foreign-thread spawn)
        // outrank the root panic it resulted from. A cascade panic from
        // `run`'s own internal abort can still slip in through the same
        // foreign-reap race. Distinguishing it would require stamping
        // stashes with a teardown epoch, which the diagnostic payoff does
        // not justify.
        let stashed = shared.worker_panic.lock().take();

        // `run` aborts the tree before it returns or unwinds, but a panic in
        // `f` itself never reaches `run`, so abort again (idempotent) so every
        // worker observes its wind-down before being joined.
        root_tree.abort();

        // Join dedicated worker threads: the tree abort cascaded to their
        // roots, so each worker winds down once it observes the abort.
        // Workers can spawn workers, so drain until the registry stays
        // empty, then close it: later dedicated spawns racing from foreign
        // threads must not create threads nobody joins. Panics are resumed
        // only after every thread has been joined.
        let mut worker_panic = None;
        loop {
            let batch = {
                let mut workers = shared.workers.lock();
                let list = workers.as_mut().expect("worker registry already closed");
                if list.is_empty() {
                    *workers = None;
                    break;
                }
                take(list)
            };
            for worker in batch {
                if let Err(payload) = worker.join() {
                    let _ = worker_panic.get_or_insert(payload);
                }
            }
        }

        // Panic precedence: earliest cause first. A worker panic stashed
        // while the root still ran predates the root's own panic (and is
        // usually its cause: a dead worker fails the tasks that depended on
        // it), so it wins. The root panic beats join-loop and teardown-era
        // payloads, which are its downstream cascade.
        if let Some(payload) = stashed {
            resume_unwind(payload);
        }
        let output = match output {
            Ok(output) => output,
            Err(payload) => resume_unwind(payload),
        };
        if let Some(payload) = shared.worker_panic.lock().take().or(worker_panic) {
            resume_unwind(payload);
        }

        gauge.dec();
        output
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

    /// Access the [Metrics] of the runtime.
    fn metrics(&self) -> Arc<Metrics> {
        self.executor().shared.metrics.clone()
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
                            let _ = panic_shared.worker_panic.lock().get_or_insert(panic);
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
            // Mark the runtime multi-worker before the thread exists so the
            // new worker (and any worker it makes reachable) can never reach
            // its own teardown check ahead of the flag.
            shared.spawned_workers.store(true, Ordering::Relaxed);
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
        let (_, metric) = spawn_metrics!(self);

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
                let _ = panic_shared.worker_panic.lock().get_or_insert(panic);
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
    /// Alarm state shared with the heap, allocated on the first pending poll
    /// (an unpolled or immediately-ready sleep registers nothing).
    state: Option<Arc<AlarmState>>,
}

struct Alarm {
    time: Instant,
    state: Arc<AlarmState>,
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
        match &self.state {
            None => {
                // First pending poll: share alarm state with the heap.
                let state = Arc::new(AlarmState {
                    waker: Mutex::new(Some(cx.waker().clone())),
                });
                executor.register_alarm(Alarm {
                    time: self.time,
                    state: Arc::clone(&state),
                });
                self.state = Some(state);
            }
            // A pending re-poll before the deadline: refresh the stored waker
            // so the alarm wakes whichever task holds the sleeper now. This
            // also fails loudly (instead of returning `Pending` with no alarm
            // left to fire) when the re-poll is the teardown wake of a worker
            // that discarded this sleeper's alarm.
            Some(state) => {
                // The alarm may fire between the deadline check above and the
                // refresh: the sleep is complete.
                if executor.refresh_alarm(state, cx.waker()) {
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
        let Some(state) = self.state.take() else {
            return;
        };
        let Some(executor) = self.executor.upgrade() else {
            return;
        };
        executor.cancel_alarm(&state);
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
            state: None,
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
mod tests {
    use super::*;
    use crate::{
        Blob as _, IoBuf, IoBufMut, Listener as _, Metrics as _, Network as _, ReadOptions,
        Resolver as _, Runner as _, Sink as _, Spawner as _, Storage as _, Strategizer as _,
        Stream as _, Supervisor as _, WriteOptions,
    };
    use commonware_parallel::Strategy as _;
    use commonware_utils::{NZUsize, channel::oneshot};
    use futures::task::{ArcWake, waker};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
        sync::{
            atomic::{AtomicBool, AtomicUsize},
            mpsc::{Receiver, SyncSender},
        },
    };

    /// Property: network timeouts at exactly the 30-year policy bound pass
    /// validation. Setup: both timeouts set to [MAX_TIMER_DURATION]. Action:
    /// drive the private validator directly so no ring is constructed.
    /// Expected: validation returns without panicking.
    #[test]
    fn test_config_accepts_maximum_network_timeouts() {
        Config::default()
            .with_connect_timeout(MAX_TIMER_DURATION)
            .with_read_write_timeout(MAX_TIMER_DURATION)
            .validate();
    }

    /// Property: a connect timeout above the 30-year policy bound is rejected
    /// at validation. Setup: connect timeout one nanosecond past the bound.
    /// Action: drive the private validator directly so no ring is
    /// constructed. Expected: panic with the documented message.
    #[test]
    #[should_panic(expected = "connect_timeout must be at most 30 years")]
    fn test_config_rejects_excessive_connect_timeout() {
        Config::default()
            .with_connect_timeout(MAX_TIMER_DURATION + Duration::from_nanos(1))
            .validate();
    }

    /// Property: a read/write timeout above the 30-year policy bound is
    /// rejected at validation. Setup: read/write timeout one nanosecond past
    /// the bound. Action: drive the private validator directly so no ring is
    /// constructed. Expected: panic with the documented message.
    #[test]
    #[should_panic(expected = "read_write_timeout must be at most 30 years")]
    fn test_config_rejects_excessive_read_write_timeout() {
        Config::default()
            .with_read_write_timeout(MAX_TIMER_DURATION + Duration::from_nanos(1))
            .validate();
    }

    /// Property: every public Config builder round-trips through its getter
    /// (including the new connect_timeout getter and the buffer-pool
    /// resolvers), so builder regressions are immediately diagnosable.
    /// Setup: set every builder to a nondefault value. Action: read every
    /// getter. Expected: each returns the value that was set, with no
    /// runtime constructed.
    #[test]
    fn test_config_builder_getter_round_trip() {
        let ring = RingConfig {
            size: 64,
            ..RingConfig::default()
        };
        let network_pool = BufferPoolConfig::for_network().with_pool_min_size(111);
        let storage_pool = BufferPoolConfig::for_storage().with_pool_min_size(222);
        let cfg = Config::default()
            .with_ring(ring)
            .with_catch_panics(true)
            .with_storage_directory("/tmp/iouring-config-round-trip")
            .with_thread_stack_size(1 << 21)
            .with_connect_timeout(Duration::from_secs(7))
            .with_read_write_timeout(Duration::from_secs(33))
            .with_tcp_nodelay(None)
            .with_zero_linger(false)
            .with_read_buffer_size(4096)
            .with_network_buffer_pool_config(network_pool)
            .with_storage_buffer_pool_config(storage_pool);

        assert_eq!(cfg.ring().size, 64);
        assert!(cfg.catch_panics());
        assert_eq!(
            cfg.storage_directory(),
            &PathBuf::from("/tmp/iouring-config-round-trip")
        );
        assert_eq!(cfg.thread_stack_size(), 1 << 21);
        assert_eq!(cfg.connect_timeout(), Duration::from_secs(7));
        assert_eq!(cfg.read_write_timeout(), Duration::from_secs(33));
        assert_eq!(cfg.tcp_nodelay(), None);
        assert!(!cfg.zero_linger());
        assert_eq!(cfg.read_buffer_size(), 4096);
        assert_eq!(
            cfg.resolved_network_buffer_pool_config().pool_min_size(),
            111
        );
        assert_eq!(
            cfg.resolved_storage_buffer_pool_config().pool_min_size(),
            222
        );
    }

    /// Root readiness is serviced once after one spawned-task batch. If the
    /// root completes at that boundary, tasks beyond the batch stay unpolled
    /// and teardown drops every child future exactly once.
    #[test]
    fn test_root_completion_tears_down_at_ready_batch_boundary() {
        struct PendingProbe {
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }

        impl Future for PendingProbe {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut std_task::Context<'_>) -> Poll<()> {
                self.polls.fetch_add(1, Ordering::AcqRel);
                Poll::Pending
            }
        }

        impl Drop for PendingProbe {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::AcqRel);
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let observed_polls = Arc::clone(&polls);
        let observed_drops = Arc::clone(&drops);

        Runner::default().start(move |context| async move {
            let mut handles = Vec::new();
            for _ in 0..=READY_TASKS_PER_TURN {
                let polls = Arc::clone(&polls);
                let drops = Arc::clone(&drops);
                handles.push(
                    context
                        .child("pending")
                        .spawn(move |_| PendingProbe { polls, drops }),
                );
            }

            let mut yielded = false;
            std::future::poll_fn(move |cx| {
                if yielded {
                    Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;

            drop(handles);
        });

        assert_eq!(
            observed_polls.load(Ordering::Acquire),
            READY_TASKS_PER_TURN,
            "only one ready batch may run before the root completes"
        );
        assert_eq!(
            observed_drops.load(Ordering::Acquire),
            READY_TASKS_PER_TURN + 1,
            "teardown must drop both polled and queued child futures"
        );
    }

    /// A lone self-waker refills unused capacity in the current task turn.
    /// A due internal alarm records the first event-service boundary, which
    /// must occur only after the task consumes four of the 64 token slots.
    #[test]
    fn test_in_turn_refill_polls_self_waker_before_event_service() {
        struct ServiceWake {
            /// Whether sleeper delivery invoked this waker.
            delivered: Arc<AtomicBool>,
            /// Resolves the root after the service boundary.
            sender: Mutex<Option<oneshot::Sender<()>>>,
        }

        impl ArcWake for ServiceWake {
            fn wake_by_ref(arc_self: &Arc<Self>) {
                arc_self.delivered.store(true, Ordering::Release);
                if let Some(sender) = arc_self.sender.lock().take() {
                    let _ = sender.send(());
                }
            }
        }

        struct RefillProbe {
            /// Worker whose sleeper queue marks the service boundary.
            executor: Arc<Executor>,
            /// Waker installed in the due alarm on the first poll.
            service_waker: Option<Waker>,
            /// Whether the worker serviced the due alarm.
            delivered: Arc<AtomicBool>,
            /// Total task polls observed.
            polls: Arc<AtomicUsize>,
        }

        impl Future for RefillProbe {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<()> {
                let poll = self.polls.fetch_add(1, Ordering::AcqRel) + 1;
                assert!(
                    !self.delivered.load(Ordering::Acquire),
                    "event service ran before in-turn refill poll {poll}"
                );
                if poll == 1 {
                    let state = Arc::new(AlarmState {
                        waker: Mutex::new(self.service_waker.take()),
                    });
                    self.executor.register_alarm(Alarm {
                        time: Instant::now(),
                        state,
                    });
                }
                if poll == 4 {
                    return Poll::Ready(());
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        let delivered = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let observed_delivered = Arc::clone(&delivered);
        let observed_polls = Arc::clone(&polls);

        Runner::default().start(move |context| async move {
            let (send, recv) = oneshot::channel();
            let service_waker = waker(Arc::new(ServiceWake {
                delivered: Arc::clone(&delivered),
                sender: Mutex::new(Some(send)),
            }));
            let executor = context.executor.upgrade().unwrap();
            let child_delivered = Arc::clone(&delivered);
            let child_polls = Arc::clone(&polls);
            context
                .child("refill")
                .spawn(move |_| RefillProbe {
                    executor,
                    service_waker: Some(service_waker),
                    delivered: child_delivered,
                    polls: child_polls,
                })
                .await
                .unwrap();

            assert_eq!(polls.load(Ordering::Acquire), 4);
            assert!(!delivered.load(Ordering::Acquire));
            recv.await.unwrap();
            assert!(delivered.load(Ordering::Acquire));
        });

        assert_eq!(observed_polls.load(Ordering::Acquire), 4);
        assert!(observed_delivered.load(Ordering::Acquire));
    }

    /// An ordinary spawned sleeper that has returned Pending consumes its
    /// timer wake before the old normal backlog drains. More than four batches
    /// of self-waking children keep the normal lane saturated, and the first
    /// child blocks long enough to make the sleeper due during that batch.
    #[test]
    fn test_spawned_sleep_event_precedes_old_ready_backlog() {
        struct Saturating {
            first: bool,
            blocked: bool,
            polls: Arc<AtomicUsize>,
            stop: Arc<AtomicBool>,
        }

        impl Future for Saturating {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<()> {
                let poll = self.polls.fetch_add(1, Ordering::AcqRel) + 1;
                assert!(
                    poll <= READY_TASKS_PER_TURN * 8,
                    "spawned sleeper was not serviced under ready saturation"
                );
                if self.first && !self.blocked {
                    self.blocked = true;
                    std::thread::sleep(Duration::from_millis(10));
                }
                if self.stop.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let pending_seen = Arc::new(AtomicBool::new(false));
        let resumed_at = Arc::new(AtomicUsize::new(usize::MAX));
        let stop = Arc::new(AtomicBool::new(false));

        Runner::default().start(move |context| async move {
            let sleeper_polls = Arc::clone(&polls);
            let sleeper_pending_seen = Arc::clone(&pending_seen);
            let sleeper_resumed_at = Arc::clone(&resumed_at);
            let sleeper = context.child("sleeper").spawn(move |context| async move {
                let mut sleep = Box::pin(context.sleep(Duration::from_millis(1)));
                let pending =
                    std::future::poll_fn(|cx| Poll::Ready(sleep.as_mut().poll(cx).is_pending()))
                        .await;
                assert!(pending, "spawned sleeper must first return Pending");
                sleeper_pending_seen.store(true, Ordering::Release);
                sleep.await;
                sleeper_resumed_at.store(sleeper_polls.load(Ordering::Acquire), Ordering::Release);
            });

            let mut handles = Vec::new();
            for i in 0..READY_TASKS_PER_TURN * 4 {
                let polls = Arc::clone(&polls);
                let stop = Arc::clone(&stop);
                handles.push(context.child("saturating").spawn(move |_| Saturating {
                    first: i == 0,
                    blocked: false,
                    polls,
                    stop,
                }));
            }

            sleeper.await.unwrap();
            let at_timer = resumed_at.load(Ordering::Acquire);
            assert!(pending_seen.load(Ordering::Acquire));
            assert!(
                at_timer < READY_TASKS_PER_TURN * 4,
                "spawned sleeper resumed after the old backlog drained at {at_timer} child polls"
            );
            assert!(
                at_timer < READY_TASKS_PER_TURN,
                "event-ready sleeper did not lead the next batch at {at_timer} child polls"
            );

            stop.store(true, Ordering::Release);
            for handle in handles {
                handle.await.unwrap();
            }
        });
    }

    /// An ordinary spawned accept consumer is polled immediately after the
    /// driver observes its CQE, before the old normal backlog drains. A proxy
    /// waker records driver observation separately from the consumer poll.
    #[test]
    fn test_spawned_accept_event_precedes_old_ready_backlog() {
        struct CompletionWake {
            task: Waker,
            polls: Arc<AtomicUsize>,
            observed_at: Arc<AtomicUsize>,
        }

        impl ArcWake for CompletionWake {
            fn wake_by_ref(arc_self: &Arc<Self>) {
                let polls = arc_self.polls.load(Ordering::Acquire);
                let _ = arc_self.observed_at.compare_exchange(
                    usize::MAX,
                    polls,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                arc_self.task.wake_by_ref();
            }
        }

        struct Saturating {
            connection_gate: Option<(SyncSender<()>, Receiver<()>)>,
            polls: Arc<AtomicUsize>,
            stop: Arc<AtomicBool>,
        }

        impl Future for Saturating {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut std_task::Context<'_>) -> Poll<()> {
                self.polls.fetch_add(1, Ordering::AcqRel);
                if let Some((start, connected)) = self.connection_gate.take() {
                    start.send(()).expect("connector thread exited");
                    connected
                        .recv_timeout(Duration::from_secs(10))
                        .expect("connector did not establish loopback connection");
                }
                if self.stop.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let completion_at = Arc::new(AtomicUsize::new(usize::MAX));
        let consumer_at = Arc::new(AtomicUsize::new(usize::MAX));
        let pending_seen = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        Runner::default().start(move |context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let (start_send, start_recv) = std::sync::mpsc::sync_channel(0);
            let (connected_send, connected_recv) = std::sync::mpsc::sync_channel(0);
            let connector = std::thread::spawn(move || {
                start_recv.recv().expect("saturating child exited");
                let client = TcpStream::connect(addr).expect("connect loopback listener");
                connected_send
                    .send(())
                    .expect("saturating child exited before connection acknowledgment");
                client
            });

            // The guard only bounds a scheduler regression. The poll-count
            // assertions below are the fairness oracle.
            let (guard_cancel_send, guard_cancel_recv) = std::sync::mpsc::channel();
            let guard_stop = Arc::clone(&stop);
            let guard = std::thread::spawn(move || {
                if guard_cancel_recv
                    .recv_timeout(Duration::from_secs(10))
                    .is_err()
                {
                    guard_stop.store(true, Ordering::Release);
                }
            });

            // Register the ordinary accept consumer before the old backlog.
            // Its first poll submits the accept and leaves its queued latch
            // clear before the first saturating child starts the connector.
            let accept_polls = Arc::clone(&polls);
            let accept_completion_at = Arc::clone(&completion_at);
            let accept_consumer_at = Arc::clone(&consumer_at);
            let accept_pending_seen = Arc::clone(&pending_seen);
            let accept_task = context.child("accept").spawn(move |_| async move {
                let mut accept = Box::pin(listener.accept());
                let accepted = std::future::poll_fn(|cx| {
                    let proxy = waker(Arc::new(CompletionWake {
                        task: cx.waker().clone(),
                        polls: Arc::clone(&accept_polls),
                        observed_at: Arc::clone(&accept_completion_at),
                    }));
                    let mut proxy_cx = std_task::Context::from_waker(&proxy);
                    let result = accept.as_mut().poll(&mut proxy_cx);
                    match result {
                        Poll::Pending => {
                            accept_pending_seen.store(true, Ordering::Release);
                            Poll::Pending
                        }
                        Poll::Ready(result) => {
                            accept_consumer_at
                                .store(accept_polls.load(Ordering::Acquire), Ordering::Release);
                            Poll::Ready(result)
                        }
                    }
                })
                .await;
                drop(accept);
                drop(listener);
                accepted
            });

            let mut connection_gate = Some((start_send, connected_recv));
            let mut handles = Vec::new();
            for _ in 0..READY_TASKS_PER_TURN * 4 {
                let connection_gate = connection_gate.take();
                let polls = Arc::clone(&polls);
                let stop = Arc::clone(&stop);
                handles.push(context.child("saturating").spawn(move |_| Saturating {
                    connection_gate,
                    polls,
                    stop,
                }));
            }

            // The first saturating child waits for the foreign connector,
            // guaranteeing the connection is queued before this batch ends.
            let accepted = accept_task.await.unwrap();

            stop.store(true, Ordering::Release);
            let _ = guard_cancel_send.send(());
            guard.join().expect("hang guard panicked");
            for handle in handles {
                handle.await.unwrap();
            }

            let client = connector.join().expect("connector thread panicked");
            let (_, sink, stream) = accepted.unwrap();
            drop(stream);
            drop(sink);
            drop(client);

            let driver_at = completion_at.load(Ordering::Acquire);
            let consumed_at = consumer_at.load(Ordering::Acquire);
            assert!(pending_seen.load(Ordering::Acquire));
            assert!(
                driver_at < READY_TASKS_PER_TURN * 4,
                "driver observed the accept CQE after {driver_at} child polls"
            );
            assert_eq!(
                consumed_at, driver_at,
                "accept consumer polled at {consumed_at}, driver observed its CQE at {driver_at}"
            );
        });
    }

    /// A dedicated task runs on its own worker with its own ring: storage
    /// and network operations issued from it must work end to end, including
    /// against a listener owned by another worker.
    #[test]
    fn test_dedicated_worker_io() {
        Runner::default().start(|context| async move {
            // Bind a listener on the root worker.
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            // The dedicated task writes durable storage through its own ring
            // and dials the root worker's listener over real TCP.
            let dedicated =
                context
                    .child("dedicated")
                    .dedicated()
                    .spawn(move |context| async move {
                        let (blob, len) = context.open("partition", b"blob").await.unwrap();
                        assert_eq!(len, 0);
                        blob.write_at(0, IoBuf::from(b"hello"), WriteOptions::default())
                            .await
                            .unwrap();
                        blob.sync().await.unwrap();
                        let read = blob.read_at(0, 5, ReadOptions::default()).await.unwrap();
                        assert_eq!(read.coalesce(), b"hello");

                        let (mut sink, mut stream) = context.dial(addr).await.unwrap();
                        sink.send(IoBuf::from(b"ping")).await.unwrap();
                        let response = stream.recv(4).await.unwrap();
                        assert_eq!(response.coalesce(), b"pong");
                    });

            // Serve the dedicated task's connection from the root worker.
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let msg = stream.recv(4).await.unwrap();
            assert_eq!(msg.coalesce(), b"ping");
            sink.send(IoBuf::from(b"pong")).await.unwrap();

            dedicated.await.unwrap();
        });
    }

    /// Aborting a dedicated task tears its worker down promptly, and the
    /// runtime joins the worker thread at teardown.
    #[test]
    fn test_dedicated_worker_abort() {
        let start = std::time::Instant::now();
        Runner::default().start(|context| async move {
            let handle = context
                .child("dedicated")
                .dedicated()
                .spawn(|context| async move {
                    loop {
                        context.sleep(Duration::from_millis(10)).await;
                    }
                });
            context.sleep(Duration::from_millis(50)).await;
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));
        });
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "worker teardown took {:?}",
            start.elapsed()
        );
    }

    /// Until a shared blocking pool lands, blocking shared tasks alias
    /// dedicated ones: std-blocking work must not starve the root executor.
    #[test]
    fn test_spawn_blocking_runs_off_thread() {
        Runner::default().start(|context| async move {
            let blocking = context
                .child("blocking")
                .shared(true)
                .spawn(|_| async move {
                    std::thread::sleep(Duration::from_millis(200));
                    42
                });

            // The root worker keeps making progress while the blocking task
            // holds its own thread.
            let start = std::time::Instant::now();
            context.sleep(Duration::from_millis(20)).await;
            assert!(start.elapsed() < Duration::from_millis(150));

            assert_eq!(blocking.await.unwrap(), 42);
        });
    }

    /// A panic while constructing the root future must still close the root
    /// worker's driver before the panic leaves `start`.
    #[test]
    fn test_root_closure_panic_closes_driver() {
        let cfg = Config::default();
        let storage_directory = cfg.storage_directory().clone();
        let escaped = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&escaped);

        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(cfg).start(move |context| -> std::future::Ready<()> {
                *capture.lock() = Some(context);
                panic!("root closure panic");
            });
        }));
        assert!(result.is_err(), "root closure should panic");

        let context = escaped.lock().take().expect("context should escape");
        let (blob, _) = futures::executor::block_on(context.open("partition", b"blob")).unwrap();
        let waker = futures::task::noop_waker();
        let mut cx = std_task::Context::from_waker(&waker);
        let mut read = Box::pin(blob.read_at(0, 1, ReadOptions::default()));
        assert!(
            matches!(
                read.as_mut().poll(&mut cx),
                Poll::Ready(Err(Error::ReadFailed))
            ),
            "escaped driver accepted work after root cleanup"
        );

        drop(read);
        drop(blob);
        drop(context);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    /// Context-backed resource constructors retain their origin worker's
    /// ring. Moving a context to another worker must reject construction
    /// before creating storage or observing a bind result.
    #[test]
    fn test_resource_construction_with_moved_context_panics_before_side_effects() {
        let cfg = Config::default().with_catch_panics(true);
        let storage_directory = cfg.storage_directory().clone();
        let test_storage_directory = storage_directory.clone();

        Runner::new(cfg).start(|context| async move {
            let storage_context = context.child("foreign_storage_context");
            let storage =
                context
                    .child("foreign_storage_worker")
                    .dedicated()
                    .spawn(move |_| async move {
                        let _ = storage_context.open("partition", b"blob").await;
                    });
            assert!(matches!(storage.await, Err(Error::Exited)));
            assert!(
                !test_storage_directory.exists(),
                "foreign open created the storage directory"
            );

            let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let occupied_addr = occupied.local_addr().unwrap();
            let network_context = context.child("foreign_network_context");
            let network =
                context
                    .child("foreign_network_worker")
                    .dedicated()
                    .spawn(move |_| async move {
                        let _ = network_context.bind(occupied_addr).await;
                    });
            assert!(
                matches!(network.await, Err(Error::Exited)),
                "foreign bind returned the kernel error before checking affinity"
            );
        });

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    /// Cached listener and stream accessors are still worker-affine. A
    /// foreign worker must not read a cached address or buffered bytes.
    #[test]
    fn test_cached_network_accessors_on_other_worker_panic() {
        let cfg = Config::default().with_catch_panics(true);
        Runner::new(cfg).start(|context| async move {
            let listener = context
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
            let local_addr =
                context
                    .child("foreign_local_addr")
                    .dedicated()
                    .spawn(move |_| async move {
                        let _ = listener.local_addr();
                    });
            assert!(
                matches!(local_addr.await, Err(Error::Exited)),
                "foreign local_addr returned cached data"
            );

            let mut listener = context
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let (mut client_sink, _client_stream) = context.dial(addr).await.unwrap();
            let (_, _server_sink, mut server_stream) = listener.accept().await.unwrap();

            client_sink.send(IoBuf::from(b"buffered")).await.unwrap();
            let first = server_stream.recv(1).await.unwrap();
            assert_eq!(first.coalesce(), b"b");
            assert_eq!(server_stream.peek(7), b"uffered");

            let peek =
                context
                    .child("foreign_buffered_peek")
                    .dedicated()
                    .spawn(move |_| async move {
                        let _ = server_stream.peek(7);
                    });
            assert!(
                matches!(peek.await, Err(Error::Exited)),
                "foreign peek returned buffered data"
            );
        });
    }

    /// Using a ring-bound resource from another worker fails loudly with the
    /// documented affinity panic (the task fails, the runtime survives): the
    /// io_uring runtime deliberately does not provide the tokio backend's
    /// location transparency for blobs, sockets, and listeners.
    #[test]
    fn test_blob_use_on_other_worker_panics() {
        #[derive(Clone, Copy, Debug)]
        enum Operation {
            Resize,
            ResizeOverflow,
            Read,
            ReadEmpty,
            ReadBufferEmpty,
            ReadOverflow,
            ReadBufferOverflow,
            WriteEmpty,
            WriteOverflow,
            WriteSyncEmpty,
            WriteSyncOverflow,
        }

        let cases = [
            ("resize", Operation::Resize),
            ("resize_overflow", Operation::ResizeOverflow),
            ("read", Operation::Read),
            ("read_empty", Operation::ReadEmpty),
            ("read_buffer_empty", Operation::ReadBufferEmpty),
            ("read_overflow", Operation::ReadOverflow),
            ("read_buffer_overflow", Operation::ReadBufferOverflow),
            ("write_empty", Operation::WriteEmpty),
            ("write_overflow", Operation::WriteOverflow),
            ("write_sync_empty", Operation::WriteSyncEmpty),
            ("write_sync_overflow", Operation::WriteSyncOverflow),
        ];

        let cfg = Config::default().with_catch_panics(true);
        Runner::new(cfg).start(|context| async move {
            let (blob, _) = context.open("partition", b"blob").await.unwrap();
            for (label, operation) in cases {
                let blob = blob.clone();
                let handle = context.child(label).dedicated().spawn(move |_| async move {
                    match operation {
                        Operation::Resize => {
                            let _ = blob.resize(1).await;
                        }
                        Operation::ResizeOverflow => {
                            let _ = blob.resize(u64::MAX).await;
                        }
                        Operation::Read => {
                            let _ = blob.read_at(0, 1, ReadOptions::default()).await;
                        }
                        Operation::ReadEmpty => {
                            let _ = blob.read_at(0, 0, ReadOptions::default()).await;
                        }
                        Operation::ReadBufferEmpty => {
                            let _ = blob
                                .read_at_buf(
                                    0,
                                    0,
                                    IoBufMut::with_capacity(1),
                                    ReadOptions::default(),
                                )
                                .await;
                        }
                        Operation::ReadOverflow => {
                            let _ = blob.read_at(u64::MAX, 1, ReadOptions::default()).await;
                        }
                        Operation::ReadBufferOverflow => {
                            let _ = blob
                                .read_at_buf(
                                    u64::MAX,
                                    1,
                                    IoBufMut::with_capacity(1),
                                    ReadOptions::default(),
                                )
                                .await;
                        }
                        Operation::WriteEmpty => {
                            let _ = blob
                                .write_at(0, Vec::<u8>::new(), WriteOptions::default())
                                .await;
                        }
                        Operation::WriteOverflow => {
                            let _ = blob
                                .write_at(u64::MAX, b"x".to_vec(), WriteOptions::default())
                                .await;
                        }
                        Operation::WriteSyncEmpty => {
                            let _ = blob.write_at(0, Vec::<u8>::new(), WriteOptions::SYNC).await;
                        }
                        Operation::WriteSyncOverflow => {
                            let _ = blob
                                .write_at(u64::MAX, b"x".to_vec(), WriteOptions::SYNC)
                                .await;
                        }
                    }
                });
                assert!(
                    matches!(handle.await, Err(Error::Exited)),
                    "{operation:?} should panic on another worker"
                );
            }
        });
    }

    /// A capacity waker panic during close must not skip the ring drain: the
    /// accepted connection is parked by the drain and remains available
    /// through the listener that escaped the root future.
    #[test]
    fn test_close_waker_panic_still_drains_ring() {
        struct PanicWake;

        struct FlagWake(AtomicBool);

        impl std::task::Wake for PanicWake {
            fn wake(self: Arc<Self>) {
                panic!("capacity wake panic");
            }
        }

        impl std::task::Wake for FlagWake {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let listener = Arc::new(Mutex::new(None));
        let escaped = Arc::clone(&listener);
        let close_progress = Arc::new(FlagWake(AtomicBool::new(false)));
        let observed_close_progress = Arc::clone(&close_progress);
        let (addr_send, addr_recv) = std::sync::mpsc::channel();
        let connector = std::thread::spawn(move || {
            let addr = addr_recv.recv().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            std::net::TcpStream::connect(addr).unwrap()
        });

        let cfg = Config::default().with_ring(RingConfig {
            size: 1,
            ..RingConfig::default()
        });
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(cfg).start(|context| async move {
                // Occupy the only waiter slot with an accept whose ticket
                // survives in the escaped listener.
                let mut first = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                let addr = first.local_addr().unwrap();
                let mut accept = Box::pin(first.accept());
                assert!(futures::poll!(accept.as_mut()).is_pending());
                drop(accept);
                *escaped.lock() = Some(first);

                // Register the non-panicking waiter first. The arena's close
                // traversal encounters the later panicking waiter before it,
                // proving one callback panic cannot skip remaining wakes.
                let mut blocked = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                let waker = Waker::from(Arc::clone(&observed_close_progress));
                let mut cx = std_task::Context::from_waker(&waker);
                let mut accept = Box::pin(blocked.accept());
                assert!(accept.as_mut().poll(&mut cx).is_pending());
                std::mem::forget(accept);
                std::mem::forget(blocked);

                // Park a later capacity admission whose wake panics. Both
                // registrations must remain live until driver close.
                let mut blocked = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                let waker = Waker::from(Arc::new(PanicWake));
                let mut cx = std_task::Context::from_waker(&waker);
                let mut accept = Box::pin(blocked.accept());
                assert!(accept.as_mut().poll(&mut cx).is_pending());
                std::mem::forget(accept);
                std::mem::forget(blocked);

                addr_send.send(addr).unwrap();
            })
        }));
        assert!(result.is_err(), "capacity waker should panic");
        assert!(
            close_progress.0.load(Ordering::Acquire),
            "capacity waker panic skipped a later close callback"
        );
        let _connection = connector.join().unwrap();

        // The root returned before the first accept was submitted. Only the
        // shutdown drain can have completed its ticket.
        let mut listener = listener.lock().take().unwrap();
        let waker = futures::task::noop_waker();
        let mut cx = std_task::Context::from_waker(&waker);
        let mut accept = Box::pin(listener.accept());
        assert!(
            matches!(accept.as_mut().poll(&mut cx), Poll::Ready(Ok(_))),
            "close-time waker panic skipped the ring drain"
        );
    }

    /// With the default `catch_panics(false)`, the affinity panic is
    /// forwarded to the root and unwinds `start` (the documented behavior).
    #[test]
    fn test_blob_use_on_other_worker_panics_uncaught() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::default().start(|context| async move {
                let (blob, _) = context.open("partition", b"blob").await.unwrap();
                let handle = context
                    .child("dedicated")
                    .dedicated()
                    .spawn(move |_| async move {
                        let _ = blob.read_at(0, 1, ReadOptions::default()).await;
                    });
                let _ = handle.await;
            })
        }));
        assert!(result.is_err(), "affinity panic must unwind start");
    }

    /// Dropping a `start_sync` completion handle on another worker must not
    /// leak the origin worker's waiter slot: the foreign drop routes through
    /// the orphan mailbox and the loop frees the parked result.
    #[test]
    fn test_start_sync_handle_dropped_on_other_worker() {
        Runner::default().start(|context| async move {
            let (blob, _) = context.open("partition", b"blob").await.unwrap();
            blob.write_at(0, IoBuf::from(b"hello"), WriteOptions::default())
                .await
                .unwrap();
            let sync_handle = blob.start_sync().await;

            // Hand the completion handle to a dedicated task, which drops it
            // without awaiting.
            context
                .child("dedicated")
                .dedicated()
                .spawn(move |_| async move {
                    drop(sync_handle);
                })
                .await
                .unwrap();

            // The mailbox wind-down frees the slot on a subsequent turn:
            // poll the runtime-wide gauge until it drains.
            let pending = |metrics: String| -> i64 {
                let line = metrics
                    .lines()
                    .find(|line| {
                        line.starts_with("runtime_iouring_pending_operations")
                            && !line.starts_with("runtime_iouring_pending_operations{")
                    })
                    .expect("pending_operations metric missing");
                line.split_whitespace().nth(1).unwrap().parse().unwrap()
            };
            let start = std::time::Instant::now();
            loop {
                if pending(context.encode()) == 0 {
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "waiter slot leaked by cross-worker handle drop"
                );
                context.sleep(Duration::from_millis(20)).await;
            }
        });
    }

    /// Worker threads of completed dedicated (or blocking shared) tasks must
    /// not accumulate for the runtime's lifetime: an exited joinable thread
    /// retains its stack mapping (and its `JoinHandle`) until joined, so a
    /// long-lived runtime that periodically spawns blocking tasks would grow
    /// without bound if completed workers were only reaped at shutdown.
    #[test]
    fn test_completed_workers_not_retained() {
        const SPAWNS: usize = 64;
        Runner::default().start(|context| async move {
            for _ in 0..SPAWNS {
                context
                    .child("blocking")
                    .shared(true)
                    .spawn(|_| async move { 42 })
                    .await
                    .unwrap();
            }
            let executor = context.executor.upgrade().unwrap();
            let retained = executor.shared.workers.lock().as_ref().unwrap().len();
            assert!(
                retained < SPAWNS,
                "{retained} exited worker threads retained until shutdown"
            );
        });
    }

    /// A pending root panic must propagate even when a context legitimately
    /// escaped to a helper thread: the escaped-context diagnostic must not
    /// replace the payload that explains why the cleanup never happened.
    #[test]
    fn test_root_panic_outranks_escape_diagnostic() {
        let (send, recv) = std::sync::mpsc::channel();
        let (release_send, release_recv) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let context: Context = recv.recv().unwrap();
            release_recv.recv().unwrap();
            drop(context);
        });

        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::default().start(|context| async move {
                send.send(context.child("escapee")).unwrap();
                panic!("root cause");
            })
        }));
        let payload = result.expect_err("root panic should propagate");
        let message = payload.downcast_ref::<&str>().copied();
        assert_eq!(message, Some("root cause"));

        release_send.send(()).unwrap();
        holder.join().unwrap();
    }

    /// A dedicated task's poll panic that races root completion must still
    /// fail `start` (with the default `catch_panics(false)`): the root's
    /// interrupt receiver is already gone, so the payload routes through the
    /// worker-panic stash instead of vanishing while the worker exits
    /// cleanly.
    #[test]
    fn test_dedicated_poll_panic_races_root_completion() {
        let (send, recv) = std::sync::mpsc::channel();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::default().start(|context| async move {
                let _handle = context
                    .child("late")
                    .dedicated()
                    .spawn(move |_| async move {
                        send.send(()).unwrap();
                        std::thread::sleep(Duration::from_millis(300));
                        panic!("late worker panic");
                    });
                // Return as soon as the task is mid-poll: the panic then
                // lands after this worker's root future (and its interrupt
                // receiver) is gone, while `start` waits in the join loop.
                recv.recv().unwrap();
            })
        }));
        let payload = result.expect_err("racing poll panic should fail start");
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("late worker panic"));
    }

    /// A default inline child on a dedicated worker can panic after the main
    /// root's interrupt receiver closes. The join phase must retain that
    /// undeliverable payload even though the dedicated worker exits normally.
    #[test]
    fn test_nested_inline_panic_after_root_receiver_closes() {
        const PAYLOAD: u64 = 0x5eed_cafe;

        let (shared_send, shared_recv) = std::sync::mpsc::channel();
        let (blocked_send, blocked_recv) = std::sync::mpsc::channel();
        let (returning_send, returning_recv) = std::sync::mpsc::channel();
        let (release_send, release_recv) = std::sync::mpsc::channel();

        let runtime = std::thread::spawn(move || {
            catch_unwind(AssertUnwindSafe(|| {
                Runner::default().start(|context| async move {
                    let executor = context.executor.upgrade().unwrap();
                    shared_send.send(Arc::clone(&executor.shared)).unwrap();

                    let _handle =
                        context
                            .child("worker")
                            .dedicated()
                            .spawn(move |context| async move {
                                let _handle = context.child("nested").spawn(move |_| async move {
                                    blocked_send.send(()).unwrap();
                                    release_recv.recv().unwrap();
                                    std::panic::panic_any(PAYLOAD);
                                });
                                futures::future::pending::<()>().await;
                            });

                    blocked_recv.recv().unwrap();
                    returning_send.send(()).unwrap();
                });
            }))
        });

        let shared = shared_recv.recv().unwrap();
        returning_recv.recv().unwrap();

        // Once the registry is empty, the main root has closed its panic
        // receiver and moved the dedicated worker into the final join batch.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let joining = shared.workers.lock().as_ref().is_some_and(Vec::is_empty);
            if joining {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "runtime did not enter join phase"
            );
            std::thread::yield_now();
        }

        release_send.send(()).unwrap();
        let result = runtime.join().expect("runtime thread should join");
        let payload = result.expect_err("nested panic should unwind start");
        assert_eq!(payload.downcast_ref::<u64>(), Some(&PAYLOAD));
    }

    /// A worker panic already observed by an opportunistic reap happened
    /// before a later root panic and must remain the payload propagated by
    /// `start` (earliest cause wins over its cascade).
    #[test]
    fn test_reaped_worker_panic_precedes_root_panic() {
        struct PanicOnDrop;

        impl Future for PanicOnDrop {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut std_task::Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }

        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("worker panic");
            }
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::default().start(|context| async move {
                let executor = context.executor.upgrade().unwrap();
                let handle = context
                    .child("panicking_worker")
                    .dedicated()
                    .spawn(|_| PanicOnDrop);
                assert!(matches!(handle.await, Err(Error::Closed)));

                // Wait until the worker has exited, then exercise the
                // opportunistic reaper so its payload is stashed before the
                // root panics.
                loop {
                    let finished = executor
                        .shared
                        .workers
                        .lock()
                        .as_ref()
                        .unwrap()
                        .iter()
                        .any(std::thread::JoinHandle::is_finished);
                    if finished {
                        break;
                    }
                    context.sleep(Duration::from_millis(10)).await;
                }
                executor.shared.reap_workers();
                assert!(executor.shared.worker_panic.lock().is_some());

                panic!("root panic");
            })
        }));

        let payload = result.expect_err("start should propagate the first panic");
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("worker panic"));
    }

    /// Completion of a dedicated task must abort the consumed context's node
    /// before the handle resolves (as the inline path does): contexts derived
    /// from it before the spawn cannot spawn afterwards.
    #[test]
    fn test_dedicated_completion_closes_parent() {
        Runner::default().start(|context| async move {
            let worker_context = context.child("worker");
            let saved = worker_context.child("saved");
            worker_context
                .dedicated()
                .spawn(|_| async {})
                .await
                .unwrap();
            let orphan = saved.spawn(|_| async {});
            assert!(matches!(orphan.await, Err(Error::Closed)));
        });
    }

    /// Aborting a dedicated task closes the consumed context's node as well.
    #[test]
    fn test_dedicated_abort_closes_parent() {
        Runner::default().start(|context| async move {
            let worker_context = context.child("worker");
            let saved = worker_context.child("saved");
            let handle = worker_context.dedicated().spawn(|context| async move {
                loop {
                    context.sleep(Duration::from_secs(1)).await;
                }
            });
            context.sleep(Duration::from_millis(50)).await;
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));
            let orphan = saved.spawn(|_| async {});
            assert!(matches!(orphan.await, Err(Error::Closed)));
        });
    }

    /// A handle resolution observed from another worker happens strictly
    /// after the completed task's node closed: post-await spawns from saved
    /// sibling contexts are rejected on any worker.
    #[test]
    fn test_inline_completion_closes_parent_across_workers() {
        Runner::default().start(|context| async move {
            let task_context = context.child("task");
            let saved = task_context.child("saved");
            let handle = task_context.spawn(|_| async {});
            let checker = context
                .child("checker")
                .dedicated()
                .spawn(move |_| async move {
                    handle.await.unwrap();
                    let orphan = saved.spawn(|_| async {});
                    matches!(orphan.await, Err(Error::Closed))
                });
            assert!(checker.await.unwrap());
        });
    }

    /// A panic in the dedicated spawn closure itself (before it returns the
    /// future) is task failure, matching the inline path: the handle
    /// resolves with [Error::Exited] and the runtime survives.
    #[test]
    fn test_dedicated_closure_panic() {
        let cfg = Config::default().with_catch_panics(true);
        Runner::new(cfg).start(|context| async move {
            let handle = context
                .child("dedicated")
                .dedicated()
                .spawn(|_| -> std::future::Ready<()> { panic!("closure panic") });
            assert!(matches!(handle.await, Err(Error::Exited)));
        });
    }

    /// Worker threads are joined even when the root task's panic unwinds
    /// `start`: the dedicated task must have been dropped by the time
    /// `start` returns.
    #[test]
    fn test_root_panic_joins_workers() {
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(Arc::clone(&dropped));
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::default().start(|context| async move {
                let _handle =
                    context
                        .child("dedicated")
                        .dedicated()
                        .spawn(move |context| async move {
                            let _guard = guard;
                            loop {
                                context.sleep(Duration::from_secs(1)).await;
                            }
                        });
                panic!("root panic");
            })
        }));
        assert!(result.is_err());
        assert!(
            dropped.load(Ordering::Acquire),
            "worker not joined before start returned"
        );
    }

    /// A dedicated task may hold another worker's context across that
    /// worker's teardown: the escape check must tolerate the cross-worker
    /// race instead of panicking.
    #[test]
    fn test_cross_worker_context_teardown() {
        /// Holds a root-worker context and releases it only after a delay,
        /// keeping the root executor's weak count non-zero while the root
        /// worker tears down.
        struct SlowRelease(Option<Context>);
        impl Drop for SlowRelease {
            fn drop(&mut self) {
                std::thread::sleep(Duration::from_millis(200));
                self.0.take();
            }
        }

        Runner::default().start(|context| async move {
            let held = SlowRelease(Some(context.child("held")));
            let _dedicated =
                context
                    .child("dedicated")
                    .dedicated()
                    .spawn(move |context| async move {
                        let _held = held;
                        loop {
                            context.sleep(Duration::from_secs(1)).await;
                        }
                    });
            // Return while the dedicated task still holds a root context.
            context.sleep(Duration::from_millis(20)).await;
        });
    }

    /// A dedicated worker may reach its teardown check while the root is
    /// already joining the worker batch (registry drained) and a sibling
    /// worker still holds one of its contexts: the escape check must key on
    /// whether this runtime ever spawned a worker, not on point-in-time
    /// registry state.
    #[test]
    fn test_dedicated_teardown_during_join_with_held_context() {
        /// Sleeps before releasing its contents, delaying a future's drop (and
        /// so its worker's teardown) by a controlled margin.
        struct SlowRelease(Option<Context>, Duration);
        impl Drop for SlowRelease {
            fn drop(&mut self) {
                std::thread::sleep(self.1);
                self.0.take();
            }
        }

        Runner::default().start(|context| async move {
            let (send, recv) = oneshot::channel();
            let _origin = context
                .child("origin")
                .dedicated()
                .spawn(move |context| async move {
                    // Hand a context of this worker to the sibling, then delay
                    // this worker's own teardown well past the root's
                    // join-batch take via a slow-dropping guard.
                    let _ = send.send(context.child("shared"));
                    let _slow = SlowRelease(None, Duration::from_millis(300));
                    loop {
                        context.sleep(Duration::from_secs(1)).await;
                    }
                });
            // The guard is a closure capture (not constructed in the async
            // body) so its slow drop runs on the holder worker even when the
            // abort cascade wins the race to the task's first poll.
            let held = SlowRelease(Some(recv.await.unwrap()), Duration::from_millis(600));
            let _holder = context
                .child("holder")
                .dedicated()
                .spawn(move |context| async move {
                    // Hold the origin worker's context past its teardown.
                    let _held = held;
                    loop {
                        context.sleep(Duration::from_secs(1)).await;
                    }
                });
            // Return immediately: both workers tear down through the abort
            // cascade while the root drains and joins.
        });
    }

    /// A task awaiting a sleep created from another worker's context must
    /// fail loudly (not hang) when that worker tears down before the
    /// deadline: the teardown wake makes the sleeper re-poll and observe the
    /// closed alarm queue.
    #[test]
    fn test_foreign_sleep_fails_on_worker_teardown() {
        let cfg = Config::default().with_catch_panics(true);
        Runner::new(cfg).start(|context| async move {
            let (send, recv) = oneshot::channel();
            let origin = context
                .child("origin")
                .dedicated()
                .spawn(move |context| async move {
                    let _ = send.send(context.child("clock"));
                    // Stay alive long enough for the sleeper to register.
                    context.sleep(Duration::from_millis(300)).await;
                });
            let clock = recv.await.unwrap();
            let sleeper = context.child("sleeper").spawn(move |_| async move {
                clock.sleep(Duration::from_secs(3600)).await;
            });
            origin.await.unwrap();
            assert!(matches!(sleeper.await, Err(Error::Exited)));
        });
    }

    /// Cancelling sleeps before their deadline (e.g. by losing a `select!`)
    /// must not retain their alarms until the deadline elapses: cancellation
    /// releases the waker immediately and compaction keeps the heap
    /// proportional to live sleepers.
    #[test]
    fn test_sleep_cancel_releases_alarm() {
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();
            let alarms = |executor: &Arc<Executor>| {
                let guard = executor.sleeping.lock();
                let sleeping = guard.as_ref().unwrap();
                (sleeping.alarms.len(), sleeping.cancelled)
            };

            // The heap may hold unrelated live alarms (e.g. the process
            // metrics collector), but nothing else runs between these reads
            // (no awaits on this single-threaded worker), so counts are exact.
            let (baseline, baseline_cancelled) = alarms(&executor);
            assert_eq!(baseline_cancelled, 0);

            // Register far-future sleeps (one pending poll each), then cancel
            // them all by dropping the futures.
            let mut sleeps = Vec::new();
            for _ in 0..8 {
                let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
                assert!(futures::poll!(sleep.as_mut()).is_pending());
                sleeps.push(sleep);
            }
            assert_eq!(alarms(&executor).0, baseline + 8);
            drop(sleeps);

            // Only the baseline alarms remain live, and tombstones are within
            // the compaction bound (so the heap cannot grow unboundedly).
            let (len, cancelled) = alarms(&executor);
            assert_eq!(len - cancelled, baseline, "cancelled sleeps retained");
            assert!(cancelled * 2 <= len, "tombstones exceed compaction bound");
        });
    }

    /// Race foreign-thread sleeps, cancellations, and re-polls against the
    /// worker's alarm firing: sleeps must neither fire early nor hang, and
    /// tombstone accounting must stay exact under churn (an accounting bug
    /// underflows `cancelled` and panics).
    #[test]
    fn test_sleep_churn_stress() {
        use futures::FutureExt as _;
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();

            // Foreign threads: timed sleeps registered against a (mostly)
            // parked runtime must complete promptly and never early.
            let mut threads = Vec::new();
            for t in 0..4 {
                let clock = context.child("timed");
                threads.push(std::thread::spawn(move || {
                    for i in 0..50 {
                        let d = Duration::from_micros(200 * ((t + i) % 7 + 1));
                        let start = std::time::Instant::now();
                        futures::executor::block_on(clock.sleep(d));
                        assert!(start.elapsed() >= d, "sleep fired early");
                    }
                    drop(clock);
                }));
            }

            // Foreign threads: register far-future alarms, poll them pending
            // once, then drop them (cancel path + compaction churn), and race
            // short-deadline drops against the worker popping due alarms
            // (cancel-vs-fire on the tombstone accounting).
            for _ in 0..4 {
                let clock = context.child("cancelled");
                threads.push(std::thread::spawn(move || {
                    for i in 0..200 {
                        let mut far = Box::pin(clock.sleep(Duration::from_secs(3600)));
                        assert!(far.as_mut().now_or_never().is_none());
                        let mut near =
                            Box::pin(clock.sleep(Duration::from_micros(50 * (i % 5 + 1))));
                        let _ = near.as_mut().now_or_never();
                        // Let the deadline elapse so the drop below races the
                        // worker's wake_ready_sleepers pop.
                        std::thread::sleep(Duration::from_micros(50 * (i % 5 + 1)));
                        drop(near);
                        drop(far);
                    }
                    drop(clock);
                }));
            }

            // Keep the worker's loop turning between parks while the churn
            // runs, so alarms fire from both the parked and running paths.
            while threads.iter().any(|thread| !thread.is_finished()) {
                context.sleep(Duration::from_micros(500)).await;
            }
            for thread in threads {
                thread.join().unwrap();
            }

            // All churned alarms are gone, up to tombstones bounded by the
            // compaction invariant (checked after cancellation and firing).
            let guard = executor.sleeping.lock();
            let sleeping = guard.as_ref().unwrap();
            assert!(
                sleeping.alarms.len() <= 32,
                "alarm heap retained churned sleeps: {}",
                sleeping.alarms.len()
            );
            assert!(sleeping.cancelled * 2 <= sleeping.alarms.len().max(1));
        });
    }

    /// A sleeper whose alarm fires between its deadline check and its waker
    /// refresh (a foreign poll racing the origin worker at the deadline) must
    /// resolve, not panic: an emptied slot under an open queue means the
    /// alarm completed.
    #[test]
    fn test_sleep_refresh_after_fire_resolves() {
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();
            let mut sleep = Box::pin(context.sleep(Duration::from_secs(3600)));
            assert!(futures::poll!(sleep.as_mut()).is_pending());

            // Fire every registered alarm as the worker loop would at its
            // deadline, emptying the sleeper's waker slot while the queue
            // stays open (the interleaving a racing foreign poll observes).
            executor.wake_ready_sleepers(Instant::now() + Duration::from_secs(7200));

            assert!(futures::poll!(sleep.as_mut()).is_ready());
        });
    }

    /// A sleep polled once in one task and then moved to another must wake
    /// the task that most recently polled it, not the original registrant.
    #[test]
    fn test_sleep_waker_refresh_across_tasks() {
        Runner::default().start(|context| async move {
            // Register the sleep with the root task's waker.
            let mut sleep = Box::pin(context.sleep(Duration::from_millis(300)));
            assert!(futures::poll!(sleep.as_mut()).is_pending());

            // Move the pending sleep to a spawned task: its first poll must
            // refresh the alarm to wake the new task at the deadline.
            let handle = context.child("mover").spawn(move |_| sleep);
            handle.await.unwrap();
        });
    }

    /// Spawning through a context whose worker fully tore down (executor
    /// dropped, not merely tree-aborted) resolves [Error::Closed] instead of
    /// panicking: the outcome must not depend on which side of the teardown
    /// race the spawn lands.
    #[test]
    fn test_spawn_on_dead_worker_resolves_closed() {
        Runner::default().start(|context| async move {
            let (send, recv) = oneshot::channel();
            let origin = context
                .child("origin")
                .dedicated()
                .spawn(move |context| async move {
                    let _ = send.send(context.child("spawner"));
                });
            let spawner = recv.await.unwrap();
            origin.await.unwrap();
            // Give the origin worker time to finish its teardown and drop
            // its executor (the handle resolves before either happens).
            context.sleep(Duration::from_millis(200)).await;

            let handle = spawner.spawn(|_| async move { 7 });
            assert!(matches!(handle.await, Err(Error::Closed)));
        });
    }

    /// Sleeping on a context whose worker already tore down fails loudly in
    /// the sleeping task instead of registering an alarm nothing will fire.
    #[test]
    fn test_sleep_on_dead_worker_fails() {
        let cfg = Config::default().with_catch_panics(true);
        Runner::new(cfg).start(|context| async move {
            let (send, recv) = oneshot::channel();
            let origin = context
                .child("origin")
                .dedicated()
                .spawn(move |context| async move {
                    let _ = send.send(context.child("clock"));
                });
            let clock = recv.await.unwrap();
            origin.await.unwrap();
            // Give the origin worker time to finish its teardown (the handle
            // resolves before the worker closes its queue).
            context.sleep(Duration::from_millis(200)).await;
            let sleeper = context.child("sleeper").spawn(move |_| async move {
                clock.sleep(Duration::from_secs(3600)).await;
            });
            assert!(matches!(sleeper.await, Err(Error::Exited)));
        });
    }

    #[test]
    fn test_network_echo() {
        // Exercise bind, accept, dial, send, and recv end-to-end on the
        // runtime's own ring (all connection setup goes through io_uring).
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = context.child("server").spawn(move |_| async move {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let msg = stream.recv(5).await.unwrap();
                assert_eq!(msg.coalesce(), b"hello");
                sink.send(IoBuf::from(b"world")).await.unwrap();
            });

            let (mut sink, mut stream) = context.dial(addr).await.unwrap();
            sink.send(IoBuf::from(b"hello")).await.unwrap();
            let response = stream.recv(5).await.unwrap();
            assert_eq!(response.coalesce(), b"world");
            server.await.unwrap();
        });
    }

    #[test]
    fn test_network_recv_timeout() {
        // Exercise a network deadline expiring while the executor drives
        // the ring (turn/park path): the recv must report a timeout close
        // to the configured budget instead of stalling.
        let op_timeout = Duration::from_millis(100);
        let cfg = Config::default().with_read_write_timeout(op_timeout);
        Runner::new(cfg).start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = context.child("server").spawn(move |_| async move {
                let (_, sink, mut stream) = listener.accept().await.unwrap();
                let result = stream.recv(1).await;
                assert!(matches!(result, Err(Error::Timeout)));
                // Keep the connection alive until the recv resolves.
                drop(sink);
            });

            // Dial but never send, so the server's recv can only expire.
            let start = std::time::Instant::now();
            let (_sink, _stream) = context.dial(addr).await.unwrap();
            server.await.unwrap();
            let elapsed = start.elapsed();
            assert!(elapsed >= op_timeout);
            assert!(elapsed < op_timeout * 30, "recv timeout took {elapsed:?}");
        });
    }

    #[test]
    fn test_fast_teardown_with_inflight_recv() {
        // A recv still in flight when the root task returns must not delay
        // teardown until its (60s) deadline: teardown cancels operations
        // whose tasks were dropped.
        let start = std::time::Instant::now();
        let cfg = Config::default().with_read_write_timeout(Duration::from_secs(60));
        Runner::new(cfg).start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            context.child("server").spawn(move |_| async move {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                // Never receives data, aborted when the root returns.
                let _ = stream.recv(1).await;
            });

            let (_sink, _stream) = context.dial(addr).await.unwrap();
            // Give the server's recv a chance to reach the kernel.
            context.sleep(Duration::from_millis(50)).await;
        });
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "teardown took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_accept_survives_reissue() {
        // An accept that waits longer than the read/write timeout is
        // transparently reissued: a connection arriving after several
        // reissue cycles must still be accepted.
        let op_timeout = Duration::from_millis(50);
        let cfg = Config::default().with_read_write_timeout(op_timeout);
        Runner::new(cfg).start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = context.child("server").spawn(move |_| async move {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let msg = stream.recv(4).await.unwrap();
                assert_eq!(msg.coalesce(), b"ping");
            });

            // Wait through multiple accept deadlines before connecting.
            context.sleep(op_timeout * 4).await;
            let (mut sink, _stream) = context.dial(addr).await.unwrap();
            sink.send(IoBuf::from(b"ping")).await.unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn test_cross_thread_wake() {
        // Verify a foreign thread can wake the runtime thread out of its
        // park: the sleep gives the runtime time to park (so the alarm is
        // registered from another thread against a parked runtime), and
        // the oneshot send must then unblock the root task.
        let executor = Runner::default();
        executor.start(|context| async move {
            let start = std::time::Instant::now();
            let (tx, rx) = oneshot::channel();
            let thread = std::thread::spawn(move || {
                futures::executor::block_on(context.sleep(Duration::from_millis(50)));
                tx.send(42).unwrap();
            });
            assert_eq!(rx.await.unwrap(), 42);

            // Join so the thread's context clone drops before teardown
            // asserts that no context escaped the runtime.
            thread.join().unwrap();

            // The wake must arrive promptly after the 50ms sleep, not at
            // the runtime's next unrelated park deadline.
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "cross-thread wake took {:?}",
                start.elapsed()
            );
        });
    }

    #[test]
    fn test_process_rss_metric() {
        let executor = Runner::default();
        executor.start(|context| async move {
            loop {
                // Wait for RSS metric to be available
                let metrics = context.encode();
                if !metrics.contains("runtime_process_rss") {
                    context.sleep(Duration::from_millis(100)).await;
                    continue;
                }

                // Verify the RSS value is eventually populated (greater than 0)
                for line in metrics.lines() {
                    if line.starts_with("runtime_process_rss")
                        && !line.starts_with("runtime_process_rss{")
                    {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let rss_value: i64 =
                                parts[1].parse().expect("Failed to parse RSS value");
                            if rss_value > 0 {
                                return;
                            }
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn test_resolver() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let addrs = context.resolve("localhost").await.unwrap();
            assert!(!addrs.is_empty());
            for addr in addrs {
                assert!(
                    addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
                        || addr == IpAddr::V6(Ipv6Addr::LOCALHOST)
                );
            }
        });
    }

    /// Pool work runs on dedicated worker threads, so awaiting a spawned
    /// strategy task exercises the loop's cross-thread wake path.
    #[test]
    fn test_parallel_strategy_spawn_completes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let strategy = context.child("pool").strategy(NZUsize!(2)).manual();
            assert_eq!(strategy.parallelism(), 2);

            let output = strategy
                .spawn(|strategy| strategy.map_collect_vec(0..2, |i| i + 1))
                .await;

            assert_eq!(output, vec![1, 2]);
        });
    }
}
