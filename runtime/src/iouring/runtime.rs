//! Worker execution and runner-wide lifecycle.
//!
//! A [pool](super::pool) of workers polls ordinary tasks, worker zero on the
//! calling thread and the others on threads of their own. Dedicated and
//! blocking tasks each get a separate thread and io_uring ring. All workers
//! share configuration and services through [`Shared`], while execution state
//! stays in each worker's [`Local`].
//!
//! ## State and ownership
//!
//! ```text
//! Context
//!   +-- Shared (Arc) <-------------------------- Local.shared
//!   |     +-- Config, metrics, stop/panic signals
//!   |     +-- Network, Storage
//!   |     +-- Pool (each pool worker's mailbox and run queue, global queue,
//!   |     |         idle state, shutdown barrier)
//!   |     |     ^-- task headers (Weak)
//!   |     +-- Tasks (every live ordinary task, for teardown)
//!   |     `-- Workers <------------------------ ActiveWorker
//!   `-- supervision tree
//!
//! Worker (one per thread)
//!   +-- Scope --------------------------------> CURRENT (TLS)
//!   |                                               |
//!   +-- Rc<RefCell<Local>> <------------------------+
//!   |     +-- Shared (Arc)
//!   |     +-- Ready (owner's end of a pool worker's run queue)
//!   |     +-- Timers (sleep registrations and deadlines)
//!   |     +-- Driver
//!   |     |     +-- io_uring ring (SQ/CQ)
//!   |     |     +-- Waiters (requests and unconsumed results)
//!   |     |     `-- ready queue, deadlines, cancellations (IDs)
//!   |     +-- Mailbox (messages and wake source)
//!   |     `-- Deferred (callbacks and retired owners)
//!   +-- inbox (batch taken from Mailbox)
//!   +-- deferred (batch detached from Local)
//!   `-- panics (first failure retained through cleanup)
//! ```
//!
//! [`Scope`] installs checked thread-local access. Task polls, callbacks, and
//! user destructors run outside local borrows. [`Worker::callbacks`] swaps the
//! local [`Deferred`] batch into the worker before running it, so callbacks can
//! reenter [`Local`] and append another batch.
//!
//! The root is pinned separately and passed to [`Worker::drive`]. On a
//! dedicated worker, the dedicated or blocking task it was started for runs as
//! its root. Pool workers after worker zero run a root that ends when worker
//! zero stops the pool.
//!
//! ## Task placement
//!
//! Factories run on the spawning caller. Registration allocates an ordinary
//! task and retains it in [`Tasks`] on the caller's thread, then delivers its
//! first runnable. A pool worker keeps it when nothing else is queued there or
//! when it is the pool's only worker. Every other spawn, including one from a
//! busy pool worker, goes to the pool's global queue, which wakes a parked
//! worker.
//!
//! A wake queues the task in the run queue of the pool worker that wakes it. A
//! wake from outside the pool or on a closing worker pushes it into the global
//! queue, which any pool worker takes from. A wake during a poll requeues the
//! task on its poller. A queued task can still move, to the global queue when
//! its run queue overflows or to a worker that steals it, as the
//! [pool](super::pool) describes.
//!
//! A push that leaves a stealable backlog offers it to a parked worker unless
//! an existing search count covers finding or handing on that work. A count
//! can belong to a searching worker or to a wake that has reserved it but has
//! not yet claimed a worker.
//!
//! ```text
//! ordinary spawn:
//!   check Tasks --> factory --> Tasks::register
//!                                  +-- pool worker, quiet or alone --> its run queue
//!                                  `-- otherwise --> global queue --> any pool worker
//!                                                                     +-- first: poll
//!                                                                     `-- rest: run queue
//!
//! dedicated / blocking spawn:
//!   Workers::reserve --> factory --> new thread
//!                                      |
//!                                      v
//!                               Worker::run_task
//!                                      |
//!                                      v
//!                               drop ActiveWorker
//! ```
//!
//! [`ActiveWorker`] keeps the launch counted from before factory construction
//! until worker cleanup and failure reporting finish. It retains only the
//! [`Workers`] barrier, allowing that worker's [`Shared`] owners to be released first.
//!
//! I/O and sleeps register directly with the worker that first polls them. When
//! one is polled later on another worker, the registering worker forwards its
//! result through a channel. Mailboxes carry root wakes, observation transfers,
//! and cancellation messages.
//!
//! Each turn polls a bounded batch of tasks and checks the root's wake flag,
//! services I/O and timers, and applies a bounded batch of mailbox messages.
//! Deferred callbacks run between these phases.
//!
//! A pool worker takes a share of the global queue every
//! [`Config::with_global_queue_interval`] takes and whenever its own run queue
//! is empty. Taking a share returns one runnable to poll next and queues the
//! rest in the run queue, no more than it has room for and no more than would
//! fill it to half. A pool worker that finds both queues empty after a service
//! pass tries to steal before parking, or relies on workers already holding
//! search counts when the search cap refuses it.
//!
//! Before parking, the worker checks readiness again because polls and
//! callbacks can produce more work. Pool workers coordinate through
//! [`Searcher`], and all workers wait through their mailbox's
//! [`Waker`](super::waker::Waker). See [`super::idle`] for parking order.
//!
//! A held search count suppresses kicks, so a worker returns it before user
//! code and before another turn without parking. Every drive-loop exit,
//! including unwinding, withdraws any live idle publication and returns a held
//! count before root destruction.
//!
//! ## Shutdown
//!
//! Once worker zero is running, runner exit follows this order:
//!
//! ```text
//! root completes or fails
//!   |
//!   v
//! destroy root (TLS and mailbox still available)
//!   |
//!   v
//! close worker registry, task set, and global queue
//!   |
//!   v
//! abort spawned tasks through the supervision tree, stop the other pool workers
//!   |
//!   v
//! every pool worker discards its run queue and drains the task set
//!   |
//!   v
//! every pool worker waits for the others to finish polling and draining
//!   |
//!   v
//! pool workers close mailbox and io_uring ring  --> join the pool workers
//!                                                    |
//!                                                    v
//!                                  collect a pool worker failure the root missed
//!                                                    |
//!                                                    v
//!                                  wait for dedicated workers to finish
//!                                                    |
//!                                                    v
//!                                        return result or resume panic
//! ```
//!
//! No pool worker closes its mailbox or io_uring ring until every pool worker
//! has drained the set and finished its last poll, since a task polled on one
//! worker can hold registrations on another, whose mailbox forwards their
//! results. A dedicated worker closes its mailbox once its root is gone.
//!
//! Work spawned by root destruction participates in shutdown. Each worker keeps
//! TLS installed while destroying tasks, draining retained writes and syncs,
//! retiring cancellations, and running deferred callbacks. Native thread-local
//! destruction on dedicated threads can follow registration release.

use super::{
    driver::Driver,
    idle::Searcher,
    mailbox::{Cancel, Forward, Mailbox, Message},
    pool::{MAX_WORKERS, Pool, Threads},
    request::{RequestOutput, RetiredResources},
    sleep::{Sleep, Timers},
    spinner::{Config as SpinnerConfig, Spinner},
    task::{AfterPoll, Ready, RootWaker, Runnable},
    tasks::Tasks,
    timeout::TimeoutWheel,
    waker::SUBMISSION_SEQ_MASK,
};
#[cfg(feature = "external")]
use crate::Pacer;
use crate::{
    BlobLayout, BlobVersion, Clock, Error, Execution, Handle, METRICS_PREFIX, Name, SinkOf,
    Spawner as _, StreamOf, Supervisor as _, child_label,
    network::{
        iouring::{Config as NetworkConfig, Network},
        metered::Network as MeteredNetwork,
    },
    prefixed_name,
    process::metered::Metrics as ProcessMetrics,
    signal::Signal,
    storage::{
        iouring::{Config as StorageConfig, Storage},
        metered::Storage as MeteredStorage,
    },
    telemetry::metrics::{
        CounterFamily, Gauge, GaugeFamily, Metric, Register, Registered, Registry, add_attribute,
        raw, task::Label, validate_label,
    },
    utils::{self, FactoryGuard, MetricHandle, Panicker, signal::Stopper, supervision::Tree},
};
use commonware_macros::select;
use commonware_parallel::Rayon;
use commonware_utils::{
    channel::oneshot,
    sync::{Condvar, Mutex},
    sys_rng,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use rand_core::{Rng, TryCryptoRng, TryRng};
use rayon::ThreadPoolBuilder;
use std::{
    any::Any,
    cell::RefCell,
    convert::Infallible,
    env,
    future::{Future, poll_fn},
    mem,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    num::{NonZeroU64, NonZeroUsize},
    ops::RangeInclusive,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
    pin::{Pin, pin},
    ptr,
    rc::Rc,
    sync::{Arc, Weak},
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

/// Maximum task polls or mailbox messages processed before yielding to other work.
const BATCH_SIZE: usize = 64;

/// Pinned future polled as a dedicated worker's root, or the runner's service
/// task before it becomes a [`Task`](super::task::Task).
type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Configuration of each worker's io_uring instance and operation timing wheel.
///
/// The runtime requires Linux 6.1 or newer and always uses single-issuer mode
/// with deferred task work. The same configuration applies to pool and
/// dedicated workers. The wheel horizon is derived from network timeout policy.
#[derive(Clone, Debug)]
pub struct RingConfig {
    /// SQ size and maximum outstanding operation SQEs, rounded up to a power of two.
    ///
    /// Must be nonzero and round to at most 32,768. Defaults to 128. The runtime
    /// chooses 1024 for its production default and 128 when built for tests.
    ///
    /// The CQ uses the kernel default of twice the rounded SQ size. Cancellation
    /// and mailbox wake CQEs also use that space, and cancellation acknowledgements
    /// can outlive their requests. The operation limit therefore does not bound
    /// all pending CQEs. The runtime relies on the kernel's CQ overflow backlog
    /// (`IORING_FEAT_NODROP`), drained by subsequent completion-service enters.
    pub size: u32,
    /// Nonzero operation deadline granularity, defaulting to 5 milliseconds.
    ///
    /// Smaller ticks improve precision but increase wheel storage and service
    /// frequency. Configuration must fit within 1,048,576 wheel slots.
    pub timeout_wheel_tick: Duration,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            size: 128,
            timeout_wheel_tick: Duration::from_millis(5),
        }
    }
}

/// Configuration for the native io_uring runtime.
///
/// A pool of [`Self::with_worker_threads`] workers polls ordinary tasks, the
/// first on the thread calling [`crate::Runner::start`]. Tasks marked dedicated
/// or blocking each receive a fresh thread and io_uring ring. Shutdown
/// completes retained writes and syncs without a configured time limit.
#[derive(Clone)]
pub struct Config {
    /// Pool workers, including the calling thread.
    worker_threads: usize,
    /// Every Nth poll of a busy pool worker looks at the global queue first,
    /// defaulting to 31.
    global_queue_interval: u32,
    /// Per-worker io_uring ring capacity and operation wheel tick.
    ring_config: RingConfig,
    /// Idle spinning policy, shared by all workers.
    idle_spinner: SpinnerConfig,
    /// Stack size for pool, dedicated worker, and Rayon threads.
    thread_stack_size: usize,
    /// Whether spawned-task panics and dedicated worker failures are caught.
    /// Task-disposal panics during worker execution are contained with either setting.
    catch_panics: bool,
    /// Base directory held while storage resources or requests remain alive.
    storage_directory: PathBuf,
    /// Accepted blob layouts, defaulting to the complete supported range.
    storage_blob_layouts: RangeInclusive<BlobLayout>,
    /// Optional TCP_NODELAY override, defaulting to Some(true).
    tcp_nodelay: Option<bool>,
    /// Request immediate reset on socket close, defaulting to true.
    zero_linger: bool,
    /// Whole-call outbound connection deadline, defaulting to 10 seconds.
    connect_timeout: Duration,
    /// Whole-call send and receive deadline, defaulting to 60 seconds.
    read_write_timeout: Duration,
    /// Network receive buffering capacity, defaulting to 64 KiB.
    read_buffer_size: usize,
}

impl Config {
    /// Return the default runtime configuration with a generated temporary directory.
    pub fn new() -> Self {
        let ring_config = RingConfig {
            size: if cfg!(test) { 128 } else { 1024 },
            ..RingConfig::default()
        };
        let suffix = sys_rng().next_u64();

        Self {
            worker_threads: 2,
            global_queue_interval: 31,
            ring_config,
            idle_spinner: SpinnerConfig::default(),
            thread_stack_size: utils::thread::system_thread_stack_size(),
            catch_panics: false,
            storage_directory: env::temp_dir().join(format!("commonware_iouring_runtime_{suffix}")),
            storage_blob_layouts: BlobLayout::ALL,
            tcp_nodelay: Some(true),
            zero_linger: true,
            connect_timeout: Duration::from_secs(10),
            read_write_timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024,
        }
    }

    /// Set the number of pool workers, including the calling thread. Defaults
    /// to 2.
    ///
    /// Must be between 1 and 64. Each worker has its own io_uring ring.
    /// Dedicated and blocking threads are additional to this count.
    pub const fn with_worker_threads(mut self, workers: usize) -> Self {
        self.worker_threads = workers;
        self
    }

    /// Set how often a busy pool worker looks at the global queue first: every
    /// `interval`th poll. Defaults to 31.
    ///
    /// Must be nonzero. A smaller interval starts tasks in the global queue
    /// sooner at the cost of more synchronization. At 1, a busy worker checks
    /// the global queue before every poll and polls its own queued tasks only
    /// while the global queue is empty.
    pub const fn with_global_queue_interval(mut self, interval: u32) -> Self {
        self.global_queue_interval = interval;
        self
    }

    /// Set io_uring ring capacity and deadline granularity. See [`RingConfig`].
    pub const fn with_ring_config(mut self, config: RingConfig) -> Self {
        self.ring_config = config;
        self
    }

    /// Set idle spinning policy. Use [`SpinnerConfig::disabled`] to disable it.
    pub const fn with_idle_spinner(mut self, config: SpinnerConfig) -> Self {
        self.idle_spinner = config;
        self
    }

    /// Set the stack size of pool, dedicated worker, and Rayon threads. Worker
    /// zero runs on the calling thread and keeps its stack.
    pub const fn with_thread_stack_size(mut self, size: usize) -> Self {
        self.thread_stack_size = size;
        self
    }

    /// Set whether spawned-task panics and dedicated worker failures are caught.
    ///
    /// Caught failures are logged without interrupting the root. Propagated
    /// failures are observed only while the root is executing. A failure of a
    /// pool worker itself, such as an io_uring error, fails the runner with
    /// either setting. It interrupts the root while the root runs, and
    /// otherwise the runner resumes it after shutdown.
    ///
    /// During worker execution, cancellation-time and task-disposal panics
    /// escaping the user-poll wrapper are contained with either setting. An
    /// unpublished result may resolve to [`Error::Closed`], while an
    /// already-published result remains available.
    /// Task factories execute synchronously and propagate panics to their caller.
    pub const fn with_catch_panics(mut self, catch: bool) -> Self {
        self.catch_panics = catch;
        self
    }

    /// Set the outbound connection timeout, including queueing and retries.
    ///
    /// Must be nonzero and no greater than 30 years. The maximum configured
    /// network timeout must fit the wheel slot limit in [`RingConfig`].
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the send and receive timeout, including queueing and partial progress.
    ///
    /// Must be nonzero and no greater than 30 years. The maximum configured
    /// network timeout must fit the wheel slot limit in [`RingConfig`].
    pub const fn with_read_write_timeout(mut self, timeout: Duration) -> Self {
        self.read_write_timeout = timeout;
        self
    }

    /// Set the best-effort TCP_NODELAY override. None leaves the system default.
    pub const fn with_tcp_nodelay(mut self, enabled: Option<bool>) -> Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Set whether sockets request zero linger when configured.
    pub const fn with_zero_linger(mut self, enabled: bool) -> Self {
        self.zero_linger = enabled;
        self
    }

    /// Set the network receive buffer size in bytes.
    pub const fn with_read_buffer_size(mut self, size: usize) -> Self {
        self.read_buffer_size = size;
        self
    }

    /// Set the storage directory, created and held when the runner starts.
    pub fn with_storage_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.storage_directory = directory.into();
        self
    }

    /// Set the blob layouts accepted by storage.
    ///
    /// New blobs use the latest layout in this range. Existing blobs outside
    /// it fail to open with [`crate::Error::BlobLayoutMismatch`]. Restrict the
    /// range to what a rollback target can read before first opening storage.
    ///
    /// # Panics
    ///
    /// Panics if `layouts` is empty.
    pub fn with_storage_blob_layouts(mut self, layouts: RangeInclusive<BlobLayout>) -> Self {
        assert!(
            !layouts.is_empty(),
            "storage blob layouts must be non-empty"
        );
        self.storage_blob_layouts = layouts;
        self
    }

    /// Return the number of pool workers, including the calling thread.
    pub const fn worker_threads(&self) -> usize {
        self.worker_threads
    }

    /// Return how often a busy pool worker looks at the global queue first:
    /// every Nth poll.
    pub const fn global_queue_interval(&self) -> u32 {
        self.global_queue_interval
    }

    /// Return per-worker io_uring ring configuration.
    pub const fn ring_config(&self) -> &RingConfig {
        &self.ring_config
    }

    /// Return per-worker idle spinning configuration.
    pub const fn idle_spinner(&self) -> &SpinnerConfig {
        &self.idle_spinner
    }

    /// Return the configured pool, dedicated worker, and Rayon thread stack size.
    pub const fn thread_stack_size(&self) -> usize {
        self.thread_stack_size
    }

    /// Return whether spawned-task panics and dedicated worker failures are caught.
    pub const fn catch_panics(&self) -> bool {
        self.catch_panics
    }

    /// Return the whole-call outbound connection timeout.
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Return the whole-call send and receive timeout.
    pub const fn read_write_timeout(&self) -> Duration {
        self.read_write_timeout
    }

    /// Return the TCP_NODELAY override.
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.tcp_nodelay
    }

    /// Return whether sockets request zero linger.
    pub const fn zero_linger(&self) -> bool {
        self.zero_linger
    }

    /// Return the network receive buffer size.
    pub const fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }

    /// Return the storage directory retained by the runtime's storage resources.
    pub const fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }

    /// Return the accepted blob layout range.
    pub const fn storage_blob_layouts(&self) -> &RangeInclusive<BlobLayout> {
        &self.storage_blob_layouts
    }

    /// Validate and normalize settings before acquiring any startup resources.
    fn validate(&mut self) {
        assert!(
            (1..=MAX_WORKERS).contains(&self.worker_threads),
            "worker threads ({}) must be between 1 and {MAX_WORKERS}",
            self.worker_threads,
        );
        assert!(
            self.global_queue_interval != 0,
            "global queue interval must be nonzero"
        );
        assert!(self.ring_config.size != 0, "ring size must be nonzero");
        self.ring_config.size = self
            .ring_config
            .size
            .checked_next_power_of_two()
            .expect("ring size overflow");
        assert!(self.ring_config.size <= 32_768, "ring size exceeds 32768");
        assert!(
            self.idle_spinner.budget_us <= self.idle_spinner.max_budget_us,
            "spinner budget_us ({}) must not exceed max_budget_us ({})",
            self.idle_spinner.budget_us,
            self.idle_spinner.max_budget_us,
        );
        assert!(
            !self.storage_blob_layouts.is_empty(),
            "storage blob layouts must be non-empty"
        );
        assert!(
            !self.connect_timeout.is_zero(),
            "connect timeout must be nonzero"
        );
        assert!(
            !self.read_write_timeout.is_zero(),
            "read/write timeout must be nonzero"
        );
        TimeoutWheel::validate_layout(self.max_timeout(), self.ring_config.timeout_wheel_tick)
            .expect("invalid io_uring operation deadline layout");
    }

    /// Largest network timeout supported by every worker's operation wheel.
    fn max_timeout(&self) -> Duration {
        self.connect_timeout.max(self.read_write_timeout)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Task counters shared by all workers in one runner.
struct TaskMetrics {
    /// Number of tasks created, including rejected spawns.
    tasks_spawned: CounterFamily<Label>,
    /// Number of tasks that have not completed or been aborted.
    tasks_running: GaugeFamily<Label>,
}

impl TaskMetrics {
    /// Register task families beneath the runtime metrics namespace.
    fn new(registry: &mut impl Register) -> Self {
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

/// Registration and cleanup barrier for dedicated workers.
#[derive(Default)]
struct Workers {
    /// Registration gate and count protected by the same lock.
    state: Mutex<WorkerCount>,
    /// Notify shutdown when the last registered worker finishes cleanup.
    idle: Condvar,
}

/// Dedicated workers that shutdown must still wait for.
#[derive(Default)]
struct WorkerCount {
    /// Whether shutdown has stopped accepting new workers.
    closed: bool,
    /// Accepted workers whose factories, execution, or cleanup have not finished.
    active: usize,
}

impl Workers {
    /// Reserve a worker before its factory runs, unless registration has closed.
    fn reserve(self: &Arc<Self>) -> Option<ActiveWorker> {
        let mut state = self.state.lock();
        if state.closed {
            return None;
        }

        // Closing registration under this same lock cannot miss an accepted launch.
        state.active += 1;
        Some(ActiveWorker(self.clone()))
    }

    /// Stop accepting workers while retaining every existing registration.
    fn close(&self) {
        self.state.lock().closed = true;
    }

    /// Wait until every accepted worker has finished runtime cleanup.
    /// Call after [`Self::close`] so no new reservation can extend the count.
    fn wait(&self) {
        let mut state = self.state.lock();
        while state.active != 0 {
            self.idle.wait(&mut state);
        }
    }
}

/// Count an accepted worker until its runtime cleanup finishes.
///
/// Retains only [`Workers`], allowing Shared and its storage hold to be released
/// before the worker count reaches zero.
struct ActiveWorker(
    /// Registry whose active count includes this reservation.
    Arc<Workers>,
);

impl Drop for ActiveWorker {
    fn drop(&mut self) {
        let mut state = self.0.state.lock();
        state.active -= 1;
        if state.active == 0 {
            self.0.idle.notify_all();
        }
        drop(state);

        #[cfg(test)]
        tests::after_release(&self.0);
    }
}

/// Runner-wide services shared by pool and dedicated workers.
pub struct Shared {
    /// Validated configuration, immutable after startup.
    pub cfg: Config,
    /// Scheduling state of the pool workers.
    pub pool: Arc<Pool>,
    /// User-visible metrics registry.
    registry: Registry,
    /// Task counters and running gauges.
    metrics: TaskMetrics,
    /// Aggregate active requests, updated with each worker's own count delta.
    pending_operations: Gauge,
    /// Stop signal and acknowledgement state.
    shutdown: Mutex<Stopper>,
    /// User task panic policy and root notification.
    panicker: Panicker,
    /// Synchronized creation and closure of dedicated workers.
    workers: Arc<Workers>,
    /// Every live ordinary task, retained so the pool workers' cleanup can
    /// drop its future.
    tasks: Tasks,
    /// Metered storage with its metadata lock and directory hold.
    storage: MeteredStorage<Storage>,
    /// Metered native socket adapter.
    network: MeteredNetwork<Network>,
}

/// Task and runtime ownership transferred to a dedicated worker's thread.
///
/// Field order destroys a rejected task and Shared before the reservation is released.
struct Launch {
    /// Task to execute, or destroy if thread creation fails.
    task: BoxedTask,
    /// Runtime services retained until execution and cleanup finish.
    shared: Arc<Shared>,
    /// Registration released after the preceding owners are destroyed.
    active: ActiveWorker,
}

impl Shared {
    /// Transfer a reserved worker's task and its cleanup responsibility to a new thread.
    fn launch(self: &Arc<Self>, task: BoxedTask, active: ActiveWorker) {
        let payload = Launch {
            task,
            shared: self.clone(),
            active,
        };

        #[cfg(test)]
        let payload = tests::before_launch(payload);

        utils::thread::spawn(self.cfg.thread_stack_size, move || {
            Worker::run_task(payload)
        });
    }
}

/// Runtime capabilities and supervision context for the current task.
///
/// Ordinary children run on the pool, including those spawned by dedicated and
/// blocking tasks. Task factories run on their caller, while ordinary futures
/// run on the pool and can move between its workers, as can resources and
/// pending I/O and sleep futures.
///
/// Registrations stay on their original worker. Closing that worker causes
/// unresolved I/O futures to fail and unresolved sleeps to panic when polled.
/// Pool workers close only at shutdown, after every pool task has been dropped,
/// while dedicated and blocking tasks may still run. Detached sync completion
/// handles can be awaited on any thread.
pub struct Context {
    /// User-facing task and metric namespace.
    name: String,
    /// Validated metric attributes inherited by children.
    attributes: Vec<(String, String)>,
    /// Shared services and runner-wide lifecycle state.
    shared: Arc<Shared>,
    /// This context's node in the mandatory supervision tree.
    tree: Arc<Tree>,
    /// Placement requested for the next consumed spawn.
    execution: Execution,
}

impl Context {
    /// Access shared task metric families for the common spawn helper.
    fn metrics(&self) -> &TaskMetrics {
        &self.shared.metrics
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
        let (_, metric) = spawn_metrics!(self);
        let parent = self.tree.clone();
        let execution = self.execution;

        // Placement applies to this spawn. Children start with ordinary placement.
        self.execution = Execution::default();
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }

        self.tree = child;
        let shared = self.shared.clone();

        // Dedicated and blocking spawns reserve a dedicated worker before the
        // factory runs, so shutdown waits for them. Ordinary spawns only check
        // that the task set still accepts tasks.
        let reservation = if matches!(execution, Execution::Dedicated | Execution::Shared(true)) {
            let Some(reservation) = shared.workers.reserve() else {
                return Handle::closed(metric);
            };
            Some(reservation)
        } else {
            if shared.tasks.is_closed() {
                return Handle::closed(metric);
            }
            None
        };

        // User construction runs on the caller with no runtime borrow or lock.
        // A reserved dedicated worker remains counted through construction and
        // launch, including when the factory unwinds or shutdown closes the
        // registry.
        let guard = FactoryGuard::new(&parent, metric);
        let future = f(self);

        // The execution wrapper takes over cleanup once the factory returns.
        let (future, handle) = Handle::init(
            future,
            guard.disarm(),
            shared.panicker.clone(),
            parent.clone(),
        );

        // A dedicated worker polls the future as its root. An ordinary spawn
        // becomes a task of the pool.
        if let Some(reservation) = reservation {
            shared.launch(Box::pin(future), reservation);
        } else if let Err(task) = shared.tasks.register(future, Arc::downgrade(&shared.pool)) {
            // Rejection after closure follows the caller's panic boundary.
            // Cancel descendants and finish metrics before destroying captures.
            parent.abort();
            task.clear();
        }
        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let resolved = self.shared.shutdown.lock().stop(value);
        let timeout = timeout.map_or_else(
            || futures::future::Either::Right(futures::future::pending()),
            |duration| futures::future::Either::Left(self.sleep(duration)),
        );
        select! {
            result = resolved => result.map_err(|_| Error::Closed),
            _ = timeout => Err(Error::Timeout),
        }
    }

    fn stopped(&self) -> Signal {
        self.shared.shutdown.lock().stopped()
    }
}

impl crate::Strategizer for Context {
    /// Returns a [Rayon] strategy whose shared pool runs `parallelism` threads, with domain pools
    /// enabled.
    ///
    /// When `parallelism` exceeds one on a Linux host with several last-level cache domains, the
    /// strategy may build a pool in a domain the first time a thread running there uses it. It
    /// can therefore hold one extra pool per domain, as [Rayon::with_domain_pools] describes.
    fn strategy(&self, parallelism: NonZeroUsize) -> Rayon {
        let pool = ThreadPoolBuilder::new()
            .num_threads(parallelism.get())
            .stack_size(self.shared.cfg.thread_stack_size)
            .build()
            .expect("failed to create io_uring Rayon thread pool");

        // Domain pools let the policy run pool work in the cache domain of the thread that
        // submits it.
        Rayon::with_pool(Arc::new(pool)).with_domain_pools(Some(self.shared.cfg.thread_stack_size))
    }
}

impl crate::Supervisor for Context {
    fn child(&self, label: &'static str) -> Self {
        let (tree, _) = Tree::child(&self.tree);
        Self {
            name: child_label(&self.name, label),
            attributes: self.attributes.clone(),
            shared: self.shared.clone(),
            tree,
            execution: Execution::default(),
        }
    }

    fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        validate_label(key);
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
        self.shared.registry.register(
            prefixed_name(&self.name, &name.into()),
            help.into(),
            self.attributes.clone(),
            Arc::new(metric),
        )
    }

    fn encode(&self) -> String {
        self.shared.registry.encode()
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static + use<> {
        Sleep::new(duration)
    }

    fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static + use<> {
        Sleep::until(deadline)
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
    type Listener = <MeteredNetwork<Network> as crate::Network>::Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.shared.network.bind(socket).await
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        self.shared.network.dial(socket).await
    }
}

impl crate::Resolver for Context {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        let host = host.to_owned();
        self.child("resolver")
            .shared(true)
            .spawn(move |_| async move {
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|address| address.ip()).collect())
                    .map_err(|error| Error::ResolveFailed(error.to_string()))
            })
            .await
            .map_err(|error| Error::ResolveFailed(error.to_string()))?
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
    type Blob = <MeteredStorage<Storage> as crate::Storage>::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        self.shared
            .storage
            .open_versioned(partition, name, versions)
            .await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.shared.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.shared.storage.scan(partition).await
    }
}

/// Sync or timer completion notification published outside Local.
type Completion = (oneshot::Sender<Result<(), Error>>, Result<(), Error>);

/// I/O result forwarded to another thread, including any returned buffers or descriptors.
type OperationResult = (
    oneshot::Sender<Result<RequestOutput, Error>>,
    Result<RequestOutput, Error>,
);

/// Which work a worker thread runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Pool worker at this index, polling ordinary tasks. Worker zero runs on
    /// the thread calling [`crate::Runner::start`] and shuts the runner down.
    Pool(u32),
    /// A worker with a thread and io_uring ring of its own, started for one
    /// dedicated or blocking task that it polls as its root.
    Dedicated,
}

impl Role {
    /// Whether this worker polls the pool's ordinary tasks.
    pub const fn is_pool(self) -> bool {
        matches!(self, Self::Pool(_))
    }

    /// Whether this is worker zero, which polls the runner's root and shuts the
    /// runner down.
    pub const fn owns_runner(self) -> bool {
        matches!(self, Self::Pool(0))
    }
}

/// A pool worker's seat in the pool: its index, the task set whose tasks it
/// polls, and its run queue. Dedicated workers have no seat.
struct Seat {
    /// Index of this worker in the pool, as in [`Role::Pool`].
    index: u32,
    /// Identity of the pool's task set, which [`Local::serves`] compares with a
    /// task's owner.
    tasks: NonZeroU64,
    /// The owner's end of this worker's FIFO run queue, whose shared end the
    /// pool keeps for thieves.
    ready: Ready,
}

/// Mutable execution state accessed only by its owning worker thread.
///
/// Polls and callbacks obtain this state through [`Self::current`] or
/// [`Self::with_current`]. They release each borrow before running user code,
/// including waker methods and destructors.
pub struct Local {
    /// This worker's seat, or `None` on a dedicated worker, which polls only
    /// its root.
    seat: Option<Seat>,
    /// The io_uring ring's owner, taken only after kernel retirement so it can
    /// be dropped unborrowed.
    pub driver: Option<Driver>,
    /// Sleeper registrations and deadlines.
    pub timers: Timers,
    /// Reject new registration and send wakes to the global queue, while
    /// allowing idempotent cancellation.
    pub closing: bool,
    /// Shared monotonic sample for the current service turn.
    pub now: Instant,
    /// Root wake flag, set by local wakes or applied mailbox messages and
    /// taken before each root poll so a wake during the poll is kept.
    pub root_ready: bool,
    /// Strong mailbox ownership retained through kernel retirement.
    pub mailbox: Arc<Mailbox>,
    /// Callbacks and retired owners collected while Local is borrowed.
    pub deferred: Deferred,
    /// Runner configuration, metrics, and shared adapters.
    shared: Arc<Shared>,
    /// This worker's contribution currently included in the aggregate gauge.
    reported_pending: usize,
}

impl Local {
    /// Construct an io_uring ring on the thread that will own all its
    /// submissions. A pool worker takes the mailbox the pool created for it and
    /// the owner's end of its run queue, and panics if its index is out of
    /// range or that end was already taken. A dedicated worker creates its own
    /// mailbox and has no run queue. An I/O error at startup returns before the
    /// run queue's owner is taken.
    fn new(shared: Arc<Shared>, role: Role) -> std::io::Result<Self> {
        #[cfg(test)]
        tests::before_startup(&shared.workers)?;

        let mailbox = match role {
            Role::Pool(index) => shared.pool.mailbox(index).clone(),
            Role::Dedicated => Arc::new(Mailbox::new()?),
        };
        let now = Instant::now();
        let driver = Driver::new(
            &shared.cfg.ring_config,
            shared.cfg.max_timeout(),
            mailbox.waker.clone(),
            now,
        )?;

        // Only this worker pushes and pops, while the pool keeps the shared
        // end for thieves.
        let seat = match role {
            Role::Pool(index) => Some(Seat {
                index,
                tasks: shared.tasks.id(),
                ready: shared.pool.queue(index).owner(),
            }),
            Role::Dedicated => None,
        };
        Ok(Self {
            seat,
            driver: Some(driver),
            timers: Timers::default(),
            closing: false,
            now,
            root_ready: true,
            mailbox,
            deferred: Deferred::default(),
            shared,
            reported_pending: 0,
        })
    }

    /// Return the worker installed on this thread, including during cleanup.
    /// Returns `None` when no worker is installed or its TLS key has been destroyed.
    pub fn current() -> Option<Rc<RefCell<Self>>> {
        // Escaped wakers can run from native TLS destructors after this key is gone.
        CURRENT
            .try_with(|current| current.borrow().clone())
            .ok()
            .flatten()
    }

    /// Return the current worker if it owns `mailbox`, including during shutdown.
    #[inline(always)]
    pub fn owner(mailbox: &Weak<Mailbox>) -> Option<Rc<RefCell<Self>>> {
        let local = Self::current()?;

        // The weak reference preserves allocation identity without retaining a worker.
        let matches = ptr::eq(Arc::as_ptr(&local.borrow().mailbox), mailbox.as_ptr());
        matches.then_some(local)
    }

    /// Run `f` with the worker installed on this thread, or with `None` when
    /// no worker is installed or its TLS key has been destroyed. The worker is
    /// borrowed in place rather than through a clone of its handle, so the
    /// caller must hold no `Local` borrow, and `f` must run no user code while
    /// it holds the worker.
    #[inline]
    pub fn with_current<R>(f: impl FnOnce(Option<&mut Self>) -> R) -> R {
        let mut f = Some(f);

        // Escaped wakers can run from native TLS destructors after this key is gone.
        let result = CURRENT.try_with(|current| {
            let current = current.borrow();
            let local = current.as_ref()?;
            let f = f.take().expect("the closure must be taken only once");
            Some(f(Some(&mut local.borrow_mut())))
        });

        if let Ok(Some(result)) = result {
            return result;
        }

        // Without a worker, `f` runs outside the TLS borrow.
        let f = f.take().expect("the closure must be taken only once");
        f(None)
    }

    /// Whether this worker polls tasks retained by `owner` and is not closing.
    /// A closing worker polls nothing more, so it serves no task set.
    #[inline]
    pub fn serves(&self, owner: NonZeroU64) -> bool {
        self.seat.as_ref().is_some_and(|seat| seat.tasks == owner) && !self.closing
    }

    /// Which work this worker runs.
    pub const fn role(&self) -> Role {
        match &self.seat {
            Some(seat) => Role::Pool(seat.index),
            None => Role::Dedicated,
        }
    }

    /// Workers in this worker's pool.
    pub fn workers(&self) -> usize {
        self.shared.pool.workers()
    }

    /// This pool worker's run queue. Panics on a dedicated worker.
    pub const fn ready(&self) -> &Ready {
        &self
            .seat
            .as_ref()
            .expect("the worker must be a pool worker")
            .ready
    }

    /// This pool worker's run queue, mutably. Panics on a dedicated worker.
    const fn ready_mut(&mut self) -> &mut Ready {
        &mut self
            .seat
            .as_mut()
            .expect("the worker must be a pool worker")
            .ready
    }

    /// Queue a runnable on this pool worker, offering stealable backlog or
    /// exporting overflow through [`Pool::enqueue`]. The runnable must belong
    /// to this pool. Panics on a dedicated worker.
    #[inline]
    pub fn enqueue(&mut self, runnable: Runnable) {
        let Self { seat, shared, .. } = self;
        let seat = seat.as_mut().expect("the worker must be a pool worker");
        shared.pool.enqueue(&mut seat.ready, runnable);
    }

    /// Release an operation or timer on its worker, directly or through its mailbox.
    ///
    /// A worker whose mailbox is closed or gone has already taken responsibility
    /// for cleanup.
    pub fn cancel(mailbox: &Weak<Mailbox>, cancel: Cancel) {
        if let Some(local) = Self::owner(mailbox) {
            // Owner-local drops also reach this path after the mailbox has closed.
            local.borrow_mut().release(cancel);
            return;
        }

        if let Some(mailbox) = mailbox.upgrade() {
            // If closure wins the race, worker cleanup will release the registration.
            let _ = mailbox.send(Message::Cancel(cancel));
        }
    }

    /// Detach observation without running callbacks under the local borrow.
    fn release(&mut self, cancel: Cancel) {
        match cancel {
            Cancel::Waiter(id) => self.driver.as_mut().unwrap().orphan(id, &mut self.deferred),
            Cancel::Timer(id) => self.timers.cancel(id, &mut self.deferred),
        }
    }

    /// Update aggregate pending-operation metrics using only this worker's delta.
    fn update_pending(&mut self) {
        // Count active requests, including queued ones. Completed results waiting
        // for their callers no longer contribute to the pending count.
        let pending = self.driver.as_ref().unwrap().len();

        // Other workers update the same gauge. Apply only our change so their
        // contributions remain intact.
        if pending > self.reported_pending {
            self.shared
                .pending_operations
                .inc_by((pending - self.reported_pending) as _);
        } else if pending < self.reported_pending {
            self.shared
                .pending_operations
                .dec_by((self.reported_pending - pending) as _);
        }
        self.reported_pending = pending;
    }

    /// Whether task polling or callbacks prevent the worker from parking. A
    /// pool worker also has the pool's global queue to take from.
    fn is_ready(&self) -> bool {
        let seat = self.seat.as_ref();
        seat.is_some_and(|seat| !seat.ready.is_empty())
            || self.root_ready
            || !self.deferred.is_empty()
            || (seat.is_some() && self.shared.pool.has_global())
    }

    /// Earliest absolute deadline across driver requests and sleepers.
    fn next_deadline(&mut self) -> Option<Instant> {
        [
            self.driver.as_mut().unwrap().next_deadline(),
            self.timers.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

thread_local! {
    /// Checked access to the one worker allowed on the current thread.
    static CURRENT: RefCell<Option<Rc<RefCell<Local>>>> = const { RefCell::new(None) };
}

/// Thread-local worker access, cleared after mandatory cleanup on every exit.
struct Scope;

impl Scope {
    /// Reject nesting before any directory hold, thread, or io_uring ring is
    /// created.
    fn assert_vacant() {
        CURRENT.with(|current| {
            assert!(
                current.borrow().is_none(),
                "nested io_uring runtime entry is not supported"
            );
        });
    }

    /// Install one worker, retaining the entry check as a defensive invariant.
    fn install(local: Rc<RefCell<Local>>) -> Self {
        CURRENT.with(|current| {
            let mut current = current.borrow_mut();
            assert!(current.is_none(), "nested io_uring worker scope");
            *current = Some(local);
        });
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            // Worker still owns Local, so clearing TLS cannot destroy it under this borrow.
            current.borrow_mut().take();
        });
    }
}

/// Panic payload reported after mandatory worker cleanup.
pub type Panic = Box<dyn Any + Send + 'static>;

/// Retain the first panic while allowing the remaining cleanup to run.
///
/// Later payloads are leaked because their destructors may panic. An unclaimed
/// first payload is also leaked when this accumulator is dropped, including
/// during an existing unwind.
#[derive(Default)]
pub struct Panics {
    /// First failure, held until the worker can report it.
    first: Option<Panic>,
}

impl Panics {
    /// Run a task poll or destructor, returning `None` if it panics.
    ///
    /// Cancellation can destroy the user future during polling, so both paths need
    /// this boundary. The caller must release worker borrows before invoking it.
    pub fn contain<T>(f: impl FnOnce() -> T) -> Option<T> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                // Loom reports a violation by panicking, and containing that
                // panic would hide it, so loom builds let every panic through.
                let result: std::thread::Result<T> = Ok(f());
            } else {
                let result = catch_unwind(AssertUnwindSafe(f));
            }
        }
        match result {
            Ok(output) => Some(output),
            Err(panic) => {
                // Payload destruction can also run user code. A secondary panic
                // cannot escape this task boundary or replace a worker failure.
                if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(panic))) {
                    mem::forget(secondary);
                }
                None
            }
        }
    }

    /// Run a callback without letting its panic interrupt cleanup.
    fn run(&mut self, f: impl FnOnce()) {
        if let Err(panic) = catch_unwind(AssertUnwindSafe(f)) {
            self.retain(panic);
        }
    }

    /// Retain the first payload and leak any later ones.
    fn retain(&mut self, panic: Panic) {
        if self.first.is_none() {
            self.first = Some(panic);
        } else {
            mem::forget(panic);
        }
    }

    /// Take the retained panic.
    fn take(&mut self) -> Option<Panic> {
        self.first.take()
    }
}

impl Drop for Panics {
    fn drop(&mut self) {
        mem::forget(self.first.take());
    }
}

/// Abort if cleanup exits before kernel-visible resources can be released.
/// Forget this guard only after all outstanding operations have retired.
struct RetirementGuard;

impl Drop for RetirementGuard {
    fn drop(&mut self) {
        std::process::abort();
    }
}

/// Callbacks and resources detached from Local before running user code.
///
/// A worker alternates two batches so callbacks can append to Local without
/// borrowing the batch currently being drained. Each vector retains its capacity.
#[derive(Default)]
pub struct Deferred {
    /// Notifications of I/O completion, timer expiry, or worker closure.
    pub wakes: Vec<Waker>,
    /// Wakers whose registrations were replaced or cancelled.
    pub drops: Vec<Waker>,
    /// Results whose observation has ended.
    pub outputs: Vec<RequestOutput>,
    /// Buffers and descriptors no longer used by the kernel.
    pub resources: Vec<RetiredResources>,
    /// Detached sync and forwarded timer notifications without I/O output.
    pub completions: Vec<Completion>,
    /// Forwarded I/O output or worker-closure errors.
    pub results: Vec<OperationResult>,
}

impl Deferred {
    /// Whether the batch contains no callbacks or owners to release.
    pub const fn is_empty(&self) -> bool {
        self.wakes.is_empty()
            && self.drops.is_empty()
            && self.outputs.is_empty()
            && self.resources.is_empty()
            && self.completions.is_empty()
            && self.results.is_empty()
    }

    /// Run each callback independently, retaining failures until cleanup finishes.
    /// The caller must release all Local borrows before invoking this method.
    fn run(&mut self, panics: &mut Panics) {
        for waker in self.wakes.drain(..) {
            panics.run(|| waker.wake());
        }
        for waker in self.drops.drain(..) {
            panics.run(|| drop(waker));
        }
        for output in self.outputs.drain(..) {
            panics.run(|| drop(output));
        }
        for resources in self.resources.drain(..) {
            panics.run(|| drop(resources));
        }

        // Publish results after releasing the completed requests' owners.
        for (sender, output) in self.completions.drain(..) {
            panics.run(|| {
                let _ = sender.send(output);
            });
        }
        for (sender, output) in self.results.drain(..) {
            panics.run(|| {
                let _ = sender.send(output);
            });
        }
    }
}

/// Execute one thread's tasks and own its state through shutdown.
///
/// Constructed before installing TLS so unwinding always has a cleanup owner.
/// Keeps callback execution outside [`Local`] borrows and retains failures until
/// all kernel-visible work has retired.
pub struct Worker {
    /// Local state retained until its driver has drained and been destroyed.
    local: Rc<RefCell<Local>>,
    /// Cleared only after local cleanup, including during an unexpected unwind.
    scope: Option<Scope>,
    /// Callback batch detached from Local and reused after draining.
    deferred: Deferred,
    /// First poll, infrastructure, or callback failure.
    panics: Panics,
    /// Retained mailbox batch, reversed once so bounded pops remain FIFO.
    inbox: Vec<Message>,
    /// Mailbox publication sequence acknowledged when whole batches enter the inbox.
    processed_seq: u32,
    /// Calls to [`Self::next_runnable`] left until the one that looks at the
    /// pool's global queue.
    until_global: u32,
    /// Configured interval between forced global checks. An empty run queue
    /// can trigger an earlier check.
    global_queue_interval: u32,
    /// False until kernel retirement and callback cleanup have finished.
    finished: bool,
}

impl Worker {
    /// Install TLS only after constructing a cleanup owner. A pool worker
    /// counts itself in the pool's shutdown barrier, and its cleanup leaves it.
    /// Panics if this thread already has a worker installed.
    fn new(local: Local) -> Self {
        if local.role().is_pool() {
            local.shared.pool.enter();
        }
        let global_queue_interval = local.shared.cfg.global_queue_interval;
        let local = Rc::new(RefCell::new(local));
        let mut worker = Self {
            local: local.clone(),
            scope: None,
            deferred: Deferred::default(),
            panics: Panics::default(),
            inbox: Vec::new(),
            processed_seq: 0,
            until_global: global_queue_interval,
            global_queue_interval,
            finished: false,
        };
        worker.scope = Some(Scope::install(local));
        worker
    }

    /// Create a worker and drive a stack-pinned root, retaining the worker for cleanup.
    ///
    /// The optional service task runs alongside the root. Only worker zero,
    /// which owns the runner, closes runner-wide reservations when its root
    /// exits.
    ///
    /// Root construction, execution, and destruction share a panic boundary.
    /// Startup errors return directly. Later failures are retained in the worker
    /// so the caller can cancel accepted tasks and clean up with TLS still installed.
    pub fn run<F, Fut>(
        shared: Arc<Shared>,
        role: Role,
        build: F,
        service: Option<BoxedTask>,
    ) -> Result<(Self, Option<Fut::Output>), Panic>
    where
        F: FnOnce() -> Fut,
        Fut: Future,
    {
        let local = Local::new(shared.clone(), role).map_err(|error| -> Panic {
            Box::new(format!(
                "failed to create native io_uring worker (Linux 6.1 with SINGLE_ISSUER and DEFER_TASKRUN is required): {error}"
            ))
        })?;
        let mut worker = Self::new(local);
        let mailbox = worker.local.borrow().mailbox.clone();

        // Register the background service as an ordinary task before constructing
        // the separately polled root.
        if let Some(service) = service
            && let Err(service) = shared.tasks.register(service, Arc::downgrade(&shared.pool))
        {
            worker.panics.run(|| service.clear());
        }
        let root_waker = RootWaker::new(Arc::downgrade(&mailbox)).into();

        // The catch owns the root, including when interrupted. Worker and TLS stay
        // outside it so root destruction can orphan operations or spawn more work.
        let result = catch_unwind(AssertUnwindSafe(|| {
            let root = build();
            worker.drive(pin!(root), &root_waker)
        }));
        let output = match result {
            Ok(output) => output,
            Err(panic) => {
                worker.panics.retain(panic);
                None
            }
        };

        // Include work spawned by root destruction in the shutdown barrier.
        if role.owns_runner() {
            shared.workers.close();
        }
        worker.begin_close();
        Ok((worker, output))
    }

    /// Execute a reserved task on this thread and report failures after cleanup.
    /// The caller's [`Launch`] owns the task, shared services, and worker reservation
    /// in drop order.
    fn run_task(payload: Launch) {
        // Bind the reservation first so unwinding releases it last.
        let Launch {
            active,
            shared,
            task,
        } = payload;

        let result = catch_unwind(AssertUnwindSafe(|| {
            // Startup may reject the builder without invoking it. Its captured
            // root keeps the same disposal boundary as an executing spawned task.
            let root = TaskRoot { task: Some(task) };
            let (mut worker, output) = Self::run(shared.clone(), Role::Dedicated, || root, None)?;
            worker.cleanup();
            worker.result(output)
        }));

        match result {
            Ok(Ok(())) => {}
            Ok(Err(panic)) | Err(panic) => shared.panicker.notify(panic),
        }

        // Runtime cleanup, Shared destruction, and failure publication precede
        // counter release. Native TLS destruction remains outside this boundary.
        drop(shared);
        drop(active);
    }

    /// Detach one callback batch and run it outside the local borrow.
    fn callbacks(&mut self, searcher: Option<&mut Searcher<'_>>) {
        // An empty batch runs no user code, so a searching worker keeps its
        // count rather than hand the search on.
        if self.local.borrow().deferred.is_empty() {
            return;
        }

        // A held count stops kicks from waking parked workers. Callbacks can
        // wake work and then wait for a peer to run it, so return the count
        // before they run.
        if let Some(searcher) = searcher {
            searcher.leave_search();
        }

        // Reuse the emptied batch while callbacks collect more work in Local.
        mem::swap(&mut self.deferred, &mut self.local.borrow_mut().deferred);
        self.deferred.run(&mut self.panics);
    }

    /// Acknowledge one transferred mailbox batch.
    const fn acknowledge_batch(&mut self) {
        self.processed_seq = self.processed_seq.wrapping_add(1) & SUBMISSION_SEQ_MASK;
    }

    /// Take the first failure retained so far.
    pub fn take_panic(&mut self) -> Option<Panic> {
        self.panics.take()
    }

    /// Close local registration. Worker zero also closes the task set and the
    /// pool. A dedicated worker closes its mailbox, retaining queued messages,
    /// while a pool worker keeps its mailbox open until every pool worker has
    /// finished its last poll, and [`Self::cleanup`] then closes it. Repeated
    /// calls leave the worker closed and preserve its existing inbox.
    fn begin_close(&mut self) {
        let mailbox = {
            let mut local = self.local.borrow_mut();
            let role = local.role();

            // Worker zero shuts the runner down. It first closes the task set,
            // so a spawn from then on is refused and disposed of on its caller.
            // It then closes the global queue, which releases workers waiting
            // for the pool to close. Because the set closed first, it retains
            // the task of every runnable the closed queue discards. Cleanup
            // drains the set. Closing again does nothing.
            if role.owns_runner() {
                local.shared.tasks.close();
                local.shared.pool.close();
            }
            local.closing = true;
            if role.is_pool() {
                return;
            }
            local.mailbox.clone()
        };
        self.close_mailbox(&mailbox);
    }

    /// Close the mailbox, retaining its queued messages in the inbox.
    fn close_mailbox(&mut self, mailbox: &Mailbox) {
        let messages = mailbox.close();

        if !messages.is_empty() {
            self.acknowledge_batch();
        }

        // Keep queued messages until cleanup can dispose of them outside the
        // local borrow. Shutdown only disposes of these messages, so no FIFO
        // reversal is needed here.
        self.inbox.extend(messages);
    }

    /// Cancel observers and finish all kernel-visible work before releasing TLS.
    /// Retains callback failures until cleanup finishes. An infrastructure
    /// failure before kernel retirement aborts the process through
    /// [`RetirementGuard`].
    ///
    /// A pool worker first waits for the pool to close, discards its run queue,
    /// and drains the task set, then waits for every other pool worker to
    /// finish polling and draining. Worker zero stops the other pool workers
    /// before it drains, so they reach that barrier too.
    pub fn cleanup(&mut self) {
        if self.finished {
            return;
        }

        // Protect every retirement transition, including observer removal
        // before the first drain turn, against unexpected infrastructure unwind.
        let retirement = RetirementGuard;
        self.begin_close();

        // A pool worker that stopped early, after a failure, waits for the
        // runner to close the pool, so the set it drains below is closed and
        // retains the task of every runnable it discards.
        let (role, shared) = {
            let local = self.local.borrow();
            (local.role(), local.shared.clone())
        };
        if role.is_pool() {
            // The drive loop withdrew this worker from the idle set and
            // returned its search count when it ended, unwinding included, so
            // no wake is spent on it and no kick waits for it here.
            shared.pool.wait_closed();
        }

        // On the runner's normal path, worker zero gets here after the
        // supervision tree is aborted, so the workers it stops destroy only
        // cancelled tasks and the runner's metrics task. Stopping them in
        // cleanup also releases the barrier below when an unwind skips the
        // runner's shutdown.
        if role.owns_runner() {
            shared.pool.stop();
        }

        if let Role::Pool(index) = role {
            // Each task is retained for teardown or already cleared, so
            // discarding its runnable runs no user code under this borrow. A
            // thief can retain runnables it took until it reaches the barrier
            // below.
            self.local.borrow_mut().ready_mut().discard();

            // Destroy futures before closing I/O so their observers can detach.
            // Clear outside local borrows and set locks. A task still polling
            // on another worker leaves destruction to that poller.
            for task in shared.tasks.drain(index as usize) {
                Panics::contain(|| task.clear());
            }

            // A task polled on one worker can hold registrations on another,
            // whose mailbox forwards their results. No pool worker closes its
            // mailbox or drops the forwards it took from it until every pool
            // worker has drained the set and finished its last poll, so no poll
            // finds a registration's worker closed. An empty set is no such
            // barrier, since another worker may still be dropping a future.
            shared.pool.finish();

            // No pool task can run from here on, so the mailbox can close.
            let mailbox = self.local.borrow().mailbox.clone();
            self.close_mailbox(&mailbox);
        }

        // Closing the driver and timer table below subsumes queued cancellations.
        // Discard queued forwarding messages so their receivers observe closure.
        // Senders can run callbacks on drop, so destroy these messages outside
        // the local borrow.
        for message in self.inbox.drain(..) {
            Panics::contain(|| drop(message));
        }

        // Detach local and forwarded observers before running callbacks.
        // Admission is closed, so subsequent handle drops find no registration
        // to detach. Only driver service can produce further deferred work.
        {
            let mut local = self.local.borrow_mut();
            let Local {
                driver,
                timers,
                deferred,
                ..
            } = &mut *local;
            driver.as_mut().unwrap().close(deferred);
            timers.clear(deferred);
            local.update_pending();
        }
        self.callbacks(None);

        // Retained writes and syncs still need to finish. Cancelled operations
        // retain their resources until their own completion arrives.
        loop {
            // A retained write may still be queued without an SQE in flight.
            // Service must stage that work before we consider waiting for a CQE.
            self.service(false);
            self.callbacks(None);

            let mut local = self.local.borrow_mut();

            if local.driver.as_ref().unwrap().is_empty() {
                assert!(
                    local.deferred.is_empty(),
                    "callbacks refilled deferred work after close"
                );
                break;
            }

            let deadline = local.next_deadline();

            // Parking only enters the kernel and invokes no user callbacks.
            // Keeping the driver in Local preserves the cleanup owner on unwind.
            let parked = local
                .driver
                .as_mut()
                .unwrap()
                .park(self.processed_seq, deadline);
            drop(local);
            parked.expect("io_uring shutdown wait failed");
        }

        // No SQE can reference request resources now. Driver destruction can
        // unwind normally, and TLS remains available until that destruction ends.
        mem::forget(retirement);
        let driver = self.local.borrow_mut().driver.take();
        self.panics.run(|| drop(driver));
        self.finished = true;
        self.scope.take();
    }

    /// Select the root result after cleanup.
    fn result<T>(&mut self, output: Option<T>) -> Result<T, Panic> {
        if let Some(panic) = self.panics.take() {
            // A failure may arrive after a successful root poll. Its output can
            // own arbitrary destructors, so preserve the first panic on disposal.
            self.panics.run(|| drop(output));
            return Err(panic);
        }

        Ok(output.expect("worker root ended without an output or failure"))
    }

    /// Apply a bounded batch of messages, taking another mailbox batch when needed.
    /// The publication sequence records accepted work independently of signaling.
    fn messages(&mut self, mailbox: &Arc<Mailbox>) {
        if self.inbox.is_empty()
            && mailbox.waker.pending(self.processed_seq)
            && mailbox.take(&mut self.inbox)
        {
            // Count transfer once, not each message application. Reversing
            // allows bounded FIFO processing without shifting the remainder.
            self.acknowledge_batch();
            self.inbox.reverse();
        }

        for _ in 0..BATCH_SIZE {
            let Some(message) = self.inbox.pop() else {
                break;
            };
            match message {
                Message::WakeRoot => self.local.borrow_mut().root_ready = true,
                Message::Forward(forward) => {
                    let mut local = self.local.borrow_mut();
                    let Local {
                        driver,
                        timers,
                        deferred,
                        ..
                    } = &mut *local;
                    match forward {
                        Forward::Waiter(id, sender) => {
                            driver.as_mut().unwrap().forward(id, sender, deferred);
                        }
                        Forward::Timer(id, sender) => timers.forward(id, sender, deferred),
                    }
                }
                Message::Cancel(cancel) => self.local.borrow_mut().release(cancel),
            }
        }
    }

    /// Service the io_uring ring and timers using one time sample, collecting
    /// callbacks. Returns whether kernel service was deferred to an idle wait.
    fn service(&mut self, defer_kernel_service: bool) -> bool {
        let mut local = self.local.borrow_mut();
        local.now = Instant::now();
        let Local {
            now,
            driver,
            timers,
            deferred,
            ..
        } = &mut *local;
        let result = driver
            .as_mut()
            .unwrap()
            .service(*now, defer_kernel_service, deferred);
        let outcome = result.expect("io_uring driver service failed");

        // Expiry defers observer notifications until after this borrow ends.
        timers.expire(*now, deferred);
        local.update_pending();
        outcome
    }

    /// Take the next runnable to poll: a share of the pool's global queue every
    /// [`Config::with_global_queue_interval`] calls, otherwise the oldest
    /// runnable in this worker's run queue, otherwise a share of the global
    /// queue. An empty global take falls back to the run queue. `pool` must be
    /// this worker's pool, and the caller must hold no Local borrow.
    // The drive loop is instantiated in the caller's crate, so the common case
    // is inlined there and the global queue sits behind a call.
    #[inline]
    #[must_use]
    fn next_runnable(&mut self, pool: &Pool) -> Option<Runnable> {
        // The interval counts every take, so runnables queued here cannot
        // keep the global queue waiting however fast they requeue. A
        // countdown keeps a division off this path.
        self.until_global -= 1;
        if self.until_global == 0 {
            self.until_global = self.global_queue_interval;
        } else {
            if let Some(runnable) = self.local.borrow_mut().ready_mut().pop() {
                return Some(runnable);
            }
            if !pool.has_global() {
                return None;
            }
        }
        Self::take_global(&self.local, pool)
    }

    /// Return the oldest global runnable and append the rest of its capped
    /// share to the run queue. Fall back to the oldest run queue runnable if
    /// the global queue was empty. `local` must be an unborrowed pool worker
    /// of `pool`.
    #[inline(never)]
    #[must_use]
    fn take_global(local: &RefCell<Local>, pool: &Pool) -> Option<Runnable> {
        let mut local = local.borrow_mut();
        let ready = local.ready_mut();
        pool.take(ready).or_else(|| ready.pop())
    }

    /// Try to steal from the other run queues, then publish this worker idle
    /// and look once more. Returns whether the search found work. `searcher`
    /// must be this worker's, with its run queue empty and Local unborrowed. A
    /// true result leaves no publication but may hold a search count. A false
    /// result leaves a live publication for the caller to end through
    /// [`Searcher::finish_park`] once its wait or spin returns.
    fn search_before_park(&self, searcher: &mut Searcher<'_>) -> bool {
        if searcher.search(self.local.borrow_mut().ready_mut()) {
            return true;
        }

        #[cfg(test)]
        tests::at_park(
            searcher.pool(),
            searcher.index(),
            tests::ParkPoint::BeforeIdle,
        );

        if searcher.publish_and_look(self.local.borrow_mut().ready_mut()) {
            return true;
        }

        #[cfg(test)]
        tests::at_park(
            searcher.pool(),
            searcher.index(),
            tests::ParkPoint::BeforeWait,
        );

        false
    }

    /// Drive tasks and one separately pinned root through bounded service turns.
    /// Returns the root output, or `None` with the first failure retained in the
    /// worker through root destruction. The caller then closes registration and
    /// cleans up the worker.
    fn drive<Fut: Future>(
        &mut self,
        mut root: Pin<&mut Fut>,
        root_waker: &Waker,
    ) -> Option<Fut::Output> {
        let (mailbox, shared, spinner_cfg, role) = {
            let local = self.local.borrow();
            (
                local.mailbox.clone(),
                local.shared.clone(),
                local.shared.cfg.idle_spinner.clone(),
                local.role(),
            )
        };
        let (pool, index) = match role {
            Role::Pool(index) => (Some(&*shared.pool), Some(index)),
            Role::Dedicated => (None, None),
        };
        let owner = shared.tasks.id();

        // A pool worker's part in searching and waking. Dropped on every
        // return and unwind of this loop, it withdraws a live idle publication
        // and returns a held search count before the caller destroys the root.
        let mut searcher = index.map(|index| Searcher::new(&shared.pool, index));

        // A pool claim signals this worker's waker without publishing a
        // message, so the spin watches the wake signal as well as the mailbox
        // sequence.
        let mut spinner = Spinner::new(&spinner_cfg, || {
            mailbox.waker.pending(self.processed_seq) || mailbox.waker.signalled()
        });
        let max_spin =
            Duration::from_micros(spinner_cfg.max_budget_us.try_into().unwrap_or(u64::MAX));

        loop {
            if self.panics.first.is_some() {
                return None;
            }

            // Bound task polling so a self-waking task cannot starve the root,
            // mailbox, or io_uring service. A dedicated worker polls only its
            // root.
            if let (Some(pool), Some(searcher)) = (pool, &mut searcher) {
                for _ in 0..BATCH_SIZE {
                    let Some(runnable) = self.next_runnable(pool) else {
                        break;
                    };

                    // User code can wake a backlog and wait for a peer to run it.
                    // Return the count so those wakes can kick a parked peer.
                    searcher.leave_search();

                    // The inner wrapper handles user polling policy. The poll also
                    // contains the destruction of a finished or cancelled future.
                    match runnable.poll(owner) {
                        AfterPoll::Done => {}

                        // Queue a self-wake at the tail of the run queue, behind
                        // the runnables already queued there. Overflow or stealing
                        // can still move it elsewhere.
                        AfterPoll::Requeue(runnable) => self.local.borrow_mut().enqueue(runnable),

                        // The future is gone, so releasing the set's reference and
                        // the runnable's runs no user code.
                        AfterPoll::Retire(task) => drop(shared.tasks.remove(&task)),
                    }
                }
            }

            // The root has no runnable. Its flag also records notifications
            // forwarded from other workers through the mailbox.
            let poll_root = mem::take(&mut self.local.borrow_mut().root_ready);

            if poll_root {
                // The root can wake work and block waiting for it just as a
                // task can, so return a held count before polling it as well.
                if let Some(searcher) = &mut searcher {
                    searcher.leave_search();
                }

                let mut cx = TaskContext::from_waker(root_waker);

                // A local wake during this poll sets root_ready again, and a
                // foreign wake queues a message that sets it when applied.
                // Pending must not clear a wake caused by the root itself.
                if let Poll::Ready(output) = root.as_mut().poll(&mut cx) {
                    return Some(output);
                }
            }

            // Polls can leave cancelled observers behind. Run one batch before
            // deciding whether kernel service can wait until parking. Reentrant
            // work remains visible to the complete readiness checks below.
            self.callbacks(searcher.as_mut());
            if self.panics.first.is_some() {
                return None;
            }

            // An apparently idle turn can combine kernel service with the wait.
            // The result records whether that enter was actually deferred.
            let defer = !self.local.borrow().is_ready()
                && self.inbox.is_empty()
                && !mailbox.waker.pending(self.processed_seq);
            let kernel_deferred = self.service(defer);

            // Apply foreign messages and completion callbacks before considering
            // a wait. Any tasks they make ready will be polled on the next turn.
            // Messages run no user code, so a held search count stays held
            // through them. The callback batch returns it before running.
            self.messages(&mailbox);
            self.callbacks(searcher.as_mut());
            if self.panics.first.is_some() {
                return None;
            }

            #[cfg(test)]
            if let (Some(pool), Some(index)) = (pool, index) {
                tests::at_park(pool, index, tests::ParkPoint::AfterMessages);
            }

            // Callbacks and messages can submit I/O or make tasks runnable, so
            // the pre-service idle decision alone is not enough to permit parking.
            let (ready, needs_kernel, pending_submissions, deadline) = {
                let mut local = self.local.borrow_mut();
                (
                    local.is_ready(),
                    !local.driver.as_ref().unwrap().is_empty(),
                    local.driver.as_ref().unwrap().has_pending_submissions(),
                    local.next_deadline(),
                )
            };

            // Queued submissions need another service turn even when no task
            // has a notification that would cause it to be polled. Going round
            // again without parking ends a search, and the catch-up's callbacks
            // run user code.
            if ready
                || pending_submissions
                || !self.inbox.is_empty()
                || mailbox.waker.pending(self.processed_seq)
            {
                if let Some(searcher) = &mut searcher {
                    searcher.leave_search();
                }

                if (kernel_deferred && needs_kernel) || (defer && pending_submissions) {
                    // An idle turn must stage work introduced by its callbacks.
                    // A wake alone needs catch-up only if GETEVENTS was deferred.
                    self.service(false);
                    self.callbacks(None);
                }

                continue;
            }

            // Busy turns use only service's time sample. Take a fresh sample
            // at this actual idle boundary after any elapsed callback time.
            // Waiting for an expired deadline would not block, so this ends a
            // search as well, and the catch-up's callbacks run user code.
            let now = Instant::now();
            if deadline.is_some_and(|deadline| deadline <= now) {
                if let Some(searcher) = &mut searcher {
                    searcher.leave_search();
                }

                if kernel_deferred && needs_kernel {
                    self.service(false);
                    self.callbacks(None);
                }

                continue;
            }

            // Steal, then publish idleness before the last look for work. A
            // push racing this look either shows up here or leaves some worker,
            // not necessarily this one, woken or running to take it.
            if let Some(searcher) = &mut searcher
                && self.search_before_park(searcher)
            {
                // Running again ends a search, and the catch-up's callbacks run
                // user code.
                searcher.leave_search();

                if kernel_deferred && needs_kernel {
                    self.service(false);
                    self.callbacks(None);
                }

                continue;
            }

            #[cfg(test)]
            tests::before_park();

            // Unfinished requests need the io_uring wait to run deferred kernel
            // work. A futex wake alone cannot advance their I/O.
            if needs_kernel {
                let result = self
                    .local
                    .borrow_mut()
                    .driver
                    .as_mut()
                    .unwrap()
                    .park(self.processed_seq, deadline);

                // Withdraw before callbacks so their kicks cannot spend a wake
                // on this already running worker. A claim's count stays held
                // until the worker returns it before user code, when it goes
                // round again, or at its next park.
                if let Some(searcher) = &mut searcher {
                    searcher.finish_park();
                }

                if !result.expect("io_uring kernel wait failed") {
                    // A rejected wait may not have entered the kernel. Complete
                    // its deferred service obligation before another polling turn.
                    self.service(false);
                    self.callbacks(searcher.as_mut());
                }
            } else {
                // A future timer by itself uses a timed futex wait. Spinning
                // is skipped when it could consume the remaining deadline.
                let near_deadline = deadline
                    .is_some_and(|deadline| deadline.saturating_duration_since(now) <= max_spin);

                if !near_deadline
                    && spinner.spin(|| {
                        mailbox.waker.pending(self.processed_seq) || mailbox.waker.signalled()
                    })
                {
                    // The worker runs again, so the next wait needs a new wake.
                    mailbox.waker.consume_signal();
                } else if let Some(duration) = mailbox.waker.park_idle(self.processed_seq, deadline)
                {
                    spinner.on_wake(duration);
                }

                // End this publication even when spinning or a latched wake
                // avoided blocking. The next park needs a fresh publication.
                if let Some(searcher) = &mut searcher {
                    searcher.finish_park();
                }
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Cleanup still runs during unwinding. Panics leaks any unclaimed
        // payload so its destruction cannot replace the original failure.
        self.cleanup();
    }
}

/// Run a dedicated or blocking task as its worker's root, containing poll and
/// disposal panics.
struct TaskRoot {
    /// Task retained until the root is destroyed.
    task: Option<BoxedTask>,
}

impl Future for TaskRoot {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        // A contained cancellation or disposal panic ends the task so the worker
        // can proceed with I/O cleanup.
        Panics::contain(|| self.task.as_mut().unwrap().as_mut().poll(cx)).unwrap_or(Poll::Ready(()))
    }
}

impl Drop for TaskRoot {
    fn drop(&mut self) {
        Panics::contain(|| drop(self.task.take()));
    }
}

/// Native io_uring runner executing ordinary tasks on a pool of workers, the
/// first on its calling thread.
///
/// The root future doesn't have to be Send and always runs on the calling
/// thread. Ordinary spawned futures run on whichever pool worker takes them,
/// and dedicated and blocking ones on threads of their own. The runner waits
/// for every pool worker, dedicated worker cleanup, and retained writes and
/// syncs before returning or resuming a panic. Native thread-local destruction
/// may follow.
pub struct Runner {
    /// Settings validated before any runtime resources are created.
    cfg: Config,
}

impl Runner {
    /// Construct a runner without acquiring storage or creating an io_uring ring.
    pub const fn new(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl crate::Runner for Runner {
    type Context = Context;

    fn start<F, Fut>(mut self, f: F) -> Fut::Output
    where
        F: FnOnce(Context) -> Fut,
        Fut: Future,
    {
        // Reject nesting and invalid settings before acquiring storage or threads.
        Scope::assert_vacant();
        self.cfg.validate();

        let mut registry = Registry::new();
        let mut runtime_registry = registry.sub_registry(METRICS_PREFIX);
        let metrics = TaskMetrics::new(&mut runtime_registry);
        let pending_operations = runtime_registry.register(
            "pending_operations",
            "Number of active logical requests across io_uring workers",
            raw::Gauge::default(),
        );
        let process = ProcessMetrics::init(&mut runtime_registry);

        let storage = Storage::new(StorageConfig {
            storage_directory: self.cfg.storage_directory.clone(),
            blob_layouts: self.cfg.storage_blob_layouts.clone(),
        });

        // Storage construction acquires the directory hold first. This sync
        // therefore includes any straggling writes from a preceding runner.
        crate::storage::sync(&self.cfg.storage_directory).unwrap_or_else(|error| {
            panic!(
                "failed to sync storage filesystem at startup ({}): {error}",
                self.cfg.storage_directory.display()
            );
        });

        let storage = MeteredStorage::new(storage, &mut runtime_registry);
        let network = MeteredNetwork::new(
            Network::new(NetworkConfig {
                tcp_nodelay: self.cfg.tcp_nodelay,
                zero_linger: self.cfg.zero_linger,
                connect_timeout: self.cfg.connect_timeout,
                read_write_timeout: self.cfg.read_write_timeout,
                read_buffer_size: self.cfg.read_buffer_size,
            }),
            &mut runtime_registry,
        );
        let (panicker, tasks) = Panicker::new(self.cfg.catch_panics);

        // Every pool worker's mailbox exists before any worker starts, so a
        // push can wake any of them from the first spawn on.
        let mailboxes = (0..self.cfg.worker_threads)
            .map(|_| Mailbox::new().map(Arc::new))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("failed to create io_uring worker mailbox: {error}"));
        let workers = mailboxes.len();

        let shared = Arc::new(Shared {
            cfg: self.cfg,
            pool: Arc::new(Pool::new(mailboxes)),
            registry,
            metrics,
            pending_operations,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            workers: Arc::new(Workers::default()),
            tasks: Tasks::new(workers),
            storage,
            network,
        });

        let label = Label::root();
        shared.metrics.tasks_spawned.get_or_create(&label).inc();

        let metric = MetricHandle::new(shared.metrics.tasks_running.get_or_create(&label).clone());
        let tree = Tree::root();
        let context_shared = shared.clone();
        let context_tree = tree.clone();

        // A pool worker that fails interrupts the root even when task panics
        // are caught, since the pool cannot run without it. The worker wakes
        // the root, which takes the failure before each poll. The receiver
        // outlives the root, so a failure after the root completes still fails
        // the runner.
        let mut threads = Threads::default();
        let (pool_panicker, mut pool_failures) = Panicker::new(false);

        // The root factory needs TLS installed so it can synchronously spawn or
        // register work, and it runs only once every pool worker has started.
        // Task panics interrupt the root inside the pool failure check, so they
        // are observed only until the root completes, before its state is
        // destroyed.
        let output = Worker::run(
            shared.clone(),
            Role::Pool(0),
            || {
                threads.start(&shared, &pool_panicker);
                let root = tasks.interrupt(f(Context {
                    name: label.name().to_string(),
                    attributes: Vec::new(),
                    shared: context_shared,
                    tree: context_tree,
                    execution: Execution::default(),
                }));
                let failures = &mut pool_failures;
                async move {
                    let mut root = pin!(root);
                    poll_fn(|cx| {
                        if let Some(panic) = failures.try_take() {
                            resume_unwind(panic);
                        }
                        root.as_mut().poll(cx)
                    })
                    .await
                }
            },
            Some(Box::pin(process.collect(Sleep::new))),
        )
        .and_then(|(mut worker, output)| {
            #[cfg(test)]
            tests::before_abort();

            // The root is gone and the pool is closed. Abort ordinary,
            // dedicated, and blocking tasks, then clean up this worker, which
            // stops the other pool workers and waits for them to drain the
            // task set.
            worker.panics.run(|| tree.abort());
            worker.cleanup();
            worker.panics.run(|| threads.join());
            if let Some(panic) = pool_failures.try_take() {
                worker.panics.retain(panic);
            }

            // Dedicated worker cleanup may depend on resources released by pool
            // task disposal or I/O retirement, so drain the pool first.
            shared.workers.wait();
            worker.result(output)
        });
        metric.finish();

        match output {
            Ok(output) => output,
            Err(panic) => resume_unwind(panic),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
pub mod tests;
