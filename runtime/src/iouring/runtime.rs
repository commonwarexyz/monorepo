//! Worker execution and runner-wide lifecycle.
//!
//! The calling thread runs the ordinary worker. Dedicated and blocking tasks
//! each get a separate thread and ring. All workers share configuration and
//! services through [`Shared`], while execution state stays in each worker's
//! [`Local`].
//!
//! ## State and ownership
//!
//! ```text
//! Context
//!   +-- Shared (Arc) <-------------------------- Local.shared
//!   |     +-- Config, metrics, stop/panic signals
//!   |     +-- Network, Storage, buffer pools
//!   |     `-- Workers <------------------------ ActiveWorker
//!   +-- supervision tree
//!   `-- ordinary worker's Mailbox (Weak)
//!
//! Worker (one per thread)
//!   +-- Scope --------------------------------> CURRENT (TLS)
//!   |                                               |
//!   +-- Rc<RefCell<Local>> <------------------------+
//!   |     +-- Shared (Arc)
//!   |     +-- Tasks (spawned futures and ready IDs)
//!   |     +-- Timers (sleep registrations and deadlines)
//!   |     +-- Driver
//!   |     |     +-- ring (SQ/CQ)
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
//! The root is pinned separately and passed to [`Worker::drive`]. On a one-off
//! worker, the selected task runs as that worker's root.
//!
//! ## Task placement
//!
//! Factories run on the spawning caller. Ordinary tasks always target the
//! runner's calling-thread worker, including when spawned from another worker.
//!
//! ```text
//! ordinary spawn:
//!   check origin --> factory --> Tasks::register
//!                                  +-- owning thread --> Tasks
//!                                  `-- other thread --> Mailbox --> Tasks
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
//! I/O registers directly with the current worker on first poll. Mailboxes carry
//! task spawns, wakes, and cancellation messages.
//!
//! Each turn polls a bounded batch of tasks and checks the root's wake flag,
//! services I/O and timers, and applies a bounded batch of mailbox messages.
//! Deferred callbacks run between these phases. Before parking, the worker checks
//! readiness again because polls and callbacks can have produced more work.
//!
//! ## Shutdown
//!
//! Once the ordinary worker is running, runner exit follows this order:
//!
//! ```text
//! root completes or fails
//!   |
//!   v
//! destroy root (TLS and mailbox still available)
//!   |
//!   v
//! close worker registry and ordinary mailbox
//!   |
//!   v
//! abort spawned tasks through the supervision tree
//!   |
//!   v
//! clean up ordinary worker --> wait for one-off registrations to reach zero
//!                               |
//!                               v
//!                       return result or resume panic
//! ```
//!
//! Work spawned by root destruction participates in shutdown. Each worker keeps
//! TLS installed while destroying tasks, draining retained writes and syncs,
//! retiring cancellations, and running deferred callbacks. Native thread-local
//! destruction on one-off threads can follow registration release.

use super::{
    driver::Driver,
    mailbox::{Mailbox, Message},
    request::{RequestOutput, RetiredResources},
    sleep::{Sleep, TimerId, Timers},
    spinner::{Config as SpinnerConfig, Spinner},
    task::{BoxedTask, Running, Target, Task, TaskWaker, Tasks},
    timeout::TimeoutWheel,
    waiter::WaiterId,
    waker::SUBMISSION_SEQ_MASK,
};
#[cfg(feature = "external")]
use crate::Pacer;
use crate::{
    BlobLayout, BlobVersion, BufferPool, BufferPoolConfig, Clock, Error, Execution, Handle,
    METRICS_PREFIX, Name, SinkOf, Spawner as _, StreamOf, Supervisor as _, child_label,
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
    utils::{self, MetricHandle, Panicked, Panicker, signal::Stopper, supervision::Tree},
};
use commonware_macros::select;
use commonware_parallel::Rayon;
use commonware_utils::{
    NZUsize,
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
    future::Future,
    mem,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    num::NonZeroUsize,
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

/// Configuration of each worker's io_uring instance and operation timing wheel.
///
/// The runtime requires Linux 6.1 or newer and always uses single-issuer mode
/// with deferred task work. The same configuration applies to ordinary and
/// one-off workers. The wheel horizon is derived from network timeout policy.
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
/// One ordinary worker runs on the thread calling [`crate::Runner::start`].
/// Tasks marked dedicated or blocking each receive a fresh thread and ring.
/// Shutdown completes retained writes and syncs without a configured time limit.
#[derive(Clone)]
pub struct Config {
    /// Per-worker ring capacity and operation wheel tick.
    ring_config: RingConfig,
    /// Idle spinning policy, shared by all workers.
    idle_spinner: SpinnerConfig,
    /// Stack size for one-off worker and Rayon threads.
    thread_stack_size: usize,
    /// Whether spawned-task panics and one-off worker failures are caught.
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
    /// Optional network pool override, otherwise configured for one worker.
    network_buffer_pool_cfg: Option<BufferPoolConfig>,
    /// Optional storage pool override, otherwise configured for one worker.
    storage_buffer_pool_cfg: Option<BufferPoolConfig>,
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
            network_buffer_pool_cfg: None,
            storage_buffer_pool_cfg: None,
        }
    }

    /// Set ring capacity and deadline granularity. See [`RingConfig`].
    pub const fn with_ring_config(mut self, config: RingConfig) -> Self {
        self.ring_config = config;
        self
    }

    /// Set idle spinning policy. Use [`SpinnerConfig::disabled`] to disable it.
    pub const fn with_idle_spinner(mut self, config: SpinnerConfig) -> Self {
        self.idle_spinner = config;
        self
    }

    /// Set one-off worker and Rayon thread stack size.
    pub const fn with_thread_stack_size(mut self, size: usize) -> Self {
        self.thread_stack_size = size;
        self
    }

    /// Set whether spawned-task panics and one-off worker failures are caught.
    ///
    /// Caught failures are logged without interrupting the root. Propagated
    /// failures are observed only while the root is executing. Failures in the
    /// calling-thread worker still fail the runner.
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

    /// Override the network buffer pool configuration.
    pub fn with_network_buffer_pool_config(mut self, config: BufferPoolConfig) -> Self {
        self.network_buffer_pool_cfg = Some(config);
        self
    }

    /// Override the storage buffer pool configuration.
    pub fn with_storage_buffer_pool_config(mut self, config: BufferPoolConfig) -> Self {
        self.storage_buffer_pool_cfg = Some(config);
        self
    }

    /// Return per-worker ring configuration.
    pub const fn ring_config(&self) -> &RingConfig {
        &self.ring_config
    }

    /// Return per-worker idle spinning configuration.
    pub const fn idle_spinner(&self) -> &SpinnerConfig {
        &self.idle_spinner
    }

    /// Return the configured one-off worker and Rayon thread stack size.
    pub const fn thread_stack_size(&self) -> usize {
        self.thread_stack_size
    }

    /// Return whether spawned-task panics and one-off worker failures are caught.
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

    /// Resolve default network pool parallelism for one ordinary worker.
    fn resolved_network_buffer_pool_config(&self) -> BufferPoolConfig {
        self.network_buffer_pool_cfg
            .clone()
            .unwrap_or_else(|| BufferPoolConfig::for_network().with_parallelism(NZUsize!(1)))
    }

    /// Resolve default storage pool parallelism for one ordinary worker.
    fn resolved_storage_buffer_pool_config(&self) -> BufferPoolConfig {
        self.storage_buffer_pool_cfg
            .clone()
            .unwrap_or_else(|| BufferPoolConfig::for_storage().with_parallelism(NZUsize!(1)))
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

/// Close supervision and finish task metrics if factory construction unwinds.
struct FactoryGuard<'a> {
    /// Supervision subtree closed if construction fails.
    tree: &'a Arc<Tree>,
    /// Metric transferred to the execution wrapper after construction succeeds.
    metric: Option<MetricHandle>,
}

impl Drop for FactoryGuard<'_> {
    fn drop(&mut self) {
        if let Some(metric) = &self.metric {
            metric.finish();
            self.tree.abort();
        }
    }
}

/// Registration and cleanup barrier for one-off workers.
#[derive(Default)]
struct Workers {
    /// Registration gate and count protected by the same lock.
    state: Mutex<WorkerCount>,
    /// Notify shutdown when the last registered worker finishes cleanup.
    idle: Condvar,
}

/// One-off workers that shutdown must still wait for.
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
struct ActiveWorker(Arc<Workers>);

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

/// Runner-wide services shared by ordinary and one-off workers.
struct Shared {
    /// Validated configuration, immutable after startup.
    cfg: Config,
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
    /// Synchronized creation and closure of one-off workers.
    workers: Arc<Workers>,
    /// Metered storage with its metadata lock and directory hold.
    storage: MeteredStorage<Storage>,
    /// Metered native socket adapter.
    network: MeteredNetwork<Network>,
    /// Shared allocation pool for network reads.
    network_buffer_pool: BufferPool,
    /// Shared allocation pool for storage reads.
    storage_buffer_pool: BufferPool,
}

/// Task and runtime ownership transferred to a one-off thread.
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
/// Ordinary children always target the runner's calling thread, including those
/// spawned by dedicated and blocking tasks. Task factories run on their caller,
/// while returned futures run on the selected worker. Resources may move between
/// workers between I/O operations. Registered I/O futures and sleeps stay bound
/// to their worker. Detached sync completion handles can be awaited on any thread.
pub struct Context {
    /// User-facing task and metric namespace.
    name: String,
    /// Validated metric attributes inherited by children.
    attributes: Vec<(String, String)>,
    /// Shared services and runner-wide lifecycle state.
    shared: Arc<Shared>,
    /// Ordinary worker origin, without extending its lifetime.
    origin: Weak<Mailbox>,
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
        let origin = self.origin.clone();
        let active = if matches!(execution, Execution::Dedicated | Execution::Shared(true)) {
            let Some(active) = shared.workers.reserve() else {
                return Handle::closed(metric);
            };
            Some(active)
        } else {
            if !Tasks::is_open(&origin) {
                return Handle::closed(metric);
            }
            None
        };

        let mut guard = FactoryGuard {
            tree: &parent,
            metric: Some(metric),
        };

        // User construction runs on the caller with no runtime borrow or lock.
        // A reserved one-off remains counted through construction and launch,
        // including when the factory unwinds or shutdown closes the registry.
        let future = f(self);

        // The execution wrapper takes over cleanup once the factory returns.
        let (future, handle) = Handle::init(
            future,
            guard.metric.take().unwrap(),
            shared.panicker.clone(),
            parent.clone(),
        );

        // Attach cancellation before another worker can begin polling the task.
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        let task = Task::boxed(future);
        let result = if let Some(active) = active {
            shared.launch(task, active);
            Ok(())
        } else {
            Tasks::register(&origin, task)
        };

        if let Err(task) = result {
            // Rejection after closure follows the caller's panic boundary.
            // Cancel descendants and finish metrics before destroying captures.
            parent.abort();
            drop(task);
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
    fn strategy(&self, parallelism: NonZeroUsize) -> Rayon {
        let pool = ThreadPoolBuilder::new()
            .num_threads(parallelism.get())
            .stack_size(self.shared.cfg.thread_stack_size)
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
            shared: self.shared.clone(),
            origin: self.origin.clone(),
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

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        Sleep::new(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
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

impl crate::BufferPooler for Context {
    fn network_buffer_pool(&self) -> &BufferPool {
        &self.shared.network_buffer_pool
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        &self.shared.storage_buffer_pool
    }
}

/// Detached sync result and the sender that publishes it outside Local.
type SyncResult = (oneshot::Sender<Result<(), Error>>, Result<(), Error>);

/// Mutable execution state accessed only by its owning worker thread.
///
/// Polls and callbacks obtain this state through [`Self::current`]. They release
/// each borrow before running user code, including waker methods and destructors.
pub struct Local {
    /// Ring owner, taken only after kernel retirement so it can be dropped unborrowed.
    pub driver: Option<Driver>,
    /// Spawned tasks and FIFO ready tokens.
    pub tasks: Tasks,
    /// Sleeper registrations and deadlines.
    pub timers: Timers,
    /// Reject new registration while allowing idempotent cancellation.
    pub closing: bool,
    /// Shared monotonic sample for the current service turn.
    pub now: Instant,
    /// Root wake flag, taken before each root poll so a wake during the poll is kept.
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
    /// Construct a ring on the thread that will own all its submissions.
    fn new(shared: Arc<Shared>) -> std::io::Result<Self> {
        #[cfg(test)]
        tests::before_startup(&shared.workers)?;

        let mailbox = Arc::new(Mailbox::new()?);
        let now = Instant::now();
        let driver = Driver::new(
            &shared.cfg.ring_config,
            shared.cfg.max_timeout(),
            mailbox.waker.clone(),
            now,
        )?;

        Ok(Self {
            driver: Some(driver),
            tasks: Tasks::default(),
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

    /// Resolve the owning worker for a registered operation or sleep.
    ///
    /// With no matching current worker, returns [`Error::Closed`] if the owner has
    /// closed, and panics otherwise. The caller checks whether a matching worker is
    /// closing before accessing its registrations.
    pub fn bound(mailbox: &Weak<Mailbox>) -> Result<Rc<RefCell<Self>>, Error> {
        if let Some(local) = Self::owner(mailbox) {
            return Ok(local);
        }

        // A closed owner has already assumed cleanup responsibility. Polling
        // elsewhere while that owner is live violates worker affinity.
        if mailbox.upgrade().is_none_or(|mailbox| !mailbox.is_open()) {
            return Err(Error::Closed);
        }

        panic!("registered io_uring handle polled outside its owning worker");
    }

    /// Release an operation or timer on its worker, directly or through its mailbox.
    ///
    /// Accepts only [`Message::Orphan`] and [`Message::CancelTimer`]. A worker whose
    /// mailbox is closed or gone has already taken responsibility for cleanup.
    pub fn cancel(mailbox: &Weak<Mailbox>, message: Message) {
        if let Some(local) = Self::owner(mailbox) {
            // Owner-local drops also reach this path after the mailbox has closed.
            let mut local = local.borrow_mut();
            match message {
                Message::Orphan(id) => local.orphan(id),
                Message::CancelTimer(id) => local.cancel_timer(id),
                _ => unreachable!("invalid cancellation message"),
            }
            return;
        }

        if let Some(mailbox) = mailbox.upgrade() {
            // If closure wins the race, worker cleanup will release the registration.
            let _ = mailbox.send(message);
        }
    }

    /// Detach observation without running callbacks under the local borrow.
    pub fn orphan(&mut self, id: WaiterId) {
        self.driver.as_mut().unwrap().orphan(id, &mut self.deferred);
    }

    /// Remove a sleep registration and defer destruction of its waker.
    fn cancel_timer(&mut self, id: TimerId) {
        if let Some(waker) = self.timers.cancel(id) {
            self.deferred.drops.push(waker);
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

    /// Whether task polling or callbacks prevent the worker from parking.
    fn is_ready(&self) -> bool {
        self.tasks.is_ready() || self.root_ready || !self.deferred.is_empty()
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
    /// Reject nesting before any directory hold, pool, thread, or ring is created.
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
type Panic = Box<dyn Any + Send + 'static>;

/// Retain the first panic while allowing the remaining cleanup to run.
///
/// Later payloads are leaked because their destructors may panic. An unclaimed
/// first payload is also leaked when this accumulator is dropped, including
/// during an existing unwind.
#[derive(Default)]
struct Panics {
    /// First failure, held until the worker can report it.
    first: Option<Panic>,
}

impl Panics {
    /// Run a task poll or destructor, returning `None` if it panics.
    ///
    /// Cancellation can destroy the user future during polling, so both paths need
    /// this boundary. The caller must release worker borrows before invoking it.
    fn contain<T>(f: impl FnOnce() -> T) -> Option<T> {
        match catch_unwind(AssertUnwindSafe(f)) {
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
    /// Notifications for tasks observing completed local transitions.
    pub wakes: Vec<Waker>,
    /// Wakers whose registrations were replaced or cancelled.
    pub drops: Vec<Waker>,
    /// Results whose observation has ended.
    pub outputs: Vec<RequestOutput>,
    /// Buffers and descriptors no longer used by the kernel.
    pub resources: Vec<RetiredResources>,
    /// Detached durable-sync publications.
    pub sync_results: Vec<SyncResult>,
}

impl Deferred {
    /// Whether the batch contains no callbacks or owners to release.
    pub const fn is_empty(&self) -> bool {
        self.wakes.is_empty()
            && self.drops.is_empty()
            && self.outputs.is_empty()
            && self.resources.is_empty()
            && self.sync_results.is_empty()
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

        // Publish detached sync results after releasing the completed requests' owners.
        for (sender, output) in self.sync_results.drain(..) {
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
struct Worker {
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
    /// False until kernel retirement and callback cleanup have finished.
    finished: bool,
}

impl Worker {
    /// Install TLS only after constructing a cleanup owner.
    fn new(local: Local) -> Self {
        let local = Rc::new(RefCell::new(local));
        let mut worker = Self {
            local: local.clone(),
            scope: None,
            deferred: Deferred::default(),
            panics: Panics::default(),
            inbox: Vec::new(),
            processed_seq: 0,
            finished: false,
        };
        worker.scope = Some(Scope::install(local));
        worker
    }

    /// Create a worker and drive a stack-pinned root, retaining the worker for cleanup.
    ///
    /// The optional service task runs alongside the root. Only the ordinary worker
    /// receives `interrupts` and closes runner-wide reservations when its root exits.
    ///
    /// Root construction, execution, and destruction share a panic boundary.
    /// Startup errors return directly. Later failures are retained in the worker
    /// so the caller can cancel accepted tasks and clean up with TLS still installed.
    fn run<F, Fut>(
        shared: Arc<Shared>,
        build: F,
        service: Option<BoxedTask>,
        interrupts: Option<Panicked>,
    ) -> Result<(Self, Option<Fut::Output>), Panic>
    where
        F: FnOnce(&Arc<Mailbox>) -> Fut,
        Fut: Future,
    {
        // Only the owning runner listens for failures from other workers.
        let owning_runner = interrupts.is_some();
        let local = Local::new(shared.clone()).map_err(|error| -> Panic {
            Box::new(format!(
                "failed to create native io_uring worker (Linux 6.1 with SINGLE_ISSUER and DEFER_TASKRUN is required): {error}"
            ))
        })?;
        let mut worker = Self::new(local);
        let mailbox = worker.local.borrow().mailbox.clone();

        // Register the background service as an ordinary task before constructing
        // the separately polled root.
        if let Some(service) = service
            && let Err(service) = Tasks::register(&Arc::downgrade(&mailbox), service)
        {
            worker.panics.run(|| drop(service));
        }
        let root_waker = TaskWaker::new(Arc::downgrade(&mailbox), Target::Root).into();

        // The catch owns the root, including when interrupted. Worker and TLS stay
        // outside it so root destruction can orphan operations or spawn more work.
        let result = catch_unwind(AssertUnwindSafe(|| {
            let root = build(&mailbox);
            match interrupts {
                Some(interrupts) => worker.drive(pin!(interrupts.interrupt(root)), &root_waker),
                None => worker.drive(pin!(root), &root_waker),
            }
        }));
        let output = match result {
            Ok(output) => output,
            Err(panic) => {
                worker.panics.retain(panic);
                None
            }
        };

        // Include work spawned by root destruction in the shutdown barrier.
        if owning_runner {
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
            let (mut worker, output) = Self::run(shared.clone(), |_| root, None, None)?;
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
    fn callbacks(&mut self) {
        // Reuse the emptied batch while callbacks collect more work in Local.
        mem::swap(&mut self.deferred, &mut self.local.borrow_mut().deferred);
        self.deferred.run(&mut self.panics);
    }

    /// Acknowledge one transferred mailbox batch.
    const fn acknowledge_batch(&mut self) {
        self.processed_seq = self.processed_seq.wrapping_add(1) & SUBMISSION_SEQ_MASK;
    }

    /// Close local registration and mailbox publication, retaining accepted tasks.
    /// Repeated calls leave the worker closed and preserve its existing inbox.
    fn begin_close(&mut self) {
        let mailbox = {
            let mut local = self.local.borrow_mut();
            local.closing = true;
            local.mailbox.clone()
        };
        let messages = mailbox.close();

        if !messages.is_empty() {
            self.acknowledge_batch();
        }

        // Keep accepted tasks alive until the caller has cancelled them and
        // cleanup can destroy their futures outside the local borrow. Shutdown
        // only disposes of these messages, so no FIFO reversal is needed here.
        self.inbox.extend(messages);
    }

    /// Cancel observers and finish all kernel-visible work before releasing TLS.
    /// Retains callback failures until cleanup finishes. An infrastructure failure
    /// before kernel retirement aborts the process through [`RetirementGuard`].
    fn cleanup(&mut self) {
        if self.finished {
            return;
        }

        // Protect every retirement transition, including observer removal
        // before the first drain turn, against unexpected infrastructure unwind.
        let retirement = RetirementGuard;
        self.begin_close();

        // Closing the driver and timer table below subsumes queued cancellations.
        // Spawn messages still own futures, which must be destroyed unborrowed.
        for message in self.inbox.drain(..) {
            Panics::contain(|| drop(message));
        }

        // Destroy tasks before closing I/O, letting their futures detach observers.
        let mut tasks = Vec::new();
        self.local.borrow_mut().tasks.clear(&mut tasks);
        for Running { task, waker, .. } in tasks {
            Panics::contain(|| drop(task));
            drop(waker);
        }

        // Close every ordinary observer and timer before running callbacks.
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
            timers.clear(&mut deferred.drops);
            local.update_pending();
        }
        self.callbacks();

        // Retained writes and syncs still need to finish. Cancelled operations
        // retain their resources until their own completion arrives.
        loop {
            // A retained write may still be queued without an SQE in flight.
            // Service must stage that work before we consider waiting for a CQE.
            self.service(false);
            self.callbacks();

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
                Message::Spawn(task) => {
                    self.local
                        .borrow_mut()
                        .tasks
                        .insert(task, Arc::downgrade(mailbox));
                }
                Message::Wake(target) => {
                    let mut local = self.local.borrow_mut();
                    match target {
                        Target::Root => local.root_ready = true,
                        Target::Task(id) => local.tasks.wake(id),
                    }
                }
                Message::Orphan(id) => self.local.borrow_mut().orphan(id),
                Message::CancelTimer(id) => self.local.borrow_mut().cancel_timer(id),
            }
        }
    }

    /// Service the ring and timers using one time sample, collecting callbacks.
    /// Returns whether kernel service was deferred to an idle wait.
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

        // Timer expiry only queues wakers. Callbacks run after this borrow ends.
        timers.expire(*now, &mut deferred.wakes);
        local.update_pending();
        outcome
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
        let (mailbox, spinner_cfg) = {
            let local = self.local.borrow();
            (local.mailbox.clone(), local.shared.cfg.idle_spinner.clone())
        };
        let mut spinner = Spinner::new(&spinner_cfg, || mailbox.waker.pending(self.processed_seq));
        let max_spin =
            Duration::from_micros(spinner_cfg.max_budget_us.try_into().unwrap_or(u64::MAX));

        loop {
            if self.panics.first.is_some() {
                return None;
            }

            // Bound task polling so a self-waking task cannot starve the root,
            // mailbox, or ring service.
            for _ in 0..BATCH_SIZE {
                let Some(mut running) = self.local.borrow_mut().tasks.take() else {
                    break;
                };

                // The inner wrapper handles user polling policy. This boundary
                // also catches destruction performed by the abort wrapper.
                let poll = Panics::contain(|| {
                    running
                        .task
                        .as_mut()
                        .poll(&mut TaskContext::from_waker(&running.waker))
                });

                if matches!(poll, Some(Poll::Pending)) {
                    // Restore the task, retaining any notification received during its poll.
                    self.local.borrow_mut().tasks.pending(running);
                } else {
                    // Retire its ID before disposal can trigger a delayed wake.
                    self.local.borrow_mut().tasks.complete(running.id);
                    let Running { task, waker, .. } = running;
                    Panics::contain(|| drop(task));
                    drop(waker);
                }
            }

            // The root has no Tasks entry. Its flag also records notifications
            // forwarded from other workers through the mailbox.
            let poll_root = mem::take(&mut self.local.borrow_mut().root_ready);

            if poll_root {
                let mut cx = TaskContext::from_waker(root_waker);

                // A wake during this poll sets root_ready again. Pending must
                // not clear it, including a wake caused by the root itself.
                if let Poll::Ready(output) = root.as_mut().poll(&mut cx) {
                    return Some(output);
                }
            }

            // Polls can leave cancelled observers behind. Run one batch before
            // deciding whether kernel service can wait until parking. Reentrant
            // work remains visible to the complete readiness checks below.
            if !self.local.borrow().deferred.is_empty() {
                self.callbacks();
                if self.panics.first.is_some() {
                    return None;
                }
            }

            // An apparently idle turn can combine kernel service with the wait.
            // The result records whether that enter was actually deferred.
            let defer = !self.local.borrow().is_ready()
                && self.inbox.is_empty()
                && !mailbox.waker.pending(self.processed_seq);
            let kernel_deferred = self.service(defer);

            // Apply foreign messages and completion callbacks before considering
            // a wait. Any tasks they make ready will be polled on the next turn.
            self.messages(&mailbox);
            self.callbacks();
            if self.panics.first.is_some() {
                return None;
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
            // has a notification that would cause it to be polled.
            if ready
                || pending_submissions
                || !self.inbox.is_empty()
                || mailbox.waker.pending(self.processed_seq)
            {
                if (kernel_deferred && needs_kernel) || (defer && pending_submissions) {
                    // An idle turn must stage work introduced by its callbacks.
                    // A wake alone needs catch-up only if GETEVENTS was deferred.
                    self.service(false);
                    self.callbacks();
                }
                continue;
            }

            // Busy turns use only service's time sample. Take a fresh sample
            // at this actual idle boundary after any elapsed callback time.
            let now = Instant::now();
            if deadline.is_some_and(|deadline| deadline <= now) {
                if kernel_deferred && needs_kernel {
                    self.service(false);
                    self.callbacks();
                }
                continue;
            }

            #[cfg(test)]
            tests::before_park();

            // Unfinished requests need the ring wait to run deferred kernel work.
            // A futex wake alone cannot advance their I/O.
            if needs_kernel {
                let result = self
                    .local
                    .borrow_mut()
                    .driver
                    .as_mut()
                    .unwrap()
                    .park(self.processed_seq, deadline);

                if !result.expect("io_uring kernel wait failed") {
                    // A rejected wait may not have entered the kernel. Complete
                    // its deferred service obligation before another polling turn.
                    self.service(false);
                    self.callbacks();
                }
            } else {
                // A future timer by itself uses a timed futex wait. Spinning
                // is skipped when it could consume the remaining deadline.
                let near_deadline = deadline
                    .is_some_and(|deadline| deadline.saturating_duration_since(now) <= max_spin);

                if !near_deadline && spinner.spin(|| mailbox.waker.pending(self.processed_seq)) {
                    continue;
                }

                if let Some(duration) = mailbox.waker.park_idle(self.processed_seq, deadline) {
                    spinner.on_wake(duration);
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

/// Run a one-off task as the worker's root, containing poll and disposal panics.
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

/// Native io_uring runner executing ordinary tasks on its calling thread.
///
/// The root future need not be Send. Spawned futures are transferred to their
/// selected worker before polling. The runner waits for one-off runtime cleanup
/// and retained writes and syncs before returning or resuming a panic. Native
/// thread-local destruction may follow.
pub struct Runner {
    /// Settings validated before any runtime resources are created.
    cfg: Config,
}

impl Runner {
    /// Construct a runner without acquiring storage or creating a ring.
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
        let network_buffer_pool = BufferPool::new(
            self.cfg.resolved_network_buffer_pool_config(),
            &mut runtime_registry.sub_registry("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            self.cfg.resolved_storage_buffer_pool_config(),
            &mut runtime_registry.sub_registry("storage_buffer_pool"),
        );

        let storage = Storage::new(
            StorageConfig {
                storage_directory: self.cfg.storage_directory.clone(),
                blob_layouts: self.cfg.storage_blob_layouts.clone(),
            },
            storage_buffer_pool.clone(),
        );

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
            Network::new(
                NetworkConfig {
                    tcp_nodelay: self.cfg.tcp_nodelay,
                    zero_linger: self.cfg.zero_linger,
                    connect_timeout: self.cfg.connect_timeout,
                    read_write_timeout: self.cfg.read_write_timeout,
                    read_buffer_size: self.cfg.read_buffer_size,
                },
                network_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );
        let (panicker, tasks) = Panicker::new(self.cfg.catch_panics);

        let shared = Arc::new(Shared {
            cfg: self.cfg,
            registry,
            metrics,
            pending_operations,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            workers: Arc::new(Workers::default()),
            storage,
            network,
            network_buffer_pool,
            storage_buffer_pool,
        });

        let label = Label::root();
        shared.metrics.tasks_spawned.get_or_create(&label).inc();

        let metric = MetricHandle::new(shared.metrics.tasks_running.get_or_create(&label).clone());
        let tree = Tree::root();
        let context_shared = shared.clone();
        let context_tree = tree.clone();

        // Context construction needs the ordinary mailbox, and the root factory
        // needs TLS installed so it can synchronously spawn or register work.
        let output = Worker::run(
            shared.clone(),
            move |mailbox| {
                f(Context {
                    name: label.name(),
                    attributes: Vec::new(),
                    shared: context_shared,
                    origin: Arc::downgrade(mailbox),
                    tree: context_tree,
                    execution: Execution::default(),
                })
            },
            Some(Task::boxed(process.collect(Sleep::new))),
            Some(tasks),
        )
        .and_then(|(mut worker, output)| {
            // The root is gone and publication is closed. Abort ordinary and
            // one-off tasks before waiting for their workers to finish cleanup.
            worker.panics.run(|| tree.abort());
            worker.cleanup();

            // One-off cleanup may depend on resources released by local task
            // disposal or I/O retirement, so drain this worker first.
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
mod tests;
