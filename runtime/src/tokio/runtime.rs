#[cfg(any(feature = "iouring-network", feature = "iouring-storage"))]
use crate::iouring;
#[cfg(feature = "iouring-network")]
use crate::network::iouring::{Config as IoUringNetworkConfig, Network as IoUringNetwork};
#[cfg(not(feature = "iouring-network"))]
use crate::network::tokio::{Config as TokioNetworkConfig, Network as TokioNetwork};
#[cfg(feature = "iouring-storage")]
use crate::storage::iouring::{Config as IoUringConfig, Storage as IoUringStorage};
#[cfg(not(feature = "iouring-storage"))]
use crate::storage::tokio::{Config as TokioStorageConfig, Storage as TokioStorage};
#[cfg(feature = "external")]
use crate::Pacer;
use crate::{
    network::metered::Network as MeteredNetwork,
    process::metered::Metrics as MeteredProcess,
    signal::Signal,
    storage::metered::Storage as MeteredStorage,
    telemetry::metrics::task::Label,
    utils::{
        self, add_attribute, signal::Stopper, supervision::Tree, MetricHandle, Panicker, Registry,
        ScopeGuard,
    },
    BufferPool, BufferPoolConfig, Clock, Error, Execution, Handle, Metrics as _, SinkOf,
    Spawner as _, StreamOf, METRICS_PREFIX,
};
use commonware_macros::{select, stability};
#[stability(BETA)]
use commonware_parallel::ThreadPool;
use commonware_utils::{
    sync::{Condvar, Mutex},
    NZUsize,
};
use futures::future::Either;
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Metric, Registry as PrometheusRegistry},
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
#[stability(BETA)]
use rayon::{ThreadPoolBuildError, ThreadPoolBuilder};
use std::{
    borrow::Cow,
    env,
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::runtime::{Builder, Handle as TokioHandle};
use tracing::{error, info_span, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(feature = "iouring-network")]
cfg_if::cfg_if! {
    if #[cfg(test)] {
        // Use a smaller ring in tests to reduce `io_uring_setup` failures
        // under parallel test load due to mlock/resource limits.
        const IOURING_NETWORK_SIZE: u32 = 128;
    } else {
        const IOURING_NETWORK_SIZE: u32 = 1024;
    }
}

#[derive(Debug)]
struct Metrics {
    tasks_spawned: Family<Label, Counter>,
    tasks_running: Family<Label, Gauge>,
}

impl Metrics {
    pub fn init(registry: &mut PrometheusRegistry) -> Self {
        let metrics = Self {
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
        };
        registry.register(
            "tasks_spawned",
            "Total number of tasks spawned",
            metrics.tasks_spawned.clone(),
        );
        registry.register(
            "tasks_running",
            "Number of tasks currently running",
            metrics.tasks_running.clone(),
        );
        metrics
    }
}

/// Tracks running spawned tasks.
#[derive(Default)]
struct TaskTracker {
    // Current state: bit 0 marks shutdown-closed task registration, the
    // remaining bits store the live tracked-task count.
    state: AtomicUsize,
    gate: Mutex<()>,
    idle: Condvar,
}

impl TaskTracker {
    const CLOSED: usize = 1;
    const LIVE_INCREMENT: usize = 2;

    #[inline]
    const fn closed(state: usize) -> bool {
        state & Self::CLOSED != 0
    }

    #[inline]
    const fn live(state: usize) -> usize {
        state >> 1
    }

    /// Reserves a task slot and returns a guard that releases it on drop.
    ///
    /// Returns `None` if shutdown has already closed task registration.
    fn track(self: &Arc<Self>) -> Option<TaskGuard> {
        // Atomically increment the live-task count only if shutdown has not
        // already closed task registration. This single state transition is
        // the linearization point between "task accepted" and "shutdown
        // closed registration".
        self.state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                if Self::closed(state) {
                    None
                } else {
                    Some(
                        state
                            .checked_add(Self::LIVE_INCREMENT)
                            .expect("task tracker overflow"),
                    )
                }
            })
            .ok()?;

        Some(TaskGuard {
            tracker: self.clone(),
        })
    }

    /// Closes task registration for shutdown.
    fn close(&self) {
        self.state.fetch_or(Self::CLOSED, Ordering::Relaxed);
    }

    /// Waits for all tracked tasks to finish.
    ///
    /// Task registration must already be closed before calling this function.
    ///
    /// Returns `true` if all tracked tasks finish before `timeout`, or `false`
    /// if shutdown timed out first.
    fn wait_for_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("shutdown timeout overflow");

        let mut gate = self.gate.lock();
        let state = self.state.load(Ordering::Relaxed);
        assert!(
            Self::closed(state),
            "task registration must be closed before waiting for idle",
        );
        if Self::live(state) == 0 {
            return true;
        }

        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        if remaining.is_zero() {
            return false;
        }

        // Unlike `std`, `parking_lot`'s `Condvar` does not wake up spuriously,
        // so we don't need to loop here:
        //
        // https://docs.rs/parking_lot/0.12.5/parking_lot/struct.Condvar.html#differences-from-the-standard-library-condvar
        self.idle.wait_for(&mut gate, remaining);
        Self::live(self.state.load(Ordering::Relaxed)) == 0
    }

    /// Decrements the live task count and wakes a shutdown waiter if this was
    /// the final tracked task.
    fn release(&self) {
        let state = self
            .state
            .fetch_sub(Self::LIVE_INCREMENT, Ordering::Relaxed);
        assert_ne!(Self::live(state), 0, "task tracker underflow");
        // Only the transition from `closed + 1 live task` to `closed + 0 live
        // tasks` needs to wake the shutdown waiter.
        if state == (Self::CLOSED | Self::LIVE_INCREMENT) {
            let _gate = self.gate.lock();
            self.idle.notify_one();
        }
    }
}

/// Guard held by a spawned task until it has fully exited.
///
/// Dropping the guard decrements the live task count and wakes waiters when the
/// final tracked task completes.
struct TaskGuard {
    tracker: Arc<TaskTracker>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.tracker.release();
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    ///
    /// Defaults to `Some(true)`.
    tcp_nodelay: Option<bool>,

    /// Whether to set `SO_LINGER` to zero on the socket.
    ///
    /// When enabled, causes an immediate RST on close, avoiding
    /// `TIME_WAIT` state. This is useful in adversarial environments to
    /// reclaim socket resources immediately when closing connections to
    /// misbehaving peers.
    ///
    /// Defaults to `true`.
    zero_linger: bool,

    /// Read/write timeout for network operations.
    ///
    /// Bounds the full `Sink::send` and `Stream::recv` calls rather than each
    /// individual socket syscall. Larger
    /// batched writes may therefore require a larger timeout.
    read_write_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tcp_nodelay: Some(true),
            zero_linger: true,
            read_write_timeout: Duration::from_secs(60),
        }
    }
}

/// Configuration for the `tokio` runtime.
#[derive(Clone)]
pub struct Config {
    /// Number of threads to use for handling async tasks.
    ///
    /// Worker threads are always active (waiting for work).
    ///
    /// Tokio sets the default value to the number of logical CPUs.
    worker_threads: usize,

    /// Maximum number of threads to use for blocking tasks.
    ///
    /// Unlike worker threads, blocking threads are created as needed and
    /// exit if left idle for too long.
    ///
    /// Tokio sets the default value to 512 to avoid hanging on lower-level
    /// operations that require blocking (like `fs` and writing to `Stdout`).
    max_blocking_threads: usize,

    /// Whether spawned tasks should catch panics instead of propagating them.
    ///
    /// Defaults to the system stack size when the current platform exposes it,
    /// and otherwise falls back to Rust's default spawned-thread stack size.
    ///
    /// See [utils::thread::system_thread_stack_size].
    thread_stack_size: usize,

    /// Whether spawned tasks should catch panics instead of propagating them.
    catch_panics: bool,

    /// Maximum time to wait for spawned tasks to finish after shutdown begins.
    shutdown_timeout: Duration,

    /// Base directory for all storage operations.
    storage_directory: PathBuf,

    /// Maximum buffer size for operations on blobs.
    ///
    /// Tokio sets the default value to 2MB.
    maximum_buffer_size: usize,

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
        let rng = OsRng.next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_tokio_runtime_{rng}"));
        Self {
            worker_threads: 2,
            max_blocking_threads: 512,
            thread_stack_size: utils::thread::system_thread_stack_size(),
            catch_panics: false,
            shutdown_timeout: Duration::from_secs(60),
            storage_directory,
            maximum_buffer_size: 2 * 1024 * 1024, // 2 MB
            network_cfg: NetworkConfig::default(),
            network_buffer_pool_cfg: None,
            storage_buffer_pool_cfg: None,
        }
    }

    // Setters
    /// See [Config]
    pub const fn with_worker_threads(mut self, n: usize) -> Self {
        self.worker_threads = n;
        self
    }
    /// See [Config]
    pub const fn with_max_blocking_threads(mut self, n: usize) -> Self {
        self.max_blocking_threads = n;
        self
    }
    /// See [Config]
    pub const fn with_thread_stack_size(mut self, n: usize) -> Self {
        self.thread_stack_size = n;
        self
    }
    /// See [Config]
    pub const fn with_catch_panics(mut self, b: bool) -> Self {
        self.catch_panics = b;
        self
    }
    /// See [Config]
    pub const fn with_shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }
    /// See [Config]
    pub const fn with_read_write_timeout(mut self, d: Duration) -> Self {
        self.network_cfg.read_write_timeout = d;
        self
    }
    /// See [Config]
    pub const fn with_tcp_nodelay(mut self, n: Option<bool>) -> Self {
        self.network_cfg.tcp_nodelay = n;
        self
    }
    /// See [Config]
    pub const fn with_zero_linger(mut self, l: bool) -> Self {
        self.network_cfg.zero_linger = l;
        self
    }
    /// See [Config]
    pub fn with_storage_directory(mut self, p: impl Into<PathBuf>) -> Self {
        self.storage_directory = p.into();
        self
    }
    /// See [Config]
    pub const fn with_maximum_buffer_size(mut self, n: usize) -> Self {
        self.maximum_buffer_size = n;
        self
    }
    /// See [Config]
    pub const fn with_network_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.network_buffer_pool_cfg = Some(cfg);
        self
    }
    /// See [Config]
    pub const fn with_storage_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.storage_buffer_pool_cfg = Some(cfg);
        self
    }

    // Getters
    /// See [Config]
    pub const fn worker_threads(&self) -> usize {
        self.worker_threads
    }
    /// See [Config]
    pub const fn max_blocking_threads(&self) -> usize {
        self.max_blocking_threads
    }
    /// See [Config]
    pub const fn thread_stack_size(&self) -> usize {
        self.thread_stack_size
    }
    /// See [Config]
    pub const fn catch_panics(&self) -> bool {
        self.catch_panics
    }
    /// See [Config]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }
    /// See [Config]
    pub const fn read_write_timeout(&self) -> Duration {
        self.network_cfg.read_write_timeout
    }
    /// See [Config]
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.network_cfg.tcp_nodelay
    }
    /// See [Config]
    pub const fn zero_linger(&self) -> bool {
        self.network_cfg.zero_linger
    }
    /// See [Config]
    pub const fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }
    /// See [Config]
    pub const fn maximum_buffer_size(&self) -> usize {
        self.maximum_buffer_size
    }

    /// Returns the network buffer pool config, deriving thread-cache
    /// parallelism from `worker_threads` if not explicitly configured.
    fn resolved_network_buffer_pool_config(&self) -> BufferPoolConfig {
        self.network_buffer_pool_cfg.clone().unwrap_or_else(|| {
            BufferPoolConfig::for_network()
                .with_thread_cache_for_parallelism(NZUsize!(self.worker_threads))
        })
    }

    /// Returns the storage buffer pool config, deriving thread-cache
    /// parallelism from `worker_threads` if not explicitly configured.
    fn resolved_storage_buffer_pool_config(&self) -> BufferPoolConfig {
        self.storage_buffer_pool_cfg.clone().unwrap_or_else(|| {
            BufferPoolConfig::for_storage()
                .with_thread_cache_for_parallelism(NZUsize!(self.worker_threads))
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime based on [Tokio](https://tokio.rs).
pub struct Executor {
    registry: Mutex<Registry>,
    metrics: Arc<Metrics>,
    handle: TokioHandle,
    shutdown: Mutex<Stopper>,
    tasks: Arc<TaskTracker>,
    panicker: Panicker,
    thread_stack_size: usize,
}

/// Implementation of [crate::Runner] for the `tokio` runtime.
pub struct Runner {
    cfg: Config,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Runner {
    /// Initialize a new `tokio` runtime with the given number of threads.
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
        // Create a new registry
        let mut registry = Registry::new();
        let runtime_registry = registry.root_mut().sub_registry_with_prefix(METRICS_PREFIX);

        // Initialize runtime
        let metrics = Arc::new(Metrics::init(runtime_registry));
        let runtime = Builder::new_multi_thread()
            .worker_threads(self.cfg.worker_threads)
            .max_blocking_threads(self.cfg.max_blocking_threads)
            .thread_stack_size(self.cfg.thread_stack_size)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");

        // Initialize panicker
        let (panicker, panicked) = Panicker::new(self.cfg.catch_panics);

        // Collect process metrics.
        //
        // We prefer to collect process metrics outside of `Context` because
        // we are using `runtime_registry` rather than the one provided by `Context`.
        let process = MeteredProcess::init(runtime_registry);
        runtime.spawn(process.collect(tokio::time::sleep));

        // Initialize buffer pools
        let network_buffer_pool = BufferPool::new(
            self.cfg.resolved_network_buffer_pool_config(),
            runtime_registry.sub_registry_with_prefix("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            self.cfg.resolved_storage_buffer_pool_config(),
            runtime_registry.sub_registry_with_prefix("storage_buffer_pool"),
        );

        // Initialize storage
        cfg_if::cfg_if! {
            if #[cfg(feature = "iouring-storage")] {
                let iouring_registry =
                    runtime_registry.sub_registry_with_prefix("iouring_storage");
                let storage = MeteredStorage::new(
                    IoUringStorage::start(
                        IoUringConfig {
                            storage_directory: self.cfg.storage_directory.clone(),
                            iouring_config: iouring::Config {
                                shutdown_timeout: Some(self.cfg.shutdown_timeout),
                                ..Default::default()
                            },
                            thread_stack_size: self.cfg.thread_stack_size,
                        },
                        iouring_registry,
                        storage_buffer_pool.clone(),
                    ),
                    runtime_registry,
                );
            } else {
                let storage = MeteredStorage::new(
                    TokioStorage::new(
                        TokioStorageConfig::new(
                            self.cfg.storage_directory.clone(),
                            self.cfg.maximum_buffer_size,
                        ),
                        storage_buffer_pool.clone(),
                    ),
                    runtime_registry,
                );
            }
        }

        // Initialize network
        cfg_if::cfg_if! {
            if #[cfg(feature = "iouring-network")] {
                let iouring_registry =
                    runtime_registry.sub_registry_with_prefix("iouring_network");
                let config = IoUringNetworkConfig {
                    tcp_nodelay: self.cfg.network_cfg.tcp_nodelay,
                    zero_linger: self.cfg.network_cfg.zero_linger,
                    read_write_timeout: self.cfg.network_cfg.read_write_timeout,
                    iouring_config: iouring::Config {
                        // TODO (#1045): make `IOURING_NETWORK_SIZE` configurable
                        size: IOURING_NETWORK_SIZE,
                        max_op_timeout: self.cfg.network_cfg.read_write_timeout,
                        shutdown_timeout: Some(self.cfg.shutdown_timeout),
                        ..Default::default()
                    },
                    thread_stack_size: self.cfg.thread_stack_size,
                    ..Default::default()
                };
                let network = MeteredNetwork::new(
                    IoUringNetwork::start(
                        config,
                        iouring_registry,
                        network_buffer_pool.clone(),
                    )
                    .unwrap(),
                    runtime_registry,
                );
            } else {
                let config = TokioNetworkConfig::default()
                    .with_read_timeout(self.cfg.network_cfg.read_write_timeout)
                    .with_write_timeout(self.cfg.network_cfg.read_write_timeout)
                    .with_tcp_nodelay(self.cfg.network_cfg.tcp_nodelay)
                    .with_zero_linger(self.cfg.network_cfg.zero_linger);
                let network = MeteredNetwork::new(
                    TokioNetwork::new(config, network_buffer_pool.clone()),
                    runtime_registry,
                );
            }
        }

        // Initialize executor
        let executor = Arc::new(Executor {
            registry: Mutex::new(registry),
            metrics,
            handle: runtime.handle().clone(),
            shutdown: Mutex::new(Stopper::default()),
            tasks: Arc::new(TaskTracker::default()),
            panicker,
            thread_stack_size: self.cfg.thread_stack_size,
        });

        // Get metrics
        let label = Label::root();
        executor.metrics.tasks_spawned.get_or_create(&label).inc();
        let metric =
            MetricHandle::new(executor.metrics.tasks_running.get_or_create(&label).clone());

        // Build the root context and run the future.
        //
        // Catch root panics and propagated child panics so we can still abort
        // descendants, finish metrics, and wait for task cleanup before
        // resuming the original unwind.
        let tree = Tree::root();
        let context = Context {
            storage,
            name: label.name(),
            attributes: Vec::new(),
            scope: None,
            executor: executor.clone(),
            network,
            network_buffer_pool,
            storage_buffer_pool,
            tree: tree.clone(),
            execution: Execution::default(),
            instrumented: false,
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(panicked.monitor(f(context)))
        }));

        // Close task registration before aborting the tree so task cleanup
        // cannot enqueue new work while shutdown is propagating.
        executor.tasks.close();
        tree.abort();
        metric.finish();

        // Enforce the shutdown timeout once across both our own task-tracker wait and
        // Tokio's runtime teardown. Reusing the full timeout for both phases would
        // allow shutdown to exceed the configured bound.
        let shutdown_deadline = Instant::now()
            .checked_add(self.cfg.shutdown_timeout)
            .expect("shutdown timeout overflow");

        // If a tracked task does not finish before the timeout (may be a blocking task we
        // cannot cancel), log the slow shutdown and continue returning or resuming
        // the original panic.
        if !executor.tasks.wait_for_idle(self.cfg.shutdown_timeout) {
            error!("unfinished tasks remaining after shutdown timeout");
        }
        runtime.shutdown_timeout(
            shutdown_deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO),
        );

        // Resume any root or propagated child panic after cleanup. If the root
        // returned normally, also check whether a child panicked while we were
        // waiting for aborted tasks to finish cleaning up.
        let (result, mut panicked) = result.unwrap_or_else(|payload| resume_unwind(payload));
        let output = match result {
            Ok(output) => output,
            Err(payload) => resume_unwind(payload),
        };
        if let Some(panicked) = panicked.as_mut() {
            if let Ok(payload) = panicked.try_recv() {
                resume_unwind(payload);
            }
        }
        output
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "iouring-storage")] {
        type Storage = MeteredStorage<IoUringStorage>;
    } else {
        type Storage = MeteredStorage<TokioStorage>;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "iouring-network")] {
        type Network = MeteredNetwork<IoUringNetwork>;
    } else {
        type Network = MeteredNetwork<TokioNetwork>;
    }
}

/// Implementation of [crate::Spawner], [crate::Clock],
/// [crate::Network], and [crate::Storage] for the `tokio`
/// runtime.
pub struct Context {
    name: String,
    attributes: Vec<(String, String)>,
    scope: Option<Arc<ScopeGuard>>,
    executor: Arc<Executor>,
    storage: Storage,
    network: Network,
    network_buffer_pool: BufferPool,
    storage_buffer_pool: BufferPool,
    tree: Arc<Tree>,
    execution: Execution,
    instrumented: bool,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        let (child, _) = Tree::child(&self.tree);
        Self {
            name: self.name.clone(),
            attributes: self.attributes.clone(),
            scope: self.scope.clone(),
            executor: self.executor.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),
            network_buffer_pool: self.network_buffer_pool.clone(),
            storage_buffer_pool: self.storage_buffer_pool.clone(),
            tree: child,
            execution: Execution::default(),
            instrumented: false,
        }
    }
}

impl Context {
    /// Access the [Metrics] of the runtime.
    fn metrics(&self) -> &Metrics {
        &self.executor.metrics
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

    fn instrumented(mut self) -> Self {
        self.instrumented = true;
        self
    }

    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Get metrics
        let (label, metric) = spawn_metrics!(self);
        let Some(task_guard) = self.executor.tasks.track() else {
            // Shutdown has started and new tasks can no longer be registered.
            return Handle::closed(metric);
        };

        // Track supervision before resetting configuration
        let parent = Arc::clone(&self.tree);
        let past = self.execution;
        let is_instrumented = self.instrumented;
        self.execution = Execution::default();
        self.instrumented = false;
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;

        // Spawn the task
        let executor = self.executor.clone();
        let future = if is_instrumented {
            let span = info_span!("task", name = %label.name());
            for (key, value) in &self.attributes {
                span.set_attribute(key.clone(), value.clone());
            }
            Either::Left(f(self).instrument(span))
        } else {
            Either::Right(f(self))
        };
        let (f, handle) = Handle::init(
            future,
            metric,
            executor.panicker.clone(),
            Arc::clone(&parent),
        );
        let f = async move {
            let _task_guard = task_guard;
            f.await;
        };

        if matches!(past, Execution::Dedicated) {
            utils::thread::spawn(executor.thread_stack_size, {
                // Ensure the task can access the tokio runtime
                let handle = executor.handle.clone();
                move || {
                    handle.block_on(f);
                }
            });
        } else if matches!(past, Execution::Shared(true)) {
            executor.handle.spawn_blocking({
                // Ensure the task can access the tokio runtime
                let handle = executor.handle.clone();
                move || {
                    handle.block_on(f);
                }
            });
        } else {
            executor.handle.spawn(f);
        }

        // Register the task on the parent
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let stop_resolved = {
            let mut shutdown = self.executor.shutdown.lock();
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
        self.executor.shutdown.lock().stopped()
    }
}

#[stability(BETA)]
impl crate::ThreadPooler for Context {
    fn create_thread_pool(
        &self,
        concurrency: NonZeroUsize,
    ) -> Result<ThreadPool, ThreadPoolBuildError> {
        ThreadPoolBuilder::new()
            .num_threads(concurrency.get())
            .spawn_handler(move |thread| {
                // Tasks spawned in a thread pool are expected to run longer than any single
                // task and thus should be provisioned as a dedicated thread.
                self.with_label("rayon_thread")
                    .dedicated()
                    .spawn(move |_| async move { thread.run() });
                Ok(())
            })
            .build()
            .map(Arc::new)
    }
}

impl crate::Metrics for Context {
    fn with_label(&self, label: &str) -> Self {
        // Construct the full label name
        let name = {
            let prefix = self.name.clone();
            if prefix.is_empty() {
                label.to_string()
            } else {
                format!("{prefix}_{label}")
            }
        };
        Self {
            name,
            ..self.clone()
        }
    }

    fn label(&self) -> String {
        self.name.clone()
    }

    fn register<N: Into<String>, H: Into<String>>(&self, name: N, help: H, metric: impl Metric) {
        let name = name.into();
        let prefixed_name = {
            let prefix = &self.name;
            if prefix.is_empty() {
                name
            } else {
                format!("{}_{}", *prefix, name)
            }
        };

        // Route to the appropriate registry (root or scoped)
        let mut registry = self.executor.registry.lock();
        let scoped = registry.get_scope(self.scope.as_ref().map(|s| s.scope_id()));
        let sub_registry = self
            .attributes
            .iter()
            .fold(scoped, |reg, (k, v): &(String, String)| {
                reg.sub_registry_with_label((Cow::Owned(k.clone()), Cow::Owned(v.clone())))
            });
        sub_registry.register(prefixed_name, help, metric);
    }

    fn encode(&self) -> String {
        self.executor.registry.lock().encode()
    }

    fn with_attribute(&self, key: &str, value: impl std::fmt::Display) -> Self {
        let mut attributes = self.attributes.clone();
        add_attribute(&mut attributes, key, value);
        Self {
            attributes,
            ..self.clone()
        }
    }

    fn with_scope(&self) -> Self {
        // If already scoped, inherit the existing scope
        if self.scope.is_some() {
            return self.clone();
        }

        // RAII guard removes the scoped registry when all clones drop.
        // Closure is infallible to avoid panicking in Drop.
        let executor = self.executor.clone();
        let scope_id = executor.registry.lock().create_scope();
        let guard = Arc::new(ScopeGuard::new(scope_id, move |id| {
            executor.registry.lock().remove_scope(id);
        }));
        Self {
            scope: Some(guard),
            ..self.clone()
        }
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        tokio::time::sleep(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        let duration_until_deadline = deadline.duration_since(self.current()).unwrap_or_default();
        tokio::time::sleep(duration_until_deadline)
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
        // Uses the host's DNS configuration (e.g. /etc/resolv.conf on Unix,
        // registry on Windows). This delegates to the system's libc resolver.
        //
        // The `:0` port is required by lookup_host's API but is not used
        // for DNS resolution.
        let addrs = tokio::net::lookup_host(format!("{host}:0"))
            .await
            .map_err(|e| Error::ResolveFailed(e.to_string()))?;
        Ok(addrs.map(|addr| addr.ip()).collect())
    }
}

impl RngCore for Context {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        OsRng.try_fill_bytes(dest)
    }
}

impl CryptoRng for Context {}

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
    use crate::Runner as _;
    use commonware_utils::channel::oneshot;
    use std::{
        future::pending,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn test_worker_threads_updates_default_buffer_pool_parallelism() {
        let cfg = Config::new().with_worker_threads(8);

        assert_eq!(cfg.worker_threads, 8);
        assert_eq!(
            cfg.resolved_network_buffer_pool_config()
                .thread_cache_config,
            BufferPoolConfig::for_network()
                .with_thread_cache_for_parallelism(NZUsize!(8))
                .thread_cache_config
        );
        assert_eq!(
            cfg.resolved_storage_buffer_pool_config()
                .thread_cache_config,
            BufferPoolConfig::for_storage()
                .with_thread_cache_for_parallelism(NZUsize!(8))
                .thread_cache_config
        );
    }

    #[test]
    fn test_default_thread_stack_size_uses_system_default() {
        let cfg = Config::new();
        assert_eq!(
            cfg.thread_stack_size(),
            utils::thread::system_thread_stack_size()
        );
    }

    #[test]
    fn test_thread_stack_size_override() {
        let cfg = Config::new().with_thread_stack_size(4 * 1024 * 1024);
        assert_eq!(cfg.thread_stack_size(), 4 * 1024 * 1024);
    }

    #[test]
    fn test_explicit_buffer_pool_configs_override_worker_threads() {
        // Order does not matter -- explicit configs always win.
        let cfg = Config::new()
            .with_network_buffer_pool_config(
                BufferPoolConfig::for_network().with_thread_cache_for_parallelism(NZUsize!(2)),
            )
            .with_worker_threads(8)
            .with_storage_buffer_pool_config(
                BufferPoolConfig::for_storage().with_thread_cache_disabled(),
            );

        assert_eq!(
            cfg.resolved_network_buffer_pool_config()
                .thread_cache_config,
            BufferPoolConfig::for_network()
                .with_thread_cache_for_parallelism(NZUsize!(2))
                .thread_cache_config
        );
        assert_eq!(
            cfg.resolved_storage_buffer_pool_config()
                .thread_cache_config,
            BufferPoolConfig::for_storage()
                .with_thread_cache_disabled()
                .thread_cache_config
        );
    }

    #[test]
    fn test_shutdown_waits_for_spawn_in_flight() {
        let (context_tx, context_rx) = mpsc::channel();
        let (allow_root_return_tx, allow_root_return_rx) = oneshot::channel();
        let (spawn_entered_tx, spawn_entered_rx) = mpsc::channel();
        let (release_spawn_tx, release_spawn_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();

        // Run the root on a separate thread so the test can drive shutdown
        // while another thread stalls a concurrent spawn call mid-flight.
        let runner = thread::spawn(move || {
            let runner =
                Runner::new(Config::default().with_shutdown_timeout(Duration::from_secs(1)));
            runner.start(|context| async move {
                context_tx
                    .send(context.clone())
                    .expect("context receiver should stay open");
                let _ = allow_root_return_rx.await;
            });
            finished_tx
                .send(())
                .expect("runner completion receiver should stay open");
        });

        // Reuse a cloned context after the root has started so spawn races with
        // root shutdown from another thread.
        let context = context_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("root should publish a cloneable context before returning");
        let spawn = thread::spawn(move || {
            let handle = context.spawn(move |_| {
                // Block inside spawn before it can finish registration.
                spawn_entered_tx
                    .send(())
                    .expect("spawn entry receiver should stay open");
                release_spawn_rx
                    .recv()
                    .expect("spawn release sender should stay open");
                async move { pending::<()>().await }
            });
            drop(handle);
        });

        // Start shutdown while the concurrent spawn is still in progress. The
        // regression was that `start()` could return from this state.
        spawn_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("spawn should block inside the in-flight window");
        allow_root_return_tx
            .send(())
            .expect("root return gate should stay open");
        let returned_early = finished_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        release_spawn_tx
            .send(())
            .expect("spawn release receiver should stay open");

        assert!(
            !returned_early,
            "root shutdown returned while a spawn was still in flight",
        );
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("runner should finish after the in-flight spawn is released");
        spawn.join().expect("spawn thread should join cleanly");
        runner.join().expect("runner thread should join cleanly");
    }

    #[test]
    fn test_cleanup_wait_keeps_propagating_panics() {
        let (root_returning_tx, root_returning_rx) = mpsc::channel();
        let (panic_now_tx, panic_now_rx) = mpsc::channel();

        // Run the runner on another thread so the test can trigger a child
        // panic after the root has already entered cleanup.
        let thread = thread::spawn(move || {
            catch_unwind(AssertUnwindSafe(|| {
                let runner =
                    Runner::new(Config::default().with_shutdown_timeout(Duration::from_secs(1)));
                runner.start(|context| async move {
                    let (started_tx, started_rx) = oneshot::channel();
                    context.shared(true).spawn(move |_| async move {
                        let _ = started_tx.send(());
                        // Hold the blocking task until the root has returned,
                        // then panic while `start()` is waiting for cleanup.
                        panic_now_rx
                            .recv()
                            .expect("panic trigger sender should stay open");
                        panic!("cleanup panic");
                    });
                    let _ = started_rx.await;
                    root_returning_tx
                        .send(())
                        .expect("root return receiver should stay open");
                });
            }))
        });

        // Confirm the root has finished its future and is in the shutdown wait
        // before letting the child panic.
        root_returning_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("root should enter cleanup after child startup");
        panic_now_tx
            .send(())
            .expect("panic trigger should stay open until cleanup");

        let result = thread
            .join()
            .expect("runner thread should catch its own unwind");
        assert!(
            result.is_err(),
            "cleanup panic should still abort the Tokio runner",
        );
    }

    #[test]
    fn test_shutdown_timeout_uses_remaining_runtime_budget() {
        let shutdown_timeout = Duration::from_millis(300);
        let (root_returned_tx, root_returned_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();

        let runner = thread::spawn(move || {
            let runner = Runner::new(Config::default().with_shutdown_timeout(shutdown_timeout));
            runner.start(|context| async move {
                let (started_tx, started_rx) = oneshot::channel();
                drop(context.shared(true).spawn(move |_| async move {
                    started_tx
                        .send(())
                        .expect("startup receiver should stay open");

                    // Block forever on the spawn_blocking thread while still owning the sender
                    // so shutdown must rely on Tokio's timeout rather than task completion.
                    let (_never_send_tx, never_send_rx) = mpsc::channel::<()>();
                    never_send_rx
                        .recv()
                        .expect("sender should stay open while blocking forever");
                }));
                started_rx.await.expect("blocking task should start");
                root_returned_tx
                    .send(Instant::now())
                    .expect("root return receiver should stay open");
            });
            finished_tx
                .send(Instant::now())
                .expect("runner completion receiver should stay open");
        });

        let root_returned_at = root_returned_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("root should enter shutdown after child startup");
        let finished_at = finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("runner should honor the shutdown timeout");

        assert!(
            finished_at.duration_since(root_returned_at) < Duration::from_millis(450),
            "shutdown exceeded the configured budget by reusing the full timeout for Tokio teardown",
        );
        runner.join().expect("runner thread should join cleanly");
    }
}
