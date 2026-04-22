#[cfg(not(feature = "iouring-network"))]
use crate::network::tokio::{Config as TokioNetworkConfig, Network as TokioNetwork};
#[cfg(feature = "iouring-storage")]
use crate::storage::iouring::{Config as IoUringConfig, Storage as IoUringStorage};
#[cfg(not(feature = "iouring-storage"))]
use crate::storage::tokio::{Config as TokioStorageConfig, Storage as TokioStorage};
#[cfg(feature = "external")]
use crate::Pacer;
#[cfg(feature = "iouring-network")]
use crate::{
    iouring,
    network::iouring::{Config as IoUringNetworkConfig, Network as IoUringNetwork},
};
use crate::{
    network::metered::Network as MeteredNetwork,
    process::metered::Metrics as MeteredProcess,
    signal::Signal,
    storage::metered::Storage as MeteredStorage,
    telemetry::metrics::task::Label,
    utils::{
        self, add_attribute, signal::Stopper, supervision::Tree, Panicker, Registry, ScopeGuard,
    },
    BufferPool, BufferPoolConfig, Clock, Error, Execution, Handle, Metrics as _, SinkOf,
    Spawner as _, StreamOf, METRICS_PREFIX,
};
use commonware_macros::{select, stability};
#[stability(BETA)]
use commonware_parallel::ThreadPool;
use commonware_utils::{channel::mpsc, sync::Mutex, NZUsize};
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
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder, Runtime};
use tracing::{info_span, Instrument};
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

    /// Stack size to use for runtime-owned threads.
    ///
    /// Defaults to the system stack size when the current platform exposes it,
    /// and otherwise falls back to Rust's default spawned-thread stack size.
    ///
    /// See [utils::thread::system_thread_stack_size].
    thread_stack_size: usize,

    /// Whether or not to catch panics.
    catch_panics: bool,

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
    runtime: Runtime,
    shutdown: Mutex<Stopper>,
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
                            iouring_config: Default::default(),
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
                        shutdown_timeout: Some(self.cfg.network_cfg.read_write_timeout),
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
            runtime,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            thread_stack_size: self.cfg.thread_stack_size,
        });

        // Get metrics
        let label = Label::root();
        executor.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = executor.metrics.tasks_running.get_or_create(&label).clone();

        // Run the future
        let context = Context {
            storage,
            name: label.name(),
            attributes: Vec::new(),
            scope: None,
            executor: executor.clone(),
            network,
            network_buffer_pool,
            storage_buffer_pool,
            tree: Tree::root(),
            execution: Execution::default(),
            instrumented: false,
            on_dedicated_thread: false,
        };
        let output = executor.runtime.block_on(panicked.interrupt(f(context)));
        gauge.dec();

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
    on_dedicated_thread: bool,
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
            on_dedicated_thread: self.on_dedicated_thread,
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
        self.execution = Execution::Dedicated(None);
        self
    }

    fn pinned(mut self, core: usize) -> Self {
        if let Some(num_cores) = utils::thread::available_cores() {
            assert!(
                core < num_cores,
                "core {core} out of range ({num_cores} available)"
            );
        }
        self.execution = Execution::Dedicated(Some(core));
        self
    }

    fn colocated(mut self) -> Self {
        self.execution = Execution::Colocated;
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

        // Track supervision before resetting configuration
        let parent = Arc::clone(&self.tree);
        let past = self.execution;
        let is_instrumented = self.instrumented;
        self.execution = Execution::default();
        self.instrumented = false;

        // The child runs on a dedicated thread if it is spawned as dedicated
        // (new thread) or colocated onto an existing dedicated thread.
        let parent_on_dedicated = self.on_dedicated_thread;
        self.on_dedicated_thread = match past {
            Execution::Dedicated(_) => true,
            Execution::Colocated if parent_on_dedicated => true,
            _ => false,
        };

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

        if let Execution::Dedicated(core) = past {
            utils::thread::spawn(executor.thread_stack_size, {
                // Ensure the task can access the tokio runtime
                let handle = executor.runtime.handle().clone();
                move || {
                    // Pin before running any work on this thread
                    if let Some(core) = core {
                        utils::thread::pin_to_core(core);
                    }

                    let owner = mpsc::runtime::LocalOwner::install();
                    let local = tokio::task::LocalSet::new();
                    handle.block_on(local.run_until(owner.run(f)));
                }
            });
        } else if matches!(past, Execution::Colocated) && parent_on_dedicated {
            tokio::task::spawn_local(f);
        } else if matches!(past, Execution::Shared(true)) {
            executor.runtime.spawn_blocking({
                // Ensure the task can access the tokio runtime
                let handle = executor.runtime.handle().clone();
                move || {
                    handle.block_on(f);
                }
            });
        } else {
            executor.runtime.spawn(f);
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
    use commonware_utils::sync::Mutex;
    use futures::future::poll_fn;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::Poll,
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
    fn test_local_owner_installed_on_dedicated_and_colocated_threads() {
        let executor = Runner::default();
        executor.start(|context| async move {
            assert_eq!(mpsc::runtime::current_owner_id(), None);

            let (dedicated_owner, colocated_owner, shared_owner) = context
                .dedicated()
                .spawn(|context| async move {
                    let dedicated_owner = mpsc::runtime::current_owner_id();
                    let colocated_owner = context
                        .clone()
                        .colocated()
                        .spawn(|_| async move { mpsc::runtime::current_owner_id() })
                        .await
                        .unwrap();
                    let shared_owner = context
                        .clone()
                        .shared(false)
                        .spawn(|_| async move { mpsc::runtime::current_owner_id() })
                        .await
                        .unwrap();
                    (dedicated_owner, colocated_owner, shared_owner)
                })
                .await
                .unwrap();

            assert!(dedicated_owner.is_some());
            assert_eq!(dedicated_owner, colocated_owner);
            assert_eq!(shared_owner, None);
        });
    }

    #[test]
    fn test_channel_created_in_parent_binds_in_colocated_child_and_promotes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let (tx, rx) = mpsc::channel(8);
            let foreign = tx.clone();
            let (local_sent_tx, local_sent_rx) = tokio::sync::oneshot::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();

            let handle = context.dedicated().spawn(move |context| async move {
                context
                    .colocated()
                    .spawn(move |_| async move {
                        let mut rx = rx;

                        poll_fn(|cx| {
                            assert!(matches!(rx.poll_recv(cx), Poll::Pending));
                            Poll::Ready(())
                        })
                        .await;

                        tx.send(1).await.unwrap();
                        local_sent_tx.send(()).unwrap();

                        let first = rx.recv().await.unwrap();
                        let second = rx.recv().await.unwrap();
                        done_tx
                            .send((mpsc::runtime::current_owner_id(), first, second))
                            .unwrap();
                    })
                    .await
                    .unwrap();
            });

            local_sent_rx.await.unwrap();
            foreign.send(2).await.unwrap();

            let (owner, first, second) = done_rx.await.unwrap();
            assert!(owner.is_some());
            assert_eq!((first, second), (1, 2));
            handle.await.unwrap();
        });
    }

    #[test]
    fn test_foreign_receiver_drop_closes_local_channel() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let (tx, rx) = mpsc::channel::<u64>(4);
            let root_tx = tx.clone();
            let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
            let (return_tx, return_rx) = tokio::sync::oneshot::channel();

            let handle = context.dedicated().spawn(move |context| async move {
                context
                    .colocated()
                    .spawn(move |_| async move {
                        let mut rx = rx;
                        poll_fn(|cx| {
                            assert!(matches!(rx.poll_recv(cx), Poll::Pending));
                            Poll::Ready(())
                        })
                        .await;
                        bound_tx.send(()).unwrap();
                        assert!(return_tx.send(rx).is_ok(), "receiver handoff failed");
                    })
                    .await
                    .unwrap();

                tx.closed().await;
                assert!(tx.is_closed());
            });

            bound_rx.await.unwrap();
            let rx = return_rx.await.unwrap();
            drop(rx);

            handle.await.unwrap();
            assert!(matches!(
                root_tx.try_send(1),
                Err(mpsc::error::TrySendError::Closed(1))
            ));
        });
    }

    #[test]
    fn test_foreign_last_sender_drop_wakes_local_receiver() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let (tx, rx) = mpsc::channel::<u64>(4);
            let foreign = tx.clone();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();

            let handle = context.dedicated().spawn(move |context| async move {
                context
                    .colocated()
                    .spawn(move |_| async move {
                        let mut rx = rx;
                        poll_fn(|cx| {
                            assert!(matches!(rx.poll_recv(cx), Poll::Pending));
                            Poll::Ready(())
                        })
                        .await;

                        drop(tx);
                        ready_tx.send(()).unwrap();
                        done_tx
                            .send((mpsc::runtime::current_owner_id(), rx.recv().await))
                            .unwrap();
                    })
                    .await
                    .unwrap();
            });

            ready_rx.await.unwrap();
            drop(foreign);

            let (owner, value) = done_rx.await.unwrap();
            assert!(owner.is_some());
            assert_eq!(value, None);
            handle.await.unwrap();
        });
    }

    #[test]
    #[ignore = "diagnostic reproducer for concurrent first-use send/recv race"]
    fn test_dedicated_concurrent_first_use_send_recv_completes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let sender_step = Arc::new(AtomicUsize::new(usize::MAX));
            let receiver_step = Arc::new(AtomicUsize::new(usize::MAX));
            let tx_state = Arc::new(Mutex::new(None));
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                for _ in 0..256 {
                    let (tx, mut rx) = mpsc::channel(128);
                    let root_tx = tx.clone();
                    *tx_state.lock() = Some(root_tx.clone());
                    sender_step.store(0, Ordering::Relaxed);
                    receiver_step.store(0, Ordering::Relaxed);
                    let barrier = Arc::new(tokio::sync::Barrier::new(2));
                    let sender_barrier = Arc::clone(&barrier);
                    let receiver_barrier = Arc::clone(&barrier);
                    let sender_step_task = Arc::clone(&sender_step);
                    let receiver_step_task = Arc::clone(&receiver_step);

                    let sender = context.clone().dedicated().spawn(move |_| async move {
                        sender_step_task.store(1, Ordering::Relaxed);
                        sender_barrier.wait().await;
                        sender_step_task.store(2, Ordering::Relaxed);
                        tx.send(()).await.unwrap();
                        sender_step_task.store(3, Ordering::Relaxed);
                    });

                    let receiver = context.clone().dedicated().spawn(move |_| async move {
                        receiver_step_task.store(1, Ordering::Relaxed);
                        receiver_barrier.wait().await;
                        receiver_step_task.store(2, Ordering::Relaxed);
                        assert_eq!(rx.recv().await, Some(()));
                        receiver_step_task.store(3, Ordering::Relaxed);
                    });

                    sender.await.unwrap();
                    receiver.await.unwrap();
                    *tx_state.lock() = None;
                    drop(root_tx);
                }
            })
            .await;

            let tx_state = tx_state.lock();
            assert!(
                result.is_ok(),
                "first-use race diagnostic timed out: sender_step={} receiver_step={} tx={:?}",
                sender_step.load(Ordering::Relaxed),
                receiver_step.load(Ordering::Relaxed),
                tx_state.as_ref(),
            );
        });
    }

    #[test]
    fn test_pinned_dedicated_ping_pong_channels() {
        let executor = Runner::default();
        executor.start(|context| async move {
            for _ in 0..32 {
                let (tx_a, mut rx_a) = mpsc::channel(128);
                let (tx_b, mut rx_b) = mpsc::channel(128);

                let context_a = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };
                let context_b = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };

                let task_a = context_a.spawn(move |_| async move {
                    for _ in 0..256 {
                        tx_a.send(()).await.unwrap();
                        rx_b.recv().await.unwrap();
                    }
                });
                let task_b = context_b.spawn(move |_| async move {
                    for _ in 0..256 {
                        tx_b.send(()).await.unwrap();
                        rx_a.recv().await.unwrap();
                    }
                });

                task_a.await.unwrap();
                task_b.await.unwrap();
            }
        });
    }

    #[test]
    #[ignore = "diagnostic reproducer for same-core large-message ping-pong mismatch"]
    fn test_same_core_large_message_ping_pong_preserves_sequence() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let sample = Arc::new(AtomicUsize::new(usize::MAX));
            let a_step = Arc::new(AtomicUsize::new(usize::MAX));
            let b_step = Arc::new(AtomicUsize::new(usize::MAX));
            let tx_a_state = Arc::new(Mutex::new(None));
            let tx_b_state = Arc::new(Mutex::new(None));
            let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                for outer in 0..1024 {
                    sample.store(outer, Ordering::Relaxed);
                    a_step.store(0, Ordering::Relaxed);
                    b_step.store(0, Ordering::Relaxed);
                    let (tx_a, mut rx_a) = mpsc::channel::<[u64; 8]>(128);
                    let (tx_b, mut rx_b) = mpsc::channel::<[u64; 8]>(128);
                    *tx_a_state.lock() = Some(tx_a.clone());
                    *tx_b_state.lock() = Some(tx_b.clone());
                    let barrier = Arc::new(tokio::sync::Barrier::new(3));
                    let barrier_a = Arc::clone(&barrier);
                    let barrier_b = Arc::clone(&barrier);
                    let a_step_task = Arc::clone(&a_step);
                    let b_step_task = Arc::clone(&b_step);

                    let context_a = if crate::available_cores().is_some() {
                        context.clone().pinned(0)
                    } else {
                        context.clone().dedicated()
                    };
                    let context_b = if crate::available_cores().is_some() {
                        context.clone().pinned(0)
                    } else {
                        context.clone().dedicated()
                    };

                    let task_a = context_a.spawn(move |_| async move {
                        a_step_task.store(1, Ordering::Relaxed);
                        barrier_a.wait().await;
                        a_step_task.store(2, Ordering::Relaxed);
                        for inner in 0..64 {
                            let mut sent = [0u64; 8];
                            sent[0] = inner;
                            a_step_task.store(3 + inner as usize * 2, Ordering::Relaxed);
                            tx_a.send(sent).await.unwrap();
                            a_step_task.store(4 + inner as usize * 2, Ordering::Relaxed);
                            let received: [u64; 8] = rx_b.recv().await.unwrap();
                            assert_eq!(received[0], inner, "task A sequence mismatch");
                        }
                        a_step_task.store(usize::MAX - 1, Ordering::Relaxed);
                    });
                    let task_b = context_b.spawn(move |_| async move {
                        b_step_task.store(1, Ordering::Relaxed);
                        barrier_b.wait().await;
                        b_step_task.store(2, Ordering::Relaxed);
                        for inner in 0..64 {
                            let mut sent = [0u64; 8];
                            sent[0] = inner;
                            b_step_task.store(3 + inner as usize * 2, Ordering::Relaxed);
                            tx_b.send(sent).await.unwrap();
                            b_step_task.store(4 + inner as usize * 2, Ordering::Relaxed);
                            let received: [u64; 8] = rx_a.recv().await.unwrap();
                            assert_eq!(received[0], inner, "task B sequence mismatch");
                        }
                        b_step_task.store(usize::MAX - 1, Ordering::Relaxed);
                    });

                    barrier.wait().await;
                    task_a.await.unwrap();
                    task_b.await.unwrap();
                    *tx_a_state.lock() = None;
                    *tx_b_state.lock() = None;
                }
            })
            .await;

            let tx_a_state = tx_a_state.lock();
            let tx_b_state = tx_b_state.lock();
            assert!(
                result.is_ok(),
                "same-core large-message ping-pong failed: sample={} a_step={} b_step={} tx_a={:?} tx_b={:?}",
                sample.load(Ordering::Relaxed),
                a_step.load(Ordering::Relaxed),
                b_step.load(Ordering::Relaxed),
                tx_a_state.as_ref(),
                tx_b_state.as_ref(),
            );
        });
    }

    #[test]
    #[ignore = "diagnostic reproducer for long same-core large-message ping-pong mismatch"]
    fn test_same_core_large_message_long_ping_pong_preserves_sequence() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let a_step = Arc::new(AtomicUsize::new(usize::MAX));
            let b_step = Arc::new(AtomicUsize::new(usize::MAX));
            let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
                let (tx_a, mut rx_a) = mpsc::channel::<[u64; 8]>(128);
                let (tx_b, mut rx_b) = mpsc::channel::<[u64; 8]>(128);
                let barrier = Arc::new(tokio::sync::Barrier::new(3));
                let barrier_a = Arc::clone(&barrier);
                let barrier_b = Arc::clone(&barrier);
                let a_step_task = Arc::clone(&a_step);
                let b_step_task = Arc::clone(&b_step);

                let context_a = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };
                let context_b = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };

                let task_a = context_a.spawn(move |_| async move {
                    barrier_a.wait().await;
                    for inner in 0..1_000_000u64 {
                        let mut sent = [0u64; 8];
                        sent[0] = inner;
                        a_step_task.store(inner as usize, Ordering::Relaxed);
                        tx_a.send(sent).await.unwrap();
                        let received: [u64; 8] = rx_b.recv().await.unwrap();
                        assert_eq!(received[0], inner, "task A long sequence mismatch");
                    }
                });
                let task_b = context_b.spawn(move |_| async move {
                    barrier_b.wait().await;
                    for inner in 0..1_000_000u64 {
                        let mut sent = [0u64; 8];
                        sent[0] = inner;
                        b_step_task.store(inner as usize, Ordering::Relaxed);
                        tx_b.send(sent).await.unwrap();
                        let received: [u64; 8] = rx_a.recv().await.unwrap();
                        assert_eq!(received[0], inner, "task B long sequence mismatch");
                    }
                });

                barrier.wait().await;
                task_a.await.unwrap();
                task_b.await.unwrap();
            })
            .await;

            assert!(
                result.is_ok(),
                "long same-core large-message ping-pong failed: a_step={} b_step={}",
                a_step.load(Ordering::Relaxed),
                b_step.load(Ordering::Relaxed),
            );
        });
    }

    #[test]
    #[ignore = "diagnostic reproducer for repeated runner same-core large-message ping-pong mismatch"]
    fn test_repeated_runner_same_core_large_message_ping_pong_preserves_sequence() {
        let num_cores = crate::available_cores();
        let cfg = num_cores.map_or_else(Config::new, |n| Config::new().with_worker_threads(n));

        for sample in 0..512usize {
            let executor = Runner::new(cfg.clone());
            executor.start(|context| async move {
                let (tx_a, mut rx_a) = mpsc::channel::<[u64; 8]>(128);
                let (tx_b, mut rx_b) = mpsc::channel::<[u64; 8]>(128);
                let barrier = Arc::new(tokio::sync::Barrier::new(3));
                let barrier_a = Arc::clone(&barrier);
                let barrier_b = Arc::clone(&barrier);

                let context_a = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };
                let context_b = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };

                let task_a = context_a.spawn(move |_| async move {
                    barrier_a.wait().await;
                    for inner in 0..256u64 {
                        let mut sent = [0u64; 8];
                        sent[0] = inner;
                        tx_a.send(sent).await.unwrap();
                        let received: [u64; 8] = rx_b
                            .recv()
                            .await
                            .unwrap_or_else(|| panic!("task A recv closed: sample={sample} inner={inner}"));
                        assert_eq!(received[0], inner, "task A repeated-runner mismatch");
                    }
                });
                let task_b = context_b.spawn(move |_| async move {
                    barrier_b.wait().await;
                    for inner in 0..256u64 {
                        let mut sent = [0u64; 8];
                        sent[0] = inner;
                        tx_b.send(sent).await.unwrap();
                        let received: [u64; 8] = rx_a
                            .recv()
                            .await
                            .unwrap_or_else(|| panic!("task B recv closed: sample={sample} inner={inner}"));
                        assert_eq!(received[0], inner, "task B repeated-runner mismatch");
                    }
                });

                barrier.wait().await;
                task_a.await.unwrap();
                task_b.await.unwrap();
            });

            std::hint::black_box(sample);
        }
    }

    #[test]
    #[ignore = "known reproducer for intermittent dedicated commonware ping-pong timeout"]
    fn test_dedicated_ping_pong_channels_complete_with_timeout() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let sample = Arc::new(AtomicUsize::new(usize::MAX));
            let a_step = Arc::new(AtomicUsize::new(usize::MAX));
            let b_step = Arc::new(AtomicUsize::new(usize::MAX));
            let tx_a_state = Arc::new(Mutex::new(None));
            let tx_b_state = Arc::new(Mutex::new(None));
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                for outer in 0..32 {
                    sample.store(outer, Ordering::Relaxed);
                    a_step.store(0, Ordering::Relaxed);
                    b_step.store(0, Ordering::Relaxed);
                    let (tx_a, mut rx_a) = mpsc::channel(128);
                    let (tx_b, mut rx_b) = mpsc::channel(128);
                    *tx_a_state.lock() = Some(tx_a.clone());
                    *tx_b_state.lock() = Some(tx_b.clone());
                    let barrier = Arc::new(tokio::sync::Barrier::new(3));
                    let barrier_a = Arc::clone(&barrier);
                    let barrier_b = Arc::clone(&barrier);
                    let a_step_task = Arc::clone(&a_step);
                    let b_step_task = Arc::clone(&b_step);

                    let task_a = context.clone().dedicated().spawn(move |_| async move {
                        a_step_task.store(1, Ordering::Relaxed);
                        barrier_a.wait().await;
                        a_step_task.store(2, Ordering::Relaxed);
                        for inner in 0..256 {
                            a_step_task.store(3 + inner * 2, Ordering::Relaxed);
                            tx_a.send(()).await.unwrap();
                            a_step_task.store(4 + inner * 2, Ordering::Relaxed);
                            rx_b.recv().await.unwrap();
                        }
                        a_step_task.store(usize::MAX - 1, Ordering::Relaxed);
                    });
                    let task_b = context.clone().dedicated().spawn(move |_| async move {
                        b_step_task.store(1, Ordering::Relaxed);
                        barrier_b.wait().await;
                        b_step_task.store(2, Ordering::Relaxed);
                        for inner in 0..256 {
                            b_step_task.store(3 + inner * 2, Ordering::Relaxed);
                            tx_b.send(()).await.unwrap();
                            b_step_task.store(4 + inner * 2, Ordering::Relaxed);
                            rx_a.recv().await.unwrap();
                        }
                        b_step_task.store(usize::MAX - 1, Ordering::Relaxed);
                    });

                    barrier.wait().await;
                    task_a.await.unwrap();
                    task_b.await.unwrap();
                    *tx_a_state.lock() = None;
                    *tx_b_state.lock() = None;
                }
            })
            .await;

            let tx_a_state = tx_a_state.lock();
            let tx_b_state = tx_b_state.lock();
            assert!(
                result.is_ok(),
                "dedicated ping-pong timed out: sample={} a_step={} b_step={} tx_a={:?} tx_b={:?}",
                sample.load(Ordering::Relaxed),
                a_step.load(Ordering::Relaxed),
                b_step.load(Ordering::Relaxed),
                tx_a_state.as_ref(),
                tx_b_state.as_ref(),
            );
        });
    }

    #[test]
    #[ignore = "diagnostic reproducer for same-core batched dedicated commonware timeout"]
    fn test_same_core_batched_ping_pong_channels_complete_with_timeout() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let a_step = Arc::new(AtomicUsize::new(usize::MAX));
            let b_step = Arc::new(AtomicUsize::new(usize::MAX));
            let tx_a_state = Arc::new(Mutex::new(None));
            let tx_b_state = Arc::new(Mutex::new(None));
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let (tx_a, mut rx_a) = mpsc::channel(128);
                let (tx_b, mut rx_b) = mpsc::channel(128);
                *tx_a_state.lock() = Some(tx_a.clone());
                *tx_b_state.lock() = Some(tx_b.clone());
                let barrier = Arc::new(tokio::sync::Barrier::new(3));
                let barrier_a = Arc::clone(&barrier);
                let barrier_b = Arc::clone(&barrier);
                let a_step_task = Arc::clone(&a_step);
                let b_step_task = Arc::clone(&b_step);

                let context_a = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };
                let context_b = if crate::available_cores().is_some() {
                    context.clone().pinned(0)
                } else {
                    context.clone().dedicated()
                };

                let task_a = context_a.spawn(move |_| async move {
                    barrier_a.wait().await;
                    for round in 0..10_000usize {
                        for inner in 0..100usize {
                            a_step_task.store(round * 10_000 + inner, Ordering::Relaxed);
                            tx_a.send(()).await.unwrap();
                        }
                        for inner in 0..100usize {
                            a_step_task
                                .store(1_000_000 + round * 10_000 + inner, Ordering::Relaxed);
                            rx_b.recv().await.unwrap();
                        }
                    }
                });
                let task_b = context_b.spawn(move |_| async move {
                    barrier_b.wait().await;
                    for round in 0..10_000usize {
                        for inner in 0..100usize {
                            b_step_task.store(round * 10_000 + inner, Ordering::Relaxed);
                            tx_b.send(()).await.unwrap();
                        }
                        for inner in 0..100usize {
                            b_step_task
                                .store(1_000_000 + round * 10_000 + inner, Ordering::Relaxed);
                            rx_a.recv().await.unwrap();
                        }
                    }
                });

                barrier.wait().await;
                task_a.await.unwrap();
                task_b.await.unwrap();
            })
            .await;

            let tx_a_state = tx_a_state.lock();
            let tx_b_state = tx_b_state.lock();
            assert!(
                result.is_ok(),
                "same-core batched ping-pong timed out: a_step={} b_step={} tx_a={:?} tx_b={:?}",
                a_step.load(Ordering::Relaxed),
                b_step.load(Ordering::Relaxed),
                tx_a_state.as_ref(),
                tx_b_state.as_ref(),
            );
        });
    }
}
