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
    utils::{signal::Stopper, supervision::Tree, Panicker},
    validate_label, Clock, Error, Execution, Handle, SinkOf, StreamOf, METRICS_PREFIX,
};
use commonware_macros::select;
use futures::{future::BoxFuture, FutureExt};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Metric, Registry},
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{
    env,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder, Runtime};
use tracing::{info_span, Instrument};

#[cfg(feature = "iouring-network")]
const IOURING_NETWORK_SIZE: u32 = 1024;
#[cfg(feature = "iouring-network")]
const IOURING_NETWORK_FORCE_POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct Metrics {
    tasks_spawned: Family<Label, Counter>,
    tasks_running: Family<Label, Gauge>,
}

impl Metrics {
    pub fn init(registry: &mut Registry) -> Self {
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
    tcp_nodelay: Option<bool>,

    /// Read/write timeout for network operations.
    read_write_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tcp_nodelay: None,
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
}

impl Config {
    /// Returns a new [Config] with default values.
    pub fn new() -> Self {
        let rng = OsRng.next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_tokio_runtime_{rng}"));
        Self {
            worker_threads: 2,
            max_blocking_threads: 512,
            catch_panics: false,
            storage_directory,
            maximum_buffer_size: 2 * 1024 * 1024, // 2 MB
            network_cfg: NetworkConfig::default(),
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
    pub fn with_storage_directory(mut self, p: impl Into<PathBuf>) -> Self {
        self.storage_directory = p.into();
        self
    }
    /// See [Config]
    pub const fn with_maximum_buffer_size(mut self, n: usize) -> Self {
        self.maximum_buffer_size = n;
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
    pub const fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }
    /// See [Config]
    pub const fn maximum_buffer_size(&self) -> usize {
        self.maximum_buffer_size
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
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(METRICS_PREFIX);

        // Initialize runtime
        let metrics = Arc::new(Metrics::init(runtime_registry));
        let runtime = Builder::new_multi_thread()
            .worker_threads(self.cfg.worker_threads)
            .max_blocking_threads(self.cfg.max_blocking_threads)
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

        // Initialize storage
        cfg_if::cfg_if! {
            if #[cfg(feature = "iouring-storage")] {
                let iouring_registry = runtime_registry.sub_registry_with_prefix("iouring_storage");
                let storage = MeteredStorage::new(
                    IoUringStorage::start(IoUringConfig {
                        storage_directory: self.cfg.storage_directory.clone(),
                        iouring_config: Default::default(),
                    }, iouring_registry),
                    runtime_registry,
                );
            } else {
                let storage = MeteredStorage::new(
                    TokioStorage::new(TokioStorageConfig::new(
                        self.cfg.storage_directory.clone(),
                        self.cfg.maximum_buffer_size,
                    )),
                    runtime_registry,
                );
            }
        }

        // Initialize network
        cfg_if::cfg_if! {
            if #[cfg(feature = "iouring-network")] {
                let iouring_registry = runtime_registry.sub_registry_with_prefix("iouring_network");
                let config = IoUringNetworkConfig {
                    tcp_nodelay: self.cfg.network_cfg.tcp_nodelay,
                    iouring_config: iouring::Config {
                        // TODO (#1045): make `IOURING_NETWORK_SIZE` configurable
                        size: IOURING_NETWORK_SIZE,
                        op_timeout: Some(self.cfg.network_cfg.read_write_timeout),
                        force_poll: IOURING_NETWORK_FORCE_POLL,
                        shutdown_timeout: Some(self.cfg.network_cfg.read_write_timeout),
                        ..Default::default()
                    },
                };
                let network = MeteredNetwork::new(
                    IoUringNetwork::start(config, iouring_registry).unwrap(),
                runtime_registry,
            );
        } else {
            let config = TokioNetworkConfig::default().with_read_timeout(self.cfg.network_cfg.read_write_timeout)
                .with_write_timeout(self.cfg.network_cfg.read_write_timeout)
                .with_tcp_nodelay(self.cfg.network_cfg.tcp_nodelay);
                let network = MeteredNetwork::new(
                    TokioNetwork::from(config),
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
        });

        // Get metrics
        let label = Label::root();
        executor.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = executor.metrics.tasks_running.get_or_create(&label).clone();

        // Run the future
        let context = Context {
            storage,
            name: label.name(),
            executor: executor.clone(),
            network,
            tree: Tree::root(),
            execution: Execution::default(),
            instrumented: false,
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
    executor: Arc<Executor>,
    storage: Storage,
    network: Network,
    tree: Arc<Tree>,
    execution: Execution,
    instrumented: bool,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        let (child, _) = Tree::child(&self.tree);
        Self {
            name: self.name.clone(),
            executor: self.executor.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),

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
        let future: BoxFuture<'_, T> = if is_instrumented {
            f(self)
                .instrument(info_span!("task", name = %label.name()))
                .boxed()
        } else {
            f(self).boxed()
        };
        let (f, handle) = Handle::init(
            future,
            metric,
            executor.panicker.clone(),
            Arc::clone(&parent),
        );

        if matches!(past, Execution::Dedicated) {
            thread::spawn({
                // Ensure the task can access the tokio runtime
                let handle = executor.runtime.handle().clone();
                move || {
                    handle.block_on(f);
                }
            });
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
            let mut shutdown = self.executor.shutdown.lock().unwrap();
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
            _ = timeout_future => {
                Err(Error::Timeout)
            }
        }
    }

    fn stopped(&self) -> Signal {
        self.executor.shutdown.lock().unwrap().stopped()
    }
}

impl crate::Metrics for Context {
    fn with_label(&self, label: &str) -> Self {
        // Ensure the label is well-formatted
        validate_label(label);

        // Construct the full label name
        let name = {
            let prefix = self.name.clone();
            if prefix.is_empty() {
                label.to_string()
            } else {
                format!("{prefix}_{label}")
            }
        };
        assert!(
            !name.starts_with(METRICS_PREFIX),
            "using runtime label is not allowed"
        );
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
        self.executor
            .registry
            .lock()
            .unwrap()
            .register(prefixed_name, help, metric)
    }

    fn encode(&self) -> String {
        let mut buffer = String::new();
        encode(&mut buffer, &self.executor.registry.lock().unwrap()).expect("encoding failed");
        buffer
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
        let now = SystemTime::now();
        let duration_until_deadline = deadline.duration_since(now).unwrap_or_else(|_| {
            // Deadline is in the past
            Duration::from_secs(0)
        });
        let target_instant = tokio::time::Instant::now() + duration_until_deadline;
        tokio::time::sleep_until(target_instant)
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

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), Error> {
        self.storage.open(partition, name).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.storage.scan(partition).await
    }
}
