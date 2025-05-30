#[cfg(feature = "iouring-storage")]
use crate::storage::iouring::{Config as IoUringConfig, Storage as IoUringStorage};

#[cfg(feature = "iouring-network")]
use crate::network::iouring::Network as IoUringNetwork;

#[cfg(not(feature = "iouring-network"))]
use crate::network::tokio::Network as TokioNetwork;

#[cfg(not(feature = "iouring-storage"))]
use crate::storage::tokio::{Config as TokioStorageConfig, Storage as TokioStorage};

use crate::network::metered::Network as MeteredNetwork;
use crate::network::tokio::Config as TokioNetworkConfig;
use crate::storage::metered::Storage as MeteredStorage;
use crate::telemetry::metrics::task::Label;
use crate::{utils::Signaler, Clock, Error, Handle, Signal, METRICS_PREFIX};
use crate::{SinkOf, StreamOf};
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
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder, Runtime};

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

    network_cfg: TokioNetworkConfig,
}

impl Config {
    /// Returns a new [Config] with default values.
    pub fn new() -> Self {
        let rng = OsRng.next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_tokio_runtime_{}", rng));
        Self {
            worker_threads: 2,
            max_blocking_threads: 512,
            catch_panics: true,
            storage_directory,
            maximum_buffer_size: 2 * 1024 * 1024, // 2 MB
            network_cfg: TokioNetworkConfig::default(),
        }
    }

    // Setters
    /// See [Config]
    pub fn with_worker_threads(mut self, n: usize) -> Self {
        self.worker_threads = n;
        self
    }
    /// See [Config]
    pub fn with_max_blocking_threads(mut self, n: usize) -> Self {
        self.max_blocking_threads = n;
        self
    }
    /// See [Config]
    pub fn with_catch_panics(mut self, b: bool) -> Self {
        self.catch_panics = b;
        self
    }
    /// See [Config]
    pub fn with_read_timeout(mut self, d: Duration) -> Self {
        self.network_cfg = self.network_cfg.with_read_timeout(d);
        self
    }
    /// See [Config]
    pub fn with_write_timeout(mut self, d: Duration) -> Self {
        self.network_cfg = self.network_cfg.with_write_timeout(d);
        self
    }
    /// See [Config]
    pub fn with_tcp_nodelay(mut self, n: Option<bool>) -> Self {
        self.network_cfg = self.network_cfg.with_tcp_nodelay(n);
        self
    }
    /// See [Config]
    pub fn with_storage_directory(mut self, p: impl Into<PathBuf>) -> Self {
        self.storage_directory = p.into();
        self
    }
    /// See [Config]
    pub fn with_maximum_buffer_size(mut self, n: usize) -> Self {
        self.maximum_buffer_size = n;
        self
    }

    // Getters
    /// See [Config]
    pub fn worker_threads(&self) -> usize {
        self.worker_threads
    }
    /// See [Config]
    pub fn max_blocking_threads(&self) -> usize {
        self.max_blocking_threads
    }
    /// See [Config]
    pub fn catch_panics(&self) -> bool {
        self.catch_panics
    }
    /// See [Config]
    pub fn read_timeout(&self) -> Duration {
        self.network_cfg.read_timeout()
    }
    /// See [Config]
    pub fn write_timeout(&self) -> Duration {
        self.network_cfg.write_timeout()
    }
    /// See [Config]
    pub fn tcp_nodelay(&self) -> Option<bool> {
        self.network_cfg.tcp_nodelay()
    }
    /// See [Config]
    pub fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }
    /// See [Config]
    pub fn maximum_buffer_size(&self) -> usize {
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
    cfg: Config,
    registry: Mutex<Registry>,
    metrics: Arc<Metrics>,
    runtime: Runtime,
    signaler: Mutex<Signaler>,
    signal: Signal,
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
    pub fn new(cfg: Config) -> Self {
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
        let (signaler, signal) = Signaler::new();

        cfg_if::cfg_if! {
            if #[cfg(feature = "iouring-storage")] {
                let iouring_registry = runtime_registry.sub_registry_with_prefix("iouring_storage");
                let storage = MeteredStorage::new(
                    IoUringStorage::start(IoUringConfig {
                        storage_directory: self.cfg.storage_directory.clone(),
                        ring_config: Default::default(),
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

        cfg_if::cfg_if! {
            if #[cfg(feature = "iouring-network")] {
                let iouring_registry = runtime_registry.sub_registry_with_prefix("iouring_network");
                let network = MeteredNetwork::new(
                    IoUringNetwork::start(crate::iouring::Config::default(),iouring_registry).unwrap(),
                    runtime_registry,
                );
            } else {
                let network = MeteredNetwork::new(
                    TokioNetwork::from(self.cfg.network_cfg.clone()),
                    runtime_registry,
                );
            }
        }

        // Initialize executor
        let executor = Arc::new(Executor {
            cfg: self.cfg,
            registry: Mutex::new(registry),
            metrics,
            runtime,
            signaler: Mutex::new(signaler),
            signal,
        });

        // Get metrics
        let label = Label::root();
        executor.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = executor.metrics.tasks_running.get_or_create(&label).clone();

        // Run the future
        let context = Context {
            storage,
            name: label.name(),
            spawned: false,
            executor: executor.clone(),
            network,
        };
        let output = executor.runtime.block_on(f(context));
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
    spawned: bool,
    executor: Arc<Executor>,
    storage: Storage,
    network: Network,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            spawned: false,
            executor: self.executor.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),
        }
    }
}

impl crate::Spawner for Context {
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let (_, gauge) = spawn_metrics!(self, future);

        // Set up the task
        let catch_panics = self.executor.cfg.catch_panics;
        let executor = self.executor.clone();
        let future = f(self);
        let (f, handle) = Handle::init_future(future, gauge, catch_panics);

        // Spawn the task
        executor.runtime.spawn(f);
        handle
    }

    fn spawn_ref<F, T>(&mut self) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");
        self.spawned = true;

        // Get metrics
        let (_, gauge) = spawn_metrics!(self, future);

        // Set up the task
        let executor = self.executor.clone();
        move |f: F| {
            let (f, handle) = Handle::init_future(f, gauge, executor.cfg.catch_panics);

            // Spawn the task
            executor.runtime.spawn(f);
            handle
        }
    }

    fn spawn_blocking<F, T>(self, dedicated: bool, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let (_, gauge) = spawn_metrics!(self, blocking, dedicated);

        // Set up the task
        let executor = self.executor.clone();
        let (f, handle) = Handle::init_blocking(|| f(self), gauge, executor.cfg.catch_panics);

        // Spawn the blocking task
        if dedicated {
            std::thread::spawn(f);
        } else {
            executor.runtime.spawn_blocking(f);
        }
        handle
    }

    fn spawn_blocking_ref<F, T>(&mut self, dedicated: bool) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");
        self.spawned = true;

        // Get metrics
        let (_, gauge) = spawn_metrics!(self, blocking, dedicated);

        // Set up the task
        let executor = self.executor.clone();
        move |f: F| {
            let (f, handle) = Handle::init_blocking(f, gauge, executor.cfg.catch_panics);

            // Spawn the blocking task
            if dedicated {
                std::thread::spawn(f);
            } else {
                executor.runtime.spawn_blocking(f);
            }
            handle
        }
    }

    fn stop(&self, value: i32) {
        self.executor.signaler.lock().unwrap().signal(value);
    }

    fn stopped(&self) -> Signal {
        self.executor.signal.clone()
    }
}

impl crate::Metrics for Context {
    fn with_label(&self, label: &str) -> Self {
        let name = {
            let prefix = self.name.clone();
            if prefix.is_empty() {
                label.to_string()
            } else {
                format!("{}_{}", prefix, label)
            }
        };
        assert!(
            !name.starts_with(METRICS_PREFIX),
            "using runtime label is not allowed"
        );
        Self {
            name,
            spawned: false,
            executor: self.executor.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),
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
        let duration_until_deadline = match deadline.duration_since(now) {
            Ok(duration) => duration,
            Err(_) => Duration::from_secs(0), // Deadline is in the past
        };
        let target_instant = tokio::time::Instant::now() + duration_until_deadline;
        tokio::time::sleep_until(target_instant)
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
