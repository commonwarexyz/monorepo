#[cfg(feature = "iouring")]
use crate::storage::iouring::Storage as IoUringStorage;
#[cfg(not(feature = "iouring"))]
use crate::storage::tokio::Storage as TokioStorage;

use crate::storage::metered::Storage as MeteredStorage;
use crate::tokio::metrics::{Metrics, Work};
use crate::{Clock, Error, Handle, Signal, Signaler, METRICS_PREFIX};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::text::encode,
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
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};
use tracing::warn;

use super::listener::Listener;
use super::sink::Sink;
use super::stream::Stream;

/// Configuration for the `tokio` runtime.
#[derive(Clone)]
pub struct Config {
    /// Number of threads to use for handling async tasks.
    ///
    /// Worker threads are always active (waiting for work).
    ///
    /// Tokio sets the default value to the number of logical CPUs.
    pub worker_threads: usize,

    /// Maximum number of threads to use for blocking tasks.
    ///
    /// Unlike worker threads, blocking threads are created as needed and
    /// exit if left idle for too long.
    ///
    /// Tokio sets the default value to 512 to avoid hanging on lower-level
    /// operations that require blocking (like `fs` and writing to `Stdout`).
    pub max_blocking_threads: usize,

    /// Whether or not to catch panics.
    pub catch_panics: bool,

    /// Duration after which to close the connection if no message is read.
    pub read_timeout: Duration,

    /// Duration after which to close the connection if a message cannot be written.
    pub write_timeout: Duration,

    /// Whether or not to disable Nagle's algorithm.
    ///
    /// The algorithm combines a series of small network packets into a single packet
    /// before sending to reduce overhead of sending multiple small packets which might not
    /// be efficient on slow, congested networks. However, to do so the algorithm introduces
    /// a slight delay as it waits to accumulate more data. Latency-sensitive networks should
    /// consider disabling it to send the packets as soon as possible to reduce latency.
    ///
    /// Note: Make sure that your compile target has and allows this configuration otherwise
    /// panics or unexpected behaviours are possible.
    pub tcp_nodelay: Option<bool>,

    /// Base directory for all storage operations.
    pub storage_directory: PathBuf,

    /// Maximum buffer size for operations on blobs.
    ///
    /// Tokio sets the default value to 2MB.
    pub maximum_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        // Generate a random directory name to avoid conflicts (used in tests, so we shouldn't need to reload)
        let rng = OsRng.next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_tokio_runtime_{}", rng));

        // Return the configuration
        Self {
            worker_threads: 2,
            max_blocking_threads: 512,
            catch_panics: true,
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            tcp_nodelay: None,
            storage_directory,
            maximum_buffer_size: 2 * 1024 * 1024, // 2 MB
        }
    }
}

/// Runtime based on [Tokio](https://tokio.rs).
pub struct Executor {
    pub(super) cfg: Config,
    pub(super) registry: Mutex<Registry>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) runtime: Runtime,
    pub(super) signaler: Mutex<Signaler>,
    pub(super) signal: Signal,
}

#[cfg(feature = "iouring")]
type Storage = MeteredStorage<IoUringStorage>;

#[cfg(not(feature = "iouring"))]
type Storage = MeteredStorage<TokioStorage>;

/// Implementation of [`crate::Spawner`], [`crate::Clock`],
/// [`crate::Network`], and [`crate::Storage`] for the `tokio`
/// runtime.
pub struct Context {
    pub(super) label: String,
    pub(super) spawned: bool,
    pub(super) executor: Arc<Executor>,
    pub(super) storage: Storage,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            spawned: false,
            executor: self.executor.clone(),
            storage: self.storage.clone(),
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
        let work = Work {
            label: self.label.clone(),
        };
        self.executor
            .metrics
            .tasks_spawned
            .get_or_create(&work)
            .inc();
        let gauge = self
            .executor
            .metrics
            .tasks_running
            .get_or_create(&work)
            .clone();

        // Set up the task
        let catch_panics = self.executor.cfg.catch_panics;
        let executor = self.executor.clone();
        let future = f(self);
        let (f, handle) = Handle::init(future, gauge, catch_panics);

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
        let work = Work {
            label: self.label.clone(),
        };
        self.executor
            .metrics
            .tasks_spawned
            .get_or_create(&work)
            .inc();
        let gauge = self
            .executor
            .metrics
            .tasks_running
            .get_or_create(&work)
            .clone();

        // Set up the task
        let executor = self.executor.clone();
        move |f: F| {
            let (f, handle) = Handle::init(f, gauge, executor.cfg.catch_panics);

            // Spawn the task
            executor.runtime.spawn(f);
            handle
        }
    }

    fn spawn_blocking<F, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let work = Work {
            label: self.label.clone(),
        };
        self.executor
            .metrics
            .blocking_tasks_spawned
            .get_or_create(&work)
            .inc();
        let gauge = self
            .executor
            .metrics
            .blocking_tasks_running
            .get_or_create(&work)
            .clone();

        // Initialize the blocking task using the new function
        let (f, handle) = Handle::init_blocking(f, gauge, self.executor.cfg.catch_panics);

        // Spawn the blocking task
        self.executor.runtime.spawn_blocking(f);
        handle
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
        let label = {
            let prefix = self.label.clone();
            if prefix.is_empty() {
                label.to_string()
            } else {
                format!("{}_{}", prefix, label)
            }
        };
        assert!(
            !label.starts_with(METRICS_PREFIX),
            "using runtime label is not allowed"
        );
        Self {
            label,
            spawned: false,
            executor: self.executor.clone(),
            storage: self.storage.clone(),
        }
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn register<N: Into<String>, H: Into<String>>(&self, name: N, help: H, metric: impl Metric) {
        let name = name.into();
        let prefixed_name = {
            let prefix = &self.label;
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

impl crate::Network<Listener, Sink, Stream> for Context {
    async fn bind(&self, socket: SocketAddr) -> Result<Listener, Error> {
        TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)
            .map(|listener| Listener {
                context: self.clone(),
                listener,
            })
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
        // Create a new TCP stream
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| Error::ConnectionFailed)?;
        self.executor.metrics.outbound_connections.inc();

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.executor.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let context = self.clone();
        let (stream, sink) = stream.into_split();
        Ok((
            Sink {
                context: context.clone(),
                sink,
            },
            Stream { context, stream },
        ))
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
