#[cfg(feature = "iouring")]
use crate::storage::iouring::{Config as IoUringConfig, Storage as IoUringStorage};
#[cfg(not(feature = "iouring"))]
use crate::storage::tokio::{Config as TokioStorageConfig, Storage as TokioStorage};

use crate::storage::metered::Storage as MeteredStorage;
use crate::tokio::metrics::{Metrics, Work};
use crate::tokio::spawner::Config as SpawnerConfig;
use crate::{utils::Signaler, Clock, Error, Handle, Signal, METRICS_PREFIX};
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
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, TcpStream},
    runtime::{Builder, Handle as TokioHandle},
    time::timeout,
};
use tracing::warn;

use super::spawner::Spawner;

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
    cfg: Config,
    registry: Mutex<Registry>,
    metrics: Arc<Metrics>,
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

        let spawner = Spawner::new(
            String::new(),
            SpawnerConfig {
                catch_panics: self.cfg.catch_panics,
            },
            runtime_registry,
            Arc::new(runtime.handle().clone()),
        );

        #[cfg(feature = "iouring")]
        let storage = MeteredStorage::new(
            IoUringStorage::start(
                &IoUringConfig {
                    storage_directory: self.cfg.storage_directory.clone(),
                    ring_config: Default::default(),
                },
                spawner.clone(),
            ),
            runtime_registry,
        );

        #[cfg(not(feature = "iouring"))]
        let storage = MeteredStorage::new(
            TokioStorage::new(TokioStorageConfig::new(
                self.cfg.storage_directory.clone(),
                self.cfg.maximum_buffer_size,
            )),
            runtime_registry,
        );

        let executor = Arc::new(Executor {
            cfg: self.cfg.clone(),
            registry: Mutex::new(registry),
            metrics,
        });

        runtime.block_on(f(Context {
            storage,
            spawner,
            executor: executor.clone(),
        }))
    }
}

#[cfg(feature = "iouring")]
type Storage = MeteredStorage<IoUringStorage>;

#[cfg(not(feature = "iouring"))]
type Storage = MeteredStorage<TokioStorage>;

/// Implementation of [`crate::Spawner`], [`crate::Clock`],
/// [`crate::Network`], and [`crate::Storage`] for the `tokio`
/// runtime.
#[derive(Clone)]
pub struct Context {
    spawner: Spawner,
    executor: Arc<Executor>,
    storage: Storage,
}

impl crate::Spawner for Context {
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Create a closure that adapts f to what Spawner::spawn expects
        let context = self.clone();
        self.spawner.spawn(|_| {
            // Call the original function with ourself as context
            f(context)
        })
    }

    fn spawn_ref<F, T>(&mut self) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.spawner.spawn_ref()
    }

    fn spawn_blocking<F, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.spawner.spawn_blocking(f)
    }

    fn stop(&self, value: i32) {
        self.spawner.stop(value);
    }

    fn stopped(&self) -> Signal {
        self.spawner.stopped()
    }
}

impl crate::Metrics for Context {
    fn with_label(&self, label: &str) -> Self {
        let label = {
            let prefix = self.spawner.label.clone();
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
            spawner: self.spawner.with_label(label),
            executor: self.executor.clone(),
            storage: self.storage.clone(),
        }
    }

    fn label(&self) -> String {
        self.spawner.label.clone()
    }

    fn register<N: Into<String>, H: Into<String>>(&self, name: N, help: H, metric: impl Metric) {
        let name = name.into();
        let prefixed_name = {
            let prefix = &self.spawner.label;
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

/// Implementation of [`crate::Listener`] for the `tokio` runtime.
pub struct Listener {
    context: Context,
    listener: TcpListener,
}

impl crate::Listener<Sink, Stream> for Listener {
    async fn accept(&mut self) -> Result<(SocketAddr, Sink, Stream), Error> {
        // Accept a new TCP stream
        let (stream, addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;
        self.context.executor.metrics.inbound_connections.inc();

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.context.executor.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let context = self.context.clone();
        let (stream, sink) = stream.into_split();
        Ok((
            addr,
            Sink {
                context: context.clone(),
                sink,
            },
            Stream { context, stream },
        ))
    }
}

impl axum::serve::Listener for Listener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, addr) = self.listener.accept().await.unwrap();
        (stream, addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Implementation of [`crate::Sink`] for the `tokio` runtime.
pub struct Sink {
    context: Context,
    sink: OwnedWriteHalf,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let len = msg.len();
        timeout(
            self.context.executor.cfg.write_timeout,
            self.sink.write_all(msg),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::SendFailed)?;
        self.context
            .executor
            .metrics
            .outbound_bandwidth
            .inc_by(len as u64);
        Ok(())
    }
}

/// Implementation of [`crate::Stream`] for the `tokio` runtime.
pub struct Stream {
    context: Context,
    stream: OwnedReadHalf,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        // Wait for the stream to be readable
        timeout(
            self.context.executor.cfg.read_timeout,
            self.stream.read_exact(buf),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::RecvFailed)?;

        // Record metrics
        self.context
            .executor
            .metrics
            .inbound_bandwidth
            .inc_by(buf.len() as u64);

        Ok(())
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

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.storage.open(partition, name).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.storage.scan(partition).await
    }
}
