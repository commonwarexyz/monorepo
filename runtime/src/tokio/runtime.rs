use crate::{utils::Signaler, Clock, Error, Handle, Signal, Storage, METRICS_PREFIX};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Metric, Registry},
};

use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{
    future::Future,
    io::{self},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    time::timeout,
};
use tracing::warn;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Work {
    label: String,
}

#[derive(Debug)]
pub struct Metrics {
    tasks_spawned: Family<Work, Counter>,
    tasks_running: Family<Work, Gauge>,
    blocking_tasks_spawned: Family<Work, Counter>,
    blocking_tasks_running: Family<Work, Gauge>,

    // As nice as it would be to track each of these by socket address,
    // it quickly becomes an OOM attack vector.
    inbound_connections: Counter,
    outbound_connections: Counter,
    inbound_bandwidth: Counter,
    outbound_bandwidth: Counter,

    pub(crate) open_blobs: Gauge,
    pub(crate) storage_reads: Counter,
    pub(crate) storage_read_bytes: Counter,
    pub(crate) storage_writes: Counter,
    pub(crate) storage_write_bytes: Counter,
}

impl Metrics {
    pub fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
            blocking_tasks_spawned: Family::default(),
            blocking_tasks_running: Family::default(),
            inbound_connections: Counter::default(),
            outbound_connections: Counter::default(),
            inbound_bandwidth: Counter::default(),
            outbound_bandwidth: Counter::default(),
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bytes: Counter::default(),
            storage_writes: Counter::default(),
            storage_write_bytes: Counter::default(),
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
        registry.register(
            "blocking_tasks_spawned",
            "Total number of blocking tasks spawned",
            metrics.blocking_tasks_spawned.clone(),
        );
        registry.register(
            "blocking_tasks_running",
            "Number of blocking tasks currently running",
            metrics.blocking_tasks_running.clone(),
        );
        registry.register(
            "inbound_connections",
            "Number of connections created by dialing us",
            metrics.inbound_connections.clone(),
        );
        registry.register(
            "outbound_connections",
            "Number of connections created by dialing others",
            metrics.outbound_connections.clone(),
        );
        registry.register(
            "inbound_bandwidth",
            "Bandwidth used by receiving data from others",
            metrics.inbound_bandwidth.clone(),
        );
        registry.register(
            "outbound_bandwidth",
            "Bandwidth used by sending data to others",
            metrics.outbound_bandwidth.clone(),
        );
        registry.register(
            "open_blobs",
            "Number of open blobs",
            metrics.open_blobs.clone(),
        );
        registry.register(
            "storage_reads",
            "Total number of disk reads",
            metrics.storage_reads.clone(),
        );
        registry.register(
            "storage_read_bytes",
            "Total amount of data read from disk",
            metrics.storage_read_bytes.clone(),
        );
        registry.register(
            "storage_writes",
            "Total number of disk writes",
            metrics.storage_writes.clone(),
        );
        registry.register(
            "storage_write_bytes",
            "Total amount of data written to disk",
            metrics.storage_write_bytes.clone(),
        );
        metrics
    }
}

/// Configuration for the `tokio` runtime.
#[derive(Clone)]
pub struct Config<S: Storage> {
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

    pub storage_config: S::Config,
}

impl<S: Storage> Default for Config<S> {
    fn default() -> Self {
        // Return the configuration
        Self {
            worker_threads: 2,
            max_blocking_threads: 512,
            catch_panics: true,
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            tcp_nodelay: None,
            storage_config: S::Config::default(),
        }
    }
}

/// Runtime based on [Tokio](https://tokio.rs).
pub struct Executor<S: Storage> {
    pub(crate) cfg: Config<S>,
    registry: Mutex<Registry>,
    pub(crate) metrics: Arc<Metrics>,
    runtime: Runtime,
    signaler: Mutex<Signaler>,
    signal: Signal,
}

impl<S: Storage> Executor<S> {
    /// Initialize a new `tokio` runtime with the given number of threads.
    pub fn init(cfg: Config<S>) -> (Runner<S>, Context<S>) {
        // Create a new registry
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(METRICS_PREFIX);

        // Initialize runtime
        let metrics = Arc::new(Metrics::init(runtime_registry));
        let runtime = Builder::new_multi_thread()
            .worker_threads(cfg.worker_threads)
            .max_blocking_threads(cfg.max_blocking_threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        let (signaler, signal) = Signaler::new();

        let storage_config = cfg.storage_config.clone();

        let executor = Arc::new(Self {
            cfg,
            registry: Mutex::new(registry),
            metrics: metrics.clone(),
            runtime,
            signaler: Mutex::new(signaler),
            signal,
        });
        (
            Runner {
                executor: executor.clone(),
            },
            Context {
                label: String::new(),
                spawned: false,
                executor,
                storage: S::new(storage_config),
            },
        )
    }

    /// Initialize a new `tokio` runtime with default configuration.
    // We'd love to implement the trait but we can't because of the return type.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> (Runner<S>, Context<S>) {
        Self::init(Config::default())
    }
}

/// Implementation of [`crate::Runner`] for the `tokio` runtime.
pub struct Runner<S: Storage> {
    executor: Arc<Executor<S>>,
}

impl<S: Storage> crate::Runner for Runner<S> {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.executor.runtime.block_on(f)
    }
}

/// Implementation of [`crate::Spawner`], [`crate::Clock`],
/// [`crate::Network`], and [`crate::Storage`] for the `tokio`
/// runtime.
/// TODO danlaine: refactor code to reduce number of places we
/// need to paramterize on S:Storage. e.g. Stream.
pub struct Context<S: Storage> {
    label: String,
    spawned: bool,
    pub(crate) executor: Arc<Executor<S>>,
    storage: S,
}

impl<S: Storage> Storage for Context<S> {
    type Blob = S::Blob;
    type Config = S::Config;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, Error> {
        self.storage.open(partition, name).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.storage.scan(partition).await
    }

    fn new(_config: Self::Config) -> Self {
        todo!()
    }
}

impl<S: Storage> Clone for Context<S> {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            spawned: false,
            executor: self.executor.clone(),
            storage: self.storage.clone(),
        }
    }
}

impl<S: Storage> crate::Spawner for Context<S> {
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

impl<S: Storage> crate::Metrics for Context<S> {
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

impl<S: Storage> Clock for Context<S> {
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

impl<S: Storage> GClock for Context<S> {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl<S: Storage> ReasonablyRealtime for Context<S> {}

impl<S: Storage> crate::Network<Listener<S>, Sink<S>, Stream<S>> for Context<S> {
    async fn bind(&self, socket: SocketAddr) -> Result<Listener<S>, Error> {
        TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)
            .map(|listener| Listener {
                context: self.clone(),
                listener,
            })
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink<S>, Stream<S>), Error> {
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
pub struct Listener<S: Storage> {
    context: Context<S>,
    listener: TcpListener,
}

impl<S: Storage> crate::Listener<Sink<S>, Stream<S>> for Listener<S> {
    async fn accept(&mut self) -> Result<(SocketAddr, Sink<S>, Stream<S>), Error> {
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

impl<S: Storage> axum::serve::Listener for Listener<S> {
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
pub struct Sink<S: Storage> {
    context: Context<S>,
    sink: OwnedWriteHalf,
}

impl<S: Storage> crate::Sink for Sink<S> {
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
pub struct Stream<S: Storage> {
    context: Context<S>,
    stream: OwnedReadHalf,
}

impl<S: Storage> crate::Stream for Stream<S> {
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

impl<S: Storage> RngCore for Context<S> {
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

impl<S: Storage> CryptoRng for Context<S> {}
