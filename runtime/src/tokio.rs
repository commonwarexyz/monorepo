//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness and storage backed by the local filesystem.
//!
//! # Panics
//!
//! By default, the runtime will catch any panic and log the error. It is
//! possible to override this behavior in the configuration.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio::Executor};
//!
//! let (executor, runtime) = Executor::default();
//! executor.start(async move {
//!     println!("Parent started");
//!     let result = runtime.spawn("child", async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! ```

use crate::{utils::Signaler, Clock, Error, Handle, Signal};
use commonware_utils::{from_hex, hex};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{
    env,
    future::Future,
    io::SeekFrom,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    sync::Mutex as AsyncMutex,
    task_local,
    time::timeout,
};
use tracing::warn;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Work {
    label: String,
}

#[derive(Debug)]
struct Metrics {
    tasks_spawned: Family<Work, Counter>,
    tasks_running: Family<Work, Gauge>,

    // As nice as it would be to track each of these by socket address,
    // it quickly becomes an OOM attack vector.
    inbound_connections: Counter,
    outbound_connections: Counter,
    inbound_bandwidth: Counter,
    outbound_bandwidth: Counter,

    open_blobs: Gauge,
    storage_reads: Counter,
    storage_read_bytes: Counter,
    storage_writes: Counter,
    storage_write_bytes: Counter,
}

impl Metrics {
    pub fn init(registry: Arc<Mutex<Registry>>) -> Self {
        let metrics = Self {
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
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
        {
            let mut registry = registry.lock().unwrap();
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
        }
        metrics
    }
}

/// Configuration for the `tokio` runtime.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Number of threads to use for the runtime.
    pub threads: usize,

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
    /// `tokio` defaults this value to 2MB.
    pub maximum_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        // Generate a random directory name to avoid conflicts (used in tests, so we shouldn't need to reload)
        let rng = OsRng.next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_tokio_runtime_{}", rng));

        // Return the configuration
        Self {
            registry: Arc::new(Mutex::new(Registry::default())),
            threads: 2,
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
    metrics: Arc<Metrics>,
    runtime: Arc<Mutex<Option<Runtime>>>,
    fs: AsyncMutex<()>,
    signaler: Mutex<Signaler>,
    signal: Signal,
}

impl Executor {
    /// Initialize a new `tokio` runtime with the given number of threads.
    pub fn init(cfg: Config) -> (Runner, Context) {
        let metrics = Arc::new(Metrics::init(cfg.registry.clone()));
        let (signaler, signal) = Signaler::new();
        let executor = Arc::new(Self {
            cfg,
            metrics,
            runtime: Arc::new(Mutex::new(None)),
            fs: AsyncMutex::new(()),
            signaler: Mutex::new(signaler),
            signal,
        });
        (
            Runner {
                executor: executor.clone(),
            },
            Context { executor },
        )
    }

    /// Initialize a new `tokio` runtime with default configuration.
    // We'd love to implement the trait but we can't because of the return type.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> (Runner, Context) {
        Self::init(Config::default())
    }
}

/// Implementation of [`crate::Runner`] for the `tokio` runtime.
pub struct Runner {
    executor: Arc<Executor>,
}

impl crate::Runner for Runner {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Set runtime
        let runtime = Builder::new_multi_thread()
            .worker_threads(self.executor.cfg.threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        self.executor.runtime.lock().unwrap().replace(runtime);

        // TODO: kill outstanding tasks when complete
        // TODOL: don't allow tasks to be spawned until after we start root task?
        let result = self.executor.runtime.block_on(f);

        // Shutdown runtime
        let runtime = self.executor.runtime.lock().unwrap().take().unwrap();
        runtime.shutdown_background();
        result
    }
}

/// Implementation of [`crate::Spawner`], [`crate::Clock`],
/// [`crate::Network`], and [`crate::Storage`] for the `tokio`
/// runtime.
#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
}

task_local! {
    static PREFIX: String;
}

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, label: &str, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Setup Work
        let label = PREFIX
            .try_with(|prefix| format!("{}_{}", prefix, label))
            .unwrap_or_else(|_| label.to_string());
        let f = PREFIX.scope(label.clone(), f);
        let work = Work { label };
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
        let (f, handle) = Handle::init(f, gauge, self.executor.cfg.catch_panics);

        // Get runtime (or panic if not set)
        let runtime = self
            .executor
            .runtime
            .lock()
            .unwrap()
            .expect("runtime not set");

        // Spawn work
        runtime.spawn(f);
        handle
    }

    fn stop(&self, value: i32) {
        self.executor.signaler.lock().unwrap().signal(value);
    }

    fn stopped(&self) -> Signal {
        self.executor.signal.clone()
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

/// Implementation of [`crate::Blob`] for the `tokio` runtime.
pub struct Blob {
    metrics: Arc<Metrics>,

    partition: String,
    name: Vec<u8>,

    // Files must be seeked prior to any read or write operation and are thus
    // not safe to concurrently interact with. If we switched to mmaping files
    // we could remove this lock.
    //
    // We also track the virtual file size because metadata isn't updated until
    // the file is synced (not to mention it is a lot less fs calls).
    file: Arc<AsyncMutex<(fs::File, u64)>>,
}

impl Blob {
    fn new(
        metrics: Arc<Metrics>,
        partition: String,
        name: &[u8],
        file: fs::File,
        len: u64,
    ) -> Self {
        metrics.open_blobs.inc();
        Self {
            metrics,
            partition,
            name: name.into(),
            file: Arc::new(AsyncMutex::new((file, len))),
        }
    }
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        // We implement `Clone` manually to ensure the `open_blobs` gauge is updated.
        self.metrics.open_blobs.inc();
        Self {
            metrics: self.metrics.clone(),
            partition: self.partition.clone(),
            name: self.name.clone(),
            file: self.file.clone(),
        }
    }
}

impl crate::Storage<Blob> for Context {
    async fn open(&self, partition: &str, name: &[u8]) -> Result<Blob, Error> {
        // Acquire the filesystem lock
        let _guard = self.executor.fs.lock().await;

        // Construct the full path
        let path = self
            .executor
            .cfg
            .storage_directory
            .join(partition)
            .join(hex(name));
        let parent = match path.parent() {
            Some(parent) => parent,
            None => return Err(Error::PartitionCreationFailed(partition.into())),
        };

        // Create the partition directory if it does not exist
        fs::create_dir_all(parent)
            .await
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file in read-write mode, create if it does not exist
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .await
            .map_err(|_| Error::BlobOpenFailed(partition.into(), hex(name)))?;

        // Set the maximum buffer size
        file.set_max_buf_size(self.executor.cfg.maximum_buffer_size);

        // Get the file length
        let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();

        // Construct the blob
        Ok(Blob::new(
            self.executor.metrics.clone(),
            partition.into(),
            name,
            file,
            len,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        // Acquire the filesystem lock
        let _guard = self.executor.fs.lock().await;

        // Remove all related files
        let path = self.executor.cfg.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(hex(name));
            fs::remove_file(blob_path)
                .await
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;
        } else {
            fs::remove_dir_all(path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        // Acquire the filesystem lock
        let _guard = self.executor.fs.lock().await;

        // Scan the partition directory
        let path = self.executor.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }
            if let Some(name) = entry.file_name().to_str() {
                let name = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                blobs.push(name);
            }
        }
        Ok(blobs)
    }
}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<u64, Error> {
        let (_, len) = *self.file.lock().await;
        Ok(len)
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        // Ensure the read is within bounds
        let mut file = self.file.lock().await;
        if offset + buf.len() as u64 > file.1 {
            return Err(Error::BlobInsufficientLength);
        }

        // Perform the read
        file.0
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::ReadFailed)?;
        file.0
            .read_exact(buf)
            .await
            .map_err(|_| Error::ReadFailed)?;
        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        // Perform the write
        let mut file = self.file.lock().await;
        file.0
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| Error::WriteFailed)?;
        file.0
            .write_all(buf)
            .await
            .map_err(|_| Error::WriteFailed)?;

        // Update the virtual file size
        let max_len = offset + buf.len() as u64;
        if max_len > file.1 {
            file.1 = max_len;
        }
        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Perform the truncate
        let mut file = self.file.lock().await;
        file.0
            .set_len(len)
            .await
            .map_err(|_| Error::BlobTruncateFailed(self.partition.clone(), hex(&self.name)))?;

        // Update the virtual file size
        file.1 = len;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let file = self.file.lock().await;
        file.0
            .sync_all()
            .await
            .map_err(|_| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name)))
    }

    async fn close(self) -> Result<(), Error> {
        let mut file = self.file.lock().await;
        file.0
            .sync_all()
            .await
            .map_err(|_| Error::BlobSyncFailed(self.partition.clone(), hex(&self.name)))?;
        file.0
            .shutdown()
            .await
            .map_err(|_| Error::BlobCloseFailed(self.partition.clone(), hex(&self.name)))
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        self.metrics.open_blobs.dec();
    }
}
