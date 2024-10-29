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
//! use commonware_runtime::{Spawner, Runner, tokio::{Config, Executor}};
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

use crate::{Clock, Error, Handle};
use bytes::Bytes;
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
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
    net::{TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    task_local,
    time::timeout,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
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

    open_files: Gauge,
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
            open_files: Gauge::default(),
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
                "open_files",
                "Number of open files",
                metrics.open_files.clone(),
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

    /// Maximum size used for all messages sent over the wire.
    ///
    /// We use this to prevent malicious peers from sending us large messages
    /// that would consume all of our memory.
    ///
    /// If this value is not synchronized across all connected peers,
    /// chunks will be parsed incorrectly (any non-terminal chunk must be of ~this
    /// size).
    ///
    /// Users of this runtime can chunk messages of this size to send over the wire.
    pub max_message_size: usize,

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry::default())),
            threads: 2,
            catch_panics: true,
            max_message_size: 1024 * 1024, // 1 MB
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            tcp_nodelay: None,
            storage_directory: env::temp_dir().join("commonware_tokio_runtime"),
        }
    }
}

/// Runtime based on [Tokio](https://tokio.rs).
pub struct Executor {
    cfg: Config,
    metrics: Arc<Metrics>,
    runtime: Runtime,
}

impl Executor {
    /// Initialize a new `tokio` runtime with the given number of threads.
    pub fn init(cfg: Config) -> (Runner, Context) {
        let metrics = Arc::new(Metrics::init(cfg.registry.clone()));
        let runtime = Builder::new_multi_thread()
            .worker_threads(cfg.threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        let executor = Arc::new(Self {
            cfg,
            metrics,
            runtime,
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
        self.executor.runtime.block_on(f)
    }
}

/// Implementation of [`crate::Spawner`] and [`crate::Clock`]
/// for the `tokio` runtime.
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
        self.executor.runtime.spawn(f);
        handle
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

pub fn codec(max_frame_len: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(max_frame_len)
        .new_codec()
}

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

        // Create a new framed stream
        let context = self.clone();
        let framed = Framed::new(stream, codec(self.executor.cfg.max_message_size));
        let (sink, stream) = framed.split();
        Ok((
            Sink {
                context: context.clone(),
                sink,
            },
            Stream { context, stream },
        ))
    }
}

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
        let framed = Framed::new(stream, codec(self.context.executor.cfg.max_message_size));
        let (sink, stream) = framed.split();
        let context = self.context.clone();
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

pub struct Sink {
    context: Context,
    sink: SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: Bytes) -> Result<(), Error> {
        let len = msg.len();
        timeout(self.context.executor.cfg.write_timeout, self.sink.send(msg))
            .await
            .map_err(|_| Error::WriteFailed)?
            .map_err(|_| Error::WriteFailed)?;
        self.context
            .executor
            .metrics
            .outbound_bandwidth
            .inc_by(len as u64);
        Ok(())
    }
}

pub struct Stream {
    context: Context,
    stream: SplitStream<Framed<TcpStream, LengthDelimitedCodec>>,
}

impl crate::Stream for Stream {
    async fn recv(&mut self) -> Result<Bytes, Error> {
        let result = timeout(self.context.executor.cfg.read_timeout, self.stream.next())
            .await
            .map_err(|_| Error::ReadFailed)?
            .ok_or(Error::Closed)?
            .map_err(|_| Error::ReadFailed)?;
        self.context
            .executor
            .metrics
            .inbound_bandwidth
            .inc_by(result.len() as u64);
        Ok(result.freeze())
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

pub struct Blob {
    file: fs::File,
    metrics: Arc<Metrics>,
}

impl crate::Storage<Blob> for Context {
    async fn open(&mut self, partition: &str, name: &str) -> Result<Blob, Error> {
        // Construct the full path
        let path = self
            .executor
            .cfg
            .storage_directory
            .join(partition)
            .join(name);

        // Create the partition directory if it does not exist
        fs::create_dir_all(path.parent().unwrap())
            .await
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file in read-write mode, create if it does not exist
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .await
            .map_err(|_| Error::BlobOpenFailed(partition.into(), name.into()))?;

        self.executor.metrics.open_files.inc();
        Ok(Blob {
            file,
            metrics: self.executor.metrics.clone(),
        })
    }

    async fn remove(&mut self, partition: &str, name: Option<&str>) -> Result<(), Error> {
        let path = self.executor.cfg.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(name);
            fs::remove_file(blob_path)
                .await
                .map_err(|_| Error::BlobMissing(partition.into(), name.into()))?;
        } else {
            fs::remove_dir_all(path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<String>, Error> {
        let path = self.executor.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                blobs.push(name.into());
            }
        }
        Ok(blobs)
    }
}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<usize, Error> {
        let metadata = self.file.metadata().await.map_err(|_| Error::ReadFailed)?;
        let len = metadata.len() as usize;
        Ok(len)
    }

    async fn read_at(&mut self, buf: &mut [u8], offset: usize) -> Result<usize, Error> {
        self.file
            .seek(SeekFrom::Start(offset as u64))
            .await
            .map_err(|_| Error::ReadFailed)?;

        let n = self.file.read(buf).await.map_err(|_| Error::ReadFailed)?;

        self.metrics.storage_reads.inc();
        self.metrics.storage_read_bytes.inc_by(n as u64);
        Ok(n)
    }

    async fn write_at(&mut self, buf: &[u8], offset: usize) -> Result<(), Error> {
        self.file
            .seek(SeekFrom::Start(offset as u64))
            .await
            .map_err(|_| Error::WriteFailed)?;

        self.file
            .write_all(buf)
            .await
            .map_err(|_| Error::WriteFailed)?;

        self.metrics.storage_writes.inc();
        self.metrics.storage_write_bytes.inc_by(buf.len() as u64);
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.file
            .sync_all()
            .await
            .map_err(|_| Error::BlobSyncFailed)
    }

    async fn close(&mut self) -> Result<(), Error> {
        self.sync().await?;
        self.file
            .shutdown()
            .await
            .map_err(|_| Error::BlobCloseFailed)
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        self.metrics.open_files.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::run_tasks;
    use crate::Runner;
    use std::io::Cursor;

    #[test]
    fn test_runs_tasks() {
        let (executor, runtime) = Executor::default();
        run_tasks(10, executor, runtime);
    }

    #[test]
    fn test_codec_invalid_frame_len() {
        // Initalize runtime
        let (runner, _) = Executor::default();
        runner.start(async move {
            // Create a stream
            let max_frame_len = 10;
            let codec = codec(max_frame_len);
            let mut framed = Framed::new(Cursor::new(Vec::new()), codec);

            // Create a message larger than the max_frame_len
            let message = vec![0; max_frame_len + 1];
            let message = Bytes::from(message);

            // Encode the message
            let result = framed.send(message).await;

            // Ensure that encoding fails due to exceeding max_frame_len
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_codec_valid_frame_len() {
        // Initialize runtime
        let (runner, _) = Executor::default();
        runner.start(async move {
            // Create a stream
            let max_frame_len = 10;
            let codec = codec(max_frame_len);
            let mut framed = Framed::new(Cursor::new(Vec::new()), codec);

            // Create a message larger than the max_frame_len
            let message = vec![0; max_frame_len];
            let message = Bytes::from(message);

            // Encode the message
            let result = framed.send(message).await;

            // Ensure that encoding fails due to exceeding max_frame_len
            assert!(result.is_ok());
        });
    }
}
