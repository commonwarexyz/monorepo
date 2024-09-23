//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness.
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
//! let cfg = Config::default();
//! let (executor, runtime) = Executor::init(cfg);
//! executor.start(async move {
//!     println!("Parent started");
//!     let result = runtime.spawn(async move {
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
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{
    future::Future,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    time::timeout,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::warn;

#[derive(Copy, Clone)]
pub struct Config {
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: 2,
            catch_panics: true,
            max_message_size: 1024 * 1024, // 1 MB
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            tcp_nodelay: None,
        }
    }
}

/// Runtime based on [Tokio](https://tokio.rs).
pub struct Executor {
    cfg: Config,
    runtime: Runtime,
}

impl Executor {
    /// Initialize a new `tokio` runtime with the given number of threads.
    pub fn init(cfg: Config) -> (Runner, Context) {
        let runtime = Builder::new_multi_thread()
            .worker_threads(cfg.threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        let executor = Arc::new(Self { cfg, runtime });
        (
            Runner {
                executor: executor.clone(),
            },
            Context { executor },
        )
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

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (f, handle) = Handle::init(f, self.executor.cfg.catch_panics);
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
        timeout(self.context.executor.cfg.write_timeout, self.sink.send(msg))
            .await
            .map_err(|_| Error::WriteFailed)?
            .map_err(|_| Error::WriteFailed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::run_tasks;
    use crate::Runner;
    use std::io::Cursor;

    #[test]
    fn test_runs_tasks() {
        let cfg = Config::default();
        let (executor, runtime) = Executor::init(cfg);
        run_tasks(10, executor, runtime);
    }

    #[test]
    fn test_codec_invalid_frame_len() {
        // Initalize runtime
        let cfg = Config::default();
        let (runner, _) = Executor::init(cfg);
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
        let cfg = Config::default();
        let (runner, _) = Executor::init(cfg);
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
