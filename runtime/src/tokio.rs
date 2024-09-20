//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness.
//!
//! # Example
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio::Executor};
//!
//! let (runner, context) = Executor::init(2);
//! runner.start(async move {
//!     println!("Parent started");
//!     let result = context.spawn(async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! ```

use crate::{timeout, Error, Handle};
use bytes::Bytes;
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    future::Future,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    sync::{mpsc, Mutex},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::warn;

pub struct Config {
    /// Number of threads to use for the runtime.
    pub threads: usize,

    /// Address to bind the TCP listener to.
    ///
    /// If not set, no address will be bound.
    pub listen: Option<SocketAddr>,

    /// Maximum size used for all messages sent over the wire.
    ///
    /// We use this to prevent malicious peers from sending us large messages
    /// that would consume all of our memory.
    ///
    /// If a message is larger than this size, it will be chunked into parts
    /// of this size or smaller.
    ///
    /// If this value is not synchronized across all connected peers,
    /// chunks will be parsed incorrectly (any non-terminal chunk must be of ~this
    /// size).
    pub max_frame_length: usize,

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
            listen: None,
            max_frame_length: 1024 * 1024, // 1 MB
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
    connections: mpsc::Sender<(SocketAddr, TcpStream)>,
}

impl Executor {
    /// Initialize a new `tokio` runtime with the given number of threads.
    pub fn init(cfg: Config) -> (Runner, Context) {
        let runtime = Builder::new_multi_thread()
            .worker_threads(cfg.threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        let (sender, receiver) = mpsc::channel(1);
        let executor = Arc::new(Self {
            cfg,
            runtime,
            connections: sender,
        });
        (
            Runner {
                executor: executor.clone(),
            },
            Context {
                executor,
                connections: Arc::new(Mutex::new(receiver)),
            },
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
        // If a port is set, bind the TCP listener
        if let Some(addr) = self.executor.cfg.listen {
            self.executor.runtime.spawn({
                let executor = self.executor.clone();
                async move {
                    let listener = match TcpListener::bind(addr).await {
                        Ok(listener) => listener,
                        Err(err) => {
                            warn!(?err, "failed to bind listener");
                            return;
                        }
                    };
                    for (stream, addr) in listener.accept().await {
                        if executor.connections.send((addr, stream)).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }

        // Start the root task
        self.executor.runtime.block_on(f)
    }
}

/// Implementation of [`crate::Spawner`] and [`crate::Clock`]
/// for the `tokio` runtime.
#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
    connections: Arc<Mutex<mpsc::Receiver<(SocketAddr, TcpStream)>>>,
}

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (f, handle) = Handle::init(f);
        self.executor.runtime.spawn(f);
        handle
    }
}

impl crate::Clock for Context {
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

pub fn codec(max_frame_len: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .max_frame_length(max_frame_len)
        .new_codec()
}

impl crate::Network<Sink, Stream> for Context {
    fn accept(&self) -> impl Future<Output = Result<(SocketAddr, Sink, Stream), Error>> + Send {
        let connections = self.connections.clone();
        let context = self.clone();
        async move {
            // Wait for a new connection
            let (addr, stream) = {
                let mut connections = connections.lock().await;
                connections.recv().await.ok_or(Error::Closed)?
            };

            // Set TCP_NODELAY if configured
            if let Some(tcp_nodelay) = self.executor.cfg.tcp_nodelay {
                if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                    warn!(?err, "failed to set TCP_NODELAY");
                }
            }

            // Create a new framed stream
            let framed = Framed::new(stream, codec(self.executor.cfg.max_frame_length));
            let (sink, stream) = framed.split();
            Ok((
                addr,
                Sink {
                    context: context.clone(),
                    sink,
                },
                Stream {
                    context: context.clone(),
                    stream,
                },
            ))
        }
    }

    fn dial(
        &self,
        socket: SocketAddr,
    ) -> impl Future<Output = Result<(Sink, Stream), Error>> + Send {
        let context = self.clone();
        async move {
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
            let framed = Framed::new(stream, codec(self.executor.cfg.max_frame_length));
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
}

pub struct Sink {
    context: Context,
    sink: SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: Bytes) -> Result<(), Error> {
        self.sink.send(msg).await.map_err(|_| Error::WriteFailed)
    }
}

pub struct Stream {
    context: Context,
    stream: SplitStream<Framed<TcpStream, LengthDelimitedCodec>>,
}

impl crate::Stream for Stream {
    async fn recv(&mut self) -> Result<Bytes, Error> {
        let stream = &mut self.stream;
        let frame = stream
            .next()
            .await
            .ok_or(Error::Closed)?
            .map_err(|_| Error::ReadFailed)?;
        Ok(frame.freeze())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::run_tasks;

    #[test]
    fn test_runs_tasks() {
        let (runner, context) = Executor::init(1);
        run_tasks(10, runner, context);
    }
}
