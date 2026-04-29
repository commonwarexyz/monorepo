use crate::{BufferPool, Error, IoBufs};
use std::{convert::identity, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tracing::warn;

/// Implementation of [crate::Sink] for the [tokio] runtime.
pub struct Sink {
    write_timeout: Duration,
    sink: OwnedWriteHalf,
    state: SinkState,
}

/// Lifecycle state for the write-half of a connection.
enum SinkState {
    /// Sends may be attempted.
    Open,
    /// A send is currently in progress.
    Sending,
    /// The write-half has been shut down.
    Closed,
}

impl Sink {
    async fn close(&mut self) {
        if matches!(self.state, SinkState::Closed) {
            return;
        }
        let _ = self.sink.shutdown().await;
        self.state = SinkState::Closed;
    }

    async fn send_single(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.sink
            .write_all(buf)
            .await
            .map_err(|_| Error::SendFailed)
    }

    async fn send_vectored(&mut self, bufs: &mut IoBufs) -> Result<(), Error> {
        self.sink
            .write_all_buf(bufs)
            .await
            .map_err(|_| Error::SendFailed)
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        match self.state {
            SinkState::Open => {}
            SinkState::Sending => {
                self.close().await;
                return Err(Error::Closed);
            }
            SinkState::Closed => return Err(Error::Closed),
        }

        // Mark the sink as sending before awaiting so cancellation can be
        // detected by the next send.
        self.state = SinkState::Sending;

        let write_timeout = self.write_timeout;
        let bufs = bufs.into();
        let send = async {
            match bufs.try_into_single() {
                Ok(buf) => self.send_single(buf.as_ref()).await,
                Err(mut bufs) => self.send_vectored(&mut bufs).await,
            }
        };

        // Time out if we take too long to write
        let result = timeout(write_timeout, send)
            .await
            .map_or(Err(Error::Timeout), identity);

        // A failed send leaves the write-half unusable.
        if result.is_err() {
            self.close().await;
            return result;
        }

        // Mark the sink reusable on success.
        self.state = SinkState::Open;
        Ok(())
    }
}

/// Implementation of [crate::Stream] for the [tokio] runtime.
///
/// Uses a [`BufReader`] to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    read_timeout: Duration,
    stream: BufReader<OwnedReadHalf>,
    pool: BufferPool,
    poisoned: bool,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if self.poisoned {
            return Err(Error::Closed);
        }

        // Pre-poison so that cancellation leaves the stream permanently closed
        // rather than silently corrupted.
        self.poisoned = true;

        let recv = async {
            // SAFETY: `len` bytes are written by read_exact below.
            let mut buf = unsafe { self.pool.alloc_len(len) };
            self.stream
                .read_exact(buf.as_mut())
                .await
                .map_err(|_| Error::RecvFailed)?;
            Ok(IoBufs::from(buf.freeze()))
        };

        // Time out if we take too long to read
        let result = timeout(self.read_timeout, recv)
            .await
            .map_or(Err(Error::Timeout), identity);

        // Unpoison on success.
        if result.is_ok() {
            self.poisoned = false;
        }

        result
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        let buffered = self.stream.buffer();
        let len = std::cmp::min(buffered.len(), max_len);
        &buffered[..len]
    }
}

/// Implementation of [crate::Listener] using the [tokio] runtime.
pub struct Listener {
    cfg: Config,
    listener: TcpListener,
    pool: BufferPool,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        // Accept a new TCP stream
        let (stream, addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Set SO_LINGER to zero if configured
        if self.cfg.zero_linger {
            if let Err(err) = stream.set_zero_linger() {
                warn!(?err, "failed to set SO_LINGER");
            }
        }

        // Return the sink and stream
        let (stream, sink) = stream.into_split();
        Ok((
            addr,
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink,
                state: SinkState::Open,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: BufReader::with_capacity(self.cfg.read_buffer_size, stream),
                pool: self.pool.clone(),
                poisoned: false,
            },
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

/// Configuration for the tokio [Network] implementation of the [crate::Network] trait.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether or not to disable Nagle's algorithm.
    ///
    /// The algorithm combines a series of small network packets into a single packet
    /// before sending to reduce overhead of sending multiple small packets which might not
    /// be efficient on slow, congested networks. However, to do so the algorithm introduces
    /// a slight delay as it waits to accumulate more data. Latency-sensitive networks should
    /// consider disabling it to send the packets as soon as possible to reduce latency.
    tcp_nodelay: Option<bool>,
    /// Whether to set `SO_LINGER` to zero on the socket.
    ///
    /// When enabled, causes an immediate RST on close, avoiding
    /// `TIME_WAIT` state. This is useful in adversarial environments to
    /// reclaim socket resources immediately when closing connections to
    /// misbehaving peers.
    zero_linger: bool,
    /// Read timeout for connections, after which the stream half returns
    /// [`Error::Timeout`] and is no longer reusable.
    ///
    /// This bounds the entire `Stream::recv` call, not each underlying socket
    /// read attempt.
    read_timeout: Duration,
    /// Write timeout for connections, after which the sink half returns
    /// [`Error::Timeout`] and is no longer reusable.
    ///
    /// This bounds the entire `Sink::send` call, not each underlying socket
    /// write attempt. If callers batch more bytes into one send, slow links may
    /// require a larger timeout.
    write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    read_buffer_size: usize,
}

#[cfg_attr(feature = "iouring-network", allow(dead_code))]
impl Config {
    // Setters
    /// See [Config]
    pub const fn with_tcp_nodelay(mut self, tcp_nodelay: Option<bool>) -> Self {
        self.tcp_nodelay = tcp_nodelay;
        self
    }
    /// See [Config]
    pub const fn with_zero_linger(mut self, zero_linger: bool) -> Self {
        self.zero_linger = zero_linger;
        self
    }
    /// See [Config]
    pub const fn with_read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }
    /// See [Config]
    pub const fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }
    /// See [Config]
    pub const fn with_read_buffer_size(mut self, read_buffer_size: usize) -> Self {
        self.read_buffer_size = read_buffer_size;
        self
    }

    // Getters
    /// See [Config]
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.tcp_nodelay
    }
    /// See [Config]
    pub const fn zero_linger(&self) -> bool {
        self.zero_linger
    }
    /// See [Config]
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
    /// See [Config]
    pub const fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
    /// See [Config]
    pub const fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: Some(true),
            zero_linger: true,
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024, // 64 KB
        }
    }
}

#[derive(Clone)]
/// [crate::Network] implementation that uses the [tokio] runtime.
pub struct Network {
    cfg: Config,
    pool: BufferPool,
}

impl Network {
    /// Creates a new Network with the given configuration and buffer pool.
    pub const fn new(cfg: Config, pool: BufferPool) -> Self {
        Self { cfg, pool }
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)
            .map(|listener| Listener {
                cfg: self.cfg.clone(),
                listener,
                pool: self.pool.clone(),
            })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        // Create a new TCP stream
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Set SO_LINGER to zero if configured
        if self.cfg.zero_linger {
            if let Err(err) = stream.set_zero_linger() {
                warn!(?err, "failed to set SO_LINGER");
            }
        }

        // Return the sink and stream
        let (stream, sink) = stream.into_split();
        Ok((
            Sink {
                write_timeout: self.cfg.write_timeout,
                sink,
                state: SinkState::Open,
            },
            Stream {
                read_timeout: self.cfg.read_timeout,
                stream: BufReader::with_capacity(self.cfg.read_buffer_size, stream),
                pool: self.pool.clone(),
                poisoned: false,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        network::{tests, tokio as TokioNetwork},
        telemetry::metrics::Registry,
        BufferPool, BufferPoolConfig, Listener as _, Network as _, Sink as _, Stream as _,
    };
    use commonware_macros::test_group;
    use std::time::{Duration, Instant};

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_network(), &mut registry)
    }

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            TokioNetwork::Network::new(
                TokioNetwork::Config::default()
                    .with_read_timeout(Duration::from_millis(100))
                    .with_write_timeout(Duration::from_millis(100)),
                test_pool(),
            )
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            TokioNetwork::Network::new(
                TokioNetwork::Config::default()
                    .with_read_timeout(Duration::from_secs(15))
                    .with_write_timeout(Duration::from_secs(15)),
                test_pool(),
            )
        })
        .await;
    }

    #[tokio::test]
    async fn test_small_send_read_quickly() {
        // Use a long read timeout to ensure we're not just waiting for timeout
        let read_timeout = Duration::from_secs(30);
        let network = TokioNetwork::Network::new(
            TokioNetwork::Config::default()
                .with_read_timeout(read_timeout)
                .with_write_timeout(Duration::from_secs(5)),
            test_pool(),
        );

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read a small message (much smaller than the 64KB buffer)
            let start = Instant::now();
            let received = stream.recv(10).await.unwrap();
            let elapsed = start.elapsed();

            (received, elapsed)
        });

        // Connect and send a small message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        sink.send(msg.clone()).await.unwrap();

        // Wait for the reader to complete
        let (received, elapsed) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(received.coalesce(), msg.as_slice());

        // Verify it completed quickly (well under the read timeout)
        // Should complete in milliseconds, not seconds
        assert!(elapsed < read_timeout);
    }

    #[tokio::test]
    async fn test_read_timeout_with_partial_data() {
        // Use a short read timeout to make the test fast
        let read_timeout = Duration::from_millis(100);
        let network = TokioNetwork::Network::new(
            TokioNetwork::Config::default()
                .with_read_timeout(read_timeout)
                .with_write_timeout(Duration::from_secs(5)),
            test_pool(),
        );

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Try to read 100 bytes, but only 5 will be sent
            let start = Instant::now();
            let result = stream.recv(100).await;
            let elapsed = start.elapsed();

            (result, elapsed)
        });

        // Connect and send only partial data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();

        // Wait for the reader to complete
        let (result, elapsed) = reader.await.unwrap();
        assert!(matches!(result, Err(crate::Error::Timeout)));

        // Verify the timeout occurred around the expected time
        assert!(elapsed >= read_timeout);
        // Allow some margin for timing variance
        assert!(elapsed < read_timeout * 2);
    }

    #[tokio::test]
    async fn test_unbuffered_mode() {
        // Set read_buffer_size to 0 to disable buffering
        let network = TokioNetwork::Network::new(
            TokioNetwork::Config::default()
                .with_read_buffer_size(0)
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5)),
            test_pool(),
        );

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // In unbuffered mode, peek should always return empty
            assert!(stream.peek(100).is_empty());

            // Read messages without buffering
            let buf1 = stream.recv(5).await.unwrap();

            // Even after recv, peek should be empty in unbuffered mode
            assert!(stream.peek(100).is_empty());

            let buf2 = stream.recv(5).await.unwrap();
            assert!(stream.peek(100).is_empty());

            (buf1, buf2)
        });

        // Connect and send two messages
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
        sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();

        // Wait for the reader to complete
        let (buf1, buf2) = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(buf1.coalesce(), &[1u8, 2, 3, 4, 5]);
        assert_eq!(buf2.coalesce(), &[6u8, 7, 8, 9, 10]);
    }

    #[tokio::test]
    async fn test_peek_with_buffered_data() {
        // Use default buffer size to enable buffering
        let network = TokioNetwork::Network::new(
            TokioNetwork::Config::default()
                .with_read_timeout(Duration::from_secs(5))
                .with_write_timeout(Duration::from_secs(5)),
            test_pool(),
        );

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Initially peek should be empty (no data received yet)
            assert!(stream.peek(100).is_empty());

            // Receive partial data - this should buffer more than requested
            let first = stream.recv(5).await.unwrap();
            assert_eq!(first.coalesce(), b"hello");

            // Peek should show remaining buffered data
            let peeked = stream.peek(100);
            assert!(!peeked.is_empty());
            assert_eq!(peeked, b" world");

            // Peek again should return the same (non-consuming)
            assert_eq!(stream.peek(100), b" world");

            // Peek with max_len should truncate
            assert_eq!(stream.peek(3), b" wo");

            // Receive the rest
            let rest = stream.recv(6).await.unwrap();
            assert_eq!(rest.coalesce(), b" world");

            // Peek should be empty after consuming all buffered data
            assert!(stream.peek(100).is_empty());
        });

        // Connect and send data
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(b"hello world").await.unwrap();

        reader.await.unwrap();
    }
}
