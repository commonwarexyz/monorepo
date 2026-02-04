//! This module provides an io_uring-based implementation of the [crate::Network] trait,
//! offering fast, high-throughput network operations on Linux systems.
//!
//! ## Architecture
//!
//! Network operations are sent via a [commonware_utils::channel::mpsc] channel to a dedicated io_uring event
//! loop running in a separate thread. Operation results are returned via a [commonware_utils::channel::oneshot]
//! channel. This implementation uses two separate io_uring instances: one for send operations and
//! one for receive operations.
//!
//! ## Memory Safety
//!
//! We pass to the kernel, via io_uring, a pointer to the buffer being read from/written into.
//! Therefore, we ensure that the memory location is valid for the duration of the operation.
//! That is, it doesn't move or go out of scope until the operation completes.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring-network` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.

use crate::{
    iouring::{self, should_retry, OpBuffer},
    BufferPool, IoBufMut, IoBufsMut,
};
use commonware_utils::channel::{mpsc, oneshot};
use futures::executor::block_on;
use io_uring::types::Fd;
use prometheus_client::registry::Registry;
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    pub tcp_nodelay: Option<bool>,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    pub read_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: None,
            iouring_config: iouring::Config::default(),
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
        }
    }
}

#[derive(Clone)]
/// [crate::Network] implementation that uses io_uring to do async I/O.
pub struct Network {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<iouring::Op>,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<iouring::Op>,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
}

impl Network {
    /// Returns a new [Network] instance.
    /// This function creates two io_uring instances, one for sending and one for receiving.
    /// This function spawns two threads to run the io_uring event loops.
    /// The threads run until the work submission channel is closed or an error occurs.
    /// The caller should take special care to ensure the io_uring `size` given in `cfg` is
    /// large enough, given the number of connections that will be maintained.
    /// Each ongoing send/recv to/from each connection will consume a slot in the io_uring.
    /// The io_uring `size` should be a multiple of the number of expected connections.
    pub(crate) fn start(
        mut cfg: Config,
        registry: &mut Registry,
        pool: BufferPool,
    ) -> Result<Self, crate::Error> {
        // Create an io_uring instance to handle send operations.
        let (send_submitter, rx) = mpsc::channel(cfg.iouring_config.size as usize);

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;

        std::thread::spawn({
            let cfg = cfg.clone();
            let registry = registry.sub_registry_with_prefix("iouring_sender");
            let metrics = Arc::new(iouring::Metrics::new(registry));
            move || block_on(iouring::run(cfg.iouring_config, metrics, rx))
        });

        // Create an io_uring instance to handle receive operations.
        let (recv_submitter, rx) = mpsc::channel(cfg.iouring_config.size as usize);
        let registry = registry.sub_registry_with_prefix("iouring_receiver");
        let metrics = Arc::new(iouring::Metrics::new(registry));
        std::thread::spawn(|| block_on(iouring::run(cfg.iouring_config, metrics, rx)));

        Ok(Self {
            tcp_nodelay: cfg.tcp_nodelay,
            send_submitter,
            recv_submitter,
            read_buffer_size: cfg.read_buffer_size,
            pool,
        })
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        let listener = TcpListener::bind(socket)
            .await
            .map_err(|_| crate::Error::BindFailed)?;
        Ok(Listener {
            tcp_nodelay: self.tcp_nodelay,
            inner: listener,
            send_submitter: self.send_submitter.clone(),
            recv_submitter: self.recv_submitter.clone(),
            read_buffer_size: self.read_buffer_size,
            pool: self.pool.clone(),
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| crate::Error::ConnectionFailed)?
            .into_std()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));
        Ok((
            Sink::new(fd.clone(), self.send_submitter.clone()),
            Stream::new(
                fd,
                self.recv_submitter.clone(),
                self.read_buffer_size,
                self.pool.clone(),
            ),
        ))
    }
}

/// Implementation of [crate::Listener] for an io-uring [Network].
pub struct Listener {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    inner: TcpListener,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: mpsc::Sender<iouring::Op>,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: mpsc::Sender<iouring::Op>,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        let (stream, remote_addr) = self
            .inner
            .accept()
            .await
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let stream = stream
            .into_std()
            .map_err(|_| crate::Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| crate::Error::ConnectionFailed)?;

        let fd = Arc::new(OwnedFd::from(stream));

        Ok((
            remote_addr,
            Sink::new(fd.clone(), self.send_submitter.clone()),
            Stream::new(
                fd,
                self.recv_submitter.clone(),
                self.read_buffer_size,
                self.pool.clone(),
            ),
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
    }
}

/// Implementation of [crate::Sink] for an io-uring [Network].
pub struct Sink {
    fd: Arc<OwnedFd>,
    /// Used to submit send operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
}

impl Sink {
    const fn new(fd: Arc<OwnedFd>, submitter: mpsc::Sender<iouring::Op>) -> Self {
        Self { fd, submitter }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, buf: impl Into<IoBufs> + Send) -> Result<(), crate::Error> {
        // Convert to contiguous IoBuf for io_uring send
        // (zero-copy if single buffer, copies if multiple)
        // TODO(#2705): Use writev to avoid this copy.
        let mut buf = buf.into().coalesce();
        let mut bytes_sent = 0;
        let buf_len = buf.len();

        while bytes_sent < buf_len {
            // Figure out how much is left to send and where to send from.
            //
            // SAFETY: `buf` is an `IoBuf` guaranteeing the memory won't move.
            // `bytes_sent` is always < `buf_len` due to the loop condition, so
            // `add(bytes_sent)` stays within bounds and `buf_len - bytes_sent`
            // correctly represents the remaining valid bytes.
            let ptr = unsafe { buf.as_ptr().add(bytes_sent) };
            let remaining_len = buf_len - bytes_sent;

            // Create the io_uring send operation
            let op =
                io_uring::opcode::Send::new(self.as_raw_fd(), ptr, remaining_len as u32).build();

            // Submit the operation to the io_uring event loop
            let (tx, rx) = oneshot::channel();
            self.submitter
                .send(iouring::Op {
                    work: op,
                    sender: tx,
                    buffer: Some(OpBuffer::Write(buf)),
                })
                .await
                .map_err(|_| crate::Error::SendFailed)?;

            // Wait for the operation to complete and get the buffer back
            let (result, returned_buf) = rx.await.map_err(|_| crate::Error::SendFailed)?;
            buf = match returned_buf.unwrap() {
                OpBuffer::Write(b) => b,
                _ => unreachable!(),
            };
            if should_retry(result) {
                continue;
            }

            // Non-positive result indicates an error or EOF.
            if result <= 0 {
                return Err(crate::Error::SendFailed);
            }

            // Mark bytes as sent.
            bytes_sent += result as usize;
        }
        Ok(())
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
///
/// Uses an internal buffer to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    fd: Arc<OwnedFd>,
    /// Used to submit recv operations to the io_uring event loop.
    submitter: mpsc::Sender<iouring::Op>,
    /// Internal read buffer.
    buffer: IoBufMut,
    /// Current read position in the buffer.
    buffer_pos: usize,
    /// Number of valid bytes in the buffer.
    buffer_len: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
}

impl Stream {
    fn new(
        fd: Arc<OwnedFd>,
        submitter: mpsc::Sender<iouring::Op>,
        buffer_capacity: usize,
        pool: BufferPool,
    ) -> Self {
        Self {
            fd,
            submitter,
            buffer: IoBufMut::with_capacity(buffer_capacity),
            buffer_pos: 0,
            buffer_len: 0,
            pool,
        }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }

    /// Submits a recv operation to io_uring.
    ///
    /// # Arguments
    /// * `buffer` - Buffer for receiving data (kernel writes into this)
    /// * `offset` - Offset into buffer to write received data
    /// * `len` - Maximum bytes to receive
    ///
    /// # Returns
    /// The buffer and either bytes received or an error.
    async fn submit_recv(
        &mut self,
        mut buffer: IoBufMut,
        offset: usize,
        len: usize,
    ) -> (IoBufMut, Result<usize, crate::Error>) {
        loop {
            // SAFETY: offset + len <= buffer.capacity() as guaranteed by callers.
            // `buffer` is an `IoBufMut` guaranteeing the memory won't move.
            let ptr = unsafe { buffer.as_mut_ptr().add(offset) };
            let op = io_uring::opcode::Recv::new(self.as_raw_fd(), ptr, len as u32).build();

            let (tx, rx) = oneshot::channel();
            if self
                .submitter
                .send(iouring::Op {
                    work: op,
                    sender: tx,
                    buffer: Some(OpBuffer::Read(buffer)),
                })
                .await
                .is_err()
            {
                // Channel closed - io_uring thread died, buffer is lost
                return (IoBufMut::default(), Err(crate::Error::RecvFailed));
            }

            let Ok((result, returned_buf)) = rx.await else {
                // Channel closed - io_uring thread died, buffer is lost
                return (IoBufMut::default(), Err(crate::Error::RecvFailed));
            };
            buffer = match returned_buf.unwrap() {
                OpBuffer::Read(b) => b,
                _ => unreachable!(),
            };

            if should_retry(result) {
                continue;
            }

            if result <= 0 {
                let err = if result == -libc::ETIMEDOUT {
                    crate::Error::Timeout
                } else {
                    crate::Error::RecvFailed
                };
                return (buffer, Err(err));
            }

            return (buffer, Ok(result as usize));
        }
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self) -> Result<usize, crate::Error> {
        self.buffer_pos = 0;
        self.buffer_len = 0;

        let buffer = std::mem::take(&mut self.buffer);
        let len = buffer.capacity();

        // If the buffer is lost due to a channel error, we don't restore it.
        // Channel errors mean the io_uring thread died, so the stream is unusable anyway.
        let (buffer, result) = self.submit_recv(buffer, 0, len).await;
        self.buffer = buffer;
        self.buffer_len = result?;
        // SAFETY: The kernel has written exactly `buffer_len` bytes into the buffer.
        unsafe { self.buffer.set_len(self.buffer_len) };
        Ok(self.buffer_len)
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, len: u64) -> Result<IoBufsMut, crate::Error> {
        let len = len as usize;
        let mut owned_buf = self.pool.alloc(len);
        // SAFETY: We will write exactly `len` bytes before returning
        // (loop continues until bytes_received == len). The buffer contents
        // are uninitialized but we only write to it, never read.
        unsafe { owned_buf.set_len(len) };
        let mut bytes_received = 0;

        while bytes_received < len {
            // First drain any buffered data
            let buffered = self.buffer_len - self.buffer_pos;
            if buffered > 0 {
                let to_copy = std::cmp::min(buffered, len - bytes_received);
                owned_buf.as_mut()[bytes_received..bytes_received + to_copy].copy_from_slice(
                    &self.buffer.as_ref()[self.buffer_pos..self.buffer_pos + to_copy],
                );
                self.buffer_pos += to_copy;
                bytes_received += to_copy;
                continue;
            }

            let remaining = len - bytes_received;

            // Skip internal buffer if disabled, or if the read is large enough
            // to fill the buffer and immediately drain it
            let buffer_capacity = self.buffer.capacity();
            if buffer_capacity == 0 || remaining >= buffer_capacity {
                let (returned_buf, result) =
                    self.submit_recv(owned_buf, bytes_received, remaining).await;
                owned_buf = returned_buf;
                bytes_received += result?;
            } else {
                // Fill internal buffer, then loop will copy
                self.fill_buffer().await?;
            }
        }

        Ok(IoBufsMut::from(owned_buf))
    }

    fn peek(&self, max_len: u64) -> &[u8] {
        let max_len = max_len as usize;
        let buffered = self.buffer_len - self.buffer_pos;
        let len = std::cmp::min(buffered, max_len);
        &self.buffer.as_ref()[self.buffer_pos..self.buffer_pos + len]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        iouring,
        network::{
            iouring::{Config, Network},
            tests,
        },
        BufferPool, BufferPoolConfig, Listener as _, Network as _, Sink as _, Stream as _,
    };
    use commonware_macros::test_group;
    use prometheus_client::registry::Registry;
    use std::time::{Duration, Instant};

    fn test_pool() -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_network(), &mut Registry::default())
    }

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        force_poll: Duration::from_millis(100),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default(),
                test_pool(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        size: 256,
                        force_poll: Duration::from_millis(100),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default(),
                test_pool(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[tokio::test]
    async fn test_small_send_read_quickly() {
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task to accept and read
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

            // Read a small message (much smaller than the 64KB buffer)
            stream.recv(10).await.unwrap()
        });

        // Connect and send a small message
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        sink.send(msg.clone()).await.unwrap();

        // Wait for the reader to complete
        let received = reader.await.unwrap();

        // Verify we got the right data
        assert_eq!(received.coalesce(), msg.as_slice());
    }

    #[tokio::test]
    async fn test_read_timeout_with_partial_data() {
        // Use a short timeout to make the test fast
        let op_timeout = Duration::from_millis(100);
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    op_timeout: Some(op_timeout),
                    force_poll: Duration::from_millis(10),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

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
        assert!(elapsed >= op_timeout);
        // Allow some margin for timing variance
        assert!(elapsed < op_timeout * 3);
    }

    #[tokio::test]
    async fn test_unbuffered_mode() {
        // Set read_buffer_size to 0 to disable buffering
        let network = Network::start(
            Config {
                read_buffer_size: 0,
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

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
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    force_poll: Duration::from_millis(100),
                    ..Default::default()
                },
                ..Default::default()
            },
            &mut Registry::default(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

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
