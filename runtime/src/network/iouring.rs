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
//! It requires Linux kernel 6.1 or newer. See [crate::iouring] for details.

use crate::{
    iouring::{self, should_retry, OpBuffer, OpFd, OpIovecs},
    Buf, BufferPool, Error, IoBuf, IoBufMut, IoBufs,
};
use commonware_utils::channel::oneshot;
use io_uring::{opcode, types::Fd};
use prometheus_client::registry::Registry;
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;
/// Cap iovec batch size: larger iovecs reduce syscall count but increase
/// per-write kernel setup overhead.
const IOVEC_BATCH_SIZE: usize = 32;

#[derive(Clone, Debug)]
pub struct Config {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    pub tcp_nodelay: Option<bool>,
    /// Whether or not to set the `SO_LINGER` socket option.
    ///
    /// When `None`, the system default is used. When
    /// `Some(duration)`, `SO_LINGER` is enabled with the given timeout.
    /// `Some(Duration::ZERO)` causes an immediate RST on close, avoiding
    /// `TIME_WAIT` state. This is useful in adversarial environments to
    /// reclaim socket resources immediately when closing connections to
    /// misbehaving peers.
    pub so_linger: Option<Duration>,
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
            so_linger: None,
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
    /// Whether or not to set the `SO_LINGER` socket option.
    so_linger: Option<Duration>,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: iouring::Submitter,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: iouring::Submitter,
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
    ) -> Result<Self, Error> {
        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;

        // Create an io_uring instance to handle send operations.
        let sender_registry = registry.sub_registry_with_prefix("iouring_sender");
        let (send_submitter, send_loop) =
            iouring::IoUringLoop::new(cfg.iouring_config.clone(), sender_registry);
        std::thread::spawn(move || send_loop.run());

        // Create an io_uring instance to handle receive operations.
        let receiver_registry = registry.sub_registry_with_prefix("iouring_receiver");
        let (recv_submitter, recv_loop) =
            iouring::IoUringLoop::new(cfg.iouring_config, receiver_registry);
        std::thread::spawn(move || recv_loop.run());

        Ok(Self {
            tcp_nodelay: cfg.tcp_nodelay,
            so_linger: cfg.so_linger,
            send_submitter,
            recv_submitter,
            read_buffer_size: cfg.read_buffer_size,
            pool,
        })
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        let listener = TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)?;
        Ok(Listener {
            tcp_nodelay: self.tcp_nodelay,
            so_linger: self.so_linger,
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
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), Error> {
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Set SO_LINGER if configured
        if let Some(so_linger) = self.so_linger {
            if let Err(err) = stream.set_linger(Some(so_linger)) {
                warn!(?err, "failed to set SO_LINGER");
            }
        }

        // Convert the stream to a std::net::TcpStream
        let stream = stream.into_std().map_err(|_| Error::ConnectionFailed)?;

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| Error::ConnectionFailed)?;

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
    /// Whether or not to set the `SO_LINGER` socket option.
    so_linger: Option<Duration>,
    inner: TcpListener,
    /// Used to submit send operations to the send io_uring event loop.
    send_submitter: iouring::Submitter,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_submitter: iouring::Submitter,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        let (stream, remote_addr) = self
            .inner
            .accept()
            .await
            .map_err(|_| Error::ConnectionFailed)?;

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Set SO_LINGER if configured
        if let Some(so_linger) = self.so_linger {
            if let Err(err) = stream.set_linger(Some(so_linger)) {
                warn!(?err, "failed to set SO_LINGER");
            }
        }

        // Convert the stream to a std::net::TcpStream
        let stream = stream.into_std().map_err(|_| Error::ConnectionFailed)?;

        // Explicitly set non-blocking mode to true
        stream
            .set_nonblocking(true)
            .map_err(|_| Error::ConnectionFailed)?;

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
    submitter: iouring::Submitter,
}

impl Sink {
    const fn new(fd: Arc<OwnedFd>, submitter: iouring::Submitter) -> Self {
        Self { fd, submitter }
    }

    fn as_raw_fd(&self) -> Fd {
        Fd(self.fd.as_raw_fd())
    }

    async fn send_single(&self, mut buf: IoBuf) -> Result<(), Error> {
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
            let op = opcode::Send::new(self.as_raw_fd(), ptr, remaining_len as u32).build();

            // Submit the operation to the io_uring event loop
            let (sender, receiver) = oneshot::channel();
            self.submitter
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(OpBuffer::Write(buf)),
                    fd: Some(OpFd::Fd(self.fd.clone())),
                    iovecs: None,
                })
                .await
                .map_err(|_| Error::SendFailed)?;

            // Wait for the operation to complete and get the buffer back
            let (return_value, return_buf) = receiver.await.map_err(|_| Error::SendFailed)?;
            buf = match return_buf {
                Some(OpBuffer::Write(b)) => b,
                _ => unreachable!("io_uring loop returns the same OpBuffer that was submitted"),
            };
            if should_retry(return_value) {
                continue;
            }

            // Non-positive result indicates an error or EOF.
            let op_bytes_sent: usize = return_value.try_into().map_err(|_| Error::SendFailed)?;
            if op_bytes_sent == 0 {
                return Err(Error::SendFailed);
            }

            // Mark bytes as sent.
            bytes_sent += op_bytes_sent;
        }

        Ok(())
    }

    async fn send_vectored(&self, mut bufs: IoBufs) -> Result<(), Error> {
        while bufs.has_remaining() {
            let (iovecs, iovecs_len) = {
                // Figure out how much is left to send and where to send from.
                //
                // Use one pre-initialized `libc::iovec` array as scratch space and
                // view it as `IoSlice` to fill via `chunks_vectored`, since
                // `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                let max_iovecs = bufs.chunk_count().min(IOVEC_BATCH_SIZE);
                assert!(
                    max_iovecs > 0,
                    "chunk_count should be > 0 if bufs.has_remaining() is true"
                );
                let mut iovecs: Box<[libc::iovec]> = std::iter::repeat_n(
                    libc::iovec {
                        iov_base: std::ptr::NonNull::<u8>::dangling().as_ptr().cast(),
                        iov_len: 0,
                    },
                    max_iovecs,
                )
                .collect();

                // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                // `iovecs` is initialized with valid empty entries, so `io_slices`
                // starts in a valid state for `chunks_vectored` to overwrite.
                let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
                        iovecs.len(),
                    )
                };
                let io_slices_len = bufs.chunks_vectored(io_slices);
                assert!(
                    io_slices_len > 0,
                    "chunks_vectored should produce at least one slice when bufs has remaining"
                );
                (OpIovecs::new(iovecs), io_slices_len)
            };

            // Create an operation to do the writev.
            let op =
                opcode::Writev::new(self.as_raw_fd(), iovecs.as_ptr(), iovecs_len as _).build();

            // Submit the operation.
            let (sender, receiver) = oneshot::channel();
            self.submitter
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(OpBuffer::WriteVectored(bufs)),
                    fd: Some(OpFd::Fd(self.fd.clone())),
                    iovecs: Some(iovecs),
                })
                .await
                .map_err(|_| Error::SendFailed)?;

            // Wait for the result.
            let (return_value, return_bufs) = receiver.await.map_err(|_| Error::SendFailed)?;
            bufs = match return_bufs {
                Some(OpBuffer::WriteVectored(b)) => b,
                _ => unreachable!("io_uring loop returns the same OpBuffer that was submitted"),
            };
            if should_retry(return_value) {
                continue;
            }

            // A negative or zero return value indicates an error.
            let op_bytes_sent: usize = return_value.try_into().map_err(|_| Error::SendFailed)?;
            if op_bytes_sent == 0 {
                return Err(Error::SendFailed);
            }

            bufs.advance(op_bytes_sent);
        }

        Ok(())
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        match bufs.into().try_into_single() {
            Ok(buf) => self.send_single(buf).await,
            Err(bufs) => self.send_vectored(bufs).await,
        }
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
///
/// Uses an internal buffer to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    fd: Arc<OwnedFd>,
    /// Used to submit recv operations to the io_uring event loop.
    submitter: iouring::Submitter,
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
        submitter: iouring::Submitter,
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
    ) -> (IoBufMut, Result<usize, Error>) {
        loop {
            // SAFETY: offset + len <= buffer.capacity() as guaranteed by callers.
            // `buffer` is an `IoBufMut` guaranteeing the memory won't move.
            let ptr = unsafe { buffer.as_mut_ptr().add(offset) };
            let op = opcode::Recv::new(self.as_raw_fd(), ptr, len as u32).build();

            let (sender, receiver) = oneshot::channel();
            if self
                .submitter
                .send(iouring::Op {
                    work: op,
                    sender,
                    buffer: Some(OpBuffer::Read(buffer)),
                    fd: Some(OpFd::Fd(self.fd.clone())),
                    iovecs: None,
                })
                .await
                .is_err()
            {
                // Channel closed - io_uring thread died, buffer is lost
                return (IoBufMut::default(), Err(Error::RecvFailed));
            }

            let Ok((return_value, return_buf)) = receiver.await else {
                // Channel closed - io_uring thread died, buffer is lost
                return (IoBufMut::default(), Err(Error::RecvFailed));
            };
            buffer = match return_buf {
                Some(OpBuffer::Read(b)) => b,
                _ => unreachable!("io_uring loop returns the same OpBuffer that was submitted"),
            };

            if should_retry(return_value) {
                continue;
            }

            if return_value <= 0 {
                let err = if return_value == -libc::ETIMEDOUT {
                    Error::Timeout
                } else {
                    Error::RecvFailed
                };
                return (buffer, Err(err));
            }

            return (buffer, Ok(return_value as usize));
        }
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self) -> Result<usize, Error> {
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
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        // SAFETY: `len` bytes are written by the recv loop below.
        let mut owned_buf = unsafe { self.pool.alloc_len(len) };
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

        Ok(IoBufs::from(owned_buf.freeze()))
    }

    fn peek(&self, max_len: usize) -> &[u8] {
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
        BufferPool, BufferPoolConfig, Error, Listener as _, Network as _, Sink as _, Stream as _,
    };
    use commonware_macros::{select, test_group};
    use prometheus_client::registry::Registry;
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    fn test_pool() -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_network(), &mut Registry::default())
    }

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            Network::start(Config::default(), &mut Registry::default(), test_pool())
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
        let network = Network::start(Config::default(), &mut Registry::default(), test_pool())
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
        assert!(matches!(result, Err(Error::Timeout)));

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
    async fn test_op_fd_keeps_descriptor_alive() {
        // When a recv future is cancelled (e.g. via select!) after the Op has
        // been sent to the io_uring channel, the Stream can be dropped while
        // the Op is still queued. The Op's `fd` field keeps the socket alive
        // so the OS cannot reuse the FD number.
        let op_timeout = Duration::from_millis(200);
        let network = Network::start(
            Config {
                iouring_config: iouring::Config {
                    op_timeout: Some(op_timeout),
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

        let (client_sink, mut client_stream) = network.dial(addr).await.unwrap();
        let (_addr, _server_sink, _server_stream) = listener.accept().await.unwrap();

        // Sink + stream + our clone.
        let fd = client_stream.fd.clone();
        assert_eq!(Arc::strong_count(&fd), 3);

        // Cancel a recv mid-flight (blocks because no data arrives).
        // Polling the future submits the Op (with an fd clone) to the
        // io_uring channel, the timeout then cancels the future.
        select! {
            _ = client_stream.recv(1) => unreachable!("no data was sent"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }

        // The queued Op holds an additional clone.
        assert_eq!(Arc::strong_count(&fd), 4);

        // Drop all handles. The queued Op still retains the fd.
        drop(client_sink);
        drop(client_stream);
        assert_eq!(Arc::strong_count(&fd), 2); // our clone + Op

        // After op_timeout, the Op completes and releases its fd clone.
        tokio::time::sleep(op_timeout).await;
        assert_eq!(Arc::strong_count(&fd), 1);
    }

    #[tokio::test]
    async fn test_peek_with_buffered_data() {
        // Use default buffer size to enable buffering
        let network = Network::start(Config::default(), &mut Registry::default(), test_pool())
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
