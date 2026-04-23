//! This module provides an io_uring-based implementation of the [crate::Network] trait,
//! offering fast, high-throughput network operations on Linux systems.
//!
//! ## Architecture
//!
//! Network operations are submitted through an io_uring [Handle][crate::iouring::Handle] to a
//! dedicated event loop running in a separate thread. This implementation uses two separate
//! io_uring instances: one for send operations and one for receive operations.
//!
//! ## Memory Safety
//!
//! Buffers and file descriptors are owned by the active request state machine inside the io_uring
//! loop, ensuring that the memory location is valid for the duration of the operation.
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
    iouring::{self},
    utils::{self, MetricScope},
    Buf, BufferPool, Error, IoBufMut, IoBufs,
};
use std::{
    net::SocketAddr,
    os::fd::OwnedFd,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

/// Configuration for the io_uring network backend.
#[derive(Clone, Debug)]
pub struct Config {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    pub tcp_nodelay: Option<bool>,
    /// Whether to set `SO_LINGER` to zero on the socket.
    ///
    /// When enabled, causes an immediate RST on close, avoiding
    /// `TIME_WAIT` state. This is useful in adversarial environments to
    /// reclaim socket resources immediately when closing connections to
    /// misbehaving peers.
    pub zero_linger: bool,
    /// Timeout budget applied to each top-level send/recv call.
    ///
    /// This is a network-level policy and is independent from io_uring loop
    /// tuning. At startup, the loop timeout horizon is raised as needed so this
    /// value is never clamped by `iouring_config.max_request_timeout`.
    pub read_write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    pub read_buffer_size: usize,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
    /// Stack size for the dedicated send and receive io_uring threads.
    pub thread_stack_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        let iouring_config = iouring::Config::default();
        Self {
            tcp_nodelay: Some(true),
            zero_linger: true,
            read_write_timeout: iouring_config.max_request_timeout,
            iouring_config,
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
            thread_stack_size: utils::thread::system_thread_stack_size(),
        }
    }
}

/// [crate::Network] implementation that uses io_uring to do async I/O.
#[derive(Clone)]
pub struct Network {
    /// If Some, explicitly sets TCP_NODELAY on the socket.
    /// Otherwise uses system default.
    tcp_nodelay: Option<bool>,
    /// Whether to set `SO_LINGER` to zero on the socket.
    zero_linger: bool,
    /// Used to submit send operations to the send io_uring event loop.
    send_handle: iouring::Handle,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_handle: iouring::Handle,
    /// Timeout budget applied to each send/recv call.
    read_write_timeout: Duration,
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
        registry: &mut MetricScope<'_>,
        pool: BufferPool,
    ) -> Result<Self, Error> {
        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        cfg.iouring_config.single_issuer = true;
        cfg.iouring_config.max_request_timeout = cfg
            .iouring_config
            .max_request_timeout
            .max(cfg.read_write_timeout);

        // Create an io_uring instance to handle send operations.
        let mut sender_registry = registry.sub_registry_with_prefix("iouring_sender");
        let (send_handle, send_loop) =
            iouring::IoUringLoop::new(cfg.iouring_config.clone(), &mut sender_registry);
        utils::thread::spawn(cfg.thread_stack_size, move || send_loop.run());

        // Create an io_uring instance to handle receive operations.
        let mut receiver_registry = registry.sub_registry_with_prefix("iouring_receiver");
        let (recv_handle, recv_loop) =
            iouring::IoUringLoop::new(cfg.iouring_config, &mut receiver_registry);
        utils::thread::spawn(cfg.thread_stack_size, move || recv_loop.run());

        Ok(Self {
            tcp_nodelay: cfg.tcp_nodelay,
            zero_linger: cfg.zero_linger,
            send_handle,
            recv_handle,
            read_write_timeout: cfg.read_write_timeout,
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
            zero_linger: self.zero_linger,
            inner: listener,
            send_handle: self.send_handle.clone(),
            recv_handle: self.recv_handle.clone(),
            read_write_timeout: self.read_write_timeout,
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

        // Set SO_LINGER to zero if configured
        if self.zero_linger {
            if let Err(err) = stream.set_zero_linger() {
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
            Sink::new(
                fd.clone(),
                self.send_handle.clone(),
                self.read_write_timeout,
            ),
            Stream::new(
                fd,
                self.recv_handle.clone(),
                self.read_write_timeout,
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
    /// Whether to set `SO_LINGER` to zero on the socket.
    zero_linger: bool,
    inner: TcpListener,
    /// Used to submit send operations to the send io_uring event loop.
    send_handle: iouring::Handle,
    /// Used to submit recv operations to the recv io_uring event loop.
    recv_handle: iouring::Handle,
    /// Timeout budget applied to each send/recv call.
    read_write_timeout: Duration,
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

        // Set SO_LINGER to zero if configured
        if self.zero_linger {
            if let Err(err) = stream.set_zero_linger() {
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
            Sink::new(
                fd.clone(),
                self.send_handle.clone(),
                self.read_write_timeout,
            ),
            Stream::new(
                fd,
                self.recv_handle.clone(),
                self.read_write_timeout,
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
    handle: iouring::Handle,
    /// Timeout budget for a top-level send call.
    timeout: Duration,
}

impl Sink {
    /// Construct a sink that submits logical send requests through one io_uring loop.
    const fn new(fd: Arc<OwnedFd>, handle: iouring::Handle, timeout: Duration) -> Self {
        Self {
            fd,
            handle,
            timeout,
        }
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }

        self.handle
            .send(self.fd.clone(), bufs, Instant::now() + self.timeout)
            .await
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
///
/// Uses an internal buffer to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    fd: Arc<OwnedFd>,
    /// Used to submit recv operations to the io_uring event loop.
    handle: iouring::Handle,
    /// Timeout budget for a top-level recv call.
    timeout: Duration,
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
    /// Construct a stream with an optional internal read buffer.
    fn new(
        fd: Arc<OwnedFd>,
        handle: iouring::Handle,
        timeout: Duration,
        buffer_capacity: usize,
        pool: BufferPool,
    ) -> Self {
        Self {
            fd,
            handle,
            timeout,
            buffer: IoBufMut::with_capacity(buffer_capacity),
            buffer_pos: 0,
            buffer_len: 0,
            pool,
        }
    }

    /// Submit a recv request to io_uring and wait for completion.
    ///
    /// `offset` is the byte offset into `buffer` where received data should
    /// start. `len` is the number of bytes to read starting at that offset.
    ///
    /// Returns the buffer and either the number of bytes read for this
    /// invocation or an error.
    async fn submit_recv(
        &self,
        buffer: IoBufMut,
        offset: usize,
        len: usize,
        exact: bool,
        deadline: Instant,
    ) -> Result<(IoBufMut, usize), (IoBufMut, Error)> {
        self.handle
            .recv(
                self.fd.clone(),
                buffer,
                offset,
                offset + len,
                exact,
                deadline,
            )
            .await
            .map(|(buf, total)| {
                // Translate the total-bytes-received into bytes-read-in-this-call.
                (buf, total - offset)
            })
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self, deadline: Instant) -> Result<usize, Error> {
        self.buffer_pos = 0;
        self.buffer_len = 0;

        let buffer = std::mem::take(&mut self.buffer);
        let len = buffer.capacity();

        self.buffer_len = match self.submit_recv(buffer, 0, len, false, deadline).await {
            Ok((buffer, read)) => {
                self.buffer = buffer;
                read
            }
            Err((buffer, err)) => {
                self.buffer = buffer;
                return Err(err);
            }
        };
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
        let deadline = Instant::now() + self.timeout;

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
                // Direct recv into the result buffer with exact=true.
                match self
                    .submit_recv(owned_buf, bytes_received, remaining, true, deadline)
                    .await
                {
                    Ok((buf, read)) => {
                        owned_buf = buf;
                        bytes_received += read;
                    }
                    Err((_, err)) => return Err(err),
                }
            } else {
                // Fill internal buffer, then loop will copy
                self.fill_buffer(deadline).await?;
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
    use super::{Sink, Stream};
    use crate::{
        iouring,
        network::{
            iouring::{Config, Network},
            tests,
        },
        telemetry::metrics::Registry,
        thread, BufferPool, BufferPoolConfig, Error, IoBuf, IoBufMut, IoBufs, Listener as _,
        Network as _, Sink as _, Stream as _,
    };
    use commonware_macros::{select, test_group};
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        sync::Arc,
        time::{Duration, Instant},
    };

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        let mut registry = registry.scope();
        let mut scope = registry.sub_registry_with_prefix("test_pool");
        BufferPool::new(BufferPoolConfig::for_network(), &mut scope)
    }

    #[test]
    fn test_default_thread_stack_size_uses_system_default() {
        assert_eq!(
            Config::default().thread_stack_size,
            thread::system_thread_stack_size()
        );
    }

    #[tokio::test]
    async fn test_trait() {
        // Verify the io_uring backend satisfies the shared network trait suite.
        tests::test_network_trait(|| {
            Network::start(
                Config::default(),
                &mut Registry::default().scope(),
                test_pool(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        // Exercise the io_uring backend under the shared stress suite.
        tests::stress_test_network_trait(|| {
            Network::start(
                Config {
                    iouring_config: iouring::Config {
                        size: 256,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                &mut Registry::default().scope(),
                test_pool(),
            )
            .expect("Failed to start io_uring")
        })
        .await;
    }

    #[tokio::test]
    async fn test_small_send_read_quickly() {
        // Verify a small message is delivered promptly through the buffered recv path.
        let network = Network::start(
            Config::default(),
            &mut Registry::default().scope(),
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
        // Verify a top-level recv returns timeout after partial progress stalls.
        // Use a short timeout to make the test fast
        let op_timeout = Duration::from_millis(100);
        let network = Network::start(
            Config {
                read_write_timeout: op_timeout,
                ..Default::default()
            },
            &mut Registry::default().scope(),
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
        // Verify disabling the internal read buffer preserves direct recv behavior.
        // Set `read_buffer_size` to zero so every recv goes straight to the caller buffer.
        let network = Network::start(
            Config {
                read_buffer_size: 0,
                ..Default::default()
            },
            &mut Registry::default().scope(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

        // Bind a listener
        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept one connection and verify that peeking never observes buffered
        // bytes because the wrapper should not retain any internal read state.
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

        // Send two independent messages so the reader exercises repeated direct recvs.
        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
        sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();

        // Both messages should arrive exactly as sent, with no extra bytes hidden in `peek`.
        let (buf1, buf2) = reader.await.unwrap();

        assert_eq!(buf1.coalesce(), &[1u8, 2, 3, 4, 5]);
        assert_eq!(buf2.coalesce(), &[6u8, 7, 8, 9, 10]);
    }

    #[tokio::test]
    async fn test_op_fd_keeps_descriptor_alive() {
        // Verify queued recv requests keep their socket fd alive after caller cancellation.
        // When a recv future is cancelled (e.g. via select!) after the Request has
        // been sent to the io_uring channel, the Stream can be dropped while
        // the request is still queued. The request's fd field keeps the socket alive
        // so the OS cannot reuse the FD number.
        let op_timeout = Duration::from_millis(200);
        let network = Network::start(
            Config {
                read_write_timeout: op_timeout,
                ..Default::default()
            },
            &mut Registry::default().scope(),
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
        select! {
            _ = client_stream.recv(1) => unreachable!("no data was sent"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }

        // The queued request holds an additional clone.
        assert_eq!(Arc::strong_count(&fd), 4);

        // Drop all handles. The queued request still retains the fd.
        drop(client_sink);
        drop(client_stream);
        assert_eq!(Arc::strong_count(&fd), 2); // our clone + request

        // After op_timeout, the request completes and releases its fd clone.
        tokio::time::sleep(op_timeout).await;
        assert_eq!(Arc::strong_count(&fd), 1);
    }

    #[tokio::test]
    async fn test_peek_with_buffered_data() {
        // Verify buffered recv calls leave unread bytes visible via peek().
        // Use default buffer size to enable buffering
        let network = Network::start(
            Config::default(),
            &mut Registry::default().scope(),
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

    #[tokio::test]
    async fn test_submit_recv_returns_bytes_for_this_call() {
        // Verify `submit_recv` translates the request state's cumulative total
        // back into the per-call byte count expected by the higher-level recv loop.
        let mut registry = Registry::default();
        let mut registry = registry.scope();
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        let handle = std::thread::spawn(move || io_loop.run());

        // Build the wrapper directly so the test exercises `submit_recv`
        // without involving the higher-level buffered recv machinery.
        let (left, mut right) = UnixStream::pair().unwrap();
        let stream = Stream::new(
            Arc::new(left.into()),
            submitter,
            Duration::from_secs(1),
            0,
            test_pool(),
        );

        // Pretend the caller already filled two bytes, then complete exactly
        // three more bytes from the socket.
        let writer = tokio::task::spawn_blocking(move || right.write_all(b"abc"));
        let buffer = IoBufMut::with_capacity(5);
        let result = stream
            .submit_recv(buffer, 2, 3, true, Instant::now() + Duration::from_secs(1))
            .await;

        // The wrapper should report only the bytes read by this invocation,
        // not the cumulative total tracked inside the request state.
        writer.await.unwrap().unwrap();
        let (_buffer, read) = result.expect("submit_recv should succeed");
        assert_eq!(read, 3);

        drop(stream);
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_vectored_send_path() {
        // Verify the network send wrapper drives the vectored `Writev` path end-to-end.
        let mut registry = Registry::default();
        let mut registry = registry.scope();
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        let handle = std::thread::spawn(move || io_loop.run());

        let (left, mut right) = UnixStream::pair().unwrap();
        let mut sink = Sink::new(Arc::new(left.into()), submitter, Duration::from_secs(1));

        // Queue two buffers so the wrapper must preserve vectored ordering.
        let mut bufs = IoBufs::default();
        bufs.append(IoBuf::from(b"ab"));
        bufs.append(IoBuf::from(b"cd"));

        // Read from the peer in one shot so the final payload ordering is unambiguous.
        let reader = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4];
            right.read_exact(&mut buf).unwrap();
            buf
        });

        // The peer should observe the concatenated payload in-order.
        sink.send(bufs).await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"abcd");

        drop(sink);
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_zero_length_send_short_circuits_before_submit() {
        // Verify empty sends return locally without depending on a live io_uring loop.
        let mut registry = Registry::default();
        let mut registry = registry.scope();
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        drop(io_loop);

        // Construct a sink whose handle would fail immediately if the wrapper
        // tried to hand work to the loop.
        let (left, _right) = UnixStream::pair().unwrap();
        let mut sink = Sink::new(Arc::new(left.into()), submitter, Duration::from_secs(1));

        sink.send(IoBufs::default()).await.unwrap();
        sink.send(IoBuf::default()).await.unwrap();
        sink.send(Vec::<u8>::new()).await.unwrap();
    }

    #[tokio::test]
    async fn test_large_recv_skips_internal_buffer() {
        // Verify reads that are at least as large as the internal buffer go
        // straight into the caller-owned output buffer.
        let network = Network::start(
            Config {
                read_buffer_size: 8,
                ..Default::default()
            },
            &mut Registry::default().scope(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = *b"abcdefgh";

        // Accept one connection and issue a recv that exactly matches the
        // internal buffer size, forcing the direct-recv branch.
        let reader = tokio::spawn(async move {
            let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
            let received = stream.recv(expected.len()).await.unwrap();
            assert!(stream.peek(1).is_empty());
            received
        });

        let (mut sink, _stream) = network.dial(addr).await.unwrap();
        sink.send(expected.to_vec()).await.unwrap();

        assert_eq!(reader.await.unwrap().coalesce(), expected);
    }

    #[tokio::test]
    async fn test_configured_socket_options_cover_accept_and_dial_paths() {
        // Verify both dial and accept exercise the configured socket-option branches.
        let network = Network::start(
            Config {
                tcp_nodelay: Some(true),
                zero_linger: true,
                ..Default::default()
            },
            &mut Registry::default().scope(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accepting the connection covers the listener-side option setters.
        let accepter = tokio::spawn(async move {
            let (_addr, _sink, _stream) = listener.accept().await.unwrap();
        });

        // Dialing the listener covers the client-side option setters.
        let (_sink, _stream) = network.dial(addr).await.unwrap();
        accepter.await.unwrap();
    }

    #[tokio::test]
    async fn test_disabled_socket_options_cover_accept_and_dial_paths() {
        // Verify both dial and accept also cover the "do not touch socket options" branches.
        let network = Network::start(
            Config {
                tcp_nodelay: None,
                zero_linger: false,
                ..Default::default()
            },
            &mut Registry::default().scope(),
            test_pool(),
        )
        .expect("Failed to start io_uring");

        let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accepter = tokio::spawn(async move {
            let (_addr, _sink, _stream) = listener.accept().await.unwrap();
        });

        let (_sink, _stream) = network.dial(addr).await.unwrap();
        accepter.await.unwrap();
    }

    #[tokio::test]
    async fn test_channel_close_fallbacks() {
        // Verify send/recv callers get wrapper-level failures if the io_uring loop disappears.
        let mut registry = Registry::default();
        let mut registry = registry.scope();
        let (submitter, io_loop) =
            iouring::IoUringLoop::new(iouring::Config::default(), &mut registry);
        let recv_handle = submitter.clone();
        drop(io_loop);

        // Send should fail locally once the submission channel has been
        // disconnected and no loop remains to accept work.
        let (send_left, _send_right) = UnixStream::pair().unwrap();
        let mut sink = Sink::new(
            Arc::new(send_left.into()),
            submitter,
            Duration::from_secs(1),
        );
        assert!(matches!(sink.send(b"hello").await, Err(Error::SendFailed)));

        // Recv should surface the symmetric wrapper-specific failure.
        let (recv_left, _recv_right) = UnixStream::pair().unwrap();
        let mut stream = Stream::new(
            Arc::new(recv_left.into()),
            recv_handle,
            Duration::from_secs(1),
            0,
            test_pool(),
        );
        assert!(matches!(stream.recv(1).await, Err(Error::RecvFailed)));
    }
}
