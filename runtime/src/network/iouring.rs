//! This module provides an io_uring-based implementation of the [crate::Network] trait,
//! offering fast, high-throughput network operations on Linux systems.
//!
//! ## Architecture
//!
//! Every ring-backed operation binds to the current worker on its first poll.
//! Connected socket halves and listeners retain descriptors and buffering policy,
//! so they can move between workers between operations. No resource owns a ring.
//!
//! Accept first tries a nonblocking syscall. Only an empty accept queue registers
//! a single-shot readiness request, and cancellation cannot consume a connection.
//!
//! ## Memory Safety
//!
//! Buffers and file descriptors are owned by the active request state machine inside the io_uring
//! loop, ensuring that the memory location is valid for the duration of the operation.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.
//! It requires Linux kernel 6.1 or newer. See [crate::iouring] for details.

use crate::{
    Buf, BufferPool, Error, IoBufMut, IoBufs,
    iouring::{
        operation::Operation,
        request::{ConnectRequest, PollRequest, RecvRequest, Request, RequestOutput, SendRequest},
        sockaddr::SockAddr,
    },
};
use std::{
    net::{SocketAddr, TcpListener},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::{Duration, Instant},
};
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
    /// Timeout for establishing an outbound TCP connection.
    ///
    /// If the timeout expires, `Network::dial` returns [`Error::Timeout`].
    pub connect_timeout: Duration,
    /// Timeout budget applied to each top-level send/recv call.
    ///
    /// The owning runner validates its timeout wheel against this policy.
    /// Moving a resource to a runner with a smaller horizon can reject an
    /// operation whose deadline cannot be represented.
    pub read_write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    ///
    /// A larger buffer reduces syscall overhead by reading more data per call,
    /// but uses more memory per connection. Defaults to 64 KB.
    pub read_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_nodelay: Some(true),
            zero_linger: true,
            connect_timeout: Duration::from_secs(10),
            read_write_timeout: Duration::from_secs(60),
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
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
    /// Timeout for establishing an outbound TCP connection.
    connect_timeout: Duration,
    /// Timeout budget applied to each send/recv call.
    read_write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
}

impl Network {
    /// Retain socket policy and shared receive buffers without creating a ring.
    pub(crate) const fn new(cfg: Config, pool: BufferPool) -> Self {
        Self {
            tcp_nodelay: cfg.tcp_nodelay,
            zero_linger: cfg.zero_linger,
            connect_timeout: cfg.connect_timeout,
            read_write_timeout: cfg.read_write_timeout,
            read_buffer_size: cfg.read_buffer_size,
            pool,
        }
    }
}

/// Apply best-effort TCP policy to a socket without transferring ownership.
fn configure_socket(fd: &OwnedFd, tcp_nodelay: Option<bool>, zero_linger: bool) {
    if let Some(enabled) = tcp_nodelay {
        let value: libc::c_int = enabled.into();
        // SAFETY: `fd` owns the live socket throughout this call. The kernel reads
        // exactly one initialized integer from `value` before setsockopt returns.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                std::ptr::from_ref(&value).cast(),
                size_of_val(&value) as libc::socklen_t,
            )
        } == -1
        {
            warn!(err = ?std::io::Error::last_os_error(), "failed to set TCP_NODELAY");
        }
    }
    if zero_linger {
        let value = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: `fd` remains owned and `value` is initialized, correctly aligned
        // linger storage. setsockopt copies its bytes synchronously.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                std::ptr::from_ref(&value).cast(),
                size_of_val(&value) as libc::socklen_t,
            )
        } == -1
        {
            warn!(err = ?std::io::Error::last_os_error(), "failed to set SO_LINGER");
        }
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        let listener = TcpListener::bind(socket).map_err(|_| Error::BindFailed)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::BindFailed)?;
        Ok(Listener {
            tcp_nodelay: self.tcp_nodelay,
            zero_linger: self.zero_linger,
            inner: Arc::new(listener),
            read_write_timeout: self.read_write_timeout,
            read_buffer_size: self.read_buffer_size,
            pool: self.pool.clone(),
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), Error> {
        // Establish one absolute budget before socket creation and admission.
        let deadline = Instant::now() + self.connect_timeout;
        let family = if socket.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        // SAFETY: socket takes only integer flags and returns a fresh descriptor
        // or -1. The successful descriptor is immediately placed in one owner.
        let raw = unsafe {
            libc::socket(
                family,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(Error::ConnectionFailed);
        }
        // SAFETY: `raw` is the unique successful result of socket above and has
        // not been closed or placed in another owning descriptor.
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let output = Operation::new(Request::Connect(ConnectRequest {
            fd: fd.clone(),
            address: Box::new(SockAddr::from(socket)),
            deadline: Some(deadline),
            result: None,
        }))
        .await
        .map_err(|_| Error::ConnectionFailed)?;
        let RequestOutput::Connect(result) = output else {
            unreachable!("connect request returned another output kind");
        };
        result.map_err(|error| match error {
            Error::Timeout => Error::Timeout,
            _ => Error::ConnectionFailed,
        })?;
        configure_socket(&fd, self.tcp_nodelay, self.zero_linger);
        Ok((
            Sink::new(fd.clone(), self.read_write_timeout),
            Stream::new(
                fd,
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
    /// Shared listener retained by every outstanding readiness observation.
    inner: Arc<TcpListener>,
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
        let (stream, remote_addr) = loop {
            // A queued connection needs no waiter or readiness SQE. This also
            // makes cancellation before readiness incapable of consuming it.
            match self.inner.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(Error::ConnectionFailed),
            }
            let output = Operation::new(Request::Poll(PollRequest {
                fd: self.inner.clone(),
                flags: libc::POLLIN as u32,
                deadline: Some(Instant::now() + self.read_write_timeout),
                result: None,
            }))
            .await
            .map_err(|_| Error::ConnectionFailed)?;
            let RequestOutput::Poll(result) = output else {
                unreachable!("readiness request returned another output kind");
            };
            match result {
                // Readiness may be stale, and an idle listener has no public
                // timeout. Both outcomes retry the nonblocking accept syscall.
                Ok(()) | Err(Error::Timeout) => {}
                Err(_) => return Err(Error::ConnectionFailed),
            }
        };
        stream
            .set_nonblocking(true)
            .map_err(|_| Error::ConnectionFailed)?;
        let fd = Arc::new(OwnedFd::from(stream));
        configure_socket(&fd, self.tcp_nodelay, self.zero_linger);
        Ok((
            remote_addr,
            Sink::new(fd.clone(), self.read_write_timeout),
            Stream::new(
                fd,
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
    /// Shared socket descriptor backing this sink half.
    fd: Arc<OwnedFd>,
    /// Timeout budget for a top-level send call.
    timeout: Duration,
    /// Tracks this sink's lifecycle.
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
    /// Construct a sink whose sends bind to their current worker.
    const fn new(fd: Arc<OwnedFd>, timeout: Duration) -> Self {
        Self {
            fd,
            timeout,
            state: SinkState::Open,
        }
    }

    fn close(&mut self) {
        if matches!(self.state, SinkState::Closed) {
            return;
        }

        // Best-effort write-half shutdown so the peer can observe that no more
        // bytes will be sent after this sink becomes unusable.
        //
        // SAFETY: `self.fd` owns a live socket descriptor for the lifetime of
        // the sink. `shutdown` does not take ownership of the descriptor.
        unsafe {
            libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR);
        }
        self.state = SinkState::Closed;
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.close();
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        match self.state {
            SinkState::Open => {}
            SinkState::Sending => {
                self.close();
                return Err(Error::Closed);
            }
            SinkState::Closed => return Err(Error::Closed),
        }

        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }

        // Mark the sink as sending before awaiting so cancellation can be
        // detected by the next send.
        self.state = SinkState::Sending;

        let result = match Operation::new(Request::Send(SendRequest {
            fd: self.fd.clone(),
            write: bufs.into(),
            deadline: Some(Instant::now() + self.timeout),
            result: None,
        }))
        .await
        {
            Ok(RequestOutput::Send(result)) => result,
            Ok(_) => unreachable!("send request returned another output kind"),
            Err(_) => Err(Error::SendFailed),
        };

        // A failed send leaves the write-half unusable.
        if result.is_err() {
            self.close();
            return result;
        }

        // Mark the sink reusable on success.
        self.state = SinkState::Open;
        Ok(())
    }
}

/// Implementation of [crate::Stream] for an io-uring [Network].
///
/// Uses an internal buffer to reduce syscall overhead. Multiple small reads
/// can be satisfied from the buffer without additional network operations.
pub struct Stream {
    /// Shared socket descriptor backing this stream half.
    fd: Arc<OwnedFd>,
    /// Timeout budget for a top-level recv call.
    timeout: Duration,
    /// Tracks whether a previous recv failure has made this stream unusable.
    poisoned: bool,
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
    fn new(fd: Arc<OwnedFd>, timeout: Duration, buffer_capacity: usize, pool: BufferPool) -> Self {
        Self {
            fd,
            timeout,
            poisoned: false,
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
    /// invocation or an error. The outer error means worker teardown retained
    /// and retired the admitted buffer, so no replacement owner is fabricated.
    async fn submit_recv(
        &self,
        buffer: IoBufMut,
        offset: usize,
        len: usize,
        exact: bool,
        deadline: Instant,
    ) -> Result<Result<(IoBufMut, usize), (IoBufMut, Error)>, Error> {
        let output = Operation::new(Request::Recv(RecvRequest {
            fd: self.fd.clone(),
            buf: buffer,
            offset,
            len: offset + len,
            exact,
            deadline: Some(deadline),
            result: None,
        }))
        .await
        .map_err(|_| Error::RecvFailed)?;
        let RequestOutput::Recv(result) = output else {
            unreachable!("recv request returned another output kind");
        };
        // Translate cumulative progress while returning only a real owned
        // buffer. Worker teardown may retire that owner before a later poll.
        Ok(result.map(|(buf, total)| (buf, total - offset)))
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self, deadline: Instant) -> Result<usize, Error> {
        self.buffer_pos = 0;
        self.buffer_len = 0;

        let buffer = std::mem::take(&mut self.buffer);
        let len = buffer.capacity();

        self.buffer_len = match self.submit_recv(buffer, 0, len, false, deadline).await? {
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
        if self.poisoned {
            return Err(Error::Closed);
        }

        // Pre-poison so that cancellation leaves the stream permanently closed
        // rather than silently corrupted.
        self.poisoned = true;

        let result = async {
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
                    match self
                        .submit_recv(owned_buf, bytes_received, remaining, true, deadline)
                        .await?
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
        .await;

        // Unpoison on success.
        if result.is_ok() {
            self.poisoned = false;
        }

        result
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
        BufferPool, BufferPoolConfig, Clock as _, Error, IoBuf, IoBufMut, IoBufs, Listener as _,
        Network as _, Runner as _, Sink as _, Spawner as _, Stream as _, Supervisor as _, iouring,
        network::{
            iouring::{Config, Network},
            tests,
        },
        telemetry::metrics::{Register, Registry},
    };
    use commonware_macros::{select, test_group};
    use std::{
        io::{Read, Write},
        os::{fd::OwnedFd, unix::net::UnixStream},
        sync::Arc,
        time::{Duration, Instant},
    };

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_network(), scope)
    }

    /// Construct socket policy with a metered receive buffer pool.
    fn test_network(cfg: Config) -> Network {
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        Network::new(cfg, pool)
    }

    #[test]
    fn test_queued_accept_and_cached_operations_without_worker() {
        let network = test_network(Config::default());
        let mut listener =
            futures::executor::block_on(network.bind("127.0.0.1:0".parse().unwrap())).unwrap();
        let peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();

        // A completed handshake is already in the accept queue. No current
        // worker exists, so success also proves no readiness request was polled.
        let (_, mut sink, mut stream) = futures::executor::block_on(listener.accept()).unwrap();
        assert!(stream.peek(1).is_empty());
        futures::executor::block_on(sink.send(IoBufs::default())).unwrap();
        assert!(
            futures::executor::block_on(stream.recv(0))
                .unwrap()
                .is_empty()
        );
        drop(peer);
    }

    #[test]
    fn test_cancel_accept_before_service_preserves_next_connection() {
        iouring::Runner::new(
            iouring::Config::default().with_ring_config(iouring::RingConfig {
                size: 1,
                ..Default::default()
            }),
        )
        .start(|_| async {
            let network = test_network(Config::default());
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let address = listener.local_addr().unwrap();

            // The first poll admits readiness but cannot consume a connection.
            // Dropping it immediately must release the sole slot and make its
            // stale staging token harmless before the connect reuses capacity.
            assert!(futures::FutureExt::now_or_never(listener.accept()).is_none());
            let (mut sender, _receiver) = network.dial(address).await.unwrap();
            let (_, _sender, mut receiver) = listener.accept().await.unwrap();
            sender.send(b"kept").await.unwrap();
            assert_eq!(receiver.recv(4).await.unwrap().coalesce(), b"kept"[..]);
        });
    }

    #[test]
    fn test_pending_network_operations_observe_worker_closure() {
        let (send, recv, peer) = iouring::Runner::default().start(|_| async {
            let (socket, peer) = UnixStream::pair().unwrap();
            let fd: Arc<OwnedFd> = Arc::new(socket.into());
            let mut registry = Registry::default();
            let mut sink = Sink::new(fd.clone(), Duration::from_secs(1));
            let mut stream = Stream::new(fd, Duration::from_secs(1), 0, test_pool(&mut registry));
            let mut send = Box::pin(async move { sink.send(b"x").await });
            let mut recv = Box::pin(async move { stream.recv(1).await });
            // Retain registered futures across shutdown, including their
            // resources, before polling their original worker's closed state.
            assert!(futures::poll!(send.as_mut()).is_pending());
            assert!(futures::poll!(recv.as_mut()).is_pending());
            (send, recv, peer)
        });
        assert!(matches!(
            futures::executor::block_on(send),
            Err(Error::SendFailed)
        ));
        assert!(matches!(
            futures::executor::block_on(recv),
            Err(Error::RecvFailed)
        ));
        drop(peer);
    }

    #[test]
    fn test_trait() {
        iouring::Runner::default().start(|context| async move {
            // Verify the io_uring backend satisfies the shared network trait suite.
            tests::test_network_trait(context, || {
                test_network(Config {
                    read_write_timeout: Duration::from_secs(15),
                    ..Default::default()
                })
            })
            .await;
        });
    }

    #[test]
    fn test_connect_timeout() {
        iouring::Runner::default().start(|context| async move {
            let connect_timeout = Duration::from_millis(100);
            let network = test_network(Config {
                connect_timeout,
                ..Default::default()
            });

            tests::test_network_connect_timeout(context, network, connect_timeout).await;
        });
    }

    #[test_group("slow")]
    #[test]
    fn test_stress_trait() {
        iouring::Runner::new(
            iouring::Config::default().with_ring_config(iouring::RingConfig {
                size: 256,
                ..Default::default()
            }),
        )
        .start(|context| async move {
            // Exercise the io_uring backend under the shared stress suite.
            tests::stress_test_network_trait(context, || {
                test_network(Config {
                    ..Default::default()
                })
            })
            .await;
        });
    }

    #[test]
    fn test_small_send_read_quickly() {
        iouring::Runner::default().start(|context| async move {
            // Verify a small message is delivered promptly through the buffered recv path.
            let network = test_network(Config::default());

            // Bind a listener
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Spawn a task to accept and read
            let reader = context.child("reader").spawn(move |_| async move {
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
        });
    }

    #[test]
    fn test_read_timeout_with_partial_data() {
        iouring::Runner::default().start(|context| async move {
            // Verify a top-level recv returns timeout after partial progress stalls.
            // Use a short timeout to make the test fast
            let op_timeout = Duration::from_millis(100);
            let network = test_network(Config {
                read_write_timeout: op_timeout,
                ..Default::default()
            });

            // Bind a listener
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = context.child("reader").spawn(move |_| async move {
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
        });
    }

    #[test]
    fn test_unbuffered_mode() {
        iouring::Runner::default().start(|context| async move {
            // Verify disabling the internal read buffer preserves direct recv behavior.
            // Set `read_buffer_size` to zero so every recv goes straight to the caller buffer.
            let network = test_network(Config {
                read_buffer_size: 0,
                ..Default::default()
            });

            // Bind a listener
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Accept one connection and verify that peeking never observes buffered
            // bytes because the wrapper should not retain any internal read state.
            let reader = context.child("reader").spawn(move |_| async move {
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
        });
    }

    #[test]
    fn test_op_fd_keeps_descriptor_alive() {
        iouring::Runner::default().start(|context| async move {
            // Verify queued recv requests keep their socket fd alive after caller cancellation.
            // When a recv future is cancelled (e.g. via select!) after the Request has
            // been admitted to the worker, the Stream can be dropped while
            // the request is still in flight. The request's fd field keeps the socket alive
            // so the OS cannot reuse the FD number.
            let op_timeout = Duration::from_millis(200);
            let network = test_network(Config {
                read_write_timeout: op_timeout,
                ..Default::default()
            });

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
                _ = context.sleep(Duration::from_millis(50)) => {},
            }

            // The queued request holds an additional clone.
            assert_eq!(Arc::strong_count(&fd), 4);

            // Drop all handles. The queued request still retains the fd.
            drop(client_sink);
            drop(client_stream);
            assert_eq!(Arc::strong_count(&fd), 2); // our clone + request

            // After op_timeout, the request completes and releases its fd clone.
            context.sleep(op_timeout).await;
            assert_eq!(Arc::strong_count(&fd), 1);
        });
    }

    #[test]
    fn test_peek_with_buffered_data() {
        iouring::Runner::default().start(|context| async move {
            // Verify buffered recv calls leave unread bytes visible via peek().
            // Use default buffer size to enable buffering
            let network = test_network(Config::default());

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = context.child("reader").spawn(move |_| async move {
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
        });
    }

    #[test]
    fn test_submit_recv_returns_bytes_for_this_call() {
        iouring::Runner::default().start(|context| async move {
            // Verify `submit_recv` translates the request state's cumulative total
            // back into the per-call byte count expected by the higher-level recv loop.
            let mut registry = Registry::default();
            let pool = test_pool(&mut registry.sub_registry("pool"));

            // Build the wrapper directly so the test exercises `submit_recv`
            // without involving the higher-level buffered recv machinery.
            let (left, mut right) = UnixStream::pair().unwrap();
            let stream = Stream::new(Arc::new(left.into()), Duration::from_secs(1), 0, pool);

            // Pretend the caller already filled two bytes, then complete exactly
            // three more bytes from the socket.
            let writer = context
                .child("writer")
                .shared(true)
                .spawn(move |_| async move { right.write_all(b"abc") });
            let buffer = IoBufMut::with_capacity(5);
            let result = stream
                .submit_recv(buffer, 2, 3, true, Instant::now() + Duration::from_secs(1))
                .await;

            // The wrapper should report only the bytes read by this invocation,
            // not the cumulative total tracked inside the request state.
            writer.await.unwrap().unwrap();
            let (_buffer, read) = result
                .expect("worker should remain open")
                .expect("submit_recv should succeed");
            assert_eq!(read, 3);

            drop(stream);
        });
    }

    #[test]
    fn test_vectored_send_path() {
        iouring::Runner::default().start(|context| async move {
            // Verify the network send wrapper drives the vectored `Writev` path end-to-end.
            let (left, mut right) = UnixStream::pair().unwrap();
            let mut sink = Sink::new(Arc::new(left.into()), Duration::from_secs(1));

            // Queue two buffers so the wrapper must preserve vectored ordering.
            let mut bufs = IoBufs::default();
            bufs.append(IoBuf::from(b"ab"));
            bufs.append(IoBuf::from(b"cd"));

            // Read from the peer in one shot so the final payload ordering is unambiguous.
            let reader = context
                .child("reader")
                .shared(true)
                .spawn(move |_| async move {
                    let mut buf = [0u8; 4];
                    right.read_exact(&mut buf).unwrap();
                    buf
                });

            // The peer should observe the concatenated payload in-order.
            sink.send(bufs).await.unwrap();
            assert_eq!(&reader.await.unwrap(), b"abcd");

            drop(sink);
        });
    }

    #[test]
    fn test_zero_length_send_short_circuits_before_submit() {
        iouring::Runner::default().start(|_| async move {
            // Empty sends finish without registering a current-worker operation.
            let (left, _right) = UnixStream::pair().unwrap();
            let mut sink = Sink::new(Arc::new(left.into()), Duration::from_secs(1));

            sink.send(IoBufs::default()).await.unwrap();
            sink.send(IoBuf::default()).await.unwrap();
            sink.send(Vec::<u8>::new()).await.unwrap();
        });
    }

    #[test]
    fn test_large_recv_skips_internal_buffer() {
        iouring::Runner::default().start(|context| async move {
            // Verify reads that are at least as large as the internal buffer go
            // straight into the caller-owned output buffer.
            let network = test_network(Config {
                read_buffer_size: 8,
                ..Default::default()
            });

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let expected = *b"abcdefgh";

            // Accept one connection and issue a recv that exactly matches the
            // internal buffer size, forcing the direct-recv branch.
            let reader = context.child("reader").spawn(move |_| async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
                let received = stream.recv(expected.len()).await.unwrap();
                assert!(stream.peek(1).is_empty());
                received
            });

            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send(expected.to_vec()).await.unwrap();

            assert_eq!(reader.await.unwrap().coalesce(), expected);
        });
    }

    #[test]
    fn test_configured_socket_options_cover_accept_and_dial_paths() {
        iouring::Runner::default().start(|context| async move {
            // Verify both dial and accept exercise the configured socket-option branches.
            let network = test_network(Config {
                tcp_nodelay: Some(true),
                zero_linger: true,
                ..Default::default()
            });

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Accepting the connection covers the listener-side option setters.
            let accepter = context.child("reader").spawn(move |_| async move {
                let (_addr, _sink, _stream) = listener.accept().await.unwrap();
            });

            // Dialing the listener covers the client-side option setters.
            let (_sink, _stream) = network.dial(addr).await.unwrap();
            accepter.await.unwrap();
        });
    }

    #[test]
    fn test_disabled_socket_options_cover_accept_and_dial_paths() {
        iouring::Runner::default().start(|context| async move {
            // Verify both dial and accept also cover the "do not touch socket options" branches.
            let network = test_network(Config {
                tcp_nodelay: None,
                zero_linger: false,
                ..Default::default()
            });

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let accepter = context.child("reader").spawn(move |_| async move {
                let (_addr, _sink, _stream) = listener.accept().await.unwrap();
            });

            let (_sink, _stream) = network.dial(addr).await.unwrap();
            accepter.await.unwrap();
        });
    }
}
