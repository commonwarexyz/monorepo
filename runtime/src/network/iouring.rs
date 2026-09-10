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
    /// Create a network with the given socket policy and receive buffer pool.
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
        // Include socket creation and time waiting for staging in the timeout.
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
        let output = Operation::register(Request::Connect(ConnectRequest {
            fd: fd.clone(),
            address: Box::new(SockAddr::from(socket)),
            deadline: Some(deadline),
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
            // Accept only while this future is being polled. A readiness
            // request left behind by cancellation cannot consume a connection.
            match self.inner.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(Error::ConnectionFailed),
            }

            let output = Operation::register(Request::Poll(PollRequest {
                fd: self.inner.clone(),
                deadline: Some(Instant::now() + self.read_write_timeout),
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

        // Accepted sockets do not inherit the listener's nonblocking flag.
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

        let result = match Operation::register(Request::Send(SendRequest {
            fd: self.fd.clone(),
            write: bufs.into(),
            deadline: Some(Instant::now() + self.timeout),
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
            pool,
        }
    }

    /// Submit a recv request to io_uring and wait for completion.
    ///
    /// `offset` is the byte offset into `buffer` where received data should
    /// start. `len` is the number of bytes to read starting at that offset.
    ///
    /// Returns the buffer and the number of bytes read by this invocation.
    /// Failed requests discard their buffers because the stream is poisoned.
    async fn submit_recv(
        &self,
        buffer: IoBufMut,
        offset: usize,
        len: usize,
        exact: bool,
        deadline: Instant,
    ) -> Result<(IoBufMut, usize), Error> {
        let output = Operation::register(Request::Recv(RecvRequest {
            fd: self.fd.clone(),
            buf: buffer,
            offset,
            len: offset + len,
            exact,
            deadline: Some(deadline),
        }))
        .await
        .map_err(|_| Error::RecvFailed)?;

        let RequestOutput::Recv(result) = output else {
            unreachable!("recv request returned another output kind");
        };

        // Request progress includes the bytes filled by earlier calls.
        result
            .map(|(buf, total)| (buf, total - offset))
            .map_err(|(_, error)| error)
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self, deadline: Instant) -> Result<(), Error> {
        self.buffer_pos = 0;

        let buffer = std::mem::take(&mut self.buffer);
        let len = buffer.capacity();

        let (buffer, read) = self.submit_recv(buffer, 0, len, false, deadline).await?;
        self.buffer = buffer;

        // SAFETY: The successful receive initialized the first `read` bytes.
        unsafe { self.buffer.set_len(read) };

        Ok(())
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
                let buffered = self.buffer.len() - self.buffer_pos;
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
                    let (buf, read) = self
                        .submit_recv(owned_buf, bytes_received, remaining, true, deadline)
                        .await?;
                    owned_buf = buf;
                    bytes_received += read;
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
        let buffered = self.buffer.len() - self.buffer_pos;
        let len = std::cmp::min(buffered, max_len);
        &self.buffer.as_ref()[self.buffer_pos..self.buffer_pos + len]
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Network, Sink, Stream};
    use crate::{
        BufferPool, BufferPoolConfig, Clock as _, Error, IoBuf, IoBufMut, IoBufs, Listener as _,
        Network as _, Runner as _, Sink as _, Spawner as _, Stream as _, Supervisor as _, iouring,
        network::tests,
        telemetry::metrics::{Register, Registry},
    };
    use commonware_macros::{select, test_group};
    use std::{
        io::Write,
        net::TcpStream,
        os::{
            fd::{AsRawFd, OwnedFd},
            unix::net::UnixStream,
        },
        sync::Arc,
        time::{Duration, Instant},
    };

    /// Allocate receive buffers with the network pool configuration.
    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_network(), scope)
    }

    /// Construct socket policy with a metered receive buffer pool.
    fn test_network(cfg: Config) -> Network {
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        Network::new(cfg, pool)
    }

    /// Read the TCP_NODELAY and SO_LINGER settings from a connected socket.
    fn socket_options(fd: &OwnedFd) -> (bool, Option<Duration>) {
        let stream = TcpStream::from(fd.try_clone().unwrap());
        let nodelay = stream.nodelay().unwrap();
        let mut linger = libc::linger {
            l_onoff: 0,
            l_linger: 0,
        };
        let mut len = size_of_val(&linger) as libc::socklen_t;

        // SAFETY: `fd` owns the socket and both output pointers refer to writable
        // storage. `len` gives the full size of the initialized linger value.
        let result = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                std::ptr::from_mut(&mut linger).cast(),
                &mut len,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(len as usize, size_of_val(&linger));

        let linger =
            (linger.l_onoff != 0).then(|| Duration::from_secs(linger.l_linger.try_into().unwrap()));
        (nodelay, linger)
    }

    #[test]
    fn test_queued_accept_and_empty_operations_without_worker() {
        let network = test_network(Config::default());
        let mut listener =
            futures::executor::block_on(network.bind("127.0.0.1:0".parse().unwrap())).unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();

        // A completed handshake is already in the accept queue. No current
        // worker exists, so success also proves no readiness request was polled.
        let (_, mut sink, mut stream) = futures::executor::block_on(listener.accept()).unwrap();
        assert!(stream.peek(1).is_empty());

        futures::executor::block_on(sink.send(IoBufs::default())).unwrap();
        futures::executor::block_on(sink.send(IoBuf::default())).unwrap();
        futures::executor::block_on(sink.send(Vec::<u8>::new())).unwrap();
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

            // Cancel readiness before driver service. Its stale queue entry
            // must not interfere with the connect that reuses the waiter slot.
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
            tests::stress_test_network_trait(context, || test_network(Config::default())).await;
        });
    }

    #[test]
    fn test_read_timeout_with_partial_data() {
        iouring::Runner::default().start(|context| async move {
            let op_timeout = Duration::from_millis(100);
            let network = test_network(Config {
                read_write_timeout: op_timeout,
                ..Default::default()
            });

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = context.child("reader").spawn(move |_| async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

                // Keep the call pending after a short read so expiry must
                // return an error instead of exposing a partial result.
                let start = Instant::now();
                let result = stream.recv(100).await;
                let elapsed = start.elapsed();

                // Failed buffered reads expose no partial data and cannot resume.
                assert!(stream.peek(100).is_empty());
                assert!(matches!(stream.recv(1).await, Err(Error::Closed)));

                (result, elapsed)
            });

            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();

            let (result, elapsed) = reader.await.unwrap();
            assert!(matches!(result, Err(Error::Timeout)));
            assert!(elapsed >= op_timeout);

            // Allow some margin for scheduling and timer precision.
            assert!(elapsed < op_timeout * 3);
        });
    }

    #[test]
    fn test_unbuffered_mode() {
        iouring::Runner::default().start(|context| async move {
            let network = test_network(Config {
                read_buffer_size: 0,
                ..Default::default()
            });

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = context.child("reader").spawn(move |_| async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

                // Direct receives must leave no unread bytes in the stream buffer.
                assert!(stream.peek(100).is_empty());
                let buf1 = stream.recv(5).await.unwrap();
                assert!(stream.peek(100).is_empty());

                let buf2 = stream.recv(5).await.unwrap();
                assert!(stream.peek(100).is_empty());

                (buf1, buf2)
            });

            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
            sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();

            let (buf1, buf2) = reader.await.unwrap();
            assert_eq!(buf1.coalesce(), &[1u8, 2, 3, 4, 5]);
            assert_eq!(buf2.coalesce(), &[6u8, 7, 8, 9, 10]);
        });
    }

    #[test]
    fn test_cancelled_recv_retains_descriptor_until_completion() {
        iouring::Runner::default().start(|context| async move {
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

            // Cancellation cannot release the descriptor before the receive CQE.
            assert_eq!(Arc::strong_count(&fd), 4);

            // Only this test and the in-flight request retain the descriptor.
            drop(client_sink);
            drop(client_stream);
            assert_eq!(Arc::strong_count(&fd), 2);

            // Allow the worker to process cancellation and retire the request.
            context.sleep(op_timeout).await;
            assert_eq!(Arc::strong_count(&fd), 1);
        });
    }

    #[test]
    fn test_peek_with_buffered_data() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mut registry = Registry::default();
        let mut stream = Stream::new(
            Arc::new(socket.into()),
            Duration::from_secs(1),
            64,
            test_pool(&mut registry),
        );
        assert!(stream.peek(100).is_empty());

        // Queue the full payload before receiving so the fill can read ahead.
        peer.write_all(b"hello world").unwrap();
        let mut stream = iouring::Runner::default().start(|_| async move {
            let first = stream.recv(5).await.unwrap();
            assert_eq!(first.coalesce(), b"hello");
            assert_eq!(stream.peek(100), b" world");

            // Peeking does not consume bytes and respects the requested limit.
            assert_eq!(stream.peek(100), b" world");
            assert_eq!(stream.peek(3), b" wo");
            assert!(stream.peek(0).is_empty());

            // A shorter refill must replace the previous readable extent.
            peer.write_all(b"xy").unwrap();
            assert_eq!(stream.recv(7).await.unwrap().coalesce(), b" worldx");
            assert_eq!(stream.peek(100), b"y");

            // Buffered prefixes and later refills must survive the direct path.
            let direct = [b'z'; 64];
            peer.write_all(&direct).unwrap();
            let received = stream.recv(65).await.unwrap().coalesce();
            assert_eq!(&received.as_ref()[..1], b"y");
            assert_eq!(&received.as_ref()[1..], &direct);
            assert!(stream.peek(100).is_empty());

            peer.write_all(b"next").unwrap();
            assert_eq!(stream.recv(2).await.unwrap().coalesce(), b"ne");
            assert_eq!(stream.peek(100), b"xt");
            stream
        });

        // Buffered bytes remain readable after the worker has shut down.
        let rest = futures::executor::block_on(stream.recv(2)).unwrap();
        assert_eq!(rest.coalesce(), b"xt");
        assert!(stream.peek(100).is_empty());
    }

    #[test]
    fn test_submit_recv_returns_bytes_for_this_call() {
        iouring::Runner::default().start(|_| async {
            let mut registry = Registry::default();
            let pool = test_pool(&mut registry.sub_registry("pool"));
            let (left, mut right) = UnixStream::pair().unwrap();
            let stream = Stream::new(Arc::new(left.into()), Duration::from_secs(1), 0, pool);

            // Preserve an existing two-byte prefix while receiving three more bytes.
            right.write_all(b"abc").unwrap();
            let buffer = IoBufMut::from(b"xy___");
            let result = stream
                .submit_recv(buffer, 2, 3, true, Instant::now() + Duration::from_secs(1))
                .await;

            // Report this call's progress while returning the whole buffer.
            let (buffer, read) = result.expect("submit_recv should succeed");
            assert_eq!(read, 3);
            assert_eq!(buffer.as_ref(), b"xyabc");
        });
    }

    #[test]
    fn test_large_recv_skips_internal_buffer() {
        iouring::Runner::default().start(|context| async move {
            let network = test_network(Config {
                read_buffer_size: 8,
                ..Default::default()
            });

            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let expected = b"abcdefgh";

            // Accept one connection and issue a recv that exactly matches the
            // internal buffer size, forcing the direct-recv branch.
            let reader = context.child("reader").spawn(move |_| async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
                let received = stream.recv(expected.len()).await.unwrap();
                assert!(stream.peek(1).is_empty());
                received
            });

            let (mut sink, _stream) = network.dial(addr).await.unwrap();
            sink.send(expected).await.unwrap();

            assert_eq!(reader.await.unwrap().coalesce(), expected);
        });
    }

    #[test]
    fn test_socket_options_on_accept_and_dial() {
        iouring::Runner::default().start(|_| async {
            for (tcp_nodelay, zero_linger) in
                [(Some(true), true), (Some(false), false), (None, false)]
            {
                let network = test_network(Config {
                    tcp_nodelay,
                    zero_linger,
                    ..Default::default()
                });
                let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
                let address = listener.local_addr().unwrap();

                let (client_sink, _client_stream) = network.dial(address).await.unwrap();
                let (_, server_sink, _server_stream) = listener.accept().await.unwrap();

                // Both connection paths must apply the policy. Unconfigured
                // sockets retain the default Nagle and disabled-linger settings.
                let expected = (
                    tcp_nodelay.unwrap_or(false),
                    zero_linger.then_some(Duration::ZERO),
                );
                for fd in [&client_sink.fd, &server_sink.fd] {
                    assert_eq!(socket_options(fd), expected);
                }
            }
        });
    }
}
