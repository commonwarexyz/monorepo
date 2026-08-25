//! This module provides an io_uring-based implementation of the [crate::Network] trait,
//! offering fast, high-throughput network operations on Linux systems.
//!
//! ## Architecture
//!
//! Network operations (including accept and connect) are submitted through an io_uring `Handle`
//! to the event loop that services the ring, which the `iouring` runtime drives on the runtime
//! thread. Socket creation and bind are cheap non-blocking syscalls performed inline.
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
    iouring::{self, RawSocketAddr},
};
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::warn;

/// Default read buffer size (64 KB).
const DEFAULT_READ_BUFFER_SIZE: usize = 64 * 1024;

/// Listen backlog requested for bound sockets.
///
/// The kernel caps this at `net.core.somaxconn`.
const LISTEN_BACKLOG: libc::c_int = 1024;

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
    /// Timeout budget applied to each top-level send/recv call and to each
    /// in-flight accept (which is transparently reissued on expiry).
    ///
    /// This is a network-level policy and is independent from io_uring loop
    /// tuning. The runtime raises the loop timeout horizon as needed so this
    /// value is never clamped by the ring's `max_request_timeout`.
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
            read_write_timeout: iouring::RingConfig::default().max_request_timeout,
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
        }
    }
}

/// Create a non-blocking TCP socket for the given address family.
fn new_socket(addr: &SocketAddr) -> Result<OwnedFd, std::io::Error> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: `socket` allocates a new descriptor and touches no caller memory.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created descriptor owned by no one else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Set or clear `TCP_NODELAY` on a socket.
fn set_tcp_nodelay(fd: &OwnedFd, enable: bool) -> Result<(), std::io::Error> {
    let value: libc::c_int = libc::c_int::from(enable);
    // SAFETY: `fd` owns a live descriptor and `value` is a valid `c_int`
    // read-only input of the provided length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&raw const value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set `SO_LINGER` to zero on a socket so close causes an immediate RST.
fn set_zero_linger(fd: &OwnedFd) -> Result<(), std::io::Error> {
    let value = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `fd` owns a live descriptor and `value` is a valid `linger`
    // read-only input of the provided length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const value).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set `SO_REUSEADDR` on a socket so rebinding does not wait out `TIME_WAIT`.
fn set_reuseaddr(fd: &OwnedFd) -> Result<(), std::io::Error> {
    let value: libc::c_int = 1;
    // SAFETY: `fd` owns a live descriptor and `value` is a valid `c_int`
    // read-only input of the provided length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Return the local address a socket is bound to.
fn local_addr(fd: &OwnedFd) -> Result<SocketAddr, std::io::Error> {
    let mut raw = RawSocketAddr::new_zeroed();
    // SAFETY: `fd` owns a live descriptor and the pointers reference scratch
    // sized for any socket address (with `len` set to its capacity).
    let rc = unsafe { libc::getsockname(fd.as_raw_fd(), raw.as_sockaddr_mut_ptr(), raw.len_mut()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    raw.to_socket_addr()
        .ok_or_else(|| std::io::Error::other("unsupported socket address family"))
}

/// Apply configured per-connection socket options, logging failures.
fn configure_socket(fd: &OwnedFd, tcp_nodelay: Option<bool>, zero_linger: bool) {
    // Set TCP_NODELAY if configured
    if let Some(tcp_nodelay) = tcp_nodelay
        && let Err(err) = set_tcp_nodelay(fd, tcp_nodelay)
    {
        warn!(?err, "failed to set TCP_NODELAY");
    }

    // Set SO_LINGER to zero if configured
    if zero_linger && let Err(err) = set_zero_linger(fd) {
        warn!(?err, "failed to set SO_LINGER");
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
    /// Used to submit operations to the io_uring event loop.
    handle: iouring::Handle,
    /// Timeout for establishing an outbound TCP connection.
    connect_timeout: Duration,
    /// Timeout budget applied to each send/recv call and each in-flight
    /// accept.
    read_write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
}

impl Network {
    /// Returns a new [Network] instance that submits operations through `handle`.
    ///
    /// The caller should take special care to ensure the ring backing `handle` is
    /// large enough, given the number of connections that will be maintained.
    /// Each in-flight send/recv to/from each connection consumes a ring slot, as
    /// does each in-flight accept and connect.
    pub(crate) const fn new(cfg: Config, handle: iouring::Handle, pool: BufferPool) -> Self {
        Self {
            tcp_nodelay: cfg.tcp_nodelay,
            zero_linger: cfg.zero_linger,
            handle,
            connect_timeout: cfg.connect_timeout,
            read_write_timeout: cfg.read_write_timeout,
            read_buffer_size: cfg.read_buffer_size,
            pool,
        }
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.handle.assert_owner();
        // Create the listening socket inline: socket setup, bind, and listen
        // are cheap non-blocking syscalls.
        let fd = new_socket(&socket).map_err(|_| Error::BindFailed)?;
        set_reuseaddr(&fd).map_err(|_| Error::BindFailed)?;
        let raw = RawSocketAddr::from_socket_addr(&socket);
        // SAFETY: `fd` owns a live descriptor and the pointer references an
        // encoded address of the provided length.
        let rc = unsafe { libc::bind(fd.as_raw_fd(), raw.as_sockaddr_ptr(), raw.len()) };
        if rc == -1 {
            return Err(Error::BindFailed);
        }
        // SAFETY: `fd` owns a live descriptor, and `listen` touches no caller memory.
        let rc = unsafe { libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) };
        if rc == -1 {
            return Err(Error::BindFailed);
        }
        let local_addr = local_addr(&fd).map_err(|_| Error::BindFailed)?;

        Ok(Listener {
            tcp_nodelay: self.tcp_nodelay,
            zero_linger: self.zero_linger,
            fd: Arc::new(fd),
            local_addr,
            handle: self.handle.clone(),
            read_write_timeout: self.read_write_timeout,
            read_buffer_size: self.read_buffer_size,
            pool: self.pool.clone(),
            pending: None,
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), Error> {
        let fd = Arc::new(new_socket(&socket).map_err(|_| Error::ConnectionFailed)?);

        // Apply socket options before connecting.
        configure_socket(&fd, self.tcp_nodelay, self.zero_linger);

        // Connect through the ring. Deadline expiry cancels the in-flight
        // connect and resolves the dial with [Error::Timeout].
        let deadline = Instant::now() + self.connect_timeout;
        self.handle.connect(fd.clone(), socket, deadline).await?;

        Ok((
            Sink::new(fd.clone(), self.handle.clone(), self.read_write_timeout),
            Stream::new(
                fd,
                self.handle.clone(),
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
    /// Listening socket descriptor, shared with in-flight accept requests.
    fd: Arc<OwnedFd>,
    /// Address the listener is bound to.
    local_addr: SocketAddr,
    /// Used to submit operations to the io_uring event loop.
    handle: iouring::Handle,
    /// Timeout budget applied to each in-flight accept and inherited by
    /// accepted connections.
    read_write_timeout: Duration,
    /// Size of the read buffer for batching network reads.
    read_buffer_size: usize,
    /// Buffer pool for recv allocations.
    pool: BufferPool,
    /// In-flight accept, retained so a cancelled accept future resumes the
    /// same request instead of losing an accepted connection.
    ///
    /// A connection accepted between `accept` calls moves into the ticket's
    /// Ready completion entry until the next call takes it or the listener
    /// drops. The request's waiter slot is already free at that point.
    pending: Option<iouring::AcceptTicket>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Best-effort disconnect so an in-flight accept fails promptly instead
        // of occupying a ring slot until its deadline expires. On Linux,
        // shutdown on a listening socket disconnects it even though the call
        // itself reports ENOTCONN.
        //
        // SAFETY: `self.fd` owns a live descriptor for the lifetime of the
        // listener. `shutdown` does not take ownership of the descriptor.
        unsafe {
            libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        loop {
            // Issue a fresh accept if none is in flight.
            if self.pending.is_none() {
                let deadline = Instant::now() + self.read_write_timeout;
                self.pending = Some(self.handle.start_accept(self.fd.clone(), deadline).await);
            }

            // Wait on the in-flight accept. If this future is dropped, the
            // ticket stays in `self.pending` and the next call resumes it.
            let ticket = self.pending.as_mut().expect("pending accept was just set");
            let result = ticket.await;
            self.pending = None;
            match result {
                Ok((fd, remote_addr)) => {
                    let fd = Arc::new(fd);
                    configure_socket(&fd, self.tcp_nodelay, self.zero_linger);
                    return Ok((
                        remote_addr,
                        Sink::new(fd.clone(), self.handle.clone(), self.read_write_timeout),
                        Stream::new(
                            fd,
                            self.handle.clone(),
                            self.read_write_timeout,
                            self.read_buffer_size,
                            self.pool.clone(),
                        ),
                    ));
                }
                // The deadline exists so an abandoned accept cannot occupy a
                // ring slot forever, and an expired accept is simply reissued.
                Err(Error::Timeout) => continue,
                // Match the tokio backend's contract: every accept failure
                // surfaces as [Error::Closed], so portable callers observe
                // the same error regardless of runtime.
                Err(_) => return Err(Error::Closed),
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.handle.assert_owner();
        Ok(self.local_addr)
    }
}

/// Implementation of [crate::Sink] for an io-uring [Network].
pub struct Sink {
    /// Shared socket descriptor backing this sink half.
    fd: Arc<OwnedFd>,
    /// Used to submit send operations to the io_uring event loop.
    handle: iouring::Handle,
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
    /// Construct a sink that submits logical send requests through one io_uring loop.
    const fn new(fd: Arc<OwnedFd>, handle: iouring::Handle, timeout: Duration) -> Self {
        Self {
            fd,
            handle,
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
        self.handle.assert_owner();
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

        let result = self
            .handle
            .send(self.fd.clone(), bufs, Instant::now() + self.timeout)
            .await;

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
    /// Used to submit recv operations to the io_uring event loop.
    handle: iouring::Handle,
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
        self.handle.assert_owner();
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
        .await;

        // Unpoison on success.
        if result.is_ok() {
            self.poisoned = false;
        }

        result
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        self.handle.assert_owner();
        let buffered = self.buffer_len - self.buffer_pos;
        let len = std::cmp::min(buffered, max_len);
        &self.buffer.as_ref()[self.buffer_pos..self.buffer_pos + len]
    }
}

#[cfg(test)]
mod tests {
    use super::{RawSocketAddr, Sink, Stream, local_addr, new_socket};
    use crate::{
        BufferPool, BufferPoolConfig, Error, IoBuf, IoBufMut, IoBufs, Listener as _, Network as _,
        Runner as _, Sink as _, Stream as _, Supervisor as _, iouring,
        iouring::testing::{TestLoop, poll_once},
        network::{
            iouring::{Config, Network},
            tests,
        },
        telemetry::metrics::{Register, Registry},
    };
    use commonware_macros::test_group;
    use std::{
        io::{Read, Write},
        net::SocketAddr,
        os::{fd::AsRawFd, unix::net::UnixStream},
        sync::Arc,
        time::{Duration, Instant},
    };

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_network(), scope)
    }

    /// Start a test network backed by a loop harness on this thread, mirroring
    /// how the runtime hands the network a driver for the runtime-driven loop.
    fn test_network_with_ring(cfg: Config, mut ring: iouring::RingConfig) -> (TestLoop, Network) {
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        // Match the runtime's startup behavior so network deadlines are never
        // clamped by the ring's timeout horizon.
        ring.max_request_timeout = ring
            .max_request_timeout
            .max(cfg.read_write_timeout)
            .max(cfg.connect_timeout);
        let harness = TestLoop::new(ring);
        let network = Network::new(cfg, harness.handle.clone(), pool);
        (harness, network)
    }

    /// [test_network_with_ring] with the default ring configuration.
    fn test_network(cfg: Config) -> (TestLoop, Network) {
        test_network_with_ring(cfg, iouring::RingConfig::default())
    }

    #[test]
    fn test_trait() {
        // Verify the io_uring backend satisfies the shared network trait suite.
        let (mut harness, network) = test_network(Config {
            read_write_timeout: Duration::from_secs(15),
            ..Default::default()
        });
        harness.block_on(tests::test_network_trait(move || network.clone()));

        // The sub-tests share one driver, so a slot leaked by any of them
        // would degrade the others: assert everything was reclaimed.
        assert_eq!(harness.tracked(), 0, "trait suite leaked waiter slots");
    }

    #[test]
    fn test_connect_timeout() {
        let connect_timeout = Duration::from_millis(100);
        let (mut harness, network) = test_network(Config {
            connect_timeout,
            ..Default::default()
        });

        // Create a loopback listener with the smallest possible accept queue
        // and fill it with one unaccepted connection, so the dial below stays
        // pending until its timeout fires. Mirrors the shared
        // `test_network_connect_timeout` helper, which needs a tokio reactor.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let fd = new_socket(&addr).expect("failed to create listener socket");
        let raw = RawSocketAddr::from_socket_addr(&addr);
        // SAFETY: `fd` owns a live descriptor and the pointer references an
        // encoded address of the provided length.
        let rc = unsafe { libc::bind(fd.as_raw_fd(), raw.as_sockaddr_ptr(), raw.len()) };
        assert!(rc != -1, "failed to bind listener socket");
        // SAFETY: `fd` owns a live descriptor, and `listen` touches no caller memory.
        let rc = unsafe { libc::listen(fd.as_raw_fd(), 0) };
        assert!(rc != -1, "failed to listen on socket");
        let listener_addr = local_addr(&fd).expect("failed to read listener address");
        let _queued_connection = std::net::TcpStream::connect(listener_addr)
            .expect("failed to fill listener accept queue");

        let start = Instant::now();
        let result = harness.block_on(network.dial(listener_addr));
        assert!(matches!(result, Err(Error::Timeout)));

        // Confirm the dial remained pending for the configured budget and
        // the timed-out connect released its waiter slot.
        assert!(start.elapsed() >= connect_timeout);
        assert_eq!(harness.tracked(), 0, "connect timeout leaked waiter slots");
    }

    #[test_group("slow")]
    #[test]
    fn test_stress_trait() {
        // Exercise the io_uring backend under the shared stress suite on the
        // real runtime, with a ring large enough that nearly every stream can
        // keep an operation in flight.
        let runner = crate::iouring::Runner::new(crate::iouring::Config::default().with_ring(
            iouring::RingConfig {
                size: 256,
                ..Default::default()
            },
        ));
        runner.start(|context| async move {
            // The context doubles as the network under test, and contexts are
            // only duplicable through the supervision tree.
            let network = context.child("network");
            tests::stress_test_network_trait(move || network.child("socket"), context).await;
        });
    }

    #[test]
    fn test_small_send_read_quickly() {
        // Verify a small message is delivered promptly through the buffered recv path.
        let (mut harness, network) = test_network(Config::default());
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

                // Read a small message (much smaller than the 64KB buffer)
                stream.recv(10).await.unwrap()
            };

            let msg = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let sender = async {
                let (mut sink, _stream) = network.dial(addr).await.unwrap();
                sink.send(msg.clone()).await.unwrap();
            };

            let (received, ()) = futures::join!(reader, sender);
            assert_eq!(received.coalesce(), msg.as_slice());
        });
    }

    #[test]
    fn test_ipv6_end_to_end() {
        // Property: the AF_INET6 socket arm and the full v6 sockaddr path
        // work end to end through bind, dial, accept, and a bidirectional
        // exchange.
        // Setup: preflight host IPv6 loopback with the standard library, so
        // the skip can never hide an io_uring regression (a backend
        // BindFailed discards errno and must fail the test, not skip it).
        // Action: bind on [::1]:0 through the io_uring front end, dial the
        // bound address, accept, and exchange one payload in each direction.
        // Expected: both payloads round-trip byte for byte.
        if std::net::TcpListener::bind("[::1]:0").is_err() {
            // This host has no IPv6 loopback, so the io_uring path cannot be
            // exercised in this environment.
            return;
        }

        let (mut harness, network) = test_network(Config::default());
        harness.block_on(async move {
            let mut listener = network.bind("[::1]:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();
            assert!(addr.is_ipv6(), "listener must bind a v6 address");

            let ping = b"ping".to_vec();
            let pong = b"pong".to_vec();

            let server = async {
                let (remote, mut sink, mut stream) = listener.accept().await.unwrap();
                assert!(remote.is_ipv6(), "accepted peer must decode as v6");
                let received = stream.recv(4).await.unwrap();
                sink.send(b"pong".to_vec()).await.unwrap();
                received
            };

            let client = async {
                let (mut sink, mut stream) = network.dial(addr).await.unwrap();
                sink.send(b"ping".to_vec()).await.unwrap();
                stream.recv(4).await.unwrap()
            };

            let (received_ping, received_pong) = futures::join!(server, client);
            assert_eq!(received_ping.coalesce(), ping.as_slice());
            assert_eq!(received_pong.coalesce(), pong.as_slice());
        });
    }

    #[test]
    fn test_read_timeout_with_partial_data() {
        // Verify a top-level recv returns timeout after partial progress stalls.
        let op_timeout = Duration::from_millis(100);
        let (mut harness, network) = test_network(Config {
            read_write_timeout: op_timeout,
            ..Default::default()
        });
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

                // Try to read 100 bytes, but only 5 will be sent
                let start = Instant::now();
                let result = stream.recv(100).await;
                let elapsed = start.elapsed();

                (result, elapsed)
            };

            // Connect and send only partial data. Keep the connection open so
            // the reader observes a stall rather than EOF.
            let sender = async {
                let (mut sink, stream) = network.dial(addr).await.unwrap();
                sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
                (sink, stream)
            };

            let ((result, elapsed), (_sink, _stream)) = futures::join!(reader, sender);
            assert!(matches!(result, Err(Error::Timeout)));

            // Verify the timeout occurred around the expected time, with some
            // margin for timing variance.
            assert!(elapsed >= op_timeout);
            assert!(elapsed < op_timeout * 3);
        });
    }

    #[test]
    fn test_unbuffered_mode() {
        // Verify disabling the internal read buffer preserves direct recv behavior.
        let (mut harness, network) = test_network(Config {
            read_buffer_size: 0,
            ..Default::default()
        });
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Accept one connection and verify that peeking never observes
            // buffered bytes because the wrapper retains no internal read state.
            let reader = async move {
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
            };

            // Send two independent messages so the reader exercises repeated
            // direct recvs.
            let sender = async {
                let (mut sink, _stream) = network.dial(addr).await.unwrap();
                sink.send([1u8, 2, 3, 4, 5].as_slice()).await.unwrap();
                sink.send([6u8, 7, 8, 9, 10].as_slice()).await.unwrap();
                (sink, _stream)
            };

            let ((buf1, buf2), (_sink, _stream)) = futures::join!(reader, sender);
            assert_eq!(buf1.coalesce(), &[1u8, 2, 3, 4, 5]);
            assert_eq!(buf2.coalesce(), &[6u8, 7, 8, 9, 10]);
        });
    }

    #[test]
    fn test_op_fd_keeps_descriptor_alive() {
        // Verify admitted recv requests keep their socket fd alive after
        // caller cancellation: the slot's fd clone prevents the OS from
        // reusing the FD number while the kernel may still reference it.
        let op_timeout = Duration::from_millis(200);
        let (mut harness, network) = test_network(Config {
            read_write_timeout: op_timeout,
            ..Default::default()
        });

        // Keep the server halves alive so the connection stays open while the
        // client recv is in flight.
        let (_server_halves, client_sink, mut client_stream) = harness.block_on(async {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accept = async { listener.accept().await.unwrap() };
            let dial = async { network.dial(addr).await.unwrap() };
            let (server_halves, (client_sink, client_stream)) = futures::join!(accept, dial);
            (server_halves, client_sink, client_stream)
        });

        // Sink + stream + our clone.
        let fd = client_stream.fd.clone();
        assert_eq!(Arc::strong_count(&fd), 3);

        // Cancel a recv mid-flight (no data arrives): admit and submit the
        // recv, then drop the future.
        {
            let mut recv = Box::pin(client_stream.recv(1));
            assert!(poll_once(&harness, &mut recv).is_pending());
            harness.driver().turn();

            // The admitted request holds an additional clone.
            assert_eq!(Arc::strong_count(&fd), 4);
        }

        // Drop all handles. The in-flight request still retains the fd until
        // the eager cancellation retires it.
        drop(client_sink);
        drop(client_stream);
        assert_eq!(Arc::strong_count(&fd), 2); // our clone + request

        // The dropped future requested cancellation, so the fd releases
        // promptly rather than at the deadline.
        let start = Instant::now();
        while Arc::strong_count(&fd) != 1 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "cancelled recv still holds fd after {:?}",
                start.elapsed()
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
    }

    #[test]
    fn test_inflight_cancel_poisons_stream() {
        // Verify cancelling a recv whose SQE already reached the kernel
        // poisons the stream while the sink stays usable: the shared-suite
        // variant drops its recv before the loop ever turns, so only this
        // test exercises the kernel-in-flight cancel with stream poisoning.
        let (mut harness, network) = test_network(Config::default());

        // Keep the server halves alive so the connection stays open.
        let (_server_halves, mut client_sink, mut client_stream) = harness.block_on(async {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accept = async { listener.accept().await.unwrap() };
            let dial = async { network.dial(addr).await.unwrap() };
            let (server_halves, (client_sink, client_stream)) = futures::join!(accept, dial);
            (server_halves, client_sink, client_stream)
        });

        // Admit and submit the recv, then drop the future mid-flight.
        {
            let mut recv = Box::pin(client_stream.recv(1));
            assert!(poll_once(&harness, &mut recv).is_pending());
            harness.driver().turn();
        }

        harness.block_on(async {
            // The stream must be poisoned by the cancellation.
            assert!(matches!(client_stream.recv(1).await, Err(Error::Closed)));

            // The sink must remain usable.
            client_sink
                .send(crate::IoBuf::from(b"ok"))
                .await
                .expect("sink should remain usable after stream cancellation");
        });
    }

    #[test]
    fn test_peek_with_buffered_data() {
        // Verify buffered recv calls leave unread bytes visible via peek().
        let (mut harness, network) = test_network(Config::default());
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let reader = async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();

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
            };

            let sender = async {
                let (mut sink, _stream) = network.dial(addr).await.unwrap();
                sink.send(b"hello world").await.unwrap();
                (sink, _stream)
            };

            let ((), (_sink, _stream)) = futures::join!(reader, sender);
        });
    }

    #[test]
    fn test_submit_recv_returns_bytes_for_this_call() {
        // Verify `submit_recv` translates the request state's cumulative total
        // back into the per-call byte count expected by the higher-level recv loop.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let mut harness = TestLoop::new(iouring::RingConfig::default());

        // Build the wrapper directly so the test exercises `submit_recv`
        // without involving the higher-level buffered recv machinery.
        let (left, mut right) = UnixStream::pair().unwrap();
        let stream = Stream::new(
            Arc::new(left.into()),
            harness.handle.clone(),
            Duration::from_secs(1),
            0,
            pool,
        );

        // Pretend the caller already filled two bytes, then complete exactly
        // three more bytes from the socket.
        right.write_all(b"abc").unwrap();
        let buffer = IoBufMut::with_capacity(5);
        let result = harness.block_on(stream.submit_recv(
            buffer,
            2,
            3,
            true,
            Instant::now() + Duration::from_secs(1),
        ));

        // The wrapper should report only the bytes read by this invocation,
        // not the cumulative total tracked inside the request state.
        let (_buffer, read) = result.expect("submit_recv should succeed");
        assert_eq!(read, 3);
    }

    #[test]
    fn test_vectored_send_path() {
        // Verify the network send wrapper drives the vectored `Writev` path end-to-end.
        let mut harness = TestLoop::new(iouring::RingConfig::default());

        let (left, mut right) = UnixStream::pair().unwrap();
        let mut sink = Sink::new(
            Arc::new(left.into()),
            harness.handle.clone(),
            Duration::from_secs(1),
        );

        // Queue two buffers so the wrapper must preserve vectored ordering.
        let mut bufs = IoBufs::default();
        bufs.append(IoBuf::from(b"ab"));
        bufs.append(IoBuf::from(b"cd"));

        // The peer should observe the concatenated payload in-order.
        harness.block_on(sink.send(bufs)).unwrap();
        let mut buf = [0u8; 4];
        right.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcd");
    }

    #[test]
    fn test_zero_length_send_short_circuits_before_submit() {
        // Verify empty sends return locally without staging any request.
        let mut harness = TestLoop::new(iouring::RingConfig::default());
        harness.driver().close();

        // Construct a sink whose driver would fail immediately if the wrapper
        // tried to hand work to the loop.
        let (left, _right) = UnixStream::pair().unwrap();
        let mut sink = Sink::new(
            Arc::new(left.into()),
            harness.handle.clone(),
            Duration::from_secs(1),
        );

        harness.block_on(sink.send(IoBufs::default())).unwrap();
        harness.block_on(sink.send(IoBuf::default())).unwrap();
        harness.block_on(sink.send(Vec::<u8>::new())).unwrap();
    }

    #[test]
    fn test_large_recv_skips_internal_buffer() {
        // Verify reads that are at least as large as the internal buffer go
        // straight into the caller-owned output buffer.
        let (mut harness, network) = test_network(Config {
            read_buffer_size: 8,
            ..Default::default()
        });
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let expected = *b"abcdefgh";

            // Accept one connection and issue a recv that exactly matches the
            // internal buffer size, forcing the direct-recv branch.
            let reader = async move {
                let (_addr, _sink, mut stream) = listener.accept().await.unwrap();
                let received = stream.recv(expected.len()).await.unwrap();
                assert!(stream.peek(1).is_empty());
                received
            };

            let sender = async {
                let (mut sink, _stream) = network.dial(addr).await.unwrap();
                sink.send(expected.to_vec()).await.unwrap();
                (sink, _stream)
            };

            let (received, (_sink, _stream)) = futures::join!(reader, sender);
            assert_eq!(received.coalesce(), expected);
        });
    }

    #[test]
    fn test_configured_socket_options_cover_accept_and_dial_paths() {
        // Verify both dial and accept exercise the configured socket-option branches.
        let (mut harness, network) = test_network(Config {
            tcp_nodelay: Some(true),
            zero_linger: true,
            ..Default::default()
        });
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            // Accepting covers the listener-side option setters, dialing the
            // client-side ones.
            let accept = async { listener.accept().await.unwrap() };
            let dial = async { network.dial(addr).await.unwrap() };
            let (_accepted, (_sink, _stream)) = futures::join!(accept, dial);
        });
    }

    #[test]
    fn test_disabled_socket_options_cover_accept_and_dial_paths() {
        // Verify both dial and accept also cover the "do not touch socket options" branches.
        let (mut harness, network) = test_network(Config {
            tcp_nodelay: None,
            zero_linger: false,
            ..Default::default()
        });
        harness.block_on(async move {
            let mut listener = network.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = listener.local_addr().unwrap();

            let accept = async { listener.accept().await.unwrap() };
            let dial = async { network.dial(addr).await.unwrap() };
            let (_accepted, (_sink, _stream)) = futures::join!(accept, dial);
        });
    }

    #[test]
    fn test_closed_driver_fallbacks() {
        // Verify send/recv callers get wrapper-level failures once the driver
        // has closed.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let mut harness = TestLoop::new(iouring::RingConfig::default());
        harness.driver().close();

        // Send should fail locally once the driver no longer admits work.
        let (send_left, _send_right) = UnixStream::pair().unwrap();
        let mut sink = Sink::new(
            Arc::new(send_left.into()),
            harness.handle.clone(),
            Duration::from_secs(1),
        );
        assert!(matches!(
            harness.block_on(sink.send(b"hello")),
            Err(Error::SendFailed)
        ));

        // Recv should surface the symmetric wrapper-specific failure.
        let (recv_left, _recv_right) = UnixStream::pair().unwrap();
        let mut stream = Stream::new(
            Arc::new(recv_left.into()),
            harness.handle.clone(),
            Duration::from_secs(1),
            0,
            pool,
        );
        assert!(matches!(
            harness.block_on(stream.recv(1)),
            Err(Error::RecvFailed)
        ));
    }

    #[test]
    fn test_closed_driver_public_dial_and_accept() {
        // Property: the public wrappers pin two deliberately different
        // closed-driver error surfaces. `Listener::accept` maps every
        // non-timeout ticket error to Closed for tokio parity, while
        // `Network::dial` propagates the internal ConnectionFailed fallback
        // unmapped.
        // Setup: bind a listener (synchronous socket setup that needs no
        // driver), then close the driver.
        // Action: await the public accept and dial wrappers.
        // Expected: accept yields Closed and retains no pending ticket, and
        // dial yields ConnectionFailed.
        let (mut harness, network) = test_network(Config::default());
        let mut listener = harness
            .block_on(network.bind("127.0.0.1:0".parse().unwrap()))
            .unwrap();
        let addr = listener.local_addr().unwrap();

        harness.driver().close();

        // The public accept surface is Closed, not the internal fallback.
        assert!(matches!(
            harness.block_on(listener.accept()),
            Err(Error::Closed)
        ));
        assert!(
            listener.pending.is_none(),
            "a failed accept must not retain a pending ticket"
        );

        // The public dial surface keeps the internal fallback unmapped.
        assert!(matches!(
            harness.block_on(network.dial(addr)),
            Err(Error::ConnectionFailed)
        ));
    }
}
