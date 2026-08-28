//! io_uring implementation of [crate::Network].
//!
//! Socket creation, bind, and socket-option setup run synchronously. Connect,
//! accept, and non-empty sends use the ring. A recv reaches the ring only when
//! cached bytes cannot satisfy it. See [crate::iouring] for runtime requirements
//! and worker-affinity rules.
//!
//! ```text
//! bind: socket -> bind -> listen -> getsockname -> Listener       (synchronous)
//! dial: socket -> Arc<fd> -> options -> Connect waiter -> Sink + Stream
//! accept: retained Accept ticket -> Arc<fd> -> options -> Sink + Stream
//! send or uncached recv: front-end state -> waiter -> SQE/CQE -> front-end state
//! ```
//!
//! A connection's [`Sink`] and [`Stream`] share one descriptor. Dropping or
//! closing the sink performs a best-effort `SHUT_WR` only. The descriptor stays
//! open while the stream or an admitted operation still owns it. Configured
//! `TCP_NODELAY` and `SO_LINGER` changes are also best effort and failures are
//! logged rather than surfaced through `dial` or `accept`.

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

/// Default timeout for each network read, write, and in-flight accept.
const DEFAULT_READ_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Listen backlog requested for bound sockets.
///
/// The kernel caps this at `net.core.somaxconn`.
const LISTEN_BACKLOG: libc::c_int = 1024;

/// Configuration for the io_uring network backend.
#[derive(Clone, Debug)]
pub struct Config {
    /// If `Some`, requests this `TCP_NODELAY` value on each connected socket.
    ///
    /// Failure is logged and the socket keeps its system default.
    pub tcp_nodelay: Option<bool>,
    /// Whether to request zero-duration `SO_LINGER` on connected sockets.
    ///
    /// When the kernel honors this option, final descriptor close is abortive
    /// and may reset a connection with queued data. Exact reset and `TIME_WAIT`
    /// behavior remains operating-system dependent. Failure is logged and the
    /// socket keeps its system default.
    pub zero_linger: bool,
    /// Timeout for establishing an outbound TCP connection.
    ///
    /// If the timeout expires, `Network::dial` returns [`Error::Timeout`].
    /// The runtime rejects zero and values above its 30-year timer policy at startup.
    pub connect_timeout: Duration,
    /// Timeout budget applied to each top-level send/recv call and to each
    /// in-flight accept (which is transparently reissued on expiry).
    ///
    /// This is a network-level policy and is independent from io_uring loop
    /// tuning. The runtime derives the loop timeout horizon from this value
    /// and [Self::connect_timeout], so this value is never clamped.
    /// Zero and values above the runtime's 30-year timer policy are rejected at startup.
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
            read_write_timeout: DEFAULT_READ_WRITE_TIMEOUT,
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

/// Set a typed socket option.
fn set_socket_option<T>(
    fd: &OwnedFd,
    level: libc::c_int,
    option: libc::c_int,
    value: &T,
) -> Result<(), std::io::Error> {
    // SAFETY: `fd` owns a live descriptor and `value` is a valid read-only
    // input of the size supplied to the kernel.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            std::ptr::from_ref(value).cast(),
            size_of::<T>() as libc::socklen_t,
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
fn configure_socket(fd: &OwnedFd, cfg: &Config) {
    if let Some(tcp_nodelay) = cfg.tcp_nodelay
        && let Err(err) = set_socket_option(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &libc::c_int::from(tcp_nodelay),
        )
    {
        warn!(?err, "failed to set TCP_NODELAY");
    }

    if cfg.zero_linger {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        if let Err(err) = set_socket_option(fd, libc::SOL_SOCKET, libc::SO_LINGER, &linger) {
            warn!(?err, "failed to set SO_LINGER");
        }
    }
}

/// [crate::Network] front-end for one worker's io_uring driver.
#[derive(Clone)]
pub struct Network {
    /// Socket policy and operation timeouts.
    cfg: Config,
    /// Affine driver used by connect, accept, send, and recv operations.
    driver_handle: iouring::DriverHandle,
    /// Pool used for connection receive buffers and returned payloads.
    pool: BufferPool,
}

impl Network {
    /// Return a network front-end that submits operations through `driver_handle`.
    ///
    /// Each admitted send, recv, accept, or connect consumes one waiter slot.
    /// When no unreserved slot remains, later operations wait in FIFO admission
    /// order rather than entering the ring immediately.
    pub(crate) const fn new(
        cfg: Config,
        driver_handle: iouring::DriverHandle,
        pool: BufferPool,
    ) -> Self {
        Self {
            cfg,
            driver_handle,
            pool,
        }
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.driver_handle.assert_owner();
        let fd = new_socket(&socket).map_err(|_| Error::BindFailed)?;
        set_socket_option(
            &fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &libc::c_int::from(true),
        )
        .map_err(|_| Error::BindFailed)?;
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
            cfg: self.cfg.clone(),
            fd: Arc::new(fd),
            local_addr,
            driver_handle: self.driver_handle.clone(),
            pool: self.pool.clone(),
            pending_accept: None,
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), Error> {
        self.driver_handle.assert_owner();
        let fd = Arc::new(new_socket(&socket).map_err(|_| Error::ConnectionFailed)?);

        configure_socket(&fd, &self.cfg);

        let deadline = Instant::now() + self.cfg.connect_timeout;
        self.driver_handle
            .connect(fd.clone(), socket, deadline)
            .await?;

        Ok((
            Sink::new(
                fd.clone(),
                self.driver_handle.clone(),
                self.cfg.read_write_timeout,
            ),
            Stream::new(
                fd,
                self.driver_handle.clone(),
                self.cfg.read_write_timeout,
                self.cfg.read_buffer_size,
                self.pool.clone(),
            ),
        ))
    }
}

/// Implementation of [crate::Listener] for an io-uring [Network].
pub struct Listener {
    /// Socket policy inherited by accepted connections.
    cfg: Config,
    /// Listening socket descriptor, shared with in-flight accept requests.
    fd: Arc<OwnedFd>,
    /// Address reported after binding, including a kernel-selected port.
    local_addr: SocketAddr,
    /// Affine driver used by retained accept tickets.
    driver_handle: iouring::DriverHandle,
    /// Pool inherited by streams created from accepted connections.
    pool: BufferPool,
    /// In-flight accept, retained so a cancelled accept future resumes the
    /// same request instead of losing an accepted connection.
    ///
    /// A connection accepted between `accept` calls moves into the ticket's
    /// Ready ticket entry until the next call takes it or the listener
    /// drops. The request's waiter slot is already free at that point.
    pending_accept: Option<iouring::AcceptTicket>,
}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        loop {
            if self.pending_accept.is_none() {
                let deadline = Instant::now() + self.cfg.read_write_timeout;
                self.pending_accept = Some(
                    self.driver_handle
                        .start_accept(self.fd.clone(), deadline)
                        .await,
                );
            }

            // Wait on the in-flight accept. If this future is dropped, the
            // ticket stays in `self.pending_accept` and the next call resumes it.
            let ticket = self
                .pending_accept
                .as_mut()
                .expect("pending accept was just set");
            let result = ticket.await;
            self.pending_accept = None;
            match result {
                Ok((fd, remote_addr)) => {
                    let fd = Arc::new(fd);
                    configure_socket(&fd, &self.cfg);
                    return Ok((
                        remote_addr,
                        Sink::new(
                            fd.clone(),
                            self.driver_handle.clone(),
                            self.cfg.read_write_timeout,
                        ),
                        Stream::new(
                            fd,
                            self.driver_handle.clone(),
                            self.cfg.read_write_timeout,
                            self.cfg.read_buffer_size,
                            self.pool.clone(),
                        ),
                    ));
                }
                // The deadline bounds how long an unpolled accept can occupy a
                // waiter slot. An expired accept is simply reissued.
                Err(Error::Timeout) => continue,
                // Match the tokio backend's contract: every accept failure
                // surfaces as `Error::Closed`, so portable callers observe
                // the same error regardless of runtime.
                Err(_) => return Err(Error::Closed),
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.driver_handle.assert_owner();
        Ok(self.local_addr)
    }
}

/// Write half of an io_uring TCP connection.
///
/// Shares its descriptor with the peer [`Stream`]. Drop closes only the write
/// direction through a best-effort `SHUT_WR`.
pub struct Sink {
    /// Shared socket descriptor backing this sink half.
    fd: Arc<OwnedFd>,
    /// Affine driver used by non-empty sends.
    driver_handle: iouring::DriverHandle,
    /// Timeout budget for a top-level send call.
    timeout: Duration,
    /// Cancellation-sensitive send lifecycle.
    state: SinkState,
}

/// Lifecycle state for the write-half of a connection.
enum SinkState {
    /// Ready to begin a send.
    Open,
    /// A send future is in progress. Dropping it makes the sink unusable.
    Sending,
    /// No further sends are permitted.
    Closed,
}

impl Sink {
    /// Construct an open sink for one shared socket descriptor.
    const fn new(
        fd: Arc<OwnedFd>,
        driver_handle: iouring::DriverHandle,
        timeout: Duration,
    ) -> Self {
        Self {
            fd,
            driver_handle,
            timeout,
            state: SinkState::Open,
        }
    }

    /// Mark the sink closed and request write-half shutdown once.
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
        self.driver_handle.assert_owner();
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
            .driver_handle
            .send(self.fd.clone(), bufs, Instant::now() + self.timeout)
            .await;

        if result.is_err() {
            self.close();
            return result;
        }

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
    /// Affine driver used when buffered bytes cannot satisfy a recv.
    driver_handle: iouring::DriverHandle,
    /// Timeout budget for a top-level recv call.
    timeout: Duration,
    /// Tracks whether a previous recv failure has made this stream unusable.
    poisoned: bool,
    /// Reusable read-ahead buffer.
    buffer: IoBufMut,
    /// Next unread byte in `buffer`.
    buffer_pos: usize,
    /// End of initialized data in `buffer`.
    buffer_len: usize,
    /// Pool used for returned recv payloads and temporary coalescing buffers.
    pool: BufferPool,
}

impl Stream {
    /// Construct an empty stream buffer for one shared socket descriptor.
    fn new(
        fd: Arc<OwnedFd>,
        driver_handle: iouring::DriverHandle,
        timeout: Duration,
        buffer_capacity: usize,
        pool: BufferPool,
    ) -> Self {
        Self {
            fd,
            driver_handle,
            timeout,
            poisoned: false,
            buffer: IoBufMut::with_capacity(buffer_capacity),
            buffer_pos: 0,
            buffer_len: 0,
            pool,
        }
    }

    /// Fills the internal buffer by reading from the socket via io_uring.
    async fn fill_buffer(&mut self, deadline: Instant) -> Result<usize, Error> {
        self.buffer_pos = 0;
        self.buffer_len = 0;

        let buffer = std::mem::take(&mut self.buffer);
        let len = buffer.capacity();

        self.buffer_len = match self
            .driver_handle
            .recv(self.fd.clone(), buffer, 0, len, false, deadline)
            .await
        {
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
        self.driver_handle.assert_owner();
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
                        .driver_handle
                        .recv(
                            self.fd.clone(),
                            owned_buf,
                            bytes_received,
                            len,
                            true,
                            deadline,
                        )
                        .await
                    {
                        Ok((buf, total)) => {
                            owned_buf = buf;
                            bytes_received = total;
                        }
                        Err((_, err)) => return Err(err),
                    }
                } else {
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
        self.driver_handle.assert_owner();
        let buffered = self.buffer_len - self.buffer_pos;
        let len = std::cmp::min(buffered, max_len);
        &self.buffer.as_ref()[self.buffer_pos..self.buffer_pos + len]
    }
}

#[cfg(test)]
#[path = "iouring_tests.rs"]
mod tests;
