//! Request types and state machines for the io_uring loop.
//!
//! Callers submit logical operations through the driver, which constructs a
//! [Request] that owns all resources (buffers, FDs, progress cursors) needed
//! to build follow-up SQEs and produce a typed [Output].

use super::waiter::{WaiterId, WaiterState};
use crate::{Buf, Error, IoBuf, IoBufMut, IoBufs};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types::Fd};
use std::{
    fs::File,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::Instant,
};

/// Cap iovec batch size: larger iovecs reduce syscall count but increase
/// per-write kernel setup overhead.
const IOVEC_BATCH_SIZE: usize = 32;

/// Normalized write buffer for [SendRequest] and [WriteAtRequest].
///
/// Preserves a single-buffer fast path and a vectored path with reusable
/// iovec scratch space. The vectored payload is boxed to keep the single
/// path (and every [Request]) small: that path already allocates for its
/// iovec scratch, so the box adds no allocation to an allocation-free path.
pub(super) enum WriteBuffers {
    Single { buf: IoBuf },
    Vectored(Box<VectoredBuffers>),
}

/// Buffers and iovec scratch for a vectored write.
pub(super) struct VectoredBuffers {
    bufs: IoBufs,
    iovecs: Box<[libc::iovec]>,
}

impl From<IoBufs> for WriteBuffers {
    /// Normalize caller-provided buffers into either a single-buffer fast path
    /// or a vectored representation with reusable iovec scratch space.
    fn from(bufs: IoBufs) -> Self {
        match bufs.try_into_single() {
            Ok(buf) => Self::Single { buf },
            Err(bufs) => {
                let max_iovecs = bufs.chunk_count().min(IOVEC_BATCH_SIZE);
                let iovecs: Box<[libc::iovec]> = std::iter::repeat_n(
                    libc::iovec {
                        iov_base: std::ptr::NonNull::<u8>::dangling().as_ptr().cast(),
                        iov_len: 0,
                    },
                    max_iovecs,
                )
                .collect();
                Self::Vectored(Box::new(VectoredBuffers { bufs, iovecs }))
            }
        }
    }
}

impl WriteBuffers {
    /// Return the remaining number of bytes that still need to be written.
    fn remaining_len(&self) -> usize {
        match self {
            Self::Single { buf } => buf.len(),
            Self::Vectored(v) => v.bufs.len(),
        }
    }

    /// Return whether all bytes have been consumed by completed writes.
    fn is_complete(&self) -> bool {
        self.remaining_len() == 0
    }

    /// Advance the remaining bytes after a successful CQE.
    fn advance(&mut self, n: usize) {
        match self {
            Self::Single { buf } => buf.advance(n),
            Self::Vectored(v) => v.bufs.advance(n),
        }
    }
}

/// In-flight request state machine stored in the waiter table.
///
/// Each variant owns all buffers and FDs needed by the kernel plus progress
/// cursors. The loop calls [build_sqe](Self::build_sqe) to produce the next
/// SQE and [on_cqe](Self::on_cqe) to evaluate completions and produce the
/// terminal [Output]. [timeout](Self::timeout) and [fail](Self::fail)
/// resolve requests the kernel never completed.
///
// SAFETY: `WriteBuffers::Vectored` owns both the `IoBufs` backing storage and
// the scratch `libc::iovec` array used to describe it to the kernel. The
// iovec entries are initialized with dangling pointers and may be stale
// between `build_sqe` calls, but they are never dereferenced in Rust. Each
// `build_sqe` refreshes them from the co-owned `IoBufs` immediately before the
// kernel can observe them, and the backing buffers remain owned by the same
// waiter slot for the request lifetime.
unsafe impl Send for Request {}

pub(super) enum Request {
    Send(SendRequest),
    Recv(RecvRequest),
    Accept(AcceptRequest),
    Connect(ConnectRequest),
    ReadAt(ReadAtRequest),
    WriteAt(WriteAtRequest),
    Sync(SyncRequest),
}

/// Terminal result of a logical request, parked in the waiter slot until the
/// owning ticket takes it.
///
/// Buffers travel inside the payloads (including error variants), so ownership
/// always returns to the caller once the kernel has retired the operation.
/// Error payloads are boxed: [enum@Error] is large, errors are cold, and outputs
/// move through the waiter slot on every operation, so success-path moves
/// should not pay for error-variant width.
pub(super) enum Output {
    Send(Result<(), Box<Error>>),
    Recv(Result<(IoBufMut, usize), Box<(IoBufMut, Error)>>),
    Accept(Result<(OwnedFd, SocketAddr), Box<Error>>),
    Connect(Result<(), Box<Error>>),
    ReadAt(Result<IoBufMut, Box<(IoBufMut, Error)>>),
    WriteAt(Result<(), Box<Error>>),
    Sync(Result<(), Box<Error>>),
}

impl Request {
    /// Return the deadline for this request, if any.
    pub const fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Send(r) => r.deadline,
            Self::Recv(r) => r.deadline,
            Self::Accept(r) => r.deadline,
            Self::Connect(r) => r.deadline,
            Self::ReadAt(_) | Self::WriteAt(_) | Self::Sync(_) => None,
        }
    }

    /// Return whether this request carries a deadline.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn has_deadline(&self) -> bool {
        self.deadline().is_some()
    }

    /// Return whether an orphaned ticket stops this request from driving
    /// follow-up SQEs.
    ///
    /// Storage write/sync behavior stays aligned with `storage/tokio/unix.rs`,
    /// where spawned blocking work continues running after caller drop, so
    /// those kinds keep making progress even without an observer.
    pub const fn orphan_stops_progress(&self) -> bool {
        match self {
            Self::Send(_)
            | Self::Recv(_)
            | Self::Accept(_)
            | Self::Connect(_)
            | Self::ReadAt(_) => true,
            Self::WriteAt(_) | Self::Sync(_) => false,
        }
    }

    /// Build the next SQE for this request, tagged with `waiter_id`.
    pub fn build_sqe(&mut self, waiter_id: WaiterId) -> SqueueEntry {
        let sqe = match self {
            Self::Send(s) => s.build_sqe(),
            Self::Recv(r) => r.build_sqe(),
            Self::Accept(a) => a.build_sqe(),
            Self::Connect(c) => c.build_sqe(),
            Self::ReadAt(r) => r.build_sqe(),
            Self::WriteAt(w) => w.build_sqe(),
            Self::Sync(s) => s.build_sqe(),
        };
        sqe.user_data(waiter_id.user_data())
    }

    /// Evaluate a CQE result against this request's progress and state.
    ///
    /// Returns the terminal [Output] when the request completed (buffers move
    /// out of the request, leaving an empty shell for the caller to drop in
    /// place), or `None` when another SQE is needed.
    pub fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Output> {
        match self {
            Self::Send(s) => s
                .on_cqe(state, result)
                .map(|r| Output::Send(r.map_err(Box::new))),
            Self::Recv(r) => {
                let result = r.on_cqe(state, result)?;
                let buf = std::mem::take(&mut r.buf);
                Some(Output::Recv(match result {
                    Ok(read) => Ok((buf, read)),
                    Err(err) => Err(Box::new((buf, err))),
                }))
            }
            Self::Accept(a) => a
                .on_cqe(state, result)
                .map(|r| Output::Accept(r.map_err(Box::new))),
            Self::Connect(c) => c
                .on_cqe(state, result)
                .map(|r| Output::Connect(r.map_err(Box::new))),
            Self::ReadAt(r) => {
                let result = r.on_cqe(state, result)?;
                let buf = std::mem::take(&mut r.buf);
                Some(Output::ReadAt(match result {
                    Ok(()) => Ok(buf),
                    Err(err) => Err(Box::new((buf, err))),
                }))
            }
            Self::WriteAt(w) => w
                .on_cqe(state, result)
                .map(|r| Output::WriteAt(r.map_err(Box::new))),
            Self::Sync(s) => s
                .on_cqe(state, result)
                .map(|r| Output::Sync(r.map_err(Box::new))),
        }
    }

    /// Return the failure result for a request that was never admitted (the
    /// driver closed before staging).
    ///
    /// Every kind resolves to its staging failure; syncs report [Error::Closed]
    /// because a sync that never ran must not report success.
    pub fn fail(self) -> Output {
        match self {
            Self::Send(_) => Output::Send(Err(Box::new(Error::SendFailed))),
            Self::Recv(r) => Output::Recv(Err(Box::new((r.buf, Error::RecvFailed)))),
            Self::Accept(_) => Output::Accept(Err(Box::new(Error::ConnectionFailed))),
            Self::Connect(_) => Output::Connect(Err(Box::new(Error::ConnectionFailed))),
            Self::ReadAt(r) => Output::ReadAt(Err(Box::new((r.buf, Error::ReadFailed)))),
            Self::WriteAt(_) => Output::WriteAt(Err(Box::new(Error::WriteFailed))),
            Self::Sync(_) => Output::Sync(Err(Box::new(Error::Closed))),
        }
    }

    /// Return a timeout result, moving any owned buffer out of the request.
    /// Used when a deadline expires before the current SQE could complete.
    pub fn timeout(&mut self) -> Output {
        match self {
            Self::Send(_) => Output::Send(Err(Box::new(Error::Timeout))),
            Self::Recv(r) => {
                Output::Recv(Err(Box::new((std::mem::take(&mut r.buf), Error::Timeout))))
            }
            Self::Accept(_) => Output::Accept(Err(Box::new(Error::Timeout))),
            Self::Connect(_) => Output::Connect(Err(Box::new(Error::Timeout))),
            Self::ReadAt(r) => {
                Output::ReadAt(Err(Box::new((std::mem::take(&mut r.buf), Error::Timeout))))
            }
            Self::WriteAt(_) => Output::WriteAt(Err(Box::new(Error::Timeout))),
            Self::Sync(_) => Output::Sync(Err(Box::new(Error::Timeout))),
        }
    }
}

/// Shared classification of a CQE result for the request state machines.
///
/// `CqeResult::from_raw` collapses the raw io_uring result space into the small
/// set of cases the per-request state machines care about:
/// - `EAGAIN`, `EWOULDBLOCK`, and `EINTR` become [`CqeResult::Retry`]
/// - `ECANCELED` becomes [`CqeResult::Cancelled`] only when the waiter was
///   already in [`WaiterState::CancelRequested`]
/// - other negative results stay as [`CqeResult::Error`]
/// - zero stays distinct because some request kinds treat it differently from
///   a hard error
/// - positive results carry their byte or item count as [`CqeResult::Positive`]
///
/// This helper intentionally does not assign request-specific meaning beyond
/// that normalization. For example, [`CqeResult::Zero`] means EOF for reads
/// and recvs, but success for fsync.
enum CqeResult {
    /// Transient kernel result that may be retried with another SQE.
    Retry,
    /// `ECANCELED` for an operation whose waiter had already timed out and
    /// requested async cancellation.
    Cancelled,
    /// Non-retryable negative CQE result code.
    Error(i32),
    /// Successful CQE with zero progress.
    Zero,
    /// Successful CQE with positive progress.
    Positive(usize),
}

impl CqeResult {
    /// Build a classified result from a raw CQE result code and waiter state.
    const fn from_raw(result: i32, state: WaiterState) -> Self {
        // Transient "try again later" results:
        // - EAGAIN / EWOULDBLOCK: no data or capacity was ready yet
        // - EINTR: interrupted before completion
        if result == -libc::EAGAIN || result == -libc::EWOULDBLOCK || result == -libc::EINTR {
            Self::Retry
        } else if result == -libc::ECANCELED && matches!(state, WaiterState::CancelRequested) {
            Self::Cancelled
        } else if result < 0 {
            Self::Error(result)
        } else if result == 0 {
            Self::Zero
        } else {
            Self::Positive(result as usize)
        }
    }
}

/// Logical network send request and its in-loop state.
pub(super) struct SendRequest {
    /// Socket used by the current send SQE.
    pub(super) fd: Arc<OwnedFd>,
    /// Write cursor and buffers that still need to be sent.
    pub(super) write: WriteBuffers,
    /// Absolute deadline for the whole logical request.
    pub(super) deadline: Option<Instant>,
}

impl SendRequest {
    /// Build the next socket send SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        match &mut self.write {
            WriteBuffers::Single { buf } => {
                let ptr = buf.as_ptr();
                let remaining = buf.remaining();
                opcode::Send::new(
                    fd,
                    ptr,
                    remaining
                        .try_into()
                        .expect("single-buffer SQE length exceeds u32"),
                )
                .build()
            }
            WriteBuffers::Vectored(v) => {
                let max_iovecs = v.bufs.chunk_count().min(v.iovecs.len());
                // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        v.iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
                        max_iovecs,
                    )
                };
                let iovecs_len = v
                    .bufs
                    .chunks_vectored(io_slices)
                    .try_into()
                    .expect("iovecs_len exceeds u32");

                // `Writev` is sufficient here because network sends only need
                // ordered byte delivery; this layer does not need sendmsg
                // ancillary data or zerocopy completion management.
                opcode::Writev::new(fd, v.iovecs.as_ptr(), iovecs_len).build()
            }
        }
    }

    /// Classify one send CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if matches!(state, WaiterState::CancelRequested) => {
                Some(Err(Error::Timeout))
            }
            CqeResult::Retry => None,
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(_) | CqeResult::Zero => Some(Err(Error::SendFailed)),
            CqeResult::Positive(n) => {
                self.write.advance(n);
                if self.write.is_complete() {
                    Some(Ok(()))
                } else if matches!(state, WaiterState::CancelRequested) {
                    // Any send error after partial progress means some prefix
                    // of the frame may already be on the wire. Callers must
                    // drop the connection rather than retrying on this sink.
                    Some(Err(Error::Timeout))
                } else {
                    None
                }
            }
        }
    }
}

/// Logical network recv request and its in-loop state.
pub(super) struct RecvRequest {
    /// Socket used by the current recv SQE.
    pub(super) fd: Arc<OwnedFd>,
    /// Destination buffer owned by the request.
    pub(super) buf: IoBufMut,
    /// Byte offset into `buf` where the next recv should write.
    pub(super) offset: usize,
    /// Total recv target, including any existing filled prefix before `offset`.
    pub(super) len: usize,
    /// Whether the recv must fill the full target before succeeding.
    pub(super) exact: bool,
    /// Absolute deadline for the whole logical request.
    pub(super) deadline: Option<Instant>,
}

impl RecvRequest {
    /// Build the next socket recv SQE for the unread suffix of the target.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        assert!(
            self.offset <= self.len && self.len <= self.buf.capacity(),
            "recv invariant violated: need offset <= len <= capacity"
        );
        // SAFETY: buf is an IoBufMut with stable memory.
        // offset <= len <= capacity.
        let ptr = unsafe { self.buf.as_mut_ptr().add(self.offset) };
        let remaining = self.len - self.offset;
        opcode::Recv::new(
            fd,
            ptr,
            remaining
                .try_into()
                .expect("single-buffer SQE length exceeds u32"),
        )
        .build()
    }

    /// Classify one recv CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<usize, Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if matches!(state, WaiterState::CancelRequested) => {
                Some(Err(Error::Timeout))
            }
            CqeResult::Retry => None,
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(_) | CqeResult::Zero => Some(Err(Error::RecvFailed)),
            CqeResult::Positive(n) => {
                let remaining = self.len - self.offset;
                assert!(
                    n <= remaining,
                    "recv CQE exceeds requested length: n={n} remaining={remaining}"
                );
                self.offset += n;
                if !self.exact || self.offset >= self.len {
                    Some(Ok(self.offset))
                } else if matches!(state, WaiterState::CancelRequested) {
                    Some(Err(Error::Timeout))
                } else {
                    None
                }
            }
        }
    }
}

/// Logical positioned file read request and its in-loop state.
pub(super) struct ReadAtRequest {
    /// File used by the current read SQE.
    pub(super) file: Arc<File>,
    /// Starting file offset for the logical read.
    pub(super) offset: u64,
    /// Total number of bytes requested.
    pub(super) len: usize,
    /// Bytes already read into `buf`.
    pub(super) read: usize,
    /// Destination buffer owned by the request.
    pub(super) buf: IoBufMut,
}

impl ReadAtRequest {
    /// Build the next positioned read SQE for the unread suffix of the target.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        assert!(
            self.read <= self.len && self.len <= self.buf.capacity(),
            "read_at invariant violated: need read <= len <= capacity"
        );
        // SAFETY: buf is an IoBufMut with stable memory. read <= len <= capacity.
        let ptr = unsafe { self.buf.as_mut_ptr().add(self.read) };
        let remaining = self.len - self.read;
        let offset = self.offset + self.read as u64;
        opcode::Read::new(
            fd,
            ptr,
            remaining
                .try_into()
                .expect("single-buffer SQE length exceeds u32"),
        )
        .offset(offset)
        .build()
    }

    /// Classify one read CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Cancelled | CqeResult::Error(_) => Some(Err(Error::ReadFailed)),
            CqeResult::Zero => Some(Err(Error::BlobInsufficientLength)),
            CqeResult::Positive(n) => {
                let remaining = self.len - self.read;
                assert!(
                    n <= remaining,
                    "read CQE exceeds requested length: n={n} remaining={remaining}"
                );
                self.read += n;
                if self.read >= self.len {
                    Some(Ok(()))
                } else {
                    None
                }
            }
        }
    }
}

/// Logical positioned file write request and its in-loop state.
pub(super) struct WriteAtRequest {
    /// File used by the current write SQE.
    pub(super) file: Arc<File>,
    /// Starting file offset for the logical write.
    pub(super) offset: u64,
    /// Bytes already written successfully.
    pub(super) written: usize,
    /// Write cursor and buffers that still need to be written.
    pub(super) write: WriteBuffers,
    /// Whether the write should be durably persisted before completion.
    pub(super) sync: bool,
}

impl WriteAtRequest {
    /// Return the flags for this write request, setting `RWF_SYNC` when `sync` is set.
    const fn rw_flags(&self) -> i32 {
        if self.sync { libc::RWF_SYNC } else { 0 }
    }

    /// Build the next positioned write SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        let offset = self.offset + self.written as u64;
        let rw_flags = self.rw_flags();
        match &mut self.write {
            WriteBuffers::Single { buf } => {
                let ptr = buf.as_ptr();
                let remaining = buf.remaining();
                opcode::Write::new(
                    fd,
                    ptr,
                    remaining
                        .try_into()
                        .expect("single-buffer SQE length exceeds u32"),
                )
                .offset(offset)
                .rw_flags(rw_flags)
                .build()
            }
            WriteBuffers::Vectored(v) => {
                let max_iovecs = v.bufs.chunk_count().min(v.iovecs.len());
                // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        v.iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
                        max_iovecs,
                    )
                };
                let iovecs_len = v
                    .bufs
                    .chunks_vectored(io_slices)
                    .try_into()
                    .expect("iovecs_len exceeds u32");

                opcode::Writev::new(fd, v.iovecs.as_ptr(), iovecs_len)
                    .offset(offset)
                    .rw_flags(rw_flags)
                    .build()
            }
        }
    }

    /// Classify one write CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Cancelled | CqeResult::Error(_) | CqeResult::Zero => {
                Some(Err(Error::WriteFailed))
            }
            CqeResult::Positive(n) => {
                self.written += n;
                self.write.advance(n);
                if self.write.is_complete() {
                    Some(Ok(()))
                } else {
                    None
                }
            }
        }
    }
}

/// Raw socket address storage passed to the kernel.
///
/// Requests box this so the pointers handed to the kernel stay stable for the
/// request lifetime. Serves as an output parameter for accept and getsockname,
/// and an input parameter for connect and bind.
pub(crate) struct RawSocketAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl RawSocketAddr {
    /// Return zeroed scratch for the kernel to fill.
    pub(crate) const fn new_zeroed() -> Self {
        Self {
            // SAFETY: `sockaddr_storage` is plain old data for which zeroes are
            // a valid (if empty) representation.
            storage: unsafe { std::mem::zeroed() },
            len: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        }
    }

    /// Return boxed zeroed scratch for the kernel to fill during accept.
    pub(super) fn zeroed() -> Box<Self> {
        Box::new(Self::new_zeroed())
    }

    /// Return a pointer to the underlying `sockaddr` for kernel reads.
    pub(crate) const fn as_sockaddr_ptr(&self) -> *const libc::sockaddr {
        (&raw const self.storage).cast::<libc::sockaddr>()
    }

    /// Return a pointer to the underlying `sockaddr` for kernel writes.
    pub(crate) const fn as_sockaddr_mut_ptr(&mut self) -> *mut libc::sockaddr {
        (&raw mut self.storage).cast::<libc::sockaddr>()
    }

    /// Return the encoded address length.
    pub(crate) const fn len(&self) -> libc::socklen_t {
        self.len
    }

    /// Return a mutable reference to the address length for kernel writes.
    pub(crate) const fn len_mut(&mut self) -> &mut libc::socklen_t {
        &mut self.len
    }

    /// Encode `addr` for the kernel to read during connect or bind.
    pub(crate) fn boxed_from_socket_addr(addr: &SocketAddr) -> Box<Self> {
        Box::new(Self::from_socket_addr(addr))
    }

    /// Encode `addr` for the kernel to read during connect or bind.
    pub(crate) const fn from_socket_addr(addr: &SocketAddr) -> Self {
        let mut raw = Self::new_zeroed();
        match addr {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        // `s_addr` is stored in network byte order, which the
                        // octets already are.
                        s_addr: u32::from_ne_bytes(v4.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: `sockaddr_in` fits within `sockaddr_storage` and the
                // destination is valid for writes.
                unsafe {
                    std::ptr::write((&raw mut raw.storage).cast::<libc::sockaddr_in>(), sin);
                }
                raw.len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            }
            SocketAddr::V6(v6) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    },
                    sin6_scope_id: v6.scope_id(),
                };
                // SAFETY: `sockaddr_in6` fits within `sockaddr_storage` and the
                // destination is valid for writes.
                unsafe {
                    std::ptr::write((&raw mut raw.storage).cast::<libc::sockaddr_in6>(), sin6);
                }
                raw.len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            }
        }
        raw
    }

    /// Decode the kernel-written address, if it is a valid TCP peer address.
    pub(crate) fn to_socket_addr(&self) -> Option<SocketAddr> {
        match i32::from(self.storage.ss_family) {
            libc::AF_INET => {
                if (self.len as usize) < size_of::<libc::sockaddr_in>() {
                    return None;
                }
                // SAFETY: the family and length checks above guarantee the
                // storage holds an initialized `sockaddr_in`.
                let sin = unsafe { &*(&raw const self.storage).cast::<libc::sockaddr_in>() };
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                if (self.len as usize) < size_of::<libc::sockaddr_in6>() {
                    return None;
                }
                // SAFETY: the family and length checks above guarantee the
                // storage holds an initialized `sockaddr_in6`.
                let sin6 = unsafe { &*(&raw const self.storage).cast::<libc::sockaddr_in6>() };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

/// Logical accept request and its in-loop state.
pub(super) struct AcceptRequest {
    /// Listening socket used by the accept SQE.
    pub(super) fd: Arc<OwnedFd>,
    /// Peer address scratch filled by the kernel on completion.
    pub(super) addr: Box<RawSocketAddr>,
    /// Absolute deadline for the whole logical request.
    ///
    /// Accept callers treat expiry as a cue to re-issue the accept, so the
    /// deadline also bounds how long an abandoned accept can occupy a waiter
    /// slot.
    pub(super) deadline: Option<Instant>,
}

impl AcceptRequest {
    /// Build the accept SQE for this request.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        // The kernel treats the address length as an in/out parameter, so it
        // must be reset before every submission.
        self.addr.len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        opcode::Accept::new(
            fd,
            (&raw mut self.addr.storage).cast::<libc::sockaddr>(),
            &raw mut self.addr.len,
        )
        .flags(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK)
        .build()
    }

    /// Classify one accept CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(
        &mut self,
        state: WaiterState,
        result: i32,
    ) -> Option<Result<(OwnedFd, SocketAddr), Error>> {
        // A non-negative result is a newly accepted descriptor. Take ownership
        // immediately, even when cancellation raced the completion, so an
        // accepted connection is never leaked.
        if result >= 0 {
            // SAFETY: a non-negative accept CQE result is a fresh descriptor
            // owned by no one else.
            let fd = unsafe { OwnedFd::from_raw_fd(result) };
            return Some(
                self.addr
                    .to_socket_addr()
                    .map_or_else(|| Err(Error::ConnectionFailed), |addr| Ok((fd, addr))),
            );
        }
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if matches!(state, WaiterState::CancelRequested) => {
                Some(Err(Error::Timeout))
            }
            CqeResult::Retry => None,
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(_) => Some(Err(Error::ConnectionFailed)),
            CqeResult::Zero | CqeResult::Positive(_) => {
                unreachable!("non-negative accept results are handled above")
            }
        }
    }
}

/// Logical connect request and its in-loop state.
pub(super) struct ConnectRequest {
    /// Socket being connected by the connect SQE.
    pub(super) fd: Arc<OwnedFd>,
    /// Target address read by the kernel.
    pub(super) addr: Box<RawSocketAddr>,
    /// Absolute deadline for the whole logical request.
    pub(super) deadline: Option<Instant>,
}

impl ConnectRequest {
    /// Build the connect SQE for this request.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        opcode::Connect::new(
            fd,
            (&raw const self.addr.storage).cast::<libc::sockaddr>(),
            self.addr.len,
        )
        .build()
    }

    /// Classify one connect CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    const fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if matches!(state, WaiterState::CancelRequested) => {
                Some(Err(Error::Timeout))
            }
            CqeResult::Retry => None,
            // A reissued connect may observe the previous attempt still in
            // progress or already established. Neither is terminal failure.
            CqeResult::Error(code) if code == -libc::EALREADY => None,
            CqeResult::Error(code) if code == -libc::EISCONN => Some(Ok(())),
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(_) => Some(Err(Error::ConnectionFailed)),
            CqeResult::Zero | CqeResult::Positive(_) => Some(Ok(())),
        }
    }
}

/// Logical fsync request and its in-loop state.
pub(super) struct SyncRequest {
    /// File descriptor to sync.
    pub(super) file: Arc<File>,
}

impl SyncRequest {
    /// Build the fsync SQE for this request.
    fn build_sqe(&self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        opcode::Fsync::new(fd).build()
    }

    /// Classify one fsync CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Cancelled => {
                let err = std::io::Error::from_raw_os_error(libc::ECANCELED);
                Some(Err(Error::Io(err.into())))
            }
            CqeResult::Error(code) => {
                let err = std::io::Error::from_raw_os_error(-code);
                Some(Err(Error::Io(err.into())))
            }
            CqeResult::Zero | CqeResult::Positive(_) => Some(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::{
            fd::{FromRawFd, IntoRawFd},
            unix::net::UnixStream,
        },
        panic::{AssertUnwindSafe, catch_unwind},
    };

    fn make_socket_fd() -> Arc<OwnedFd> {
        let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
        Arc::new(left.into())
    }

    fn make_file_fd() -> Arc<File> {
        let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
        // SAFETY: `left` is a valid owned fd and is transferred into `File`.
        let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
        Arc::new(file)
    }

    fn unwrap_send(output: Output) -> Result<(), Error> {
        match output {
            Output::Send(result) => result.map_err(|e| *e),
            _ => panic!("expected send output"),
        }
    }

    fn unwrap_recv(output: Output) -> Result<(IoBufMut, usize), (IoBufMut, Error)> {
        match output {
            Output::Recv(result) => result.map_err(|e| *e),
            _ => panic!("expected recv output"),
        }
    }

    fn unwrap_read_at(output: Output) -> Result<IoBufMut, (IoBufMut, Error)> {
        match output {
            Output::ReadAt(result) => result.map_err(|e| *e),
            _ => panic!("expected read-at output"),
        }
    }

    fn unwrap_write_at(output: Output) -> Result<(), Error> {
        match output {
            Output::WriteAt(result) => result.map_err(|e| *e),
            _ => panic!("expected write-at output"),
        }
    }

    fn unwrap_sync(output: Output) -> Result<(), Error> {
        match output {
            Output::Sync(result) => result.map_err(|e| *e),
            _ => panic!("expected sync output"),
        }
    }

    #[test]
    fn test_cqe_result_from_raw_retryable_codes() {
        for code in [-libc::EAGAIN, -libc::EWOULDBLOCK, -libc::EINTR] {
            assert!(matches!(
                CqeResult::from_raw(code, WaiterState::Active { target_tick: None }),
                CqeResult::Retry
            ));
        }

        for code in [0, -libc::EINVAL, -libc::ETIMEDOUT] {
            assert!(!matches!(
                CqeResult::from_raw(code, WaiterState::Active { target_tick: None }),
                CqeResult::Retry
            ));
        }
    }

    #[test]
    fn test_request_deadline_helpers_and_invariants() {
        // Verify deadline helpers only report deadlines for network requests and
        // that invalid low-level request shapes still fail before reaching the kernel.
        // Network requests carry optional deadlines that should be surfaced.
        let send_deadline = Instant::now();
        let send = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: Some(send_deadline),
        });
        assert_eq!(send.deadline(), Some(send_deadline));
        assert!(send.has_deadline());

        let recv_deadline = Instant::now();
        let recv = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(8),
            offset: 0,
            len: 8,
            exact: true,
            deadline: Some(recv_deadline),
        });
        assert_eq!(recv.deadline(), Some(recv_deadline));
        assert!(recv.has_deadline());

        let read = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 4,
            read: 0,
            buf: IoBufMut::with_capacity(4),
        });
        assert_eq!(read.deadline(), None);
        assert!(!read.has_deadline());

        // Invalid request shapes should still panic as soon as low-level SQE
        // construction would observe them.
        let recv_overread = std::panic::catch_unwind(|| {
            let mut request = Request::Recv(RecvRequest {
                fd: make_socket_fd(),
                buf: IoBufMut::with_capacity(4),
                offset: 5,
                len: 4,
                exact: true,
                deadline: None,
            });
            let _ = request.build_sqe(WaiterId::new(0, 0));
        });
        assert!(recv_overread.is_err());

        let recv_oversized = std::panic::catch_unwind(|| {
            let mut request = Request::Recv(RecvRequest {
                fd: make_socket_fd(),
                buf: IoBufMut::with_capacity(4),
                offset: 0,
                len: 5,
                exact: true,
                deadline: None,
            });
            let _ = request.build_sqe(WaiterId::new(0, 0));
        });
        assert!(recv_oversized.is_err());

        let read_oversized = std::panic::catch_unwind(|| {
            let mut request = Request::ReadAt(ReadAtRequest {
                file: make_file_fd(),
                offset: 0,
                len: 5,
                read: 0,
                buf: IoBufMut::with_capacity(4),
            });
            let _ = request.build_sqe(WaiterId::new(0, 0));
        });
        assert!(read_oversized.is_err());

        let read_overread = std::panic::catch_unwind(|| {
            let mut request = Request::ReadAt(ReadAtRequest {
                file: make_file_fd(),
                offset: 0,
                len: 4,
                read: 5,
                buf: IoBufMut::with_capacity(8),
            });
            let _ = request.build_sqe(WaiterId::new(0, 0));
        });
        assert!(read_overread.is_err());
    }

    #[test]
    fn test_active_send_paths() {
        // Verify send state handling across retry, timeout, success, and hard-failure CQEs.

        // Retryable CQEs should simply requeue while the request is still active.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
                .is_none()
        );

        // Partial progress followed by a retry after timeout should resolve to timeout.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 2)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::EAGAIN)
            .expect("terminal CQE");
        assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

        // Partial progress after timeout must also resolve to timeout rather than requeueing.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 2)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::CancelRequested, 1)
            .expect("terminal CQE");
        assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

        // A canceled send that comes back as ECANCELED should also resolve to timeout.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::ECANCELED)
            .expect("terminal CQE");
        assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

        // Vectored writes should advance across multiple CQEs and complete once all bytes are sent.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: vectored.into(),
            deadline: None,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 3)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 2)
            .expect("terminal CQE");
        unwrap_send(output).expect("send should complete successfully");

        // Zero-byte and hard-error CQEs should both surface as send failures.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 0)
            .expect("terminal CQE");
        assert!(matches!(unwrap_send(output), Err(Error::SendFailed)));

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        assert!(matches!(unwrap_send(output), Err(Error::SendFailed)));

        // A fully successful CQE still wins even if timeout was already requested.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, 5)
            .expect("terminal CQE");
        unwrap_send(output).expect("send should complete successfully");
    }

    #[test]
    fn test_active_recv_paths() {
        // Verify recv state handling across buffered progress, timeout, success, and hard failure.

        // Retryable CQEs should requeue while the recv is still active.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
                .is_none()
        );

        // Non-exact recv should complete as soon as any positive byte count arrives.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: false,
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 3)
            .expect("terminal CQE");
        let (_buf, read) = unwrap_recv(output).expect("recv should complete successfully");
        assert_eq!(read, 3);

        // Exact recv should requeue after partial progress, but timeout wins if the follow-up CQE
        // arrives after cancellation was requested.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 3)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::CancelRequested, 1)
            .expect("terminal CQE");
        assert!(matches!(unwrap_recv(output), Err((_, Error::Timeout))));

        // Retryable and ECANCELED completions after timeout should both resolve to timeout.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::EINTR)
            .expect("terminal CQE");
        assert!(matches!(unwrap_recv(output), Err((_, Error::Timeout))));

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::ECANCELED)
            .expect("terminal CQE");
        assert!(matches!(unwrap_recv(output), Err((_, Error::Timeout))));

        // A fully successful CQE still wins after timeout was requested.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, 5)
            .expect("terminal CQE");
        let (_buf, read) = unwrap_recv(output).expect("recv should complete successfully");
        assert_eq!(read, 5);

        // A kernel completion larger than the requested remaining length must
        // trip the local invariant before it can corrupt buffer state.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        let overflow = catch_unwind(AssertUnwindSafe(|| {
            let _ = request.on_cqe(WaiterState::Active { target_tick: None }, 6);
        }));
        assert!(overflow.is_err());

        // Zero-byte and hard-error CQEs should both surface as recv failures.
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 0)
            .expect("terminal CQE");
        assert!(matches!(unwrap_recv(output), Err((_, Error::RecvFailed))));

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        assert!(matches!(unwrap_recv(output), Err((_, Error::RecvFailed))));
    }

    #[test]
    fn test_active_read_at_paths() {
        // Verify read-at state handling across retry, EOF, timeout-cancel, and hard failure.

        // Retryable CQEs should requeue the positioned read.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
                .is_none()
        );

        // Partial reads should requeue until the full logical length is satisfied.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 2)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 3)
            .expect("terminal CQE");
        unwrap_read_at(output).expect("read should complete successfully");

        // EOF and hard-error CQEs should map to the storage read error surface.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 0)
            .expect("terminal CQE");
        assert!(matches!(
            unwrap_read_at(output),
            Err((_, Error::BlobInsufficientLength))
        ));

        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        assert!(matches!(
            unwrap_read_at(output),
            Err((_, Error::ReadFailed))
        ));

        // Timeout cancellation should also surface as a read failure.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::ECANCELED)
            .expect("terminal CQE");
        assert!(matches!(
            unwrap_read_at(output),
            Err((_, Error::ReadFailed))
        ));
    }

    #[test]
    fn test_active_write_at_paths() {
        // Verify write-at state handling across retry, partial progress, timeout-cancel, and failure.

        // Retryable CQEs should requeue the positioned write.
        let write = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        };
        assert_eq!(write.rw_flags(), 0);
        let mut request = Request::WriteAt(write);
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
                .is_none()
        );

        // Single-buffer writes should track partial progress until complete.
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 2)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 3)
            .expect("terminal CQE");
        unwrap_write_at(output).expect("write should complete successfully");

        // Vectored writes should advance across buffer boundaries and then complete.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: vectored.into(),
            sync: false,
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 4)
                .is_none()
        );
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 1)
            .expect("terminal CQE");
        unwrap_write_at(output).expect("vectored write should complete successfully");

        // Zero-byte and hard-error CQEs should surface as write failures.
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 0)
            .expect("terminal CQE");
        assert!(matches!(unwrap_write_at(output), Err(Error::WriteFailed)));

        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        assert!(matches!(unwrap_write_at(output), Err(Error::WriteFailed)));

        // Synchronous writes use the same logical error surface as regular
        // writes, `sync` only changes the SQE flags.
        let write = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: true,
        };
        assert_eq!(write.rw_flags(), libc::RWF_SYNC);
        let mut request = Request::WriteAt(write);
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINVAL)
            .expect("terminal CQE");
        assert!(matches!(unwrap_write_at(output), Err(Error::WriteFailed)));

        // Timeout cancellation should also surface as a write failure.
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::ECANCELED)
            .expect("terminal CQE");
        assert!(matches!(unwrap_write_at(output), Err(Error::WriteFailed)));
    }

    #[test]
    fn test_active_sync_paths() {
        // Verify sync state handling across retry, timeout-cancel, error conversion, and success.

        // Retryable CQEs should requeue the fsync request.
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR)
                .is_none()
        );

        // Timeout cancellation should preserve the kernel ECANCELED surface for sync callers.
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let output = request
            .on_cqe(WaiterState::CancelRequested, -libc::ECANCELED)
            .expect("terminal CQE");
        let err = unwrap_sync(output).expect_err("expected timeout cancel error");
        match err {
            Error::Io(err) => assert_eq!(err.raw_os_error(), Some(libc::ECANCELED)),
            other => panic!("expected io error, got {other:?}"),
        }

        // Hard errors should round-trip as std::io::Error values.
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        let err = unwrap_sync(output).expect_err("expected hard error");
        match err {
            Error::Io(err) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected io error, got {other:?}"),
        }

        // Both zero and positive CQE results should count as sync success.
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 0)
            .expect("terminal CQE");
        unwrap_sync(output).expect("sync should succeed on zero");

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 1)
            .expect("terminal CQE");
        unwrap_sync(output).expect("sync should succeed on positive");

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let err = unwrap_sync(request.timeout()).expect_err("expected timeout error");
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn test_fail_uses_fallback_results() {
        // Verify closed-driver staging failures deliver each kind's fallback result.
        // Network and storage requests each have their own fallback error surface.

        // Network sends and recvs should preserve their wrapper-specific fallback errors.
        let request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        assert!(matches!(
            unwrap_send(request.fail()),
            Err(Error::SendFailed)
        ));

        let request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        assert!(matches!(
            unwrap_recv(request.fail()),
            Err((_, Error::RecvFailed))
        ));

        // Storage reads and writes should surface the corresponding storage wrapper errors.
        let request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        assert!(matches!(
            unwrap_read_at(request.fail()),
            Err((_, Error::ReadFailed))
        ));

        let request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        });
        assert!(matches!(
            unwrap_write_at(request.fail()),
            Err(Error::WriteFailed)
        ));

        // A sync that never ran must fail rather than report durability.
        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        assert!(matches!(unwrap_sync(request.fail()), Err(Error::Closed)));
    }

    #[test]
    fn test_finish_timeout_delivers_timeout_results() {
        // Verify the loop's immediate-timeout path delivers timeout to each request variant.
        // Network and storage requests should each receive their type-specific
        // timeout surface when no CQE was processed yet.

        // Network operations should map directly to the shared logical timeout.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        assert!(matches!(
            unwrap_send(request.timeout()),
            Err(Error::Timeout)
        ));

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        });
        assert!(matches!(
            unwrap_recv(request.timeout()),
            Err((_, Error::Timeout))
        ));

        // Storage reads and writes also use the common logical timeout surface.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
        });
        assert!(matches!(
            unwrap_read_at(request.timeout()),
            Err((_, Error::Timeout))
        ));

        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            sync: false,
        });
        assert!(matches!(
            unwrap_write_at(request.timeout()),
            Err(Error::Timeout)
        ));

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let err = unwrap_sync(request.timeout()).expect_err("sync timeout should be an error");
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn test_raw_socket_addr_round_trip() {
        // Verify encode/decode preserves v4 and v6 addresses end to end.
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let raw = RawSocketAddr::from_socket_addr(&v4);
        assert_eq!(raw.to_socket_addr(), Some(v4));

        let v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            7,
            9,
        ));
        let raw = RawSocketAddr::from_socket_addr(&v6);
        assert_eq!(raw.to_socket_addr(), Some(v6));

        // Zeroed scratch (family AF_UNSPEC) has no decodable address.
        assert_eq!(RawSocketAddr::new_zeroed().to_socket_addr(), None);
    }

    fn make_accept() -> AcceptRequest {
        AcceptRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::zeroed(),
            deadline: None,
        }
    }

    #[test]
    fn test_active_accept_paths() {
        // Transient results retry with another SQE.
        let mut accept = make_accept();
        assert!(
            accept
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN)
                .is_none()
        );

        // Hard errors are terminal connection failures.
        assert!(matches!(
            accept.on_cqe(
                WaiterState::Active { target_tick: None },
                -libc::ECONNABORTED
            ),
            Some(Err(Error::ConnectionFailed))
        ));

        // Cancellation after a timeout maps to a logical timeout.
        let mut accept = make_accept();
        assert!(matches!(
            accept.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            Some(Err(Error::Timeout))
        ));

        // A success CQE takes ownership of the descriptor and decodes the
        // peer address, even when cancellation raced the completion.
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let (left, _right) = UnixStream::pair().unwrap();
        let raw_fd = left.into_raw_fd();
        let mut accept = make_accept();
        accept.addr = RawSocketAddr::boxed_from_socket_addr(&peer);
        let (owned, addr) = accept
            .on_cqe(WaiterState::CancelRequested, raw_fd)
            .expect("missing accept result")
            .expect("racing accept success should win over cancellation");
        assert_eq!(addr, peer);
        assert_eq!(owned.as_raw_fd(), raw_fd);

        // An undecodable peer address still takes (and releases) ownership of
        // the accepted descriptor.
        let (left, _right) = UnixStream::pair().unwrap();
        let raw_fd = left.into_raw_fd();
        let mut accept = make_accept();
        assert!(matches!(
            accept.on_cqe(WaiterState::Active { target_tick: None }, raw_fd),
            Some(Err(Error::ConnectionFailed))
        ));
    }

    #[test]
    fn test_accept_build_sqe_resets_addr_len() {
        // The kernel treats the address length as an in/out parameter, so a
        // reissued accept must restore it to the scratch capacity.
        let mut accept = make_accept();
        accept.addr.len = 0;
        let _ = accept.build_sqe();
        assert_eq!(
            accept.addr.len as usize,
            size_of::<libc::sockaddr_storage>()
        );
    }

    #[test]
    fn test_active_connect_paths() {
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let make_connect = || ConnectRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::boxed_from_socket_addr(&target),
            deadline: None,
        };

        // A zero result is a successful connect.
        let mut connect = make_connect();
        assert!(matches!(
            connect.on_cqe(WaiterState::Active { target_tick: None }, 0),
            Some(Ok(()))
        ));

        // Transient results retry with another SQE, and a reissued connect
        // may observe the previous attempt still in progress or already
        // established.
        let mut connect = make_connect();
        assert!(
            connect
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR)
                .is_none()
        );
        assert!(
            connect
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EALREADY)
                .is_none()
        );
        assert!(matches!(
            connect.on_cqe(WaiterState::Active { target_tick: None }, -libc::EISCONN),
            Some(Ok(()))
        ));

        // Refused connections are terminal failures.
        let mut connect = make_connect();
        assert!(matches!(
            connect.on_cqe(
                WaiterState::Active { target_tick: None },
                -libc::ECONNREFUSED
            ),
            Some(Err(Error::ConnectionFailed))
        ));

        // Cancellation after a timeout maps to a logical timeout.
        let mut connect = make_connect();
        assert!(matches!(
            connect.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            Some(Err(Error::Timeout))
        ));
    }
}
