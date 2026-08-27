//! Request types and state machines for the io_uring loop.
//!
//! Callers submit logical operations through the driver, which constructs a
//! [Request] that owns all resources (buffers, FDs, progress cursors) needed
//! to build follow-up SQEs and produce a typed [Output].
//!
//! ## Request policy
//!
//! Each row describes one logical request, not one SQE. "Transient" means
//! `EAGAIN`, `EWOULDBLOCK`, or `EINTR`. "Reason" maps
//! [`CancelReason::Deadline`] to [`Error::Timeout`] and
//! [`CancelReason::Shutdown`] to [`Error::Closed`]. A terminal success wins a
//! cancellation race. An `ECANCELED` CQE is cancellation only while the
//! waiter is in [`WaiterState::CancelRequested`]. Cache fallback retries
//! without `RWF_DONTCACHE` after `EOPNOTSUPP`.
//!
//! | Kind | SQE family | Partial progress | Zero CQE | Deadline | Orphan continuation | Retry | Cancellation |
//! | --- | --- | --- | --- | --- | --- | --- | --- |
//! | [`Request::Send`] | `Send` or `SendMsg` | Resubmit to empty | [`Error::SendFailed`] | Optional | No | Transient while active | Reason |
//! | [`Request::Recv`] | `Recv` | Resubmit to target when exact | [`Error::RecvFailed`] | Optional | No | Transient while active | Reason |
//! | [`Request::Accept`] | `Accept` | None | Accepted fd `0` | Optional | No | Transient while active | Reason |
//! | [`Request::Connect`] | `Connect` | None | Success | Optional | No | Transient while active, `EALREADY` always | Reason |
//! | [`Request::ReadAt`] | `Read` | Resubmit to requested length | [`Error::BlobInsufficientLength`] | None | No | Transient, cache fallback | [`Error::Closed`] |
//! | [`Request::WriteAt`] | `Write` or `Writev`, optional `Fsync` | Resubmit to empty, then sync | [`Error::WriteFailed`] while writing, success while syncing | None | Yes | Transient, cache fallback | [`Error::Closed`] |
//! | [`Request::Sync`] | `Fsync` | None | Success | None | Yes | Transient | [`Error::Closed`] |

use super::waiter::{CancelReason, WaiterId, WaiterState};
use crate::{Buf, Error, IoBuf, IoBufMut, IoBufs};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types::Fd};
use std::{
    fs::File,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum
/// so storage writes span as few submissions as possible.
pub(super) const IOVEC_BATCH_SIZE: usize = 1024;

/// Return the largest single-buffer length representable by a CQE result.
///
/// A CQE reports progress as an `i32`, so larger buffers must be staged over
/// multiple submissions even though an SQE length is an unsigned 32-bit value.
#[inline]
const fn single_buffer_sqe_len(len: usize) -> u32 {
    if len > i32::MAX as usize {
        i32::MAX as u32
    } else {
        len as u32
    }
}

/// Page-cache policy for a positioned I/O request.
pub(crate) enum Cache {
    /// Use the operating system's normal page-cache behavior.
    Enabled,
    /// Best-effort bypass of the page cache while the backend supports it.
    Disabled(Arc<AtomicBool>),
}

#[allow(clippy::missing_const_for_fn)]
impl Cache {
    /// Return the flag for this request, falling back to normal caching if
    /// another request has already found the hint unsupported.
    fn rw_flag(&mut self) -> i32 {
        match self {
            Self::Disabled(supported) if supported.load(Ordering::Relaxed) => libc::RWF_DONTCACHE,
            Self::Disabled(_) => {
                *self = Self::Enabled;
                0
            }
            Self::Enabled => 0,
        }
    }

    /// Fall back to normal caching when `code` reports that cache bypass is
    /// unsupported.
    fn fallback_if_unsupported(&mut self, code: i32) -> bool {
        if code != -libc::EOPNOTSUPP {
            return false;
        }
        match std::mem::replace(self, Self::Enabled) {
            Self::Disabled(supported) => {
                supported.store(false, Ordering::Relaxed);
                true
            }
            Self::Enabled => false,
        }
    }
}

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
    iovecs: IovecScratch,
    message: MessageHeader,
}

/// Reusable iovec scratch describing co-owned buffers to the kernel.
///
/// This newtype exists to carry the narrowest possible unsafe `Send`
/// contract: `libc::iovec` contains raw pointers (making it `!Send` by
/// default), so vouching at this level lets every containing type regain
/// compiler-checked auto traits.
struct IovecScratch(Box<[libc::iovec]>);

// SAFETY: the scratch entries are initialized with dangling pointers and may
// be stale between `build_sqe` calls, but they are never dereferenced in
// Rust. Each `build_sqe` refreshes them from the co-owned `IoBufs` (owned by
// the same waiter slot, itself `Send`) immediately before the kernel can
// observe them, so the pointers never outlive or alias the buffers they
// describe on any thread.
unsafe impl Send for IovecScratch {}

/// Stable message header for a vectored socket send.
///
/// The containing [VectoredBuffers] is boxed, so this header remains at a
/// stable address while an SQE refers to it.
struct MessageHeader(libc::msghdr);

// SAFETY: the header starts with only null pointers and zero lengths. Before
// submission, `refresh_message` points it at iovec scratch owned by the same
// boxed `VectoredBuffers`. Rust never dereferences the raw pointers, and the
// co-owned buffers and scratch remain alive until the kernel completes the
// SQE, including if the request moves between threads.
unsafe impl Send for MessageHeader {}

impl MessageHeader {
    /// Return an empty message header with no name or ancillary data.
    const fn new() -> Self {
        // SAFETY: an all-zero `msghdr` represents an empty message with null
        // optional pointers and zero lengths.
        Self(unsafe { std::mem::zeroed() })
    }
}

impl std::ops::Deref for IovecScratch {
    type Target = [libc::iovec];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for IovecScratch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
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
                Self::Vectored(Box::new(VectoredBuffers {
                    bufs,
                    iovecs: IovecScratch(iovecs),
                    message: MessageHeader::new(),
                }))
            }
        }
    }
}

impl VectoredBuffers {
    /// Refresh the iovec scratch from the current chunks and return the
    /// pointer and entry count for the next vectored SQE.
    #[inline]
    fn refresh_iovecs(&mut self) -> (*const libc::iovec, u32) {
        let max_iovecs = self.bufs.chunk_count().min(self.iovecs.len());
        // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
        let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
            std::slice::from_raw_parts_mut(
                self.iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
                max_iovecs,
            )
        };
        let iovecs_len = self
            .bufs
            .chunks_vectored(io_slices)
            .try_into()
            .expect("iovecs_len exceeds u32");
        (self.iovecs.as_ptr(), iovecs_len)
    }

    /// Refresh and return the stable message header for a socket send.
    fn refresh_message(&mut self) -> *const libc::msghdr {
        let (iovecs, iovecs_len) = self.refresh_iovecs();
        self.message.0.msg_iov = iovecs.cast_mut();
        self.message.0.msg_iovlen = iovecs_len as usize;
        &raw const self.message.0
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
/// terminal [Output]. [interrupt](Self::interrupt) and [fail](Self::fail)
/// resolve requests the kernel never completed.
pub(super) enum Request {
    /// Sends the full remaining payload over a socket.
    Send(SendRequest),
    /// Receives into an owned buffer, optionally requiring the full target.
    Recv(RecvRequest),
    /// Accepts one connection and captures its peer address.
    Accept(AcceptRequest),
    /// Connects a socket to one target address.
    Connect(ConnectRequest),
    /// Reads the requested byte range from a file.
    ReadAt(ReadAtRequest),
    /// Writes a full byte range and optionally data-syncs it.
    WriteAt(WriteAtRequest),
    /// Data-syncs a file.
    Sync(SyncRequest),
}

/// Terminal result of a logical request.
///
/// For an ordinary op, the waiter owns this output in `Ready` until the op
/// future consumes or drops it, so the waiter continues to occupy ring
/// capacity. For a detached ticket, the completion arena owns the output
/// after publication, and the driver recycles the waiter before its task
/// waker runs.
///
/// Kernel-referenced resources remain in the pending request until terminal
/// retirement. A recv or positional-read buffer then moves into this output
/// and remains driver-owned until the result is consumed or dropped. Send and
/// positional-write buffers are request-only, so they are dropped when the
/// terminal output is published. Error payloads are boxed because [enum@Error]
/// is large and errors are cold. Success-path moves should not pay for
/// error-variant width.
pub(super) enum Output {
    /// Send completion without a retained payload.
    Send(Result<(), Box<Error>>),
    /// Receive completion that returns the buffer on success or failure.
    Recv(Result<(IoBufMut, usize), Box<(IoBufMut, Error)>>),
    /// Accept completion with the connected descriptor and peer address.
    Accept(Result<(OwnedFd, SocketAddr), Box<Error>>),
    /// Connect completion without a retained payload.
    Connect(Result<(), Box<Error>>),
    /// Positioned-read completion that returns the buffer on success or failure.
    ReadAt(Result<IoBufMut, Box<(IoBufMut, Error)>>),
    /// Positioned-write completion without a retained payload.
    WriteAt(Result<(), Box<Error>>),
    /// Data-sync completion without a retained payload.
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

    /// Return whether an orphaned ticket stops this request from driving
    /// follow-up SQEs.
    ///
    /// Storage write/sync behavior stays aligned with `storage/tokio/blob.rs`,
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
    /// Every kind resolves to its staging failure, and syncs report
    /// [Error::Closed] because a sync that never ran must not report success.
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

    /// Resolve a request the loop is retiring before completion (a deadline
    /// expiry surfaces [Error::Timeout], a shutdown [Error::Closed]), moving
    /// any owned buffer out of the request.
    pub fn interrupt(&mut self, error: Error) -> Output {
        match self {
            Self::Send(_) => Output::Send(Err(Box::new(error))),
            Self::Recv(r) => Output::Recv(Err(Box::new((std::mem::take(&mut r.buf), error)))),
            Self::Accept(_) => Output::Accept(Err(Box::new(error))),
            Self::Connect(_) => Output::Connect(Err(Box::new(error))),
            Self::ReadAt(r) => Output::ReadAt(Err(Box::new((std::mem::take(&mut r.buf), error)))),
            Self::WriteAt(_) => Output::WriteAt(Err(Box::new(error))),
            Self::Sync(_) => Output::Sync(Err(Box::new(error))),
        }
    }

    /// Return a timeout result, moving any owned buffer out of the request.
    /// Used when a deadline expires before the current SQE could complete.
    pub fn timeout(&mut self) -> Output {
        self.interrupt(Error::Timeout)
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
    /// `ECANCELED` for an operation whose waiter had already requested async
    /// cancellation, carrying why (deadline expiry or runtime shutdown).
    Cancelled(CancelReason),
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
        } else if result == -libc::ECANCELED
            && let WaiterState::CancelRequested { reason } = state
        {
            Self::Cancelled(reason)
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
                opcode::Send::new(fd, ptr, single_buffer_sqe_len(remaining)).build()
            }
            WriteBuffers::Vectored(v) => {
                let message = v.refresh_message();
                opcode::SendMsg::new(fd, message)
                    .flags(libc::MSG_NOSIGNAL as u32)
                    .build()
            }
        }
    }

    /// Classify one send CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => match state {
                // Cancellation raced a retryable completion: resolve with the
                // cancellation's error instead of issuing another SQE.
                WaiterState::CancelRequested { reason } => Some(Err(reason.into_error())),
                WaiterState::Active { .. } => None,
            },
            CqeResult::Cancelled(reason) => Some(Err(reason.into_error())),
            CqeResult::Error(_) | CqeResult::Zero => Some(Err(Error::SendFailed)),
            CqeResult::Positive(n) => {
                self.write.advance(n);
                if self.write.is_complete() {
                    Some(Ok(()))
                } else if let WaiterState::CancelRequested { reason } = state {
                    // Any send error after partial progress means some prefix
                    // of the frame may already be on the wire. Callers must
                    // drop the connection rather than retrying on this sink.
                    Some(Err(reason.into_error()))
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
        opcode::Recv::new(fd, ptr, single_buffer_sqe_len(remaining)).build()
    }

    /// Classify one recv CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<usize, Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => match state {
                // Cancellation raced a retryable completion: resolve with the
                // cancellation's error instead of issuing another SQE.
                WaiterState::CancelRequested { reason } => Some(Err(reason.into_error())),
                WaiterState::Active { .. } => None,
            },
            CqeResult::Cancelled(reason) => Some(Err(reason.into_error())),
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
                } else if let WaiterState::CancelRequested { reason } = state {
                    Some(Err(reason.into_error()))
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
    /// Page-cache policy for this request.
    pub(super) cache: Cache,
}

impl ReadAtRequest {
    /// Return the flags for the next positioned read.
    fn rw_flags(&mut self) -> i32 {
        self.cache.rw_flag()
    }

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
        let rw_flags = self.rw_flags();
        opcode::Read::new(fd, ptr, single_buffer_sqe_len(remaining))
            .offset(offset)
            .rw_flags(rw_flags)
            .build()
    }

    /// Classify one read CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Error(code) if self.cache.fallback_if_unsupported(code) => None,
            // Preserve the kernel errno (e.g. EIO vs ENOSPC) as SyncRequest
            // does, so operators can distinguish failure causes. Requested
            // cancellation is not a kernel failure: it surfaces as closed.
            CqeResult::Cancelled(_) => Some(Err(Error::Closed)),
            CqeResult::Error(code) => {
                let err = std::io::Error::from_raw_os_error(-code);
                Some(Err(Error::Io(err.into())))
            }
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

/// Progress and durability policy for one positioned write request.
#[derive(Eq, PartialEq)]
pub(super) enum WriteAtState {
    /// Submit writes without per-write durability.
    Writing,
    /// Submit plain writes, then issue one trailing data sync.
    WritingBeforeSync,
    /// Issue the trailing data sync.
    Syncing,
}

/// Build a data-only fsync SQE.
fn build_datasync_sqe(file: &File) -> SqueueEntry {
    opcode::Fsync::new(Fd(file.as_raw_fd()))
        .flags(io_uring::types::FsyncFlags::DATASYNC)
        .build()
}

/// Classify one data-sync CQE.
fn on_sync_cqe(state: WaiterState, result: i32) -> Option<Result<(), Error>> {
    match CqeResult::from_raw(result, state) {
        CqeResult::Retry => None,
        CqeResult::Cancelled(_) => Some(Err(Error::Closed)),
        CqeResult::Error(code) => {
            let err = std::io::Error::from_raw_os_error(-code);
            Some(Err(Error::Io(err.into())))
        }
        CqeResult::Zero | CqeResult::Positive(_) => Some(Ok(())),
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
    /// Current write and durability phase.
    pub(super) state: WriteAtState,
    /// Page-cache policy for this request.
    pub(super) cache: Cache,
}

impl WriteAtRequest {
    /// Return the cache policy for the next write SQE.
    fn rw_flags(&mut self) -> i32 {
        self.cache.rw_flag()
    }

    /// Build the next positioned write SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        if self.state == WriteAtState::Syncing {
            return build_datasync_sqe(&self.file);
        }

        let fd = Fd(self.file.as_raw_fd());
        let offset = self.offset + self.written as u64;
        let rw_flags = self.rw_flags();
        match &mut self.write {
            WriteBuffers::Single { buf } => {
                let ptr = buf.as_ptr();
                let remaining = buf.remaining();
                opcode::Write::new(fd, ptr, single_buffer_sqe_len(remaining))
                    .offset(offset)
                    .rw_flags(rw_flags)
                    .build()
            }
            WriteBuffers::Vectored(v) => {
                let (ptr, len) = v.refresh_iovecs();
                opcode::Writev::new(fd, ptr, len)
                    .offset(offset)
                    .rw_flags(rw_flags)
                    .build()
            }
        }
    }

    /// Classify one write CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        if self.state == WriteAtState::Syncing {
            return on_sync_cqe(state, result);
        }

        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Error(code) if self.cache.fallback_if_unsupported(code) => None,
            // Preserve the kernel errno (e.g. EIO vs ENOSPC) as SyncRequest
            // does. A zero-length write carries no errno and stays the
            // kind-specific failure. Requested cancellation is not a kernel
            // failure: it surfaces as closed.
            CqeResult::Cancelled(_) => Some(Err(Error::Closed)),
            CqeResult::Error(code) => {
                let err = std::io::Error::from_raw_os_error(-code);
                Some(Err(Error::Io(err.into())))
            }
            CqeResult::Zero => Some(Err(Error::WriteFailed)),
            CqeResult::Positive(n) => {
                self.written += n;
                self.write.advance(n);
                if self.write.is_complete() {
                    if self.state == WriteAtState::WritingBeforeSync {
                        self.state = WriteAtState::Syncing;
                        None
                    } else {
                        Some(Ok(()))
                    }
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
                    sin6_flowinfo: v6.flowinfo().to_be(),
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
                    u32::from_be(sin6.sin6_flowinfo),
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
            CqeResult::Retry => match state {
                // Cancellation raced a retryable completion: resolve with the
                // cancellation's error instead of issuing another SQE.
                WaiterState::CancelRequested { reason } => Some(Err(reason.into_error())),
                WaiterState::Active { .. } => None,
            },
            CqeResult::Cancelled(reason) => Some(Err(reason.into_error())),
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
            CqeResult::Retry => match state {
                // Cancellation raced a retryable completion: resolve with the
                // cancellation's error instead of issuing another SQE.
                WaiterState::CancelRequested { reason } => Some(Err(reason.into_error())),
                WaiterState::Active { .. } => None,
            },
            // A reissued connect may observe the previous attempt still in
            // progress or already established. Neither is terminal failure.
            // A connect reissued after a retry-classified completion (e.g.
            // EINTR) can find the socket already in SYN_SENT. Requeueing
            // retries immediately, which can spin the loop at full speed for
            // up to an RTT: EALREADY completes without waiting. The spin is
            // bounded by the connect deadline, and needs a prior retry to
            // arise at all. Retrying via a writability poll instead is
            // deliberate future work.
            CqeResult::Error(code) if code == -libc::EALREADY => None,
            CqeResult::Error(code) if code == -libc::EISCONN => Some(Ok(())),
            CqeResult::Cancelled(reason) => Some(Err(reason.into_error())),
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
        build_datasync_sqe(&self.file)
    }

    /// Classify one fsync CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        on_sync_cqe(state, result)
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
