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
//! | [`Request::Send`] | `Send` or `Writev` | Resubmit to empty | [`Error::SendFailed`] | Optional | No | Transient while active | Reason |
//! | [`Request::Recv`] | `Recv` | Resubmit to target when exact | [`Error::RecvFailed`] | Optional | No | Transient while active | Reason |
//! | [`Request::Accept`] | `Accept` | None | Accepted fd `0` | Optional | No | Transient while active | Reason |
//! | [`Request::Connect`] | `Connect` | None | Success | Optional | No | Transient while active, `EALREADY` always | Reason |
//! | [`Request::ReadAt`] | `Read` | Resubmit to requested length | [`Error::BlobInsufficientLength`] | None | No | Transient, cache fallback | Shutdown to [`Error::Closed`], deadline to `Io(ECANCELED)` |
//! | [`Request::WriteAt`] | `Write` or `Writev`, optional `Fsync` | Resubmit to empty, then sync | [`Error::WriteFailed`] while writing, success while syncing | None | Yes | Transient, cache fallback | Shutdown to [`Error::Closed`], deadline to `Io(ECANCELED)` |
//! | [`Request::Sync`] | `Fsync` | None | Success | None | Yes | Transient | Shutdown to [`Error::Closed`], deadline to `Io(ECANCELED)` |

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
                }))
            }
        }
    }
}

impl VectoredBuffers {
    /// Refresh the iovec scratch from the current chunks and return the
    /// pointer and entry count for the next `Writev` SQE.
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
                let (ptr, len) = v.refresh_iovecs();

                // `Writev` is sufficient here because network sends only need
                // ordered byte delivery. This layer does not need sendmsg
                // ancillary data or zerocopy completion management.
                opcode::Writev::new(fd, ptr, len).build()
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
        opcode::Read::new(
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

    /// Classify one read CQE and return the terminal result, or `None` when
    /// another SQE is needed.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Error(code) if self.cache.fallback_if_unsupported(code) => None,
            // Preserve the kernel errno (e.g. EIO vs ENOSPC) as SyncRequest
            // does, so operators can distinguish failure causes. A shutdown
            // cancellation is not a kernel failure: it surfaces as closed.
            CqeResult::Cancelled(CancelReason::Shutdown) => Some(Err(Error::Closed)),
            CqeResult::Cancelled(CancelReason::Deadline) => {
                let err = std::io::Error::from_raw_os_error(libc::ECANCELED);
                Some(Err(Error::Io(err.into())))
            }
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
        CqeResult::Cancelled(CancelReason::Shutdown) => Some(Err(Error::Closed)),
        CqeResult::Cancelled(CancelReason::Deadline) => {
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
            // kind-specific failure. A shutdown cancellation is not a kernel
            // failure: it surfaces as closed.
            CqeResult::Cancelled(CancelReason::Shutdown) => Some(Err(Error::Closed)),
            CqeResult::Cancelled(CancelReason::Deadline) => {
                let err = std::io::Error::from_raw_os_error(libc::ECANCELED);
                Some(Err(Error::Io(err.into())))
            }
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

    fn make_read_request(cache: Cache) -> ReadAtRequest {
        ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache,
        }
    }

    fn make_write_request(cache: Cache, state: WriteAtState) -> WriteAtRequest {
        WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state,
            cache,
        }
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

    fn unwrap_accept(output: Output) -> Result<(OwnedFd, SocketAddr), Error> {
        match output {
            Output::Accept(result) => result.map_err(|e| *e),
            _ => panic!("expected accept output"),
        }
    }

    fn unwrap_connect(output: Output) -> Result<(), Error> {
        match output {
            Output::Connect(result) => result.map_err(|e| *e),
            _ => panic!("expected connect output"),
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
    fn test_unsolicited_ecanceled_remains_an_error() {
        assert!(matches!(
            CqeResult::from_raw(
                -libc::ECANCELED,
                WaiterState::Active { target_tick: None }
            ),
            CqeResult::Error(code) if code == -libc::ECANCELED
        ));
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
            cache: Cache::Enabled,
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
                cache: Cache::Enabled,
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
                cache: Cache::Enabled,
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::EAGAIN,
            )
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                1,
            )
            .expect("terminal CQE");
        assert!(matches!(unwrap_send(output), Err(Error::Timeout)));

        // A canceled send that comes back as ECANCELED should also resolve to timeout.
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        });
        let output = request
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED,
            )
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                5,
            )
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                1,
            )
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::EINTR,
            )
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED,
            )
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                5,
            )
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
            cache: Cache::Enabled,
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
            cache: Cache::Enabled,
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
            cache: Cache::Enabled,
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
            cache: Cache::Enabled,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        match unwrap_read_at(output) {
            Err((_, Error::Io(err))) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected EIO read failure, got {other:?}"),
        }

        // Timeout cancellation should also surface as a read failure.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
        });
        let output = request
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED,
            )
            .expect("terminal CQE");
        match unwrap_read_at(output) {
            Err((_, Error::Io(err))) => assert_eq!(err.raw_os_error(), Some(libc::ECANCELED)),
            other => panic!("expected cancelled read failure, got {other:?}"),
        }
    }

    #[test]
    fn test_uncached_read_fallback_preserves_progress_and_is_shared_with_writes() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut read = make_read_request(Cache::Disabled(supported.clone()));

        assert_eq!(read.rw_flags(), libc::RWF_DONTCACHE);
        assert!(
            read.on_cqe(WaiterState::Active { target_tick: None }, 2)
                .is_none()
        );
        assert_eq!(read.read, 2);
        assert_eq!(read.rw_flags(), libc::RWF_DONTCACHE);

        assert!(
            read.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
                .is_none()
        );
        assert_eq!(read.read, 2);
        assert!(!supported.load(Ordering::Relaxed));
        assert_eq!(read.rw_flags(), 0);

        let mut sibling_write =
            make_write_request(Cache::Disabled(supported), WriteAtState::Writing);
        assert_eq!(sibling_write.rw_flags(), 0);

        let supported = Arc::new(AtomicBool::new(true));
        let mut write =
            make_write_request(Cache::Disabled(supported.clone()), WriteAtState::Writing);
        assert_eq!(write.rw_flags(), libc::RWF_DONTCACHE);
        assert!(
            write
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
                .is_none()
        );
        let mut sibling_read = make_read_request(Cache::Disabled(supported));
        assert_eq!(sibling_read.rw_flags(), 0);

        let supported = Arc::new(AtomicBool::new(true));
        let mut failing_read = make_read_request(Cache::Disabled(supported.clone()));
        assert_eq!(failing_read.rw_flags(), libc::RWF_DONTCACHE);
        match failing_read
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("hard read error should be terminal")
        {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected EIO read failure, got {other:?}"),
        }
        assert!(supported.load(Ordering::Relaxed));
    }

    #[test]
    fn test_cached_positional_io_reports_unsupported_as_terminal_error() {
        let mut read = make_read_request(Cache::Enabled);
        let read_result = read
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .expect("cached read EOPNOTSUPP should be terminal");
        match read_result {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP)),
            other => panic!("expected EOPNOTSUPP read failure, got {other:?}"),
        }
        assert_eq!(read.read, 0);

        let mut write = make_write_request(Cache::Enabled, WriteAtState::Writing);
        let write_result = write
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
            .expect("cached write EOPNOTSUPP should be terminal");
        match write_result {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP)),
            other => panic!("expected EOPNOTSUPP write failure, got {other:?}"),
        }
        assert_eq!(write.written, 0);
        assert_eq!(write.write.remaining_len(), 5);
        assert!(matches!(write.state, WriteAtState::Writing));
    }

    #[test]
    fn test_queued_cache_fallbacks_retry() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut first = make_read_request(Cache::Disabled(supported.clone()));
        let mut second = make_read_request(Cache::Disabled(supported.clone()));

        assert_eq!(first.rw_flags(), libc::RWF_DONTCACHE);
        assert_eq!(second.rw_flags(), libc::RWF_DONTCACHE);
        assert!(
            first
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
                .is_none()
        );
        assert!(
            second
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
                .is_none()
        );
        assert!(!supported.load(Ordering::Relaxed));
        assert_eq!(first.rw_flags(), 0);
        assert_eq!(second.rw_flags(), 0);
    }

    #[test]
    fn test_active_write_at_paths() {
        // Verify write-at state handling across retry, partial progress, timeout-cancel, and failure.

        // Retryable CQEs should requeue the positioned write.
        let mut write = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
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
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
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
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
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
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
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
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
        });
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("terminal CQE");
        match unwrap_write_at(output) {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected EIO write failure, got {other:?}"),
        }

        // A durable write reports write errors before entering its sync phase.
        let mut write = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::WritingBeforeSync,
            cache: Cache::Enabled,
        };
        assert_eq!(write.rw_flags(), 0);
        let mut request = Request::WriteAt(write);
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINVAL)
            .expect("terminal CQE");
        match unwrap_write_at(output) {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EINVAL)),
            other => panic!("expected EINVAL write failure, got {other:?}"),
        }

        // Timeout cancellation should also surface as a write failure.
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
        });
        let output = request
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED,
            )
            .expect("terminal CQE");
        match unwrap_write_at(output) {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::ECANCELED)),
            other => panic!("expected cancelled write failure, got {other:?}"),
        }
    }

    #[test]
    fn test_single_submission_sync_write_finishes_with_datasync() {
        let mut request = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::WritingBeforeSync,
            cache: Cache::Enabled,
        };

        let write = request.build_sqe();
        assert_eq!(write.get_opcode(), u32::from(opcode::Write::CODE));
        assert_eq!(request.rw_flags(), 0);
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 5)
                .is_none()
        );
        assert!(matches!(request.state, WriteAtState::Syncing));

        let sync = request.build_sqe();
        assert_eq!(sync.get_opcode(), u32::from(opcode::Fsync::CODE));
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR)
                .is_none()
        );
        assert!(matches!(request.state, WriteAtState::Syncing));
        assert!(matches!(
            request.on_cqe(WaiterState::Active { target_tick: None }, 0),
            Some(Ok(()))
        ));
    }

    #[test]
    fn test_uncached_durable_write_retries_without_hint_when_unsupported() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut request = make_write_request(
            Cache::Disabled(supported.clone()),
            WriteAtState::WritingBeforeSync,
        );

        assert_eq!(request.rw_flags(), libc::RWF_DONTCACHE);
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP)
                .is_none()
        );
        assert!(!supported.load(Ordering::Relaxed));
        request.cache = Cache::Disabled(supported);
        assert_eq!(request.rw_flags(), 0);
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 5)
                .is_none()
        );
        assert!(matches!(request.state, WriteAtState::Syncing));
        assert!(matches!(
            request.on_cqe(WaiterState::Active { target_tick: None }, 0),
            Some(Ok(()))
        ));
    }

    #[test]
    fn test_sync_write_reports_trailing_datasync_error() {
        let mut request = make_write_request(Cache::Enabled, WriteAtState::WritingBeforeSync);

        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 5)
                .is_none()
        );
        assert!(matches!(request.state, WriteAtState::Syncing));
        let result = request
            .on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO)
            .expect("data-sync failure should be terminal");
        match result {
            Err(Error::Io(err)) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected EIO data-sync failure, got {other:?}"),
        }
    }

    #[test]
    fn test_multi_submission_sync_write_finishes_with_datasync() {
        let mut bufs = IoBufs::default();
        for _ in 0..=IOVEC_BATCH_SIZE {
            bufs.append(IoBuf::from(b"x"));
        }
        let mut request = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: bufs.into(),
            state: WriteAtState::WritingBeforeSync,
            cache: Cache::Enabled,
        };

        let first = request.build_sqe();
        assert_eq!(first.get_opcode(), u32::from(opcode::Writev::CODE));
        assert!(
            request
                .on_cqe(
                    WaiterState::Active { target_tick: None },
                    IOVEC_BATCH_SIZE as i32
                )
                .is_none()
        );
        assert!(matches!(request.state, WriteAtState::WritingBeforeSync));

        let second = request.build_sqe();
        assert_eq!(second.get_opcode(), u32::from(opcode::Writev::CODE));
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 1)
                .is_none()
        );
        assert!(matches!(request.state, WriteAtState::Syncing));

        let sync = request.build_sqe();
        assert_eq!(sync.get_opcode(), u32::from(opcode::Fsync::CODE));
        assert!(matches!(
            request.on_cqe(WaiterState::Active { target_tick: None }, 0),
            Some(Ok(()))
        ));
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED,
            )
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
        // Property: closed-driver staging failures deliver each kind's
        // fallback result. Setup: one request of every variant. Action: fail
        // each without staging. Expected: each kind's own fallback error
        // surface (accepts and connects share ConnectionFailed).

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

        // Accepts and connects both collapse to the connection fallback.
        let request = Request::Accept(AcceptRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::zeroed(),
            deadline: None,
        });
        assert!(matches!(
            unwrap_accept(request.fail()),
            Err(Error::ConnectionFailed)
        ));

        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let request = Request::Connect(ConnectRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::boxed_from_socket_addr(&target),
            deadline: None,
        });
        assert!(matches!(
            unwrap_connect(request.fail()),
            Err(Error::ConnectionFailed)
        ));

        // Storage reads and writes should surface the corresponding storage wrapper errors.
        let request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
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
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
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
        // Property: the loop's immediate-timeout path delivers timeout to
        // each request variant. Setup: one request of every variant with no
        // CQE processed yet. Action: time each out locally. Expected: every
        // kind surfaces the shared logical Error::Timeout.

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

        // Accepts and connects also surface the shared logical timeout.
        let mut request = Request::Accept(AcceptRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::zeroed(),
            deadline: None,
        });
        assert!(matches!(
            unwrap_accept(request.timeout()),
            Err(Error::Timeout)
        ));

        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let mut request = Request::Connect(ConnectRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::boxed_from_socket_addr(&target),
            deadline: None,
        });
        assert!(matches!(
            unwrap_connect(request.timeout()),
            Err(Error::Timeout)
        ));

        // Storage reads and writes also use the common logical timeout surface.
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
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
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
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
        // Property: encode/decode preserves v4 and v6 addresses end to end,
        // and adversarial kernel-written lengths shorter than the family's
        // sockaddr are rejected instead of decoded from truncated storage.
        // Setup: valid encoded v4 and v6 addresses. Action: decode each with
        // its valid length and with a length one byte below the family's
        // sockaddr size. Expected: valid lengths round-trip and short
        // lengths decode to None, with the valid decode restored after.
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut raw = RawSocketAddr::from_socket_addr(&v4);
        assert_eq!(raw.to_socket_addr(), Some(v4));

        // A length one byte below sockaddr_in must be rejected, and restoring
        // the valid length must decode again.
        let valid_len = raw.len();
        *raw.len_mut() = (size_of::<libc::sockaddr_in>() - 1) as libc::socklen_t;
        assert_eq!(raw.to_socket_addr(), None);
        *raw.len_mut() = valid_len;
        assert_eq!(raw.to_socket_addr(), Some(v4));

        let v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            7,
            9,
        ));
        let mut raw = RawSocketAddr::from_socket_addr(&v6);
        assert_eq!(raw.to_socket_addr(), Some(v6));

        // Same boundary for sockaddr_in6.
        let valid_len = raw.len();
        *raw.len_mut() = (size_of::<libc::sockaddr_in6>() - 1) as libc::socklen_t;
        assert_eq!(raw.to_socket_addr(), None);
        *raw.len_mut() = valid_len;
        assert_eq!(raw.to_socket_addr(), Some(v6));

        // Zeroed scratch (family AF_UNSPEC) has no decodable address.
        assert_eq!(RawSocketAddr::new_zeroed().to_socket_addr(), None);
    }

    #[test]
    fn test_raw_socket_addr_ipv6_flowinfo_encode_uses_network_order() {
        const FLOWINFO: u32 = 0x0123_4567;
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, FLOWINFO, 9));

        let raw = RawSocketAddr::from_socket_addr(&addr);
        assert_eq!(raw.len() as usize, size_of::<libc::sockaddr_in6>());
        // SAFETY: the encoder stored a full sockaddr_in6 for an IPv6 address.
        let sin6 = unsafe { &*(&raw const raw.storage).cast::<libc::sockaddr_in6>() };
        assert_eq!(sin6.sin6_flowinfo.to_ne_bytes(), FLOWINFO.to_be_bytes());
    }

    #[test]
    fn test_raw_socket_addr_ipv6_flowinfo_decode_uses_network_order() {
        const FLOWINFO: u32 = 0x0123_4567;
        let mut raw = RawSocketAddr::new_zeroed();
        let sin6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 443u16.to_be(),
            sin6_flowinfo: u32::from_ne_bytes(FLOWINFO.to_be_bytes()),
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 9,
        };
        assert_eq!(sin6.sin6_flowinfo.to_ne_bytes(), FLOWINFO.to_be_bytes());
        // SAFETY: sockaddr_in6 fits within sockaddr_storage and the destination
        // is valid for writes.
        unsafe {
            std::ptr::write((&raw mut raw.storage).cast::<libc::sockaddr_in6>(), sin6);
        }
        *raw.len_mut() = size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let Some(SocketAddr::V6(decoded)) = raw.to_socket_addr() else {
            panic!("kernel-form IPv6 address did not decode");
        };
        assert_eq!(decoded.flowinfo(), FLOWINFO);
    }

    #[test]
    fn test_shutdown_cancellation_resolves_retry_and_partial_races() {
        // Property: a CQE racing a shutdown cancellation resolves with the
        // shutdown's error (Closed), not the deadline path's Timeout, and
        // only the reason distinguishes them. Setup: every kind placed in
        // shutdown cancel-requested state. Action (interleaving): feed each
        // a retryable, partial-progress, or ECANCELED CQE. Expected: network
        // kinds map retry and partial CQEs to Closed, while storage kinds
        // map ECANCELED to Closed and requeue retry CQEs (None).
        let shutdown = WaiterState::CancelRequested {
            reason: CancelReason::Shutdown,
        };

        // Retry races across all four network kinds.
        let mut send = SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        };
        assert!(matches!(
            send.on_cqe(shutdown, -libc::EAGAIN),
            Some(Err(Error::Closed))
        ));

        let mut recv = RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        };
        assert!(matches!(
            recv.on_cqe(shutdown, -libc::EAGAIN),
            Some(Err(Error::Closed))
        ));

        let mut accept = AcceptRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::zeroed(),
            deadline: None,
        };
        assert!(matches!(
            accept.on_cqe(shutdown, -libc::EAGAIN),
            Some(Err(Error::Closed))
        ));

        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let mut connect = ConnectRequest {
            fd: make_socket_fd(),
            addr: RawSocketAddr::boxed_from_socket_addr(&target),
            deadline: None,
        };
        assert!(matches!(
            connect.on_cqe(shutdown, -libc::EAGAIN),
            Some(Err(Error::Closed))
        ));

        // Partial-progress races: a send with bytes still unsent and an
        // exact recv with bytes still missing.
        let mut send = SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        };
        assert!(matches!(send.on_cqe(shutdown, 2), Some(Err(Error::Closed))));

        let mut recv = RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
        };
        assert!(matches!(recv.on_cqe(shutdown, 2), Some(Err(Error::Closed))));

        // Storage kinds under the same shutdown state carry two distinct
        // expectations. First, ECANCELED (classified as a cancellation only
        // because the waiter already requested one) resolves to Closed. The
        // owned buffer stays inside the request for the waiter layer to
        // return with the parked output.
        let mut read_at = ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
        };
        assert!(matches!(
            read_at.on_cqe(shutdown, -libc::ECANCELED),
            Some(Err(Error::Closed))
        ));
        assert_eq!(read_at.buf.capacity(), 5, "read buffer must stay owned");

        let mut write_at = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
        };
        assert!(matches!(
            write_at.on_cqe(shutdown, -libc::ECANCELED),
            Some(Err(Error::Closed))
        ));

        let mut sync = SyncRequest {
            file: make_file_fd(),
        };
        assert!(matches!(
            sync.on_cqe(shutdown, -libc::ECANCELED),
            Some(Err(Error::Closed))
        ));

        // Second, a retry errno under the same shutdown state yields None:
        // unlike the four network kinds above, the storage on_cqe arms map
        // CqeResult::Retry to None unconditionally (CqeResult::from_raw
        // classifies retry errnos before cancellation state), and the
        // pending cancellation is resolved later by the staging layer when
        // the requeued request is restaged.
        let mut read_at = ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
        };
        assert!(read_at.on_cqe(shutdown, -libc::EAGAIN).is_none());

        let mut write_at = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
        };
        assert!(write_at.on_cqe(shutdown, -libc::EAGAIN).is_none());

        let mut sync = SyncRequest {
            file: make_file_fd(),
        };
        assert!(sync.on_cqe(shutdown, -libc::EAGAIN).is_none());
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
            accept.on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED
            ),
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
            .on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                raw_fd,
            )
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

    /// Ground truth for what a vectored `build_sqe` must describe to the
    /// kernel: `chunks_vectored` is the same call `build_sqe` uses to fill
    /// the scratch and compute the SQE's iovec count, so its output pins the
    /// submitted pointers, lengths, and `iovcnt` without cracking the opaque
    /// squeue entry.
    fn expected_iovecs(bufs: &IoBufs, cap: usize) -> Vec<(*const u8, usize)> {
        use crate::Buf as _;
        let mut slices = vec![std::io::IoSlice::new(&[]); cap];
        let filled = bufs.chunks_vectored(&mut slices);
        slices[..filled]
            .iter()
            .map(|slice| (slice.as_ptr(), slice.len()))
            .collect()
    }

    /// Assert the scratch prefix matches the ground-truth chunk pointers and
    /// lengths (pointer identity, not mere non-nullness: a stale entry can
    /// hold a plausible non-null pointer into freed memory).
    fn check_vectored_scratch(write: &WriteBuffers, expected_lens: &[usize]) {
        let WriteBuffers::Vectored(v) = write else {
            panic!("expected vectored write buffers");
        };
        let expected = expected_iovecs(&v.bufs, v.iovecs.len());
        assert_eq!(expected.len(), expected_lens.len());
        for (i, (ptr, len)) in expected.iter().enumerate() {
            assert_eq!(*len, expected_lens[i], "iovec {i} length");
            assert_eq!(
                v.iovecs[i].iov_base.cast::<u8>().cast_const(),
                *ptr,
                "iovec {i} must point at the current chunk"
            );
            assert_eq!(v.iovecs[i].iov_len, *len, "iovec {i} scratch length");
        }
    }

    #[test]
    fn test_vectored_build_sqe_refreshes_iovecs_across_restaging() {
        // Verify the reusable iovec scratch is refreshed from the co-owned
        // buffers on every staging: after partial progress drops a fully
        // consumed chunk (freeing its backing memory), the rebuilt SQE must
        // describe only the remaining bytes and never reuse a stale entry.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"defg"));
        vectored.append(IoBuf::from(b"hi"));
        let mut request = SendRequest {
            fd: make_socket_fd(),
            write: vectored.into(),
            deadline: None,
        };

        // First staging describes all three chunks.
        let _ = request.build_sqe();
        check_vectored_scratch(&request.write, &[3, 4, 2]);

        // Consume the first chunk plus one byte of the second: the freed
        // chunk's iovec entry is now stale until the next staging.
        assert!(
            request
                .on_cqe(WaiterState::Active { target_tick: None }, 4)
                .is_none()
        );

        // Restaging refreshes the scratch from the advanced buffers.
        let _ = request.build_sqe();
        check_vectored_scratch(&request.write, &[3, 2]);

        // Finish the request: the remaining five bytes complete it.
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 5)
            .expect("terminal CQE");
        output.expect("vectored send should complete");
    }

    #[test]
    fn test_vectored_build_sqe_caps_iovec_batch() {
        // More chunks than IOVEC_BATCH_SIZE must clamp the SQE to the scratch
        // capacity, and later stagings pick up the tail as earlier chunks drain.
        let mut vectored = IoBufs::default();
        for _ in 0..(IOVEC_BATCH_SIZE + 4) {
            vectored.append(IoBuf::from(b"x"));
        }
        let mut request = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: vectored.into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
        };

        let _ = request.build_sqe();
        {
            let WriteBuffers::Vectored(v) = &request.write else {
                panic!("expected vectored write buffers");
            };
            // The scratch (and so the submitted iovcnt) is clamped to the
            // batch size even though more chunks are queued.
            assert_eq!(v.iovecs.len(), IOVEC_BATCH_SIZE);
        }
        check_vectored_scratch(&request.write, &[1; IOVEC_BATCH_SIZE]);

        // Drain one full batch, and the remaining four chunks stage next.
        assert!(
            request
                .on_cqe(
                    WaiterState::Active { target_tick: None },
                    IOVEC_BATCH_SIZE as i32
                )
                .is_none()
        );
        let _ = request.build_sqe();
        check_vectored_scratch(&request.write, &[1, 1, 1, 1]);
        let output = request
            .on_cqe(WaiterState::Active { target_tick: None }, 4)
            .expect("terminal CQE");
        output.expect("vectored write should complete");
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
            connect.on_cqe(
                WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                },
                -libc::ECANCELED
            ),
            Some(Err(Error::Timeout))
        ));
    }
}
