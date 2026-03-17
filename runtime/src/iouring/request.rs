//! Request types and active state machines for the io_uring loop.
//!
//! Callers submit a [Request] to the loop via [super::Submitter]. The loop
//! converts it into an [ActiveRequest] that owns all resources (buffers, FDs,
//! progress cursors, completion sender) needed to build follow-up SQEs and
//! deliver a typed result.

use super::waiter::{WaiterId, WaiterState};
use crate::{Buf, Error, IoBuf, IoBufMut, IoBufs};
use commonware_utils::channel::oneshot;
use io_uring::{opcode, squeue::Entry as SqueueEntry, types::Fd};
use std::{
    fs::File,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    time::Instant,
};

/// Cap iovec batch size: larger iovecs reduce syscall count but increase
/// per-write kernel setup overhead.
const IOVEC_BATCH_SIZE: usize = 32;

/// High-level request submitted by callers to the io_uring loop.
pub enum Request {
    #[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
    Send(SendRequest),
    #[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
    Recv(RecvRequest),
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    ReadAt(ReadAtRequest),
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    WriteAt(WriteAtRequest),
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    Sync(SyncRequest),
}

impl Request {
    /// Return the deadline for this request, if any.
    pub const fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Send(r) => r.deadline,
            Self::Recv(r) => r.deadline,
            Self::ReadAt(_) | Self::WriteAt(_) | Self::Sync(_) => None,
        }
    }

    /// Return whether this request carries a deadline.
    pub const fn has_deadline(&self) -> bool {
        self.deadline().is_some()
    }
}

/// Network send request. Completes when all bytes are written.
pub struct SendRequest {
    pub fd: Arc<OwnedFd>,
    pub bufs: IoBufs,
    pub deadline: Option<Instant>,
    pub sender: oneshot::Sender<Result<(), Error>>,
}

/// Network receive request. When `exact` is false, any positive byte count
/// completes successfully. When `exact` is true, exactly `len` bytes must be
/// received.
pub struct RecvRequest {
    pub fd: Arc<OwnedFd>,
    pub buf: IoBufMut,
    /// Total byte count target (includes `received` offset).
    pub len: usize,
    /// Byte offset into `buf` where received data starts. The active request
    /// tracks progress from this offset.
    pub received: usize,
    pub exact: bool,
    pub deadline: Option<Instant>,
    pub sender: oneshot::Sender<(IoBufMut, Result<usize, Error>)>,
}

/// Storage read request. Completes when exactly `len` bytes are read.
pub struct ReadAtRequest {
    pub file: Arc<File>,
    pub offset: u64,
    pub len: usize,
    pub buf: IoBufMut,
    pub sender: oneshot::Sender<(IoBufMut, Result<(), Error>)>,
}

/// Storage write request. Completes when all bytes are written.
pub struct WriteAtRequest {
    pub file: Arc<File>,
    pub offset: u64,
    pub bufs: IoBufs,
    pub sender: oneshot::Sender<Result<(), Error>>,
}

/// Storage fsync request.
pub struct SyncRequest {
    pub file: Arc<File>,
    pub sender: oneshot::Sender<std::io::Result<()>>,
}

/// Normalized write buffer for [ActiveSend] and [ActiveWriteAt].
///
/// Single-buffer writes track a byte cursor. Vectored writes track progress
/// via [IoBufs::advance] and reuse a pre-allocated iovec scratch buffer.
enum WriteBuffers {
    Single {
        buf: IoBuf,
        cursor: usize,
    },
    Vectored {
        bufs: IoBufs,
        iovecs: Box<[libc::iovec]>,
    },
}

impl WriteBuffers {
    fn new(bufs: IoBufs) -> Self {
        match bufs.try_into_single() {
            Ok(buf) => Self::Single { buf, cursor: 0 },
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
                Self::Vectored { bufs, iovecs }
            }
        }
    }

    fn remaining_len(&self) -> usize {
        match self {
            Self::Single { buf, cursor } => buf.len() - *cursor,
            Self::Vectored { bufs, .. } => bufs.len(),
        }
    }

    fn is_complete(&self) -> bool {
        self.remaining_len() == 0
    }

    fn advance(&mut self, n: usize) {
        match self {
            Self::Single { cursor, .. } => *cursor += n,
            Self::Vectored { bufs, .. } => bufs.advance(n),
        }
    }
}

/// Refresh the iovec scratch from the current `IoBufs` state.
fn refresh_iovecs(bufs: &IoBufs, iovecs: &mut Box<[libc::iovec]>) -> usize {
    let max_iovecs = bufs.chunk_count().min(iovecs.len());
    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
    let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
        std::slice::from_raw_parts_mut(
            iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
            max_iovecs,
        )
    };
    bufs.chunks_vectored(io_slices)
}

/// Classified raw CQE result code.
///
/// `classify` pre-merges `ECANCELED + CancelRequested` into [`RawResult::TimeoutCancel`]
/// so that per-variant `on_cqe` handlers never see a raw ECANCELED.
enum RawResult {
    Retryable,
    TimeoutCancel,
    HardError(i32),
    Zero,
    Positive(usize),
}

/// Classify a raw CQE result code against the current waiter state.
const fn classify_result(result: i32, state: WaiterState) -> RawResult {
    if super::should_retry(result) {
        RawResult::Retryable
    } else if result == -libc::ECANCELED && matches!(state, WaiterState::CancelRequested) {
        RawResult::TimeoutCancel
    } else if result < 0 {
        RawResult::HardError(result)
    } else if result == 0 {
        RawResult::Zero
    } else {
        RawResult::Positive(result as usize)
    }
}

/// Action the loop takes after evaluating a CQE against a request.
pub enum CqeAction {
    /// Request is terminal. Remove from waiter table and deliver result.
    Complete,
    /// Request needs another SQE. Enqueue in the ready queue.
    Requeue,
}

/// In-flight request state machine stored in the waiter table.
///
/// Each variant owns its completion sender, all buffers and FDs needed by the
/// kernel, and progress cursors. The loop calls [build_sqe](Self::build_sqe)
/// to produce the next SQE, [on_cqe](Self::on_cqe) to evaluate completions,
/// and [finish](Self::finish) or [finish_timeout](Self::finish_timeout) to
/// deliver results.
///
// SAFETY: The raw iovec pointers in `WriteBuffers::Vectored` point into the
// `IoBufs` co-owned in the same variant. The pointed-to memory remains valid
// for the request lifetime because both live in the same waiter slot.
unsafe impl Send for ActiveRequest {}

pub enum ActiveRequest {
    Send(ActiveSend),
    Recv(ActiveRecv),
    ReadAt(ActiveReadAt),
    WriteAt(ActiveWriteAt),
    Sync(ActiveSync),
}

impl ActiveRequest {
    /// Convert a caller-submitted [Request] into an active state machine.
    pub fn from_request(request: Request) -> Self {
        match request {
            Request::Send(r) => Self::Send(ActiveSend {
                fd: r.fd,
                write: WriteBuffers::new(r.bufs),
                result: None,
                sender: r.sender,
            }),
            Request::Recv(r) => {
                assert!(
                    r.received <= r.len && r.len <= r.buf.capacity(),
                    "recv invariant violated: need received <= len <= capacity"
                );
                Self::Recv(ActiveRecv {
                    fd: r.fd,
                    buf: r.buf,
                    len: r.len,
                    received: r.received,
                    exact: r.exact,
                    result: None,
                    sender: r.sender,
                })
            }
            Request::ReadAt(r) => {
                assert!(
                    r.len <= r.buf.capacity(),
                    "read_at len exceeds buffer capacity"
                );
                Self::ReadAt(ActiveReadAt {
                    file: r.file,
                    offset: r.offset,
                    len: r.len,
                    read: 0,
                    buf: r.buf,
                    result: None,
                    sender: r.sender,
                })
            }
            Request::WriteAt(r) => Self::WriteAt(ActiveWriteAt {
                file: r.file,
                offset: r.offset,
                written: 0,
                write: WriteBuffers::new(r.bufs),
                result: None,
                sender: r.sender,
            }),
            Request::Sync(r) => Self::Sync(ActiveSync {
                file: r.file,
                result: None,
                sender: r.sender,
            }),
        }
    }

    /// Build the next SQE for this request, tagged with `waiter_id`.
    pub fn build_sqe(&mut self, waiter_id: WaiterId) -> SqueueEntry {
        let sqe = match self {
            Self::Send(s) => s.build_sqe(),
            Self::Recv(r) => r.build_sqe(),
            Self::ReadAt(r) => r.build_sqe(),
            Self::WriteAt(w) => w.build_sqe(),
            Self::Sync(s) => s.build_sqe(),
        };
        sqe.user_data(waiter_id.user_data())
    }

    /// Evaluate a CQE result against this request's progress and state.
    ///
    /// Returns [CqeAction::Complete] when the request reached a terminal
    /// state, or [CqeAction::Requeue] when another SQE is needed.
    pub fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match self {
            Self::Send(s) => s.on_cqe(state, result),
            Self::Recv(r) => r.on_cqe(state, result),
            Self::ReadAt(r) => r.on_cqe(state, result),
            Self::WriteAt(w) => w.on_cqe(state, result),
            Self::Sync(s) => s.on_cqe(state, result),
        }
    }

    /// Deliver the stored result to the caller via its oneshot sender.
    pub fn finish(self) {
        match self {
            Self::Send(s) => s.finish(),
            Self::Recv(r) => r.finish(),
            Self::ReadAt(r) => r.finish(),
            Self::WriteAt(w) => w.finish(),
            Self::Sync(s) => s.finish(),
        }
    }

    /// Deliver a timeout error. Used when a deadline expires before the
    /// first SQE is submitted.
    pub fn finish_timeout(self) {
        match self {
            Self::Send(s) => {
                let _ = s.sender.send(Err(Error::Timeout));
            }
            Self::Recv(r) => {
                let _ = r.sender.send((r.buf, Err(Error::Timeout)));
            }
            Self::ReadAt(r) => {
                let _ = r.sender.send((r.buf, Err(Error::Timeout)));
            }
            Self::WriteAt(w) => {
                let _ = w.sender.send(Err(Error::Timeout));
            }
            Self::Sync(s) => {
                let _ = s.sender.send(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request timed out",
                )));
            }
        }
    }
}

pub struct ActiveSend {
    fd: Arc<OwnedFd>,
    write: WriteBuffers,
    result: Option<Result<(), Error>>,
    sender: oneshot::Sender<Result<(), Error>>,
}

impl ActiveSend {
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        match &mut self.write {
            WriteBuffers::Single { buf, cursor } => {
                // SAFETY: buf is an IoBuf with stable memory. cursor <= buf.len().
                let ptr = unsafe { buf.as_ptr().add(*cursor) };
                let remaining = buf.len() - *cursor;
                opcode::Send::new(fd, ptr, remaining as u32).build()
            }
            WriteBuffers::Vectored { bufs, iovecs } => {
                let iovecs_len = refresh_iovecs(bufs, iovecs);
                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len as _).build()
            }
        }
    }

    fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match classify_result(result, state) {
            RawResult::Retryable if matches!(state, WaiterState::CancelRequested) => {
                self.result = Some(Err(Error::Timeout));
                CqeAction::Complete
            }
            RawResult::Retryable => CqeAction::Requeue,
            RawResult::TimeoutCancel => {
                self.result = Some(Err(Error::Timeout));
                CqeAction::Complete
            }
            RawResult::HardError(_) | RawResult::Zero => {
                self.result = Some(Err(Error::SendFailed));
                CqeAction::Complete
            }
            RawResult::Positive(n) => {
                self.write.advance(n);
                if self.write.is_complete() {
                    self.result = Some(Ok(()));
                    CqeAction::Complete
                } else if matches!(state, WaiterState::CancelRequested) {
                    self.result = Some(Err(Error::Timeout));
                    CqeAction::Complete
                } else {
                    CqeAction::Requeue
                }
            }
        }
    }

    fn finish(self) {
        let _ = self
            .sender
            .send(self.result.unwrap_or(Err(Error::SendFailed)));
    }
}

pub struct ActiveRecv {
    fd: Arc<OwnedFd>,
    buf: IoBufMut,
    len: usize,
    received: usize,
    exact: bool,
    result: Option<Result<usize, Error>>,
    sender: oneshot::Sender<(IoBufMut, Result<usize, Error>)>,
}

impl ActiveRecv {
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        // SAFETY: buf is an IoBufMut with stable memory. received <= len <= capacity.
        let ptr = unsafe { self.buf.as_mut_ptr().add(self.received) };
        let remaining = self.len - self.received;
        opcode::Recv::new(fd, ptr, remaining as u32).build()
    }

    fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match classify_result(result, state) {
            RawResult::Retryable if matches!(state, WaiterState::CancelRequested) => {
                self.result = Some(Err(Error::Timeout));
                CqeAction::Complete
            }
            RawResult::Retryable => CqeAction::Requeue,
            RawResult::TimeoutCancel => {
                self.result = Some(Err(Error::Timeout));
                CqeAction::Complete
            }
            RawResult::HardError(_) | RawResult::Zero => {
                self.result = Some(Err(Error::RecvFailed));
                CqeAction::Complete
            }
            RawResult::Positive(n) => {
                self.received += n;
                if !self.exact || self.received >= self.len {
                    self.result = Some(Ok(self.received));
                    CqeAction::Complete
                } else if matches!(state, WaiterState::CancelRequested) {
                    self.result = Some(Err(Error::Timeout));
                    CqeAction::Complete
                } else {
                    CqeAction::Requeue
                }
            }
        }
    }

    fn finish(self) {
        let _ = self
            .sender
            .send((self.buf, self.result.unwrap_or(Err(Error::RecvFailed))));
    }
}

pub struct ActiveReadAt {
    file: Arc<File>,
    offset: u64,
    len: usize,
    read: usize,
    buf: IoBufMut,
    result: Option<Result<(), Error>>,
    sender: oneshot::Sender<(IoBufMut, Result<(), Error>)>,
}

impl ActiveReadAt {
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        // SAFETY: buf is an IoBufMut with stable memory. read <= len <= capacity.
        let ptr = unsafe { self.buf.as_mut_ptr().add(self.read) };
        let remaining = self.len - self.read;
        let offset = self.offset + self.read as u64;
        opcode::Read::new(fd, ptr, remaining as u32)
            .offset(offset as _)
            .build()
    }

    fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match classify_result(result, state) {
            RawResult::Retryable => CqeAction::Requeue,
            RawResult::TimeoutCancel | RawResult::HardError(_) => {
                self.result = Some(Err(Error::ReadFailed));
                CqeAction::Complete
            }
            RawResult::Zero => {
                self.result = Some(Err(Error::BlobInsufficientLength));
                CqeAction::Complete
            }
            RawResult::Positive(n) => {
                self.read += n;
                if self.read >= self.len {
                    self.result = Some(Ok(()));
                    CqeAction::Complete
                } else {
                    CqeAction::Requeue
                }
            }
        }
    }

    fn finish(self) {
        let _ = self
            .sender
            .send((self.buf, self.result.unwrap_or(Err(Error::ReadFailed))));
    }
}

pub struct ActiveWriteAt {
    file: Arc<File>,
    offset: u64,
    written: usize,
    write: WriteBuffers,
    result: Option<Result<(), Error>>,
    sender: oneshot::Sender<Result<(), Error>>,
}

impl ActiveWriteAt {
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        let offset = self.offset + self.written as u64;
        match &mut self.write {
            WriteBuffers::Single { buf, cursor } => {
                // SAFETY: buf is an IoBuf with stable memory. cursor <= buf.len().
                let ptr = unsafe { buf.as_ptr().add(*cursor) };
                let remaining = buf.len() - *cursor;
                opcode::Write::new(fd, ptr, remaining as u32)
                    .offset(offset as _)
                    .build()
            }
            WriteBuffers::Vectored { bufs, iovecs } => {
                let iovecs_len = refresh_iovecs(bufs, iovecs);
                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len as _)
                    .offset(offset as _)
                    .build()
            }
        }
    }

    fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match classify_result(result, state) {
            RawResult::Retryable => CqeAction::Requeue,
            RawResult::TimeoutCancel | RawResult::HardError(_) | RawResult::Zero => {
                self.result = Some(Err(Error::WriteFailed));
                CqeAction::Complete
            }
            RawResult::Positive(n) => {
                self.written += n;
                self.write.advance(n);
                if self.write.is_complete() {
                    self.result = Some(Ok(()));
                    CqeAction::Complete
                } else {
                    CqeAction::Requeue
                }
            }
        }
    }

    fn finish(self) {
        let _ = self
            .sender
            .send(self.result.unwrap_or(Err(Error::WriteFailed)));
    }
}

pub struct ActiveSync {
    file: Arc<File>,
    result: Option<std::io::Result<()>>,
    sender: oneshot::Sender<std::io::Result<()>>,
}

impl ActiveSync {
    fn build_sqe(&self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        opcode::Fsync::new(fd).build()
    }

    fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match classify_result(result, state) {
            RawResult::Retryable => CqeAction::Requeue,
            RawResult::TimeoutCancel => {
                self.result = Some(Err(std::io::Error::from_raw_os_error(libc::ECANCELED)));
                CqeAction::Complete
            }
            RawResult::HardError(code) => {
                self.result = Some(Err(std::io::Error::from_raw_os_error(-code)));
                CqeAction::Complete
            }
            RawResult::Zero | RawResult::Positive(_) => {
                self.result = Some(Ok(()));
                CqeAction::Complete
            }
        }
    }

    fn finish(self) {
        let _ = self.sender.send(self.result.unwrap_or(Ok(())));
    }
}
