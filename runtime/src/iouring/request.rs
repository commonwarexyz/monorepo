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
/// completes successfully. When `exact` is true, exactly `len - offset`
/// additional bytes must be received.
pub struct RecvRequest {
    pub fd: Arc<OwnedFd>,
    pub buf: IoBufMut,
    /// Byte offset into `buf` where the next recv should write.
    pub offset: usize,
    /// Total target length tracked by the active request.
    ///
    /// This request fills `buf[offset..len]` and may requeue until `offset`
    /// reaches `len`.
    pub len: usize,
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
    /// Normalize caller-provided buffers into either a single-buffer fast path
    /// or a vectored representation with reusable iovec scratch space.
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

    /// Return the remaining number of bytes that still need to be written.
    fn remaining_len(&self) -> usize {
        match self {
            Self::Single { buf, cursor } => buf.len() - *cursor,
            Self::Vectored { bufs, .. } => bufs.len(),
        }
    }

    /// Return whether all bytes have been consumed by completed writes.
    fn is_complete(&self) -> bool {
        self.remaining_len() == 0
    }

    /// Advance the logical write cursor after a successful CQE.
    fn advance(&mut self, n: usize) {
        match self {
            Self::Single { cursor, .. } => *cursor += n,
            Self::Vectored { bufs, .. } => bufs.advance(n),
        }
    }
}

/// Refresh the iovec scratch from the current `IoBufs` state.
fn refresh_iovecs(bufs: &IoBufs, iovecs: &mut Box<[libc::iovec]>) -> u32 {
    let max_iovecs = bufs.chunk_count().min(iovecs.len());
    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
    let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
        std::slice::from_raw_parts_mut(
            iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
            max_iovecs,
        )
    };
    bufs.chunks_vectored(io_slices)
        .try_into()
        .expect("iovecs_len exceeds u32")
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
/// and [finish](Self::finish) or [timeout](Self::timeout) to
/// deliver results.
///
// SAFETY: `WriteBuffers::Vectored` owns both the `IoBufs` backing storage and
// the scratch `libc::iovec` array used to describe it to the kernel. The
// iovec entries are initialized with dangling pointers and may be stale
// between `build_sqe` calls, but they are never dereferenced in Rust. Each
// `build_sqe` refreshes them from the co-owned `IoBufs` immediately before the
// kernel can observe them, and the backing buffers remain owned by the same
// waiter slot for the request lifetime.
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
                    r.offset <= r.len && r.len <= r.buf.capacity(),
                    "recv invariant violated: need offset <= len <= capacity"
                );
                Self::Recv(ActiveRecv {
                    fd: r.fd,
                    buf: r.buf,
                    offset: r.offset,
                    len: r.len,
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
    pub fn timeout(self) {
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
                // Sync requests currently do not carry deadlines, but keep the
                // timeout path consistent with storage's std::io::Result API.
                let _ = s.sender.send(Err(sync_timeout_error()));
            }
        }
    }
}

/// Build the std::io::Error used if storage requests ever time out locally.
fn sync_timeout_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "request timed out")
}

/// Active state for a logical network send request.
pub struct ActiveSend {
    /// Socket used by the current send SQE.
    fd: Arc<OwnedFd>,
    /// Write cursor and buffers that still need to be sent.
    write: WriteBuffers,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    result: Option<Result<(), Error>>,
    /// Completion channel for the top-level caller.
    sender: oneshot::Sender<Result<(), Error>>,
}

impl ActiveSend {
    /// Build the next socket send SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        match &mut self.write {
            WriteBuffers::Single { buf, cursor } => {
                assert!(
                    *cursor <= buf.len(),
                    "send cursor exceeds buffer length: cursor={} len={}",
                    *cursor,
                    buf.len()
                );
                // SAFETY: buf is an IoBuf with stable memory. cursor <= buf.len().
                let ptr = unsafe { buf.as_ptr().add(*cursor) };
                let remaining = buf.len() - *cursor;
                opcode::Send::new(
                    fd,
                    ptr,
                    remaining
                        .try_into()
                        .expect("single-buffer SQE length exceeds u32"),
                )
                .build()
            }
            WriteBuffers::Vectored { bufs, iovecs } => {
                let iovecs_len = refresh_iovecs(bufs, iovecs);
                // `Writev` is sufficient here because network sends only need
                // ordered byte delivery; this layer does not need sendmsg
                // ancillary data or zerocopy completion management.
                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len).build()
            }
        }
    }

    /// Classify one send CQE and decide whether the logical request completes
    /// or needs another SQE.
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
                    // Any send error after partial progress means some prefix
                    // of the frame may already be on the wire. Callers must
                    // drop the connection rather than retrying on this sink.
                    self.result = Some(Err(Error::Timeout));
                    CqeAction::Complete
                } else {
                    CqeAction::Requeue
                }
            }
        }
    }

    /// Deliver the cached terminal send result to the caller.
    fn finish(self) {
        let _ = self
            .sender
            .send(self.result.unwrap_or(Err(Error::SendFailed)));
    }
}

/// Active state for a logical network recv request.
pub struct ActiveRecv {
    /// Socket used by the current recv SQE.
    fd: Arc<OwnedFd>,
    /// Destination buffer owned by the request.
    buf: IoBufMut,
    /// Byte offset into `buf` where the next recv should write.
    offset: usize,
    /// Total recv target, including any existing filled prefix before `offset`.
    len: usize,
    /// Whether the recv must fill the full target before succeeding.
    exact: bool,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    result: Option<Result<usize, Error>>,
    /// Completion channel for the top-level caller.
    sender: oneshot::Sender<(IoBufMut, Result<usize, Error>)>,
}

impl ActiveRecv {
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

    /// Classify one recv CQE and decide whether the logical request completes
    /// or needs another SQE.
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
                let remaining = self.len - self.offset;
                assert!(
                    n <= remaining,
                    "recv CQE exceeds requested length: n={n} remaining={remaining}"
                );
                self.offset += n;
                if !self.exact || self.offset >= self.len {
                    self.result = Some(Ok(self.offset));
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

    /// Deliver the cached recv result and owned buffer to the caller.
    fn finish(self) {
        let _ = self
            .sender
            .send((self.buf, self.result.unwrap_or(Err(Error::RecvFailed))));
    }
}

/// Active state for a logical positioned file read request.
pub struct ActiveReadAt {
    /// File used by the current read SQE.
    file: Arc<File>,
    /// Starting file offset for the logical read.
    offset: u64,
    /// Total number of bytes requested.
    len: usize,
    /// Bytes already read into `buf`.
    read: usize,
    /// Destination buffer owned by the request.
    buf: IoBufMut,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    result: Option<Result<(), Error>>,
    /// Completion channel for the top-level caller.
    sender: oneshot::Sender<(IoBufMut, Result<(), Error>)>,
}

impl ActiveReadAt {
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

    /// Classify one read CQE and decide whether the logical request completes
    /// or needs another SQE.
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
                let remaining = self.len - self.read;
                assert!(
                    n <= remaining,
                    "read CQE exceeds requested length: n={n} remaining={remaining}"
                );
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

    /// Deliver the cached read result and owned buffer to the caller.
    fn finish(self) {
        let _ = self
            .sender
            .send((self.buf, self.result.unwrap_or(Err(Error::ReadFailed))));
    }
}

/// Active state for a logical positioned file write request.
pub struct ActiveWriteAt {
    /// File used by the current write SQE.
    file: Arc<File>,
    /// Starting file offset for the logical write.
    offset: u64,
    /// Bytes already written successfully.
    written: usize,
    /// Write cursor and buffers that still need to be written.
    write: WriteBuffers,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    result: Option<Result<(), Error>>,
    /// Completion channel for the top-level caller.
    sender: oneshot::Sender<Result<(), Error>>,
}

impl ActiveWriteAt {
    /// Build the next positioned write SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        let offset = self.offset + self.written as u64;
        match &mut self.write {
            WriteBuffers::Single { buf, cursor } => {
                assert_eq!(
                    self.written, *cursor,
                    "single-buffer write cursor must match written byte count"
                );
                assert!(
                    *cursor <= buf.len(),
                    "write_at cursor exceeds buffer length: cursor={} len={}",
                    *cursor,
                    buf.len()
                );
                // SAFETY: buf is an IoBuf with stable memory. cursor <= buf.len().
                let ptr = unsafe { buf.as_ptr().add(*cursor) };
                let remaining = buf.len() - *cursor;
                opcode::Write::new(
                    fd,
                    ptr,
                    remaining
                        .try_into()
                        .expect("single-buffer SQE length exceeds u32"),
                )
                .offset(offset)
                .build()
            }
            WriteBuffers::Vectored { bufs, iovecs } => {
                let iovecs_len = refresh_iovecs(bufs, iovecs);
                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len)
                    .offset(offset)
                    .build()
            }
        }
    }

    /// Classify one write CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> CqeAction {
        match classify_result(result, state) {
            RawResult::Retryable => CqeAction::Requeue,
            RawResult::TimeoutCancel | RawResult::HardError(_) | RawResult::Zero => {
                self.result = Some(Err(Error::WriteFailed));
                CqeAction::Complete
            }
            RawResult::Positive(n) => {
                if let WriteBuffers::Single { cursor, .. } = &self.write {
                    assert_eq!(
                        self.written, *cursor,
                        "single-buffer write cursor must match written byte count"
                    );
                }
                self.written += n;
                self.write.advance(n);
                if let WriteBuffers::Single { cursor, .. } = &self.write {
                    assert_eq!(
                        self.written, *cursor,
                        "single-buffer write cursor must match written byte count"
                    );
                }
                if self.write.is_complete() {
                    self.result = Some(Ok(()));
                    CqeAction::Complete
                } else {
                    CqeAction::Requeue
                }
            }
        }
    }

    /// Deliver the cached write result to the caller.
    fn finish(self) {
        let _ = self
            .sender
            .send(self.result.unwrap_or(Err(Error::WriteFailed)));
    }
}

/// Active state for a logical fsync request.
pub struct ActiveSync {
    /// File descriptor to sync.
    file: Arc<File>,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    result: Option<std::io::Result<()>>,
    /// Completion channel for the top-level caller.
    sender: oneshot::Sender<std::io::Result<()>>,
}

impl ActiveSync {
    /// Build the fsync SQE for this request.
    fn build_sqe(&self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        opcode::Fsync::new(fd).build()
    }

    /// Classify one fsync CQE and decide whether the logical request completes
    /// or needs another SQE.
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

    /// Deliver the cached fsync result to the caller.
    fn finish(self) {
        let _ = self.sender.send(self.result.unwrap_or(Ok(())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::channel::oneshot;
    use futures::executor::block_on;
    use std::{
        os::{
            fd::{FromRawFd, IntoRawFd},
            unix::net::UnixStream,
        },
        panic::{catch_unwind, AssertUnwindSafe},
    };

    type SendRx = oneshot::Receiver<Result<(), Error>>;
    type RecvRx = oneshot::Receiver<(IoBufMut, Result<usize, Error>)>;
    type ReadRx = oneshot::Receiver<(IoBufMut, Result<(), Error>)>;
    type SyncRx = oneshot::Receiver<std::io::Result<()>>;

    fn active_state() -> WaiterState {
        WaiterState::Active { target_tick: None }
    }

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

    fn make_send_request(bufs: IoBufs) -> (ActiveRequest, SendRx) {
        let (tx, rx) = oneshot::channel();
        (
            ActiveRequest::from_request(Request::Send(SendRequest {
                fd: make_socket_fd(),
                bufs,
                deadline: None,
                sender: tx,
            })),
            rx,
        )
    }

    fn make_recv_request(len: usize, offset: usize, exact: bool) -> (ActiveRequest, RecvRx) {
        let (tx, rx) = oneshot::channel();
        (
            ActiveRequest::from_request(Request::Recv(RecvRequest {
                fd: make_socket_fd(),
                buf: IoBufMut::with_capacity(len),
                offset,
                len,
                exact,
                deadline: None,
                sender: tx,
            })),
            rx,
        )
    }

    fn make_read_request(len: usize) -> (ActiveRequest, ReadRx) {
        let (tx, rx) = oneshot::channel();
        (
            ActiveRequest::from_request(Request::ReadAt(ReadAtRequest {
                file: make_file_fd(),
                offset: 0,
                len,
                buf: IoBufMut::with_capacity(len),
                sender: tx,
            })),
            rx,
        )
    }

    fn make_write_request(bufs: IoBufs) -> (ActiveRequest, SendRx) {
        let (tx, rx) = oneshot::channel();
        (
            ActiveRequest::from_request(Request::WriteAt(WriteAtRequest {
                file: make_file_fd(),
                offset: 0,
                bufs,
                sender: tx,
            })),
            rx,
        )
    }

    fn make_sync_request() -> (ActiveRequest, SyncRx) {
        let (tx, rx) = oneshot::channel();
        (
            ActiveRequest::from_request(Request::Sync(SyncRequest {
                file: make_file_fd(),
                sender: tx,
            })),
            rx,
        )
    }

    #[test]
    fn test_request_deadline_helpers_and_invariants() {
        // Verify deadline helpers only report deadlines for network requests and
        // that invalid request invariants still fail fast at construction time.
        // Network requests carry optional deadlines that should be surfaced.
        let send_deadline = Instant::now();
        let send = Request::Send(SendRequest {
            fd: make_socket_fd(),
            bufs: IoBufs::from(IoBuf::from(b"hello")),
            deadline: Some(send_deadline),
            sender: oneshot::channel().0,
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
            sender: oneshot::channel().0,
        });
        assert_eq!(recv.deadline(), Some(recv_deadline));
        assert!(recv.has_deadline());

        let read = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 4,
            buf: IoBufMut::with_capacity(4),
            sender: oneshot::channel().0,
        });
        assert_eq!(read.deadline(), None);
        assert!(!read.has_deadline());

        // Invalid request shapes should still panic at construction time so the
        // loop never has to defend against impossible in-flight state.
        let recv_overread = std::panic::catch_unwind(|| {
            let _ = ActiveRequest::from_request(Request::Recv(RecvRequest {
                fd: make_socket_fd(),
                buf: IoBufMut::with_capacity(4),
                offset: 5,
                len: 4,
                exact: true,
                deadline: None,
                sender: oneshot::channel().0,
            }));
        });
        assert!(recv_overread.is_err());

        let recv_oversized = std::panic::catch_unwind(|| {
            let _ = ActiveRequest::from_request(Request::Recv(RecvRequest {
                fd: make_socket_fd(),
                buf: IoBufMut::with_capacity(4),
                offset: 0,
                len: 5,
                exact: true,
                deadline: None,
                sender: oneshot::channel().0,
            }));
        });
        assert!(recv_oversized.is_err());

        let read_oversized = std::panic::catch_unwind(|| {
            let _ = ActiveRequest::from_request(Request::ReadAt(ReadAtRequest {
                file: make_file_fd(),
                offset: 0,
                len: 5,
                buf: IoBufMut::with_capacity(4),
                sender: oneshot::channel().0,
            }));
        });
        assert!(read_oversized.is_err());
    }

    #[test]
    fn test_active_send_paths() {
        // Verify send state handling across retry, timeout, success, and hard-failure CQEs.

        // Retryable CQEs should simply requeue while the request is still active.
        let (mut request, _rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EAGAIN),
            CqeAction::Requeue
        ));

        // Partial progress followed by a retry after timeout should resolve to timeout.
        let (mut request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), 2),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::EAGAIN),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing send result"),
            Err(Error::Timeout)
        ));

        // Partial progress after timeout must also resolve to timeout rather than requeueing.
        let (mut request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), 2),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, 1),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing partial-timeout result"),
            Err(Error::Timeout)
        ));

        // A canceled send that comes back as ECANCELED should also resolve to timeout.
        let (mut request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing timeout-cancel result"),
            Err(Error::Timeout)
        ));

        // Vectored writes should advance across multiple CQEs and complete once all bytes are sent.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));
        let (mut request, rx) = make_send_request(vectored);
        assert!(matches!(
            request.on_cqe(active_state(), 3),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(active_state(), 2),
            CqeAction::Complete
        ));
        request.finish();
        block_on(rx)
            .expect("missing send completion")
            .expect("send should complete successfully");

        // Zero-byte and hard-error CQEs should both surface as send failures.
        let (mut request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), 0),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing zero-result completion"),
            Err(Error::SendFailed)
        ));

        let (mut request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EIO),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing hard-error completion"),
            Err(Error::SendFailed)
        ));

        // A fully successful CQE still wins even if timeout was already requested.
        let (mut request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, 5),
            CqeAction::Complete
        ));
        request.finish();
        block_on(rx)
            .expect("missing send completion")
            .expect("send should complete successfully");
    }

    #[test]
    fn test_active_recv_paths() {
        // Verify recv state handling across buffered progress, timeout, success, and hard failure.

        // Retryable CQEs should requeue while the recv is still active.
        let (mut request, _rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EAGAIN),
            CqeAction::Requeue
        ));

        // Non-exact recv should complete as soon as any positive byte count arrives.
        let (mut request, rx) = make_recv_request(5, 0, false);
        assert!(matches!(
            request.on_cqe(active_state(), 3),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing recv completion");
        assert_eq!(result.expect("recv should complete successfully"), 3);

        // Exact recv should requeue after partial progress, but timeout wins if the follow-up CQE
        // arrives after cancellation was requested.
        let (mut request, rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(active_state(), 3),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, 1),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing timeout completion");
        assert!(matches!(result, Err(Error::Timeout)));

        // Retryable and ECANCELED completions after timeout should both resolve to timeout.
        let (mut request, rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::EINTR),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing retryable completion");
        assert!(matches!(result, Err(Error::Timeout)));

        let (mut request, rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing timeout-cancel completion");
        assert!(matches!(result, Err(Error::Timeout)));

        // A fully successful CQE still wins after timeout was requested.
        let (mut request, rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, 5),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing successful completion");
        assert_eq!(result.expect("recv should complete successfully"), 5);

        // A kernel completion larger than the requested remaining length must
        // trip the local invariant before it can corrupt buffer state.
        let (mut request, _rx) = make_recv_request(5, 0, true);
        let overflow = catch_unwind(AssertUnwindSafe(|| {
            let _ = request.on_cqe(active_state(), 6);
        }));
        assert!(overflow.is_err());

        // Zero-byte and hard-error CQEs should both surface as recv failures.
        let (mut request, rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(active_state(), 0),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing zero completion");
        assert!(matches!(result, Err(Error::RecvFailed)));

        let (mut request, rx) = make_recv_request(5, 0, true);
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EIO),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing error completion");
        assert!(matches!(result, Err(Error::RecvFailed)));
    }

    #[test]
    fn test_active_read_at_paths() {
        // Verify read-at state handling across retry, EOF, timeout-cancel, and hard failure.

        // Retryable CQEs should requeue the positioned read.
        let (mut request, _rx) = make_read_request(5);
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EAGAIN),
            CqeAction::Requeue
        ));

        // Partial reads should requeue until the full logical length is satisfied.
        let (mut request, rx) = make_read_request(5);
        assert!(matches!(
            request.on_cqe(active_state(), 2),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(active_state(), 3),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing read completion");
        result.expect("read should complete successfully");

        // EOF and hard-error CQEs should map to the storage read error surface.
        let (mut request, rx) = make_read_request(5);
        assert!(matches!(
            request.on_cqe(active_state(), 0),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing eof completion");
        assert!(matches!(result, Err(Error::BlobInsufficientLength)));

        let (mut request, rx) = make_read_request(5);
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EIO),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing read failure");
        assert!(matches!(result, Err(Error::ReadFailed)));

        // Timeout cancellation should also surface as a read failure.
        let (mut request, rx) = make_read_request(5);
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            CqeAction::Complete
        ));
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing timeout-cancel failure");
        assert!(matches!(result, Err(Error::ReadFailed)));
    }

    #[test]
    fn test_active_write_at_paths() {
        // Verify write-at state handling across retry, partial progress, timeout-cancel, and failure.

        // Retryable CQEs should requeue the positioned write.
        let (mut request, _rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EAGAIN),
            CqeAction::Requeue
        ));

        // Single-buffer writes should track partial progress until complete.
        let (mut request, rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), 2),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(active_state(), 3),
            CqeAction::Complete
        ));
        request.finish();
        block_on(rx)
            .expect("missing write completion")
            .expect("write should complete successfully");

        // Vectored writes should advance across buffer boundaries and then complete.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));
        let (mut request, rx) = make_write_request(vectored);
        assert!(matches!(
            request.on_cqe(active_state(), 4),
            CqeAction::Requeue
        ));
        assert!(matches!(
            request.on_cqe(active_state(), 1),
            CqeAction::Complete
        ));
        request.finish();
        block_on(rx)
            .expect("missing vectored write completion")
            .expect("vectored write should complete successfully");

        // Zero-byte and hard-error CQEs should surface as write failures.
        let (mut request, rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), 0),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing zero-result write"),
            Err(Error::WriteFailed)
        ));

        let (mut request, rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EIO),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing write failure"),
            Err(Error::WriteFailed)
        ));

        // Timeout cancellation should also surface as a write failure.
        let (mut request, rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            CqeAction::Complete
        ));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing timeout-cancel write failure"),
            Err(Error::WriteFailed)
        ));
    }

    #[test]
    fn test_active_sync_paths() {
        // Verify sync state handling across retry, timeout-cancel, error conversion, and success.

        // Retryable CQEs should requeue the fsync request.
        let (mut request, _rx) = make_sync_request();
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EINTR),
            CqeAction::Requeue
        ));

        // Timeout cancellation should preserve the kernel ECANCELED surface for sync callers.
        let (mut request, rx) = make_sync_request();
        assert!(matches!(
            request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED),
            CqeAction::Complete
        ));
        request.finish();
        let err = block_on(rx)
            .expect("missing timeout cancel result")
            .expect_err("expected timeout cancel error");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));

        // Hard errors should round-trip as std::io::Error values.
        let (mut request, rx) = make_sync_request();
        assert!(matches!(
            request.on_cqe(active_state(), -libc::EIO),
            CqeAction::Complete
        ));
        request.finish();
        let err = block_on(rx)
            .expect("missing hard error result")
            .expect_err("expected hard error");
        assert_eq!(err.raw_os_error(), Some(libc::EIO));

        // Both zero and positive CQE results should count as sync success.
        let (mut request, rx) = make_sync_request();
        assert!(matches!(
            request.on_cqe(active_state(), 0),
            CqeAction::Complete
        ));
        request.finish();
        block_on(rx)
            .expect("missing zero-result completion")
            .expect("sync should succeed on zero");

        let (mut request, rx) = make_sync_request();
        assert!(matches!(
            request.on_cqe(active_state(), 1),
            CqeAction::Complete
        ));
        request.finish();
        block_on(rx)
            .expect("missing positive-result completion")
            .expect("sync should succeed on positive");

        // Local timeout delivery should use TimedOut for the storage-facing API.
        let (request, rx) = make_sync_request();
        request.timeout();
        let err = block_on(rx)
            .expect("missing timeout result")
            .expect_err("expected timeout error");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_finish_without_cqe_uses_fallback_results() {
        // Verify shutdown-abandonment fallback results are delivered even if no CQE was processed.
        // Network and storage requests each have their own fallback error surface.

        // Network sends and recvs should preserve their wrapper-specific fallback errors.
        let (request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing send fallback"),
            Err(Error::SendFailed)
        ));

        let (request, rx) = make_recv_request(5, 0, true);
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing recv fallback");
        assert!(matches!(result, Err(Error::RecvFailed)));

        // Storage reads and writes should surface the corresponding storage wrapper errors.
        let (request, rx) = make_read_request(5);
        request.finish();
        let (_buf, result) = block_on(rx).expect("missing read fallback");
        assert!(matches!(result, Err(Error::ReadFailed)));

        let (request, rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        request.finish();
        assert!(matches!(
            block_on(rx).expect("missing write fallback"),
            Err(Error::WriteFailed)
        ));

        // Sync fallback remains success because the wrapper treats "no CQE seen"
        // as an already-finished local sync during shutdown abandonment.
        let (request, rx) = make_sync_request();
        request.finish();
        block_on(rx)
            .expect("missing sync fallback")
            .expect("sync fallback should be success");
    }

    #[test]
    fn test_finish_timeout_delivers_timeout_results() {
        // Verify the loop's immediate-timeout path delivers timeout to each request variant.
        // Network and storage requests should each receive their type-specific
        // timeout surface when no CQE was processed yet.

        // Network operations should map directly to the shared logical timeout.
        let (request, rx) = make_send_request(IoBufs::from(IoBuf::from(b"hello")));
        request.timeout();
        assert!(matches!(
            block_on(rx).expect("missing send timeout"),
            Err(Error::Timeout)
        ));

        let (request, rx) = make_recv_request(5, 0, true);
        request.timeout();
        let (_buf, result) = block_on(rx).expect("missing recv timeout");
        assert!(matches!(result, Err(Error::Timeout)));

        // Storage reads and writes also use the common logical timeout surface.
        let (request, rx) = make_read_request(5);
        request.timeout();
        let (_buf, result) = block_on(rx).expect("missing read timeout");
        assert!(matches!(result, Err(Error::Timeout)));

        let (request, rx) = make_write_request(IoBufs::from(IoBuf::from(b"hello")));
        request.timeout();
        assert!(matches!(
            block_on(rx).expect("missing write timeout"),
            Err(Error::Timeout)
        ));

        // Sync uses `std::io::ErrorKind::TimedOut` to match its storage-facing API.
        let (request, rx) = make_sync_request();
        request.timeout();
        let err = block_on(rx)
            .expect("missing sync timeout")
            .expect_err("sync timeout should be an error");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
