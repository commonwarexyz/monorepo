//! Request types and state machines for the io_uring loop.
//!
//! Callers submit logical operations through [super::Handle]. The handle
//! constructs a [Request] that owns all resources (buffers, FDs, progress
//! cursors, completion sender) needed to build follow-up SQEs and deliver a
//! typed result.

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

/// Normalized write buffer for [SendRequest] and [WriteAtRequest].
///
/// Preserves a single-buffer fast path and a vectored path with reusable
/// iovec scratch space.
pub(super) enum WriteBuffers {
    Single {
        buf: IoBuf,
    },
    Vectored {
        bufs: IoBufs,
        iovecs: Box<[libc::iovec]>,
    },
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
                Self::Vectored { bufs, iovecs }
            }
        }
    }
}

impl WriteBuffers {
    /// Return the remaining number of bytes that still need to be written.
    fn remaining_len(&self) -> usize {
        match self {
            Self::Single { buf } => buf.len(),
            Self::Vectored { bufs, .. } => bufs.len(),
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
            Self::Vectored { bufs, .. } => bufs.advance(n),
        }
    }
}

/// In-flight request state machine stored in the waiter table.
///
/// Each variant owns its completion sender, all buffers and FDs needed by the
/// kernel, and progress cursors. The loop calls [build_sqe](Self::build_sqe)
/// to produce the next SQE, [on_cqe](Self::on_cqe) to evaluate completions,
/// and [complete](Self::complete) or [timeout](Self::timeout) to
/// deliver results.
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

    /// Return whether this request should be treated as orphaned.
    ///
    /// A request is orphaned only when its completion receiver has been dropped
    /// and this request kind stops driving follow-up SQEs in that state.
    pub fn is_orphaned(&self) -> bool {
        match self {
            Self::Send(s) => s.sender.is_closed(),
            Self::Recv(r) => r.sender.is_closed(),
            Self::ReadAt(r) => r.sender.is_closed(),
            // Keep storage write/sync behavior aligned with `storage/tokio/unix.rs`,
            // where spawned blocking work continues running after caller drop.
            Self::WriteAt(_) | Self::Sync(_) => false,
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
    /// Returns `true` when the request reached a terminal state, or `false`
    /// when another SQE is needed.
    pub fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match self {
            Self::Send(s) => s.on_cqe(state, result),
            Self::Recv(r) => r.on_cqe(state, result),
            Self::ReadAt(r) => r.on_cqe(state, result),
            Self::WriteAt(w) => w.on_cqe(state, result),
            Self::Sync(s) => s.on_cqe(state, result),
        }
    }

    /// Deliver the stored result to the caller via its oneshot sender.
    pub fn complete(self) {
        match self {
            Self::Send(s) => {
                let _ = s.sender.send(s.result.unwrap_or(Err(Error::SendFailed)));
            }
            Self::Recv(r) => {
                let result = match r.result.unwrap_or(Err(Error::RecvFailed)) {
                    Ok(read) => Ok((r.buf, read)),
                    Err(err) => Err((r.buf, err)),
                };
                let _ = r.sender.send(result);
            }
            Self::ReadAt(r) => {
                let result = match r.result.unwrap_or(Err(Error::ReadFailed)) {
                    Ok(()) => Ok(r.buf),
                    Err(err) => Err((r.buf, err)),
                };
                let _ = r.sender.send(result);
            }
            Self::WriteAt(w) => {
                let _ = w.sender.send(w.result.unwrap_or(Err(Error::WriteFailed)));
            }
            Self::Sync(s) => {
                let _ = s.sender.send(s.result.unwrap_or(Ok(())));
            }
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
                let _ = r.sender.send(Err((r.buf, Error::Timeout)));
            }
            Self::ReadAt(r) => {
                let _ = r.sender.send(Err((r.buf, Error::Timeout)));
            }
            Self::WriteAt(w) => {
                let _ = w.sender.send(Err(Error::Timeout));
            }
            Self::Sync(s) => {
                // Sync requests currently do not carry deadlines, but keep the
                // timeout path consistent with storage's std::io::Result API.
                let _ = s.sender.send(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request timed out",
                )));
            }
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
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    pub(super) result: Option<Result<(), Error>>,
    /// Completion channel for the top-level caller.
    pub(super) sender: oneshot::Sender<Result<(), Error>>,
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
            WriteBuffers::Vectored { bufs, iovecs } => {
                let max_iovecs = bufs.chunk_count().min(iovecs.len());
                // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
                        max_iovecs,
                    )
                };
                let iovecs_len = bufs
                    .chunks_vectored(io_slices)
                    .try_into()
                    .expect("iovecs_len exceeds u32");

                // `Writev` is sufficient here because network sends only need
                // ordered byte delivery; this layer does not need sendmsg
                // ancillary data or zerocopy completion management.
                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len).build()
            }
        }
    }

    /// Classify one send CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if matches!(state, WaiterState::CancelRequested) => {
                self.result = Some(Err(Error::Timeout));
                true
            }
            CqeResult::Retry => false,
            CqeResult::Cancelled => {
                self.result = Some(Err(Error::Timeout));
                true
            }
            CqeResult::Error(_) | CqeResult::Zero => {
                self.result = Some(Err(Error::SendFailed));
                true
            }
            CqeResult::Positive(n) => {
                self.write.advance(n);
                if self.write.is_complete() {
                    self.result = Some(Ok(()));
                    true
                } else if matches!(state, WaiterState::CancelRequested) {
                    // Any send error after partial progress means some prefix
                    // of the frame may already be on the wire. Callers must
                    // drop the connection rather than retrying on this sink.
                    self.result = Some(Err(Error::Timeout));
                    true
                } else {
                    false
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
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    pub(super) result: Option<Result<usize, Error>>,
    /// Completion channel for the top-level caller.
    pub(super) sender: oneshot::Sender<Result<(IoBufMut, usize), (IoBufMut, Error)>>,
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

    /// Classify one recv CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if matches!(state, WaiterState::CancelRequested) => {
                self.result = Some(Err(Error::Timeout));
                true
            }
            CqeResult::Retry => false,
            CqeResult::Cancelled => {
                self.result = Some(Err(Error::Timeout));
                true
            }
            CqeResult::Error(_) | CqeResult::Zero => {
                self.result = Some(Err(Error::RecvFailed));
                true
            }
            CqeResult::Positive(n) => {
                let remaining = self.len - self.offset;
                assert!(
                    n <= remaining,
                    "recv CQE exceeds requested length: n={n} remaining={remaining}"
                );
                self.offset += n;
                if !self.exact || self.offset >= self.len {
                    self.result = Some(Ok(self.offset));
                    true
                } else if matches!(state, WaiterState::CancelRequested) {
                    self.result = Some(Err(Error::Timeout));
                    true
                } else {
                    false
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
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    pub(super) result: Option<Result<(), Error>>,
    /// Completion channel for the top-level caller.
    pub(super) sender: oneshot::Sender<Result<IoBufMut, (IoBufMut, Error)>>,
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

    /// Classify one read CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => false,
            CqeResult::Cancelled | CqeResult::Error(_) => {
                self.result = Some(Err(Error::ReadFailed));
                true
            }
            CqeResult::Zero => {
                self.result = Some(Err(Error::BlobInsufficientLength));
                true
            }
            CqeResult::Positive(n) => {
                let remaining = self.len - self.read;
                assert!(
                    n <= remaining,
                    "read CQE exceeds requested length: n={n} remaining={remaining}"
                );
                self.read += n;
                if self.read >= self.len {
                    self.result = Some(Ok(()));
                    true
                } else {
                    false
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
    /// Per-write flags passed to the kernel.
    pub(super) rw_flags: libc::c_int,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    pub(super) result: Option<Result<(), Error>>,
    /// Completion channel for the top-level caller.
    pub(super) sender: oneshot::Sender<Result<(), Error>>,
}

impl WriteAtRequest {
    /// Build the next positioned write SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        let offset = self.offset + self.written as u64;
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
                .rw_flags(self.rw_flags)
                .build()
            }
            WriteBuffers::Vectored { bufs, iovecs } => {
                let max_iovecs = bufs.chunk_count().min(iovecs.len());
                // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                let io_slices: &mut [std::io::IoSlice<'_>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        iovecs.as_mut_ptr().cast::<std::io::IoSlice<'_>>(),
                        max_iovecs,
                    )
                };
                let iovecs_len = bufs
                    .chunks_vectored(io_slices)
                    .try_into()
                    .expect("iovecs_len exceeds u32");

                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len)
                    .offset(offset)
                    .rw_flags(self.rw_flags)
                    .build()
            }
        }
    }

    /// Classify one write CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => false,
            CqeResult::Cancelled | CqeResult::Error(_) | CqeResult::Zero => {
                self.result = Some(Err(Error::WriteFailed));
                true
            }
            CqeResult::Positive(n) => {
                self.written += n;
                self.write.advance(n);
                if self.write.is_complete() {
                    self.result = Some(Ok(()));
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// Logical fsync request and its in-loop state.
pub(super) struct SyncRequest {
    /// File descriptor to sync.
    pub(super) file: Arc<File>,
    /// Terminal result captured by `on_cqe` and delivered by `finish`.
    pub(super) result: Option<std::io::Result<()>>,
    /// Completion channel for the top-level caller.
    pub(super) sender: oneshot::Sender<std::io::Result<()>>,
}

impl SyncRequest {
    /// Build the fsync SQE for this request.
    fn build_sqe(&self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        opcode::Fsync::new(fd).build()
    }

    /// Classify one fsync CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => false,
            CqeResult::Cancelled => {
                self.result = Some(Err(std::io::Error::from_raw_os_error(libc::ECANCELED)));
                true
            }
            CqeResult::Error(code) => {
                self.result = Some(Err(std::io::Error::from_raw_os_error(-code)));
                true
            }
            CqeResult::Zero | CqeResult::Positive(_) => {
                self.result = Some(Ok(()));
                true
            }
        }
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
            result: None,
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
            result: None,
            sender: oneshot::channel().0,
        });
        assert_eq!(recv.deadline(), Some(recv_deadline));
        assert!(recv.has_deadline());

        let read = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 4,
            read: 0,
            buf: IoBufMut::with_capacity(4),
            result: None,
            sender: oneshot::channel().0,
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
                result: None,
                sender: oneshot::channel().0,
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
                result: None,
                sender: oneshot::channel().0,
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
                result: None,
                sender: oneshot::channel().0,
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
                result: None,
                sender: oneshot::channel().0,
            });
            let _ = request.build_sqe(WaiterId::new(0, 0));
        });
        assert!(read_overread.is_err());
    }

    #[test]
    fn test_active_send_paths() {
        // Verify send state handling across retry, timeout, success, and hard-failure CQEs.

        // Retryable CQEs should simply requeue while the request is still active.
        let (tx, _rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Partial progress followed by a retry after timeout should resolve to timeout.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::EAGAIN));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing send result"),
            Err(Error::Timeout)
        ));

        // Partial progress after timeout must also resolve to timeout rather than requeueing.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::CancelRequested, 1));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing partial-timeout result"),
            Err(Error::Timeout)
        ));

        // A canceled send that comes back as ECANCELED should also resolve to timeout.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing timeout-cancel result"),
            Err(Error::Timeout)
        ));

        // Vectored writes should advance across multiple CQEs and complete once all bytes are sent.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: vectored.into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        request.complete();
        block_on(rx)
            .expect("missing send completion")
            .expect("send should complete successfully");

        // Zero-byte and hard-error CQEs should both surface as send failures.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing zero-result completion"),
            Err(Error::SendFailed)
        ));

        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing hard-error completion"),
            Err(Error::SendFailed)
        ));

        // A fully successful CQE still wins even if timeout was already requested.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, 5));
        request.complete();
        block_on(rx)
            .expect("missing send completion")
            .expect("send should complete successfully");
    }

    #[test]
    fn test_active_recv_paths() {
        // Verify recv state handling across buffered progress, timeout, success, and hard failure.

        // Retryable CQEs should requeue while the recv is still active.
        let (tx, _rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Non-exact recv should complete as soon as any positive byte count arrives.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: false,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        request.complete();
        let (_buf, read) = block_on(rx)
            .expect("missing recv completion")
            .expect("recv should complete successfully");
        assert_eq!(read, 3);

        // Exact recv should requeue after partial progress, but timeout wins if the follow-up CQE
        // arrives after cancellation was requested.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        assert!(request.on_cqe(WaiterState::CancelRequested, 1));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing timeout completion"),
            Err((_, Error::Timeout))
        ));

        // Retryable and ECANCELED completions after timeout should both resolve to timeout.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::EINTR));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing retryable completion"),
            Err((_, Error::Timeout))
        ));

        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing timeout-cancel completion"),
            Err((_, Error::Timeout))
        ));

        // A fully successful CQE still wins after timeout was requested.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, 5));
        request.complete();
        let (_buf, read) = block_on(rx)
            .expect("missing successful completion")
            .expect("recv should complete successfully");
        assert_eq!(read, 5);

        // A kernel completion larger than the requested remaining length must
        // trip the local invariant before it can corrupt buffer state.
        let (tx, _rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        let overflow = catch_unwind(AssertUnwindSafe(|| {
            let _ = request.on_cqe(WaiterState::Active { target_tick: None }, 6);
        }));
        assert!(overflow.is_err());

        // Zero-byte and hard-error CQEs should both surface as recv failures.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing zero completion"),
            Err((_, Error::RecvFailed))
        ));

        let (tx, rx) = oneshot::channel();
        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing error completion"),
            Err((_, Error::RecvFailed))
        ));
    }

    #[test]
    fn test_active_read_at_paths() {
        // Verify read-at state handling across retry, EOF, timeout-cancel, and hard failure.

        // Retryable CQEs should requeue the positioned read.
        let (tx, _rx) = oneshot::channel();
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Partial reads should requeue until the full logical length is satisfied.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        request.complete();
        block_on(rx)
            .expect("missing read completion")
            .expect("read should complete successfully");

        // EOF and hard-error CQEs should map to the storage read error surface.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing eof completion"),
            Err((_, Error::BlobInsufficientLength))
        ));

        let (tx, rx) = oneshot::channel();
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing read failure"),
            Err((_, Error::ReadFailed))
        ));

        // Timeout cancellation should also surface as a read failure.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing timeout-cancel failure"),
            Err((_, Error::ReadFailed))
        ));
    }

    #[test]
    fn test_active_write_at_paths() {
        // Verify write-at state handling across retry, partial progress, timeout-cancel, and failure.

        // Retryable CQEs should requeue the positioned write.
        let (tx, _rx) = oneshot::channel();
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Single-buffer writes should track partial progress until complete.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        request.complete();
        block_on(rx)
            .expect("missing write completion")
            .expect("write should complete successfully");

        // Vectored writes should advance across buffer boundaries and then complete.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));
        let (tx, rx) = oneshot::channel();
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: vectored.into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 4));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 1));
        request.complete();
        block_on(rx)
            .expect("missing vectored write completion")
            .expect("vectored write should complete successfully");

        // Zero-byte and hard-error CQEs should surface as write failures.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing zero-result write"),
            Err(Error::WriteFailed)
        ));

        let (tx, rx) = oneshot::channel();
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing write failure"),
            Err(Error::WriteFailed)
        ));

        // Timeout cancellation should also surface as a write failure.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing timeout-cancel write failure"),
            Err(Error::WriteFailed)
        ));
    }

    #[test]
    fn test_active_sync_paths() {
        // Verify sync state handling across retry, timeout-cancel, error conversion, and success.

        // Retryable CQEs should requeue the fsync request.
        let (tx, _rx) = oneshot::channel();
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR));

        // Timeout cancellation should preserve the kernel ECANCELED surface for sync callers.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        request.complete();
        let err = block_on(rx)
            .expect("missing timeout cancel result")
            .expect_err("expected timeout cancel error");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));

        // Hard errors should round-trip as std::io::Error values.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        request.complete();
        let err = block_on(rx)
            .expect("missing hard error result")
            .expect_err("expected hard error");
        assert_eq!(err.raw_os_error(), Some(libc::EIO));

        // Both zero and positive CQE results should count as sync success.
        let (tx, rx) = oneshot::channel();
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        request.complete();
        block_on(rx)
            .expect("missing zero-result completion")
            .expect("sync should succeed on zero");

        let (tx, rx) = oneshot::channel();
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 1));
        request.complete();
        block_on(rx)
            .expect("missing positive-result completion")
            .expect("sync should succeed on positive");

        // Local timeout delivery should use TimedOut for the storage-facing API.
        let (tx, rx) = oneshot::channel();
        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
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
        let (tx, rx) = oneshot::channel();
        let request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing send fallback"),
            Err(Error::SendFailed)
        ));

        let (tx, rx) = oneshot::channel();
        let request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing recv fallback"),
            Err((_, Error::RecvFailed))
        ));

        // Storage reads and writes should surface the corresponding storage wrapper errors.
        let (tx, rx) = oneshot::channel();
        let request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing read fallback"),
            Err((_, Error::ReadFailed))
        ));

        let (tx, rx) = oneshot::channel();
        let request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        request.complete();
        assert!(matches!(
            block_on(rx).expect("missing write fallback"),
            Err(Error::WriteFailed)
        ));

        // Sync fallback remains success because the wrapper treats "no CQE seen"
        // as an already-finished local sync during shutdown abandonment.
        let (tx, rx) = oneshot::channel();
        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        request.complete();
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
        let (tx, rx) = oneshot::channel();
        let request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
            sender: tx,
        });
        request.timeout();
        assert!(matches!(
            block_on(rx).expect("missing send timeout"),
            Err(Error::Timeout)
        ));

        let (tx, rx) = oneshot::channel();
        let request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
            sender: tx,
        });
        request.timeout();
        assert!(matches!(
            block_on(rx).expect("missing recv timeout"),
            Err((_, Error::Timeout))
        ));

        // Storage reads and writes also use the common logical timeout surface.
        let (tx, rx) = oneshot::channel();
        let request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            result: None,
            sender: tx,
        });
        request.timeout();
        assert!(matches!(
            block_on(rx).expect("missing read timeout"),
            Err((_, Error::Timeout))
        ));

        let (tx, rx) = oneshot::channel();
        let request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            rw_flags: 0,
            result: None,
            sender: tx,
        });
        request.timeout();
        assert!(matches!(
            block_on(rx).expect("missing write timeout"),
            Err(Error::Timeout)
        ));

        // Sync uses `std::io::ErrorKind::TimedOut` to match its storage-facing API.
        let (tx, rx) = oneshot::channel();
        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
            sender: tx,
        });
        request.timeout();
        let err = block_on(rx)
            .expect("missing sync timeout")
            .expect_err("sync timeout should be an error");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
