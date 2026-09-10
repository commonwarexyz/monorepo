//! Request types and state machines for the io_uring loop.
//!
//! A [`Request`] owns every descriptor, buffer, and scratch allocation referenced
//! by its SQEs, and only its worker advances its progress. A terminal completion
//! splits it into a typed [`RequestOutput`] for the observer and
//! [`RetiredResources`] that the driver drops outside its local borrow, so no
//! external destructor runs while runtime state is borrowed. Consumed write
//! chunks therefore stay owned until retirement.
//!
//! A cancel acknowledgement never retires resources. Once an operation SQE is
//! in flight, only its CQE establishes that the kernel has stopped accessing them.

use super::{
    sockaddr::SockAddr,
    waiter::{WaiterId, WaiterState},
};
use crate::{Error, IoBuf, IoBufMut, IoBufs, storage::hold::Held};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types::Fd};
use std::{
    fs::File,
    net::TcpListener,
    os::fd::{AsRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
/// span as few submissions as possible.
pub const IOVEC_BATCH_SIZE: usize = 1024;

/// Normalized write buffer for [SendRequest] and [WriteAtRequest].
///
/// Preserves a single-buffer fast path and a vectored path with reusable
/// iovec scratch space.
pub enum WriteBuffers {
    /// Contiguous bytes and their completed prefix.
    Single {
        /// Original owner, retained through terminal completion.
        buf: IoBuf,
        /// Number of bytes already written.
        offset: usize,
    },
    /// Chunked bytes and stable scratch for each vectored submission.
    Vectored {
        /// Original owners, including completely consumed chunks.
        bufs: IoBufs,
        /// Index of the next chunk to write.
        chunk: usize,
        /// Completed prefix within the current chunk.
        offset: usize,
        /// Number of bytes left across all chunks.
        remaining: usize,
        /// Kernel-visible iovec array with stable backing storage.
        iovecs: Box<[libc::iovec]>,
    },
}

// SAFETY: `WriteBuffers` owns both the immutable byte owners and the boxed iovec
// array. Scratch pointers are never dereferenced by Rust and are refreshed from
// those owners before submission. Moving this owner does not move either backing
// allocation. Only its owning worker accesses it while a submission is active.
unsafe impl Send for WriteBuffers {}

impl From<IoBufs> for WriteBuffers {
    /// Normalize caller-provided buffers into either a single-buffer fast path
    /// or a vectored representation with reusable iovec scratch space.
    fn from(bufs: IoBufs) -> Self {
        match bufs.try_into_single() {
            Ok(buf) => Self::Single { buf, offset: 0 },
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
                Self::Vectored {
                    remaining: bufs.len(),
                    bufs,
                    chunk: 0,
                    offset: 0,
                    iovecs,
                }
            }
        }
    }
}

impl WriteBuffers {
    /// Return the remaining number of bytes that still need to be written.
    fn remaining_len(&self) -> usize {
        match self {
            Self::Single { buf, offset } => buf.len() - offset,
            Self::Vectored { remaining, .. } => *remaining,
        }
    }

    /// Return whether all bytes have been consumed by completed writes.
    fn is_complete(&self) -> bool {
        self.remaining_len() == 0
    }

    /// Advance progress without destroying or cloning any buffer owner.
    ///
    /// A consumed chunk may own a user value whose destructor reenters the
    /// runtime. Retain it until request retirement outside the local borrow.
    fn advance(&mut self, mut n: usize) {
        assert!(
            n <= self.remaining_len(),
            "write CQE exceeds remaining bytes"
        );
        match self {
            Self::Single { offset, .. } => *offset += n,
            Self::Vectored {
                bufs,
                chunk,
                offset,
                remaining,
                ..
            } => {
                *remaining -= n;
                while n > 0 {
                    let len = bufs.chunk_at(*chunk).expect("missing write chunk").len() - *offset;
                    if n < len {
                        *offset += n;
                        break;
                    }

                    // Move the cursor past a consumed chunk while retaining its owner.
                    n -= len;
                    *chunk += 1;
                    *offset = 0;
                }
            }
        }
    }
}

/// Fill stable iovec scratch from the current cursor without touching owners.
fn fill_iovecs(bufs: &IoBufs, chunk: usize, offset: usize, iovecs: &mut [libc::iovec]) -> u32 {
    let mut count = 0;
    for (index, iovec) in iovecs.iter_mut().enumerate() {
        let Some(bytes) = bufs.chunk_at(chunk + index) else {
            break;
        };
        let bytes = if index == 0 { &bytes[offset..] } else { bytes };
        *iovec = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        count += 1;
    }
    count
}

/// In-flight request state machine stored in the waiter table.
///
/// Each variant owns all buffers and FDs needed by the kernel, and progress
/// cursors. The loop calls [build_sqe](Self::build_sqe) to produce the next
/// SQE, [on_cqe](Self::on_cqe) to evaluate completions, and
/// [complete](Self::complete) to combine a terminal status with its owned
/// resources without invoking observers.
pub enum Request {
    /// Send a whole logical buffer sequence.
    Send(SendRequest),
    /// Receive bytes into a retained destination buffer.
    Recv(RecvRequest),
    /// Read a fixed byte range from a held file.
    ReadAt(ReadAtRequest),
    /// Write a fixed byte range, optionally followed by data sync.
    WriteAt(WriteAtRequest),
    /// Make a held file durable.
    Sync(SyncRequest),
    /// Connect a socket using a stable native address.
    Connect(ConnectRequest),
    /// Observe one readiness event without consuming socket data.
    Poll(PollRequest),
}

impl Request {
    /// Return the deadline for this request, if any.
    pub const fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Send(r) => r.deadline,
            Self::Recv(r) => r.deadline,
            Self::Connect(r) => r.deadline,
            Self::Poll(r) => r.deadline,
            Self::ReadAt(_) | Self::WriteAt(_) | Self::Sync(_) => None,
        }
    }

    /// Return whether logical work continues after its observer disappears.
    ///
    /// Storage mutations retain the same detached-work contract as blocking
    /// storage. Cancellation of reads and network requests stops follow-up SQEs.
    pub const fn retains_on_orphan(&self) -> bool {
        matches!(self, Self::WriteAt(_) | Self::Sync(_))
    }

    /// Build the next SQE for this request, tagged with `waiter_id`.
    pub fn build_sqe(&mut self, waiter_id: WaiterId) -> SqueueEntry {
        let sqe = match self {
            Self::Send(s) => s.build_sqe(),
            Self::Recv(r) => r.build_sqe(),
            Self::ReadAt(r) => r.build_sqe(),
            Self::WriteAt(w) => w.build_sqe(),
            Self::Sync(s) => s.build_sqe(),
            Self::Connect(r) => r.build_sqe(),
            Self::Poll(r) => r.build_sqe(),
        };
        sqe.user_data(waiter_id.user_data())
    }

    /// Evaluate a CQE result against this request's progress and state.
    ///
    /// Returns the terminal status, or `None` when another SQE is needed.
    /// The caller passes terminal status to [`Self::complete`] without storing
    /// it in the pending request. When this returns `None` for a waiter in
    /// [`WaiterState::CancelRequested`], the waiter table completes the request
    /// with a timeout instead of requeueing it.
    pub fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match self {
            Self::Send(s) => s.on_cqe(state, result),
            Self::Recv(r) => r.on_cqe(state, result),
            Self::ReadAt(r) => r.on_cqe(state, result),
            Self::WriteAt(w) => w.on_cqe(state, result),
            Self::Sync(s) => s.on_cqe(state, result),
            Self::Connect(r) => r.on_cqe(state, result),
            Self::Poll(r) => r.on_cqe(state, result),
        }
    }

    /// Take the typed result and every owner that is no longer kernel-visible.
    ///
    /// The driver calls this only when no operation SQE is in flight. Both
    /// returned values must leave the local borrow before they can be destroyed
    /// or delivered to an observer.
    pub fn complete(self, result: Result<(), Error>) -> (RequestOutput, RetiredResources) {
        match self {
            Self::Send(r) => (
                RequestOutput::Send(result),
                RetiredResources::Send {
                    _fd: r.fd,
                    _write: r.write,
                },
            ),
            Self::Recv(r) => {
                let result = match result {
                    Ok(()) => Ok((r.buf, r.offset)),
                    Err(err) => Err((r.buf, err)),
                };
                (
                    RequestOutput::Recv(result),
                    RetiredResources::Socket { _fd: r.fd },
                )
            }
            Self::ReadAt(r) => {
                let result = match result {
                    Ok(()) => Ok(r.buf),
                    Err(err) => Err((r.buf, err)),
                };
                (
                    RequestOutput::ReadAt(result),
                    RetiredResources::File {
                        _file: r.file,
                        _cache: Some(r.cache),
                        _write: None,
                    },
                )
            }
            Self::WriteAt(r) => (
                RequestOutput::WriteAt(result),
                RetiredResources::File {
                    _file: r.file,
                    _cache: Some(r.cache),
                    _write: Some(r.write),
                },
            ),
            Self::Sync(r) => (
                RequestOutput::Sync(result),
                RetiredResources::File {
                    _file: r.file,
                    _cache: None,
                    _write: None,
                },
            ),
            Self::Connect(r) => (
                RequestOutput::Connect(result),
                RetiredResources::Connect {
                    _fd: r.fd,
                    _address: r.address,
                },
            ),
            Self::Poll(r) => (
                RequestOutput::Poll(result),
                RetiredResources::Listener { _listener: r.fd },
            ),
        }
    }
}

/// Typed terminal results retained after their driver requests retire.
#[derive(Debug)]
pub enum RequestOutput {
    /// Completion of a logical network send.
    Send(Result<(), Error>),
    /// Receive result and its destination owner, including on error.
    Recv(Result<(IoBufMut, usize), (IoBufMut, Error)>),
    /// Positioned read result and its destination owner, including on error.
    ReadAt(Result<IoBufMut, (IoBufMut, Error)>),
    /// Completion of the whole positioned write and durability sequence.
    WriteAt(Result<(), Error>),
    /// Completion of a data sync.
    Sync(Result<(), Error>),
    /// Completion of a socket connection attempt.
    Connect(Result<(), Error>),
    /// Completion of one socket readiness observation.
    Poll(Result<(), Error>),
}

/// Owners detached at terminal completion.
///
/// The driver drops them after releasing its local borrow.
pub enum RetiredResources {
    /// Listener used by a readiness observation.
    Listener {
        /// Shared listener to release outside the worker borrow.
        _listener: Arc<TcpListener>,
    },
    /// Socket retained by a receive operation.
    Socket {
        /// Descriptor no longer referenced by an operation SQE.
        _fd: Arc<OwnedFd>,
    },
    /// Socket and all write owners retained by a logical send.
    Send {
        /// Descriptor used by the completed send sequence.
        _fd: Arc<OwnedFd>,
        /// Original byte owners, including consumed chunks.
        _write: WriteBuffers,
    },
    /// File, directory hold, and any positioned I/O buffer/cache owners.
    File {
        /// File owner carrying its original storage directory hold.
        _file: Arc<Held>,
        /// Shared capability state retained by positioned I/O.
        _cache: Option<Cache>,
        /// Original write owners, absent for reads and standalone sync.
        _write: Option<WriteBuffers>,
    },
    /// Socket and stable address retained by a connection attempt.
    Connect {
        /// Descriptor used by the connection attempt.
        _fd: Arc<OwnedFd>,
        /// Boxed native address whose kernel access has ended.
        _address: Box<SockAddr>,
    },
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
    /// `ECANCELED` for an operation whose waiter had requested cancellation.
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

/// Return the byte count capped at the SQE length limit.
fn scalar_len(remaining: usize) -> u32 {
    remaining.min(u32::MAX as usize) as u32
}

/// Logical network send request and its in-loop state.
pub struct SendRequest {
    /// Socket used by the current send SQE.
    pub fd: Arc<OwnedFd>,
    /// Write cursor and buffers that still need to be sent.
    pub write: WriteBuffers,
    /// Absolute deadline for the whole logical request.
    pub deadline: Option<Instant>,
}

impl SendRequest {
    /// Build the next socket send SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.fd.as_raw_fd());
        match &mut self.write {
            WriteBuffers::Single { buf, offset } => {
                let bytes = &buf.as_ref()[*offset..];
                let ptr = bytes.as_ptr();
                let remaining = bytes.len();
                opcode::Send::new(fd, ptr, scalar_len(remaining)).build()
            }
            WriteBuffers::Vectored {
                bufs,
                chunk,
                offset,
                iovecs,
                ..
            } => {
                let iovecs_len = fill_iovecs(bufs, *chunk, *offset, iovecs);

                // `Writev` is sufficient here because network sends only need
                // ordered byte delivery. This layer does not need sendmsg
                // ancillary data or zerocopy completion management.
                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len).build()
            }
        }
    }

    /// Classify one send CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(_) | CqeResult::Zero => Some(Err(Error::SendFailed)),
            CqeResult::Positive(n) => {
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

/// Logical network recv request and its in-loop state.
pub struct RecvRequest {
    /// Socket used by the current recv SQE.
    pub fd: Arc<OwnedFd>,
    /// Destination buffer owned by the request.
    pub buf: IoBufMut,
    /// Byte offset into `buf` where the next recv should write.
    pub offset: usize,
    /// Total recv target, including any existing filled prefix before `offset`.
    pub len: usize,
    /// Whether the recv must fill the full target before succeeding.
    pub exact: bool,
    /// Absolute deadline for the whole logical request.
    pub deadline: Option<Instant>,
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
        opcode::Recv::new(fd, ptr, scalar_len(remaining)).build()
    }

    /// Classify one recv CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
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
                    Some(Ok(()))
                } else {
                    None
                }
            }
        }
    }
}

/// Logical positioned file read request and its in-loop state.
pub struct ReadAtRequest {
    /// File used by the current read SQE.
    pub file: Arc<Held>,
    /// Starting file offset for the logical read.
    pub offset: u64,
    /// Total number of bytes requested.
    pub len: usize,
    /// Bytes already read into `buf`.
    pub read: usize,
    /// Destination buffer owned by the request.
    pub buf: IoBufMut,
    /// Page-cache policy for this request.
    pub cache: Cache,
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
        let rw_flags = self.cache.rw_flag();
        opcode::Read::new(fd, ptr, scalar_len(remaining))
            .offset(offset)
            .rw_flags(rw_flags)
            .build()
    }

    /// Classify one read CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Error(code) if self.cache.fallback(code) => None,
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

/// Page-cache policy for a positioned I/O request.
pub enum Cache {
    /// Use the operating system's normal page-cache behavior.
    Enabled,
    /// Best-effort bypass of the page cache while the backend supports it.
    Disabled(Arc<AtomicBool>),
}

#[allow(clippy::missing_const_for_fn)]
impl Cache {
    /// Return the flag for this request, falling back to normal caching if another request has
    /// already found the hint unsupported.
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

    /// Retry without cache bypass if the kernel rejected the hint.
    fn fallback(&mut self, code: i32) -> bool {
        if code != -libc::EOPNOTSUPP {
            return false;
        }

        // Each request that submitted the hint must retry, even if a sibling
        // has already updated the shared capability flag.
        match std::mem::replace(self, Self::Enabled) {
            Self::Disabled(supported) => {
                supported.store(false, Ordering::Relaxed);
                true
            }
            Self::Enabled => false,
        }
    }
}

/// Progress and durability policy for one positioned write request.
#[derive(Eq, PartialEq)]
pub enum WriteAtState {
    /// Submit writes without per-write durability.
    Writing,
    /// Submit writes with `RWF_DSYNC`.
    WritingSync,
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

/// Return the terminal data-sync status, or `None` for a retry.
fn on_sync_cqe(state: WaiterState, result: i32) -> Option<Result<(), Error>> {
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

/// Logical positioned file write request and its in-loop state.
pub struct WriteAtRequest {
    /// File used by the current write SQE.
    pub file: Arc<Held>,
    /// Starting file offset for the logical write.
    pub offset: u64,
    /// Bytes already written successfully.
    pub written: usize,
    /// Write cursor and buffers that still need to be written.
    pub write: WriteBuffers,
    /// Current write and durability phase.
    pub state: WriteAtState,
    /// Page-cache policy for this request.
    pub cache: Cache,
}

impl WriteAtRequest {
    /// Use `RWF_DSYNC` because the write contract does not require timestamp-only metadata.
    fn rw_flags(&mut self) -> i32 {
        let sync = if self.state == WriteAtState::WritingSync {
            libc::RWF_DSYNC
        } else {
            0
        };
        sync | self.cache.rw_flag()
    }

    /// Build the next positioned write SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        if self.state == WriteAtState::Syncing {
            return build_datasync_sqe(&self.file);
        }

        let fd = Fd(self.file.as_raw_fd());
        let file_offset = self.offset + self.written as u64;
        let rw_flags = self.rw_flags();
        match &mut self.write {
            WriteBuffers::Single { buf, offset } => {
                let bytes = &buf.as_ref()[*offset..];
                let ptr = bytes.as_ptr();
                opcode::Write::new(fd, ptr, scalar_len(bytes.len()))
                    .offset(file_offset)
                    .rw_flags(rw_flags)
                    .build()
            }
            WriteBuffers::Vectored {
                bufs,
                chunk,
                offset,
                iovecs,
                ..
            } => {
                let iovecs_len = fill_iovecs(bufs, *chunk, *offset, iovecs);

                opcode::Writev::new(fd, iovecs.as_ptr(), iovecs_len)
                    .offset(file_offset)
                    .rw_flags(rw_flags)
                    .build()
            }
        }
    }

    /// Classify one write CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        if self.state == WriteAtState::Syncing {
            return on_sync_cqe(state, result);
        }

        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Error(code) if self.cache.fallback(code) => None,
            CqeResult::Cancelled | CqeResult::Error(_) | CqeResult::Zero => {
                Some(Err(Error::WriteFailed))
            }
            CqeResult::Positive(n) => {
                self.written += n;
                self.write.advance(n);
                if self.write.is_complete() {
                    if self.state == WriteAtState::WritingBeforeSync {
                        // All batches must finish before the trailing sync starts.
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

/// Logical fsync request and its in-loop state.
pub struct SyncRequest {
    /// File descriptor to sync.
    pub file: Arc<Held>,
}

impl SyncRequest {
    /// Build the fsync SQE for this request.
    fn build_sqe(&self) -> SqueueEntry {
        build_datasync_sqe(&self.file)
    }

    /// Classify one fsync CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        on_sync_cqe(state, result)
    }
}

/// Socket connection request with stable kernel address storage.
pub struct ConnectRequest {
    /// Socket retained through its operation CQE.
    pub fd: Arc<OwnedFd>,
    /// Native address that cannot move after its pointer is staged.
    pub address: Box<SockAddr>,
    /// Absolute deadline for the whole logical request.
    pub deadline: Option<Instant>,
}

impl ConnectRequest {
    /// Build a connection SQE pointing into the boxed native address.
    fn build_sqe(&self) -> SqueueEntry {
        let (address, len) = self.address.as_raw();
        opcode::Connect::new(Fd(self.fd.as_raw_fd()), address, len).build()
    }

    /// Preserve connection success when it races a cancellation request.
    fn on_cqe(&self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        if result == -libc::EISCONN || result == 0 {
            return Some(Ok(()));
        }

        // A repeated connect can report that the previous attempt is still pending.
        let result = if result == -libc::EALREADY {
            -libc::EAGAIN
        } else {
            result
        };

        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(code) => Some(Err(Error::Io(
                std::io::Error::from_raw_os_error(-code).into(),
            ))),
            CqeResult::Zero | CqeResult::Positive(_) => Some(Err(Error::ConnectionFailed)),
        }
    }
}

/// Single-shot readiness observation that never consumes an accepted socket.
pub struct PollRequest {
    /// Descriptor retained until readiness completes or cancellation retires.
    pub fd: Arc<TcpListener>,
    /// Native poll flags identifying the readiness event of interest.
    pub flags: u32,
    /// Absolute deadline for this readiness observation.
    pub deadline: Option<Instant>,
}

impl PollRequest {
    /// Build one readiness SQE, leaving multishot mode disabled.
    fn build_sqe(&self) -> SqueueEntry {
        opcode::PollAdd::new(Fd(self.fd.as_raw_fd()), self.flags).build()
    }

    /// Treat readiness as a hint, allowing the caller to retry the actual syscall.
    fn on_cqe(&self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Cancelled => Some(Err(Error::Timeout)),
            CqeResult::Error(code) => Some(Err(Error::Io(
                std::io::Error::from_raw_os_error(-code).into(),
            ))),
            CqeResult::Zero | CqeResult::Positive(_) => Some(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{iouring::waiter::tests::waiter_id, storage::hold::Hold};
    use bytes::Bytes;
    use std::{
        net::SocketAddr,
        os::unix::net::UnixStream,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{OnceLock, atomic::AtomicUsize},
    };

    /// Waiter state before any deadline or orphan cancellation.
    const ACTIVE: WaiterState = WaiterState::Active { target_tick: None };

    /// Create a socket owner for SQE construction without submitting kernel I/O.
    fn make_socket_fd() -> Arc<OwnedFd> {
        let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
        Arc::new(left.into())
    }

    /// Retain a descriptor and directory hold for simulated storage requests.
    fn make_file_fd() -> Arc<Held> {
        let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
        let file = File::from(OwnedFd::from(left));

        // All requests in this process share the directory exclusion.
        static HOLD: OnceLock<Arc<Hold>> = OnceLock::new();
        let hold = HOLD.get_or_init(|| {
            Hold::acquire(
                &std::env::temp_dir()
                    .join(format!("commonware_request_test_{}", std::process::id())),
            )
            .unwrap()
        });
        Held::new(file, hold.clone())
    }

    /// Create a five-byte send with no deadline.
    fn make_send_request() -> SendRequest {
        SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
        }
    }

    /// Create a five-byte receive, optionally requiring the entire buffer.
    fn make_recv_request(exact: bool) -> RecvRequest {
        RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact,
            deadline: None,
        }
    }

    /// Create a five-byte positioned read with the requested cache policy.
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

    /// Create a five-byte positioned write with no durability requirement.
    fn make_write_request(cache: Cache) -> WriteAtRequest {
        WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache,
        }
    }

    /// Create a connection request with stable storage for a native address.
    fn make_connect_request(address: &str) -> ConnectRequest {
        ConnectRequest {
            fd: make_socket_fd(),
            address: Box::new(address.parse::<SocketAddr>().unwrap().into()),
            deadline: None,
        }
    }

    /// Create a listener readiness request without accepting a connection.
    fn make_poll_request() -> PollRequest {
        PollRequest {
            fd: Arc::new(TcpListener::bind("127.0.0.1:0").unwrap()),
            flags: libc::POLLIN as u32,
            deadline: None,
        }
    }

    /// Apply a terminal CQE, release retired resources, and return the typed output.
    fn complete(mut request: Request, state: WaiterState, result: i32) -> RequestOutput {
        let status = request.on_cqe(state, result).expect("terminal completion");
        let (output, retired) = request.complete(status);
        drop(retired);
        output
    }

    #[test]
    fn test_write_cursor_retains_owners_across_batches() {
        /// Byte owner that records when the write cursor releases it.
        struct Owner {
            /// Count shared by every chunk in the logical write.
            dropped: Arc<AtomicUsize>,
            /// Stable bytes referenced by the generated iovecs.
            bytes: [u8; 3],
        }

        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let count = IOVEC_BATCH_SIZE + 2;
        let mut bufs = IoBufs::default();
        for _ in 0..count {
            bufs.append(IoBuf::from(Bytes::from_owner(Owner {
                dropped: dropped.clone(),
                bytes: *b"abc",
            })));
        }

        let mut write = WriteBuffers::from(bufs);
        let inspect = |write: &mut WriteBuffers, expected: &[u8], expected_count| {
            let WriteBuffers::Vectored {
                bufs,
                chunk,
                offset,
                iovecs,
                ..
            } = write
            else {
                panic!("expected vectored buffers");
            };
            assert_eq!(fill_iovecs(bufs, *chunk, *offset, iovecs), expected_count);
            assert_eq!(iovecs[0].iov_len, expected.len());
            // SAFETY: scratch points into `bufs`, retained and immutably borrowed
            // throughout this inspection. Its length describes initialized bytes.
            let first = unsafe {
                std::slice::from_raw_parts(iovecs[0].iov_base.cast::<u8>(), iovecs[0].iov_len)
            };
            assert_eq!(first, expected);
        };

        // Partial progress changes only the first iovec's starting offset.
        inspect(&mut write, b"abc", IOVEC_BATCH_SIZE as u32);
        write.advance(1);
        inspect(&mut write, b"bc", IOVEC_BATCH_SIZE as u32);

        // Crossing a batch boundary reuses scratch without releasing earlier chunks.
        write.advance(2);
        inspect(&mut write, b"abc", IOVEC_BATCH_SIZE as u32);
        write.advance(3 * IOVEC_BATCH_SIZE);
        inspect(&mut write, b"abc", 1);
        write.advance(3);
        assert!(write.is_complete());
        assert_eq!(dropped.load(Ordering::Relaxed), 0);

        drop(write);
        assert_eq!(dropped.load(Ordering::Relaxed), count);
    }

    #[test]
    fn test_write_cursor_single_and_overrun() {
        let mut write = WriteBuffers::from(IoBufs::from(IoBuf::from(b"abc")));
        write.advance(1);
        let WriteBuffers::Single { buf, offset } = &write else {
            panic!("expected single buffer");
        };
        assert_eq!(buf.as_ref(), b"abc");
        assert_eq!(*offset, 1);

        // Reject excess progress before changing the cursor.
        assert!(catch_unwind(AssertUnwindSafe(|| write.advance(3))).is_err());
        assert_eq!(write.remaining_len(), 2);

        write.advance(2);
        assert!(write.is_complete());
    }

    #[test]
    fn test_connect_completion_rules() {
        // The address remains stable when the request moves between staging attempts.
        for address in ["127.0.0.1:1234", "[::1]:1234"] {
            let connect = make_connect_request(address);
            let pointer = connect.address.as_raw();
            connect.build_sqe();
            let connect = std::hint::black_box(connect);
            assert_eq!(connect.address.as_raw(), pointer);

            for result in [-libc::EALREADY, -libc::EAGAIN, -libc::EINTR] {
                assert!(connect.on_cqe(ACTIVE, result).is_none());
            }
        }

        // A completed connection wins over a concurrent cancellation request.
        for result in [0, -libc::EISCONN] {
            let request = Request::Connect(make_connect_request("127.0.0.1:1234"));
            assert!(matches!(
                complete(request, WaiterState::CancelRequested, result),
                RequestOutput::Connect(Ok(()))
            ));
        }

        let request = Request::Connect(make_connect_request("127.0.0.1:1234"));
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, -libc::ECANCELED),
            RequestOutput::Connect(Err(Error::Timeout))
        ));

        for code in [libc::ECONNREFUSED, libc::ECANCELED] {
            let request = Request::Connect(make_connect_request("127.0.0.1:1234"));
            let RequestOutput::Connect(Err(Error::Io(error))) = complete(request, ACTIVE, -code)
            else {
                panic!("expected connect I/O error");
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn test_poll_completion_rules() {
        let poll = make_poll_request();
        assert!(poll.on_cqe(ACTIVE, -libc::EINTR).is_none());

        // Readiness is only a hint to retry accept, including an empty event mask.
        for result in [0, libc::POLLIN as i32] {
            let request = Request::Poll(make_poll_request());
            assert!(matches!(
                complete(request, WaiterState::CancelRequested, result),
                RequestOutput::Poll(Ok(()))
            ));
        }

        let request = Request::Poll(make_poll_request());
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, -libc::ECANCELED),
            RequestOutput::Poll(Err(Error::Timeout))
        ));

        // An unsolicited cancellation remains an I/O error.
        for code in [libc::ECANCELED, libc::EBADF] {
            let request = Request::Poll(make_poll_request());
            let RequestOutput::Poll(Err(Error::Io(error))) = complete(request, ACTIVE, -code)
            else {
                panic!("expected poll I/O error");
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn test_partial_progress_retires_reentrant_panicking_owner() {
        /// Buffer owner that reenters local state when it is released.
        struct Owner {
            /// Stand-in for the worker borrow, also counting released owners.
            local: Arc<commonware_utils::sync::Mutex<usize>>,
            /// Payload retained across partial send completions.
            bytes: [u8; 3],
            /// Whether releasing this owner also tests panic containment.
            panic: bool,
        }

        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl Drop for Owner {
            fn drop(&mut self) {
                *self
                    .local
                    .try_lock()
                    .expect("owner dropped under local borrow") += 1;
                if self.panic {
                    panic!("external owner panic");
                }
            }
        }

        let local = Arc::new(commonware_utils::sync::Mutex::new(0));
        let mut bufs = IoBufs::from(IoBuf::from(Bytes::from_owner(Owner {
            local: local.clone(),
            bytes: *b"abc",
            panic: true,
        })));
        bufs.append(IoBuf::from(Bytes::from_owner(Owner {
            local: local.clone(),
            bytes: *b"def",
            panic: false,
        })));
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: bufs.into(),
            deadline: None,
        });

        // Consuming a whole chunk must leave its destructor for after the borrow.
        let guard = local.lock();
        assert!(request.on_cqe(ACTIVE, 3).is_none());
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(output, RequestOutput::Send(Err(Error::Timeout))));
        assert_eq!(*guard, 0);
        drop(guard);

        // One outer boundary contains the owner panic while ordinary container
        // drop glue releases the remaining nonpanicking owner.
        let panic = catch_unwind(AssertUnwindSafe(|| drop(retired)))
            .expect_err("owner panic was not caught");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"external owner panic"));
        assert_eq!(*local.lock(), 2);
    }

    #[test]
    fn test_cqe_result_from_raw_retryable_codes() {
        for code in [-libc::EAGAIN, -libc::EWOULDBLOCK, -libc::EINTR] {
            assert!(matches!(
                CqeResult::from_raw(code, ACTIVE),
                CqeResult::Retry
            ));
        }

        for code in [0, -libc::EINVAL, -libc::ETIMEDOUT] {
            assert!(!matches!(
                CqeResult::from_raw(code, ACTIVE),
                CqeResult::Retry
            ));
        }
    }

    #[test]
    fn test_request_metadata_and_sqe_tags() {
        let id = waiter_id(3, 7);
        for deadline in [None, Some(Instant::now())] {
            let mut send = make_send_request();
            send.deadline = deadline;
            let mut recv = make_recv_request(true);
            recv.deadline = deadline;
            let mut connect = make_connect_request("127.0.0.1:1234");
            connect.deadline = deadline;
            let mut poll = make_poll_request();
            poll.deadline = deadline;

            // Every request tags its SQE. Only network requests have deadlines,
            // and only storage mutations continue after their observer disappears.
            let requests = [
                (Request::Send(send), opcode::Send::CODE, deadline, false),
                (Request::Recv(recv), opcode::Recv::CODE, deadline, false),
                (
                    Request::ReadAt(make_read_request(Cache::Enabled)),
                    opcode::Read::CODE,
                    None,
                    false,
                ),
                (
                    Request::WriteAt(make_write_request(Cache::Enabled)),
                    opcode::Write::CODE,
                    None,
                    true,
                ),
                (
                    Request::Sync(SyncRequest {
                        file: make_file_fd(),
                    }),
                    opcode::Fsync::CODE,
                    None,
                    true,
                ),
                (
                    Request::Connect(connect),
                    opcode::Connect::CODE,
                    deadline,
                    false,
                ),
                (Request::Poll(poll), opcode::PollAdd::CODE, deadline, false),
            ];
            for (mut request, opcode, deadline, retained) in requests {
                assert_eq!(request.deadline(), deadline);
                assert_eq!(request.retains_on_orphan(), retained);
                let sqe = request.build_sqe(id);
                assert_eq!(sqe.get_opcode(), opcode as u32);
                assert_eq!(sqe.get_user_data(), id.user_data());
            }
        }
    }

    #[test]
    fn test_read_builders_reject_invalid_buffer_bounds() {
        // Check both sides of progress <= target <= capacity before the
        // builders perform pointer arithmetic for the next SQE.
        for (progress, len) in [(6, 5), (0, 6)] {
            let mut recv = make_recv_request(true);
            recv.offset = progress;
            recv.len = len;
            assert!(catch_unwind(AssertUnwindSafe(|| recv.build_sqe())).is_err());

            let mut read = make_read_request(Cache::Enabled);
            read.read = progress;
            read.len = len;
            assert!(catch_unwind(AssertUnwindSafe(|| read.build_sqe())).is_err());
        }
    }

    #[test]
    fn test_scalar_length_prefix_boundary() {
        for len in [0, 1, u32::MAX as usize - 1, u32::MAX as usize] {
            assert_eq!(scalar_len(len), len as u32);
        }

        #[cfg(target_pointer_width = "64")]
        for len in [u32::MAX as usize + 1, usize::MAX] {
            assert_eq!(scalar_len(len), u32::MAX);
        }
    }

    #[test]
    fn test_scalar_builders_preserve_partial_progress() {
        let deadline = Some(Instant::now());
        let mut send = SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline,
        };
        let mut recv = RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline,
        };
        let mut read = make_read_request(Cache::Enabled);
        read.offset = 7;

        // Real buffers remain valid while each builder advances to its suffix.
        for progress in [2, 3] {
            assert_eq!(send.build_sqe().get_opcode(), opcode::Send::CODE as u32);
            assert_eq!(recv.build_sqe().get_opcode(), opcode::Recv::CODE as u32);
            assert_eq!(read.build_sqe().get_opcode(), opcode::Read::CODE as u32);
            assert_eq!(send.on_cqe(ACTIVE, progress).is_some(), progress == 3);
            assert_eq!(recv.on_cqe(ACTIVE, progress).is_some(), progress == 3);
            assert_eq!(read.on_cqe(ACTIVE, progress).is_some(), progress == 3);
            assert_eq!(send.deadline, deadline);
            assert_eq!(recv.deadline, deadline);
        }

        assert!(send.write.is_complete());
        assert_eq!(recv.offset, 5);
        assert_eq!(read.read, 5);
        assert_eq!(read.offset, 7);
    }

    #[test]
    fn test_active_send_paths() {
        let mut request = Request::Send(make_send_request());
        assert!(request.on_cqe(ACTIVE, -libc::EAGAIN).is_none());

        // Vectored progress crosses a chunk boundary before completing.
        let mut send = make_send_request();
        let mut bufs = IoBufs::from(IoBuf::from(b"abc"));
        bufs.append(IoBuf::from(b"de"));
        send.write = bufs.into();
        let mut request = Request::Send(send);
        assert!(request.on_cqe(ACTIVE, 3).is_none());
        assert!(matches!(
            complete(request, ACTIVE, 2),
            RequestOutput::Send(Ok(()))
        ));

        for result in [0, -libc::EIO] {
            let request = Request::Send(make_send_request());
            assert!(matches!(
                complete(request, ACTIVE, result),
                RequestOutput::Send(Err(Error::SendFailed))
            ));
        }

        // Cancellation wins only if the operation did not already finish.
        let request = Request::Send(make_send_request());
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, -libc::ECANCELED),
            RequestOutput::Send(Err(Error::Timeout))
        ));

        let request = Request::Send(make_send_request());
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, 5),
            RequestOutput::Send(Ok(()))
        ));
    }

    #[test]
    fn test_active_recv_paths() {
        let mut request = Request::Recv(make_recv_request(true));
        assert!(request.on_cqe(ACTIVE, -libc::EAGAIN).is_none());

        // A non-exact receive completes on the first positive byte count.
        let request = Request::Recv(make_recv_request(false));
        assert!(matches!(
            complete(request, ACTIVE, 3),
            RequestOutput::Recv(Ok((_, 3)))
        ));

        for result in [0, -libc::EIO] {
            let request = Request::Recv(make_recv_request(true));
            assert!(matches!(
                complete(request, ACTIVE, result),
                RequestOutput::Recv(Err((_, Error::RecvFailed)))
            ));
        }

        // Cancellation wins only if the operation did not already finish.
        let request = Request::Recv(make_recv_request(true));
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, -libc::ECANCELED),
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));

        let request = Request::Recv(make_recv_request(true));
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, 5),
            RequestOutput::Recv(Ok((_, 5)))
        ));

        // Reject a CQE that claims to have written beyond the requested suffix.
        let mut request = Request::Recv(make_recv_request(true));
        let overflow = catch_unwind(AssertUnwindSafe(|| request.on_cqe(ACTIVE, 6)));
        assert!(overflow.is_err());
    }

    #[test]
    fn test_active_read_at_paths() {
        let mut request = Request::ReadAt(make_read_request(Cache::Enabled));
        assert!(request.on_cqe(ACTIVE, -libc::EAGAIN).is_none());

        // Positioned reads accumulate progress until the full range is available.
        assert!(request.on_cqe(ACTIVE, 2).is_none());
        assert!(matches!(
            complete(request, ACTIVE, 3),
            RequestOutput::ReadAt(Ok(_))
        ));

        let request = Request::ReadAt(make_read_request(Cache::Enabled));
        assert!(matches!(
            complete(request, ACTIVE, 0),
            RequestOutput::ReadAt(Err((_, Error::BlobInsufficientLength)))
        ));

        let request = Request::ReadAt(make_read_request(Cache::Enabled));
        assert!(matches!(
            complete(request, ACTIVE, -libc::EIO),
            RequestOutput::ReadAt(Err((_, Error::ReadFailed)))
        ));

        // An orphaned read may be cancelled while its SQE is still in flight.
        let request = Request::ReadAt(make_read_request(Cache::Enabled));
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, -libc::ECANCELED),
            RequestOutput::ReadAt(Err((_, Error::ReadFailed)))
        ));
    }

    #[test]
    fn test_uncached_read_fallback_preserves_progress_and_is_shared_with_writes() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut read = make_read_request(Cache::Disabled(supported.clone()));

        // Preserve completed bytes while retrying without the rejected cache hint.
        assert_eq!(read.cache.rw_flag(), libc::RWF_DONTCACHE);
        assert!(read.on_cqe(ACTIVE, 2).is_none());
        assert_eq!(read.read, 2);
        assert_eq!(read.cache.rw_flag(), libc::RWF_DONTCACHE);

        assert!(read.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert_eq!(read.read, 2);
        assert!(!supported.load(Ordering::Relaxed));
        assert_eq!(read.cache.rw_flag(), 0);

        // Capability loss is shared in both directions across sibling requests.
        let mut sibling_write = make_write_request(Cache::Disabled(supported));
        assert_eq!(sibling_write.rw_flags(), 0);

        let supported = Arc::new(AtomicBool::new(true));
        let mut write = make_write_request(Cache::Disabled(supported.clone()));
        assert_eq!(write.rw_flags(), libc::RWF_DONTCACHE);
        assert!(write.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        let mut sibling_read = make_read_request(Cache::Disabled(supported));
        assert_eq!(sibling_read.cache.rw_flag(), 0);

        // Unrelated I/O failures must not disable the hint for future requests.
        let supported = Arc::new(AtomicBool::new(true));
        let mut failing_read = make_read_request(Cache::Disabled(supported.clone()));
        assert_eq!(failing_read.cache.rw_flag(), libc::RWF_DONTCACHE);
        let result = failing_read.on_cqe(ACTIVE, -libc::EIO);
        assert!(supported.load(Ordering::Relaxed));
        assert!(matches!(result, Some(Err(Error::ReadFailed))));
    }

    #[test]
    fn test_queued_cache_fallbacks_retry() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut first = make_read_request(Cache::Disabled(supported.clone()));
        let mut second = make_read_request(Cache::Disabled(supported.clone()));

        // Requests queued before the shared downgrade must each requeue without the hint.
        assert_eq!(first.cache.rw_flag(), libc::RWF_DONTCACHE);
        assert_eq!(second.cache.rw_flag(), libc::RWF_DONTCACHE);
        assert!(first.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(second.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(!supported.load(Ordering::Relaxed));
        assert_eq!(first.cache.rw_flag(), 0);
        assert_eq!(second.cache.rw_flag(), 0);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_large_single_write_preserves_progress_and_durability() {
        // Keep one demand-paged zero allocation across the durability variants.
        // Simulated CQEs advance cursors without reading the large payload.
        let len = u32::MAX as usize + 1;
        let buf = IoBuf::from(vec![0; len]);
        for state in [
            WriteAtState::Writing,
            WriteAtState::WritingSync,
            WriteAtState::WritingBeforeSync,
        ] {
            let trailing_sync = state == WriteAtState::WritingBeforeSync;
            let mut write = WriteAtRequest {
                file: make_file_fd(),
                offset: 0,
                written: 0,
                write: IoBufs::from(buf.clone()).into(),
                state,
                cache: Cache::Enabled,
            };

            // A signed CQE cannot report the entire u32-sized prefix at once.
            for _ in 0..2 {
                assert_eq!(write.build_sqe().get_opcode(), opcode::Write::CODE as u32);
                assert!(write.on_cqe(ACTIVE, i32::MAX).is_none());
            }

            assert_eq!(write.write.remaining_len(), 2);
            assert_eq!(write.build_sqe().get_opcode(), opcode::Write::CODE as u32);
            let mut result = write.on_cqe(ACTIVE, 2);
            assert_eq!(write.written, len);
            assert!(write.write.is_complete());

            if trailing_sync {
                assert!(result.is_none());
                assert_eq!(write.build_sqe().get_opcode(), opcode::Fsync::CODE as u32);
                result = write.on_cqe(ACTIVE, 0);
            }

            assert!(matches!(result, Some(Ok(()))));
        }
    }

    #[test]
    fn test_active_write_at_paths() {
        let mut write = make_write_request(Cache::Enabled);
        assert_eq!(write.rw_flags(), 0);
        let mut request = Request::WriteAt(write);
        assert!(request.on_cqe(ACTIVE, -libc::EAGAIN).is_none());

        // Single-buffer writes preserve their completed prefix across retries.
        assert!(request.on_cqe(ACTIVE, 2).is_none());
        assert!(matches!(
            complete(request, ACTIVE, 3),
            RequestOutput::WriteAt(Ok(()))
        ));

        // The same completion path handles progress spanning several chunks.
        let mut write = make_write_request(Cache::Enabled);
        let mut bufs = IoBufs::from(IoBuf::from(b"abc"));
        bufs.append(IoBuf::from(b"de"));
        write.write = bufs.into();
        let mut request = Request::WriteAt(write);
        assert!(request.on_cqe(ACTIVE, 4).is_none());
        assert!(matches!(
            complete(request, ACTIVE, 1),
            RequestOutput::WriteAt(Ok(()))
        ));

        for result in [0, -libc::EIO, -libc::ECANCELED] {
            let request = Request::WriteAt(make_write_request(Cache::Enabled));
            assert!(matches!(
                complete(request, ACTIVE, result),
                RequestOutput::WriteAt(Err(Error::WriteFailed))
            ));
        }

        // Per-write durability changes the flags but keeps the same error mapping.
        let mut write = make_write_request(Cache::Enabled);
        write.state = WriteAtState::WritingSync;
        assert_eq!(write.rw_flags(), libc::RWF_DSYNC);
        assert!(matches!(
            complete(Request::WriteAt(write), ACTIVE, -libc::EINVAL),
            RequestOutput::WriteAt(Err(Error::WriteFailed))
        ));
    }

    #[test]
    fn test_uncached_sync_write_retries_without_hint_when_unsupported() {
        let dont_cache_supported = Arc::new(AtomicBool::new(true));

        let mut request = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::WritingSync,
            cache: Cache::Disabled(dont_cache_supported.clone()),
        };

        assert_eq!(request.rw_flags(), libc::RWF_DSYNC | libc::RWF_DONTCACHE);
        assert!(request.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        request.cache = Cache::Disabled(dont_cache_supported);
        assert_eq!(request.rw_flags(), libc::RWF_DSYNC);
        assert!(!request.cache.fallback(-libc::EOPNOTSUPP));
    }

    #[test]
    fn test_active_sync_paths() {
        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        assert!(request.on_cqe(ACTIVE, -libc::EINTR).is_none());

        // A sync exposes the kernel error code, including unsolicited ECANCELED.
        for code in [libc::ECANCELED, libc::EIO] {
            let request = Request::Sync(SyncRequest {
                file: make_file_fd(),
            });
            let RequestOutput::Sync(Err(Error::Io(error))) = complete(request, ACTIVE, -code)
            else {
                panic!("expected sync I/O error");
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }

        for result in [0, 1] {
            let request = Request::Sync(SyncRequest {
                file: make_file_fd(),
            });
            assert!(matches!(
                complete(request, ACTIVE, result),
                RequestOutput::Sync(Ok(()))
            ));
        }
    }

    #[test]
    fn test_complete_preserves_status_and_read_buffers() {
        // Completion can run without any CQE, for example for queued cancellation.
        // It packages the supplied status without changing its error variant.
        let request = Request::Send(make_send_request());
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(output, RequestOutput::Send(Err(Error::Timeout))));
        drop(retired);

        // Both read variants return the original destination even on failure.
        let mut recv = make_recv_request(true);
        let pointer = recv.buf.as_mut_ptr();
        let (output, retired) = Request::Recv(recv).complete(Err(Error::Timeout));
        let RequestOutput::Recv(Err((mut buf, Error::Timeout))) = output else {
            panic!("expected recv timeout and buffer");
        };
        assert_eq!(buf.as_mut_ptr(), pointer);
        drop(retired);

        let mut read = make_read_request(Cache::Enabled);
        let pointer = read.buf.as_mut_ptr();
        let (output, retired) = Request::ReadAt(read).complete(Err(Error::Timeout));
        let RequestOutput::ReadAt(Err((mut buf, Error::Timeout))) = output else {
            panic!("expected read timeout and buffer");
        };
        assert_eq!(buf.as_mut_ptr(), pointer);
        drop(retired);

        let request = Request::WriteAt(make_write_request(Cache::Enabled));
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(
            output,
            RequestOutput::WriteAt(Err(Error::Timeout))
        ));
        drop(retired);

        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
        });
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(output, RequestOutput::Sync(Err(Error::Timeout))));
        drop(retired);

        let request = Request::Connect(make_connect_request("127.0.0.1:1234"));
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(
            output,
            RequestOutput::Connect(Err(Error::Timeout))
        ));
        drop(retired);

        let request = Request::Poll(make_poll_request());
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(output, RequestOutput::Poll(Err(Error::Timeout))));
        drop(retired);
    }
}
