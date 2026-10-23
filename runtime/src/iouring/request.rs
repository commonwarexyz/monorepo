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
use crate::{Error, IoBuf, IoBufMut, IoBufs, storage::iouring::Shared};
use bytes::Buf as _;
use commonware_utils::{NZUsize, sync::AsyncMutex};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types::Fd};
use std::{
    fs::File,
    net::TcpListener,
    os::fd::{AsRawFd, OwnedFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
/// span as few submissions as possible.
pub const IOVEC_BATCH_SIZE: usize = 1024;

/// Alignment of the file offset, length and destination address of every direct read.
pub(crate) const DIRECT_ALIGN: usize = 4096;

/// Largest length of one direct read: `i32::MAX` rounded down to [DIRECT_ALIGN].
///
/// The kernel returns at most `MAX_RW_COUNT` (`INT_MAX` rounded down to the page size) bytes from
/// one read. On pages larger than [DIRECT_ALIGN] that is a short read whose length is still a
/// multiple of [DIRECT_ALIGN], so the read continues from an aligned cursor.
const DIRECT_CHUNK: usize = i32::MAX as usize / DIRECT_ALIGN * DIRECT_ALIGN;

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

    /// Gate shared by every durability operation on this open.
    pub fn durability(&self) -> Option<&Arc<AsyncMutex<()>>> {
        match self {
            Self::Sync(r) => Some(&r.file.durability),
            Self::WriteAt(r) if r.state != WriteAtState::Writing => Some(&r.file.durability),
            _ => None,
        }
    }

    /// Resolve a durability request that needs no SQE, with its permit held.
    pub fn prepare_durability(&self) -> Option<Result<(), Error>> {
        match self {
            Self::Sync(r) => match r.file.needs_sync() {
                Ok(true) => None,
                Ok(false) => Some(Ok(())),
                Err(error) => Some(Err(error)),
            },
            Self::WriteAt(r) => r.file.tracker.failure().map(Err),
            _ => unreachable!("durability permit for another request kind"),
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
            Self::ReadAt(mut r) => {
                let result = match result {
                    Ok(()) => Ok(r.buf),
                    Err(err) => {
                        // The kernel may not have written the buffer, so none of it is readable.
                        r.buf.clear();
                        Err((r.buf, err))
                    }
                };
                (
                    RequestOutput::ReadAt(result),
                    RetiredResources::File {
                        _file: r.file,
                        _write: None,
                    },
                )
            }
            Self::WriteAt(r) => {
                // Only plain writes stay in `Writing`. Settle here so a caller that stopped
                // waiting still leaves the open's debt correct.
                let result = r.file.wrote(
                    r.state != WriteAtState::Writing,
                    matches!(r.state, WriteAtState::WritingSync | WriteAtState::Syncing),
                    result,
                );

                // A successful trailing sync also covers the mutations completed before the
                // request. Credit them before the durability permit is released.
                let result = match result {
                    Ok(()) if r.state == WriteAtState::Syncing => r.file.tracker.end_sync(r.seen),
                    result => result,
                };
                (
                    RequestOutput::WriteAt(result),
                    RetiredResources::File {
                        _file: r.file,
                        _write: Some(r.write),
                    },
                )
            }
            Self::Sync(r) => {
                let result = match result {
                    Ok(()) => r.file.tracker.end_sync(r.seen),
                    Err(error) => {
                        r.file.sync_failed(&error);
                        Err(error)
                    }
                };
                (
                    RequestOutput::Sync(result),
                    RetiredResources::File {
                        _file: r.file,
                        _write: None,
                    },
                )
            }
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
    /// Storage open, directory hold, and any positioned write buffers.
    File {
        /// Storage open carrying its file, directory hold, and durability debt.
        _file: Arc<Shared>,
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
///
/// A direct read covers the aligned superset of its range through the open's direct
/// descriptor: `offset` is the superset's offset, `buf` its unadvanced aligned buffer and
/// `read` the completed prefix. A completion that can neither finish nor continue it switches
/// the request, at most once, to a buffered read of the range.
pub struct ReadAtRequest {
    /// Open whose file the current read SQE uses.
    pub file: Arc<Shared>,
    /// Starting file offset for the logical read, or for the superset of a direct read.
    pub offset: u64,
    /// Bytes already read into `buf`.
    pub read: usize,
    /// Fixed-length destination buffer owned by the request.
    pub buf: IoBufMut,
    /// Page-cache policy for this request.
    pub cache: Cache,
    /// The range inside `buf` while the request reads with direct I/O.
    direct: Option<Direct>,
}

/// Direct phase of a [ReadAtRequest].
#[derive(Clone, Copy)]
struct Direct {
    /// The open's direct descriptor. It outlives the request, which retains the open, and the
    /// open sets it at most once and never takes it.
    fd: RawFd,
    /// Bytes of `buf` before the range.
    skip: usize,
    /// Length of the range.
    len: usize,
}

impl ReadAtRequest {
    /// Read `buf.len()` bytes at `offset` through the open's file.
    pub const fn new(file: Arc<Shared>, offset: u64, buf: IoBufMut, cache: Cache) -> Self {
        Self {
            file,
            offset,
            read: 0,
            buf,
            cache,
            direct: None,
        }
    }

    /// Read the `len` bytes at physical `offset` with direct I/O through `fd`, the open's direct
    /// descriptor, into an exact-size buffer holding their [DIRECT_ALIGN]-aligned superset.
    ///
    /// `None` when the range cannot be read directly: it is empty, its superset overflows or
    /// ends beyond the largest file offset, or the superset's aligned buffer has no allocation
    /// layout.
    pub fn direct(file: Arc<Shared>, fd: RawFd, offset: u64, len: usize) -> Option<Self> {
        if len == 0 {
            return None;
        }

        // The superset spans the aligned blocks that hold the range and must end within the
        // largest file offset.
        let skip = (offset % DIRECT_ALIGN as u64) as usize;
        let aligned_len = skip
            .checked_add(len)?
            .checked_next_multiple_of(DIRECT_ALIGN)?;
        let aligned_offset = offset - skip as u64;

        if aligned_offset.checked_add(aligned_len as u64)? > i64::MAX as u64 {
            return None;
        }

        let mut buf = IoBufMut::try_with_alignment(aligned_len, NZUsize!(DIRECT_ALIGN))?;

        // SAFETY: Only the kernel writes this buffer, and nothing reads it before a completion.
        // `on_cqe` narrows it to the range on success, once completions reported every byte of
        // the range, and on a fallback, whose buffered read fills every byte before it reports
        // success. A failed request returns it through `Request::complete`, which clears its
        // length.
        unsafe { buf.set_len(aligned_len) };

        Some(Self {
            file,
            offset: aligned_offset,
            read: 0,
            buf,
            cache: Cache::Disabled,
            direct: Some(Direct { fd, skip, len }),
        })
    }

    /// Build the next positioned read SQE for the unread suffix of the target.
    fn build_sqe(&mut self) -> SqueueEntry {
        let fd = Fd(self.file.as_raw_fd());
        let len = self.buf.len();
        assert!(
            self.read <= len,
            "read_at progress exceeds destination length"
        );

        // SAFETY: buf owns stable memory with read <= buf.len() <= capacity.
        let ptr = unsafe { self.buf.as_mut_ptr().add(self.read) };
        let remaining = len - self.read;
        let offset = self.offset + self.read as u64;

        // A direct read submits at most one chunk of its unread superset, without RWF flags.
        if let Some(direct) = self.direct {
            let len = remaining.min(DIRECT_CHUNK);
            assert!(
                len > 0
                    && len.is_multiple_of(DIRECT_ALIGN)
                    && ptr.addr().is_multiple_of(DIRECT_ALIGN)
                    && offset.is_multiple_of(DIRECT_ALIGN as u64),
                "direct read is empty or not aligned"
            );
            return opcode::Read::new(Fd(direct.fd), ptr, scalar_len(len))
                .offset(offset)
                .build();
        }
        let rw_flags = self.cache.rw_flag(&self.file.dont_cache_supported);
        opcode::Read::new(fd, ptr, scalar_len(remaining))
            .offset(offset)
            .rw_flags(rw_flags)
            .build()
    }

    /// Classify one read CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> Option<Result<(), Error>> {
        // Direct completions never reach the cache fallback below, so they never clear the
        // open's RWF_DONTCACHE support.
        if let Some(direct) = self.direct {
            let end = direct.skip + direct.len;
            let cancelling = matches!(state, WaiterState::CancelRequested);

            match CqeResult::from_raw(result, state) {
                CqeResult::Retry => return None,
                CqeResult::Cancelled => return Some(Err(Error::ReadFailed)),
                CqeResult::Error(code) if code == -libc::ECANCELED => {
                    return Some(Err(Error::ReadFailed));
                }
                CqeResult::Positive(n) => {
                    let submitted = (self.buf.len() - self.read).min(DIRECT_CHUNK);
                    assert!(
                        n <= submitted,
                        "direct read CQE exceeds submitted length: n={n} submitted={submitted}"
                    );
                    self.read += n;

                    // A completion covering the range finishes it, even under a cancellation
                    // request. Only bytes completions reported remain reachable.
                    if self.read >= end {
                        self.buf.truncate(end);
                        self.buf.advance(direct.skip);
                        return Some(Ok(()));
                    }

                    // Aligned progress continues. Under a cancellation request any progress
                    // ends the read, which the waiter table times out without resubmitting.
                    if n.is_multiple_of(DIRECT_ALIGN) || cancelling {
                        return None;
                    }
                }
                CqeResult::Zero | CqeResult::Error(_) => {}
            }

            // Under a cancellation request the read ends instead, which the waiter table times
            // out without resubmitting it.
            if cancelling {
                return None;
            }

            // An empty or unaligned short read, or any other error, switches an active read to a
            // buffered read of the whole range into the narrowed buffer.
            self.buf.truncate(end);
            self.buf.advance(direct.skip);
            self.read = 0;
            self.offset += direct.skip as u64;
            self.cache = Cache::Disabled;
            self.direct = None;

            return None;
        }
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => None,
            CqeResult::Error(code)
                if self.cache.fallback(&self.file.dont_cache_supported, code) =>
            {
                None
            }
            CqeResult::Cancelled | CqeResult::Error(_) => Some(Err(Error::ReadFailed)),
            CqeResult::Zero => Some(Err(Error::BlobInsufficientLength)),
            CqeResult::Positive(n) => {
                let remaining = self.buf.len() - self.read;
                assert!(
                    n <= remaining,
                    "read CQE exceeds requested length: n={n} remaining={remaining}"
                );
                self.read += n;
                if self.read >= self.buf.len() {
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
    Disabled,
}

impl Cache {
    /// Return the flag for this request, falling back to normal caching if another request has
    /// already found the hint unsupported.
    fn rw_flag(&mut self, supported: &AtomicBool) -> i32 {
        match self {
            Self::Disabled if supported.load(Ordering::Relaxed) => libc::RWF_DONTCACHE,
            Self::Disabled => {
                *self = Self::Enabled;
                0
            }
            Self::Enabled => 0,
        }
    }

    /// Retry without cache bypass if the kernel rejected the hint.
    fn fallback(&mut self, supported: &AtomicBool, code: i32) -> bool {
        if code != -libc::EOPNOTSUPP {
            return false;
        }

        // Each request that submitted the hint must retry, even if a sibling
        // has already updated the shared capability flag.
        match std::mem::replace(self, Self::Enabled) {
            Self::Disabled => {
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
    /// Open whose file the current write SQE uses.
    pub file: Arc<Shared>,
    /// File offset for the next write SQE.
    pub offset: u64,
    /// Write cursor and buffers that still need to be written.
    pub write: WriteBuffers,
    /// Current write and durability phase.
    pub state: WriteAtState,
    /// Page-cache policy for this request.
    pub cache: Cache,
    /// Completed mutations that preceded this request, which a trailing sync covers.
    seen: u64,
}

impl WriteAtRequest {
    /// Record the mutation frontier a trailing sync can cover before ring submission.
    pub fn new(
        file: Arc<Shared>,
        offset: u64,
        write: WriteBuffers,
        state: WriteAtState,
        cache: Cache,
    ) -> Self {
        let seen = file.tracker.begin_sync();
        Self {
            file,
            offset,
            write,
            state,
            cache,
            seen,
        }
    }

    /// Use `RWF_DSYNC` because the write contract does not require timestamp-only metadata.
    fn rw_flags(&mut self) -> i32 {
        let sync = if self.state == WriteAtState::WritingSync {
            libc::RWF_DSYNC
        } else {
            0
        };
        sync | self.cache.rw_flag(&self.file.dont_cache_supported)
    }

    /// Build the next positioned write SQE for the remaining bytes.
    fn build_sqe(&mut self) -> SqueueEntry {
        if self.state == WriteAtState::Syncing {
            return build_datasync_sqe(&self.file);
        }

        let fd = Fd(self.file.as_raw_fd());
        let rw_flags = self.rw_flags();
        match &mut self.write {
            WriteBuffers::Single { buf, offset } => {
                let bytes = &buf.as_ref()[*offset..];
                let ptr = bytes.as_ptr();
                opcode::Write::new(fd, ptr, scalar_len(bytes.len()))
                    .offset(self.offset)
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
                    .offset(self.offset)
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
            CqeResult::Error(code)
                if self.cache.fallback(&self.file.dont_cache_supported, code) =>
            {
                None
            }
            CqeResult::Error(code) if self.state == WriteAtState::WritingSync => Some(Err(
                Error::Io(std::io::Error::from_raw_os_error(-code).into()),
            )),
            CqeResult::Cancelled | CqeResult::Error(_) | CqeResult::Zero => {
                Some(Err(Error::WriteFailed))
            }
            CqeResult::Positive(n) => {
                self.write.advance(n);
                self.offset += n as u64;
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
    /// Open whose file the fsync SQE uses.
    pub file: Arc<Shared>,
    /// Completed mutations that preceded this request's construction.
    seen: u64,
}

impl SyncRequest {
    /// Record the mutation frontier this sync can cover before ring submission.
    pub fn new(file: Arc<Shared>) -> Self {
        let seen = file.tracker.begin_sync();
        Self { file, seen }
    }

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
    /// Absolute deadline for this readiness observation.
    pub deadline: Option<Instant>,
}

impl PollRequest {
    /// Build one readiness SQE, leaving multishot mode disabled.
    fn build_sqe(&self) -> SqueueEntry {
        opcode::PollAdd::new(Fd(self.fd.as_raw_fd()), libc::POLLIN as u32).build()
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
    fn make_file() -> Arc<Shared> {
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
        Shared::detached(file, hold.clone())
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
    fn make_read_request(file: Arc<Shared>, cache: Cache) -> ReadAtRequest {
        ReadAtRequest::new(file, 0, IoBufMut::zeroed(5), cache)
    }

    /// Create a five-byte positioned write with no durability requirement.
    fn make_write_request(file: Arc<Shared>, cache: Cache) -> WriteAtRequest {
        WriteAtRequest::new(
            file,
            0,
            IoBufs::from(IoBuf::from(b"hello")).into(),
            WriteAtState::Writing,
            cache,
        )
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

    /// Retain a simulated open whose direct descriptor is open, returning it with that
    /// descriptor.
    fn make_direct_file() -> (Arc<Shared>, RawFd) {
        let file = make_file();
        let (direct, _peer) = UnixStream::pair().expect("failed to create unix socket pair");
        let fd = file.set_direct(File::from(OwnedFd::from(direct)));
        (file, fd)
    }

    /// Create a direct read of the 4096 bytes at physical offset 4196, whose superset is the
    /// 8192 bytes at 4096.
    fn make_direct_request(file: Arc<Shared>, fd: RawFd) -> ReadAtRequest {
        ReadAtRequest::direct(file, fd, 4196, 4096).unwrap()
    }

    /// Positioned read fields of an SQE: opcode, descriptor, offset, address, length and RWF
    /// flags.
    fn read_fields(sqe: &SqueueEntry) -> (u8, i32, u64, u64, u32, i32) {
        const _: () = assert!(size_of::<SqueueEntry>() == 64);

        // SAFETY: SqueueEntry is a repr(C) wrapper of the kernel's 64-byte io_uring_sqe, whose
        // fields are integers without padding, and opcode builders zero it before setting them.
        let bytes: [u8; 64] = unsafe { std::mem::transmute_copy(sqe) };
        let u32_at = |at: usize| u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
        (
            bytes[0],
            u32_at(4) as i32,
            u64_at(8),
            u64_at(16),
            u32_at(24),
            u32_at(28) as i32,
        )
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
                    Request::ReadAt(make_read_request(make_file(), Cache::Enabled)),
                    opcode::Read::CODE,
                    None,
                    false,
                ),
                (
                    Request::WriteAt(make_write_request(make_file(), Cache::Enabled)),
                    opcode::Write::CODE,
                    None,
                    true,
                ),
                (
                    Request::Sync(SyncRequest::new(make_file())),
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
        }

        let mut read = make_read_request(make_file(), Cache::Enabled);
        read.read = 6;
        assert!(catch_unwind(AssertUnwindSafe(|| read.build_sqe())).is_err());
    }

    #[test]
    fn test_scalar_length_prefix_boundary() {
        for len in [0, 1, u32::MAX as usize - 1, u32::MAX as usize] {
            assert_eq!(scalar_len(len), len as u32);
        }

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
        let mut read = make_read_request(make_file(), Cache::Enabled);
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
        let mut request = Request::ReadAt(make_read_request(make_file(), Cache::Enabled));
        assert!(request.on_cqe(ACTIVE, -libc::EAGAIN).is_none());

        // Positioned reads accumulate progress until the full range is available.
        assert!(request.on_cqe(ACTIVE, 2).is_none());
        assert!(matches!(
            complete(request, ACTIVE, 3),
            RequestOutput::ReadAt(Ok(_))
        ));

        let request = Request::ReadAt(make_read_request(make_file(), Cache::Enabled));
        assert!(matches!(
            complete(request, ACTIVE, 0),
            RequestOutput::ReadAt(Err((_, Error::BlobInsufficientLength)))
        ));

        let request = Request::ReadAt(make_read_request(make_file(), Cache::Enabled));
        assert!(matches!(
            complete(request, ACTIVE, -libc::EIO),
            RequestOutput::ReadAt(Err((_, Error::ReadFailed)))
        ));

        // An orphaned read may be cancelled while its SQE is still in flight.
        let request = Request::ReadAt(make_read_request(make_file(), Cache::Enabled));
        assert!(matches!(
            complete(request, WaiterState::CancelRequested, -libc::ECANCELED),
            RequestOutput::ReadAt(Err((_, Error::ReadFailed)))
        ));
    }

    #[test]
    fn test_uncached_read_fallback_preserves_progress_and_is_shared_with_writes() {
        let file = make_file();
        let mut read = make_read_request(file.clone(), Cache::Disabled);

        // Preserve completed bytes while retrying without the rejected cache hint.
        assert_eq!(
            read.cache.rw_flag(&file.dont_cache_supported),
            libc::RWF_DONTCACHE
        );
        assert!(read.on_cqe(ACTIVE, 2).is_none());
        assert_eq!(read.read, 2);
        assert_eq!(
            read.cache.rw_flag(&file.dont_cache_supported),
            libc::RWF_DONTCACHE
        );

        assert!(read.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert_eq!(read.read, 2);
        assert!(!file.dont_cache_supported.load(Ordering::Relaxed));
        assert_eq!(read.cache.rw_flag(&file.dont_cache_supported), 0);

        // Capability loss is shared in both directions across sibling requests.
        let mut sibling_write = make_write_request(file, Cache::Disabled);
        assert_eq!(sibling_write.rw_flags(), 0);

        let file = make_file();
        let mut write = make_write_request(file.clone(), Cache::Disabled);
        assert_eq!(write.rw_flags(), libc::RWF_DONTCACHE);
        assert!(write.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        let mut sibling_read = make_read_request(file.clone(), Cache::Disabled);
        assert_eq!(sibling_read.cache.rw_flag(&file.dont_cache_supported), 0);

        // Unrelated I/O failures must not disable the hint for future requests.
        let file = make_file();
        let mut failing_read = make_read_request(file.clone(), Cache::Disabled);
        assert_eq!(
            failing_read.cache.rw_flag(&file.dont_cache_supported),
            libc::RWF_DONTCACHE
        );
        let result = failing_read.on_cqe(ACTIVE, -libc::EIO);
        assert!(file.dont_cache_supported.load(Ordering::Relaxed));
        assert!(matches!(result, Some(Err(Error::ReadFailed))));
    }

    #[test]
    fn test_queued_cache_fallbacks_retry() {
        let file = make_file();
        let mut first = make_read_request(file.clone(), Cache::Disabled);
        let mut second = make_read_request(file.clone(), Cache::Disabled);

        // Requests queued before the shared downgrade must each requeue without the hint.
        assert_eq!(
            first.cache.rw_flag(&file.dont_cache_supported),
            libc::RWF_DONTCACHE
        );
        assert_eq!(
            second.cache.rw_flag(&file.dont_cache_supported),
            libc::RWF_DONTCACHE
        );
        assert!(first.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(second.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(!file.dont_cache_supported.load(Ordering::Relaxed));
        assert_eq!(first.cache.rw_flag(&file.dont_cache_supported), 0);
        assert_eq!(second.cache.rw_flag(&file.dont_cache_supported), 0);
    }

    /// A direct read covers the aligned superset of its range with an exact-size aligned buffer,
    /// and its first SQE reads that superset through the direct descriptor.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_direct_read_covers_the_aligned_superset() {
        let (file, fd) = make_direct_file();

        // The superset of each (offset, len), as (offset, skip, length). The last ends at the
        // largest aligned file offset.
        let top = (1u64 << 63) - 2 * DIRECT_ALIGN as u64;

        for ((offset, len), (aligned_offset, skip, aligned_len)) in [
            ((4096, 4096), (4096, 0, 4096)),
            ((4103, 10), (4096, 7, 4096)),
            ((8189, 6), (4096, 4093, 8192)),
            ((8192, 1), (8192, 0, 4096)),
            ((8, 4096), (0, 8, 8192)),
            ((top + 10, 4086), (top, 10, 4096)),
        ] {
            // The request starts at the superset, in an exact-size aligned buffer, and records
            // where the range lies in it.
            let mut read = ReadAtRequest::direct(file.clone(), fd, offset, len).unwrap();
            assert_eq!((read.offset, read.read), (aligned_offset, 0));
            assert_eq!(
                (read.buf.len(), read.buf.capacity()),
                (aligned_len, aligned_len)
            );
            let base = read.buf.as_mut_ptr() as u64;
            assert!(base.is_multiple_of(DIRECT_ALIGN as u64));
            assert!(matches!(read.cache, Cache::Disabled));
            let direct = read.direct.unwrap();
            assert_eq!((direct.fd, direct.skip, direct.len), (fd, skip, len));

            // Its first SQE reads the whole superset through the direct descriptor, without RWF
            // flags even though the open supports RWF_DONTCACHE.
            assert_eq!(
                read_fields(&read.build_sqe()),
                (
                    opcode::Read::CODE,
                    fd,
                    aligned_offset,
                    base,
                    aligned_len as u32,
                    0
                )
            );
        }

        // An empty range, a superset whose length or end overflows, and a superset crossing the
        // largest file offset while the range does not are not read directly.
        for (offset, len) in [
            (0, 0),
            (4095, usize::MAX - 4094),
            (0, usize::MAX - 100),
            (u64::MAX - 1, 1),
            (top + DIRECT_ALIGN as u64, 1),
        ] {
            assert!(
                ReadAtRequest::direct(file.clone(), fd, offset, len).is_none(),
                "{offset} {len}"
            );
        }
    }

    /// A superset one page longer than a chunk is read in two chunks without a fallback under
    /// every page size's cap on one kernel read.
    #[test]
    fn test_direct_chunks_progress_under_every_page_cap() {
        assert_eq!(DIRECT_CHUNK % DIRECT_ALIGN, 0);
        assert!(DIRECT_CHUNK <= i32::MAX as usize);

        // The superset's buffer stays demand-paged because simulated completions write nothing.
        // The kernel caps one read at i32::MAX rounded down to its page size, for 4, 16 and
        // 64 KiB pages.
        let (file, fd) = make_direct_file();

        for page in [4096usize, 16 << 10, 64 << 10] {
            let kernel_cap = i32::MAX as usize & !(page - 1);

            for skip in [0, 100] {
                let len = DIRECT_CHUNK + 1 - skip;
                let mut read = ReadAtRequest::direct(file.clone(), fd, skip as u64, len).unwrap();
                assert_eq!(read.buf.len(), DIRECT_CHUNK + DIRECT_ALIGN);

                let mut chunks = 0;

                loop {
                    // Each SQE submits an aligned chunk at the cursor.
                    let (_, _, offset, _, submitted, _) = read_fields(&read.build_sqe());
                    let submitted = submitted as usize;
                    assert_eq!(offset, read.read as u64);
                    assert!(submitted > 0 && submitted <= DIRECT_CHUNK);
                    assert!(submitted.is_multiple_of(DIRECT_ALIGN));
                    chunks += 1;

                    // The kernel reports at most its cap, which is still aligned progress, so
                    // the read continues until it covers the range.
                    let result = i32::try_from(submitted.min(kernel_cap)).unwrap();

                    match read.on_cqe(ACTIVE, result) {
                        None => assert!(read.read.is_multiple_of(DIRECT_ALIGN)),
                        Some(result) => {
                            assert!(result.is_ok());
                            break;
                        }
                    }
                }

                // Two chunks covered the range, and the buffer is narrowed to it.
                assert_eq!(chunks, 2);
                assert_eq!(read.buf.len(), len);
            }
        }
    }

    /// Sequences of completions, applied to direct reads as the kernel reports them, end each
    /// read as expected and expose exactly the reported bytes of its range. Every SQE goes
    /// through the descriptor of the read's phase.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_direct_read_completion_sequences() {
        /// How a sequence of completions ended.
        #[derive(Debug, PartialEq)]
        enum Served {
            /// Served by direct reads.
            Direct,
            /// Served by a buffered read after a fallback.
            Buffered,
            /// Failed.
            Failed,
            /// Timed out under a cancellation request, without output.
            TimedOut,
            /// Still needs another completion.
            Pending,
        }

        /// Byte at physical offset `offset` of the simulated file.
        const fn byte(offset: u64) -> u8 {
            (offset % 251) as u8
        }

        /// Simulate the kernel completing the first `n` bytes of the next read SQE of `read`.
        fn kernel_read(read: &mut ReadAtRequest, n: usize) {
            let (_, fd, offset, address, len, flags) = read_fields(&read.build_sqe());

            // A direct read goes through the direct descriptor without RWF flags, and its
            // fallback through the open's file with the RWF_DONTCACHE hint.
            let phase = match read.direct {
                Some(direct) => (direct.fd, 0),
                None => (read.file.as_raw_fd(), libc::RWF_DONTCACHE),
            };

            assert_eq!((fd, flags), phase);

            // The SQE targets the unread part of the buffer, which the kernel then writes.
            let base = read.buf.as_mut_ptr();
            assert_eq!(address, base as u64 + read.read as u64);
            assert!(n <= len as usize);

            for i in 0..n {
                // SAFETY: The SQE's destination is `read.read` bytes into the buffer and holds
                // `len >= n` bytes.
                unsafe { base.add(read.read + i).write(byte(offset + i as u64)) };
            }
        }

        /// Apply `completions` to a direct read of `len` bytes at physical `offset`, the
        /// kernel writing each positive count, and return the outcome with the exposed bytes.
        /// Completions from index `cancel_from` on arrive under a cancellation request.
        fn serve(
            offset: u64,
            len: usize,
            seed: Option<u8>,
            completions: &[i32],
            cancel_from: usize,
        ) -> (Served, Option<Vec<u8>>) {
            let (file, fd) = make_direct_file();
            let mut read = ReadAtRequest::direct(file.clone(), fd, offset, len).unwrap();

            if let Some(seed) = seed {
                // SAFETY: The buffer holds `buf.len()` bytes.
                unsafe { std::ptr::write_bytes(read.buf.as_mut_ptr(), seed, read.buf.len()) };
            }

            for (index, &result) in completions.iter().enumerate() {
                if result > 0 {
                    kernel_read(&mut read, result as usize);
                }

                let cancelling = index >= cancel_from;
                let state = if cancelling {
                    WaiterState::CancelRequested
                } else {
                    ACTIVE
                };

                // No direct completion changes the open's RWF_DONTCACHE support.
                let outcome = read.on_cqe(state, result);
                assert!(file.dont_cache_supported.load(Ordering::Relaxed));

                match outcome {
                    Some(Ok(())) => {
                        // The bytes around the range stay unreachable through every conversion.
                        let buf = read.buf.freeze().try_into_mut().unwrap();
                        assert_eq!(buf.len(), len);
                        return (Served::Direct, Some(buf.as_ref().to_vec()));
                    }
                    // A failed read's output exposes nothing.
                    Some(Err(Error::ReadFailed)) => {
                        let (output, _) = Request::ReadAt(read).complete(Err(Error::ReadFailed));

                        let RequestOutput::ReadAt(Err((buf, _))) = output else {
                            panic!("expected a failed read");
                        };

                        assert_eq!(buf.len(), 0);
                        return (Served::Failed, None);
                    }
                    Some(Err(error)) => panic!("unexpected {error:?}"),
                    // The cursor may be unaligned, but no further read is submitted.
                    None if cancelling => return (Served::TimedOut, None),
                    // A fallback reads the whole range again into the narrowed buffer.
                    None if read.direct.is_none() => {
                        assert_eq!((read.offset, read.read, read.buf.len()), (offset, 0, len));
                        kernel_read(&mut read, len);
                        let result = i32::try_from(len).unwrap();
                        assert!(matches!(read.on_cqe(ACTIVE, result), Some(Ok(()))));
                        return (Served::Buffered, Some(read.buf.as_ref().to_vec()));
                    }
                    // A retry or aligned progress keeps the read direct.
                    None => assert!(read.read.is_multiple_of(DIRECT_ALIGN)),
                }
            }

            (Served::Pending, None)
        }

        const NEVER: usize = usize::MAX;
        let page = DIRECT_ALIGN as i32;
        let long = 3 * DIRECT_ALIGN - 200;

        // (offset, len, completions, index of the first completion under a cancellation
        // request, outcome)
        let cases: &[(u64, usize, &[i32], usize, Served)] = &[
            // One covering read, aligned or not.
            (0, DIRECT_ALIGN, &[page], NEVER, Served::Direct),
            (4196, 50, &[page], NEVER, Served::Direct),
            (4093, 6, &[2 * page], NEVER, Served::Direct),
            // A short read at the end of the file that still covers the range, and one that
            // ends a byte short of it.
            (8192 + 10, 100, &[200], NEVER, Served::Direct),
            (8192 + 10, 100, &[110], NEVER, Served::Direct),
            (8192 + 10, 100, &[109], NEVER, Served::Buffered),
            // Retries, then aligned progress, then a covering read.
            (
                100,
                long,
                &[-libc::EAGAIN, page, -libc::EINTR, 2 * page],
                NEVER,
                Served::Direct,
            ),
            (100, long, &[page, page, page - 100], NEVER, Served::Direct),
            (
                100,
                long,
                &[page, page, page - 101],
                NEVER,
                Served::Buffered,
            ),
            // Fallbacks after a direct prefix or none, for an empty or unaligned short read or
            // any error but a cancellation.
            (100, long, &[page, 10], NEVER, Served::Buffered),
            (100, long, &[page, 0], NEVER, Served::Buffered),
            (100, long, &[page, -libc::EOPNOTSUPP], NEVER, Served::Buffered),
            (7, 10, &[-libc::EINVAL], NEVER, Served::Buffered),
            (7, 10, &[-libc::EOPNOTSUPP], NEVER, Served::Buffered),
            (7, 10, &[-libc::EFAULT], NEVER, Served::Buffered),
            (7, 10, &[-libc::ENOMEM], NEVER, Served::Buffered),
            (4096, 4096, &[-libc::EIO], NEVER, Served::Buffered),
            // Kernel cancellation and unfinished reads expose nothing.
            (7, 10, &[-libc::ECANCELED], NEVER, Served::Failed),
            (100, long, &[page, -libc::EAGAIN], NEVER, Served::Pending),
            // Under a cancellation request a covering completion still exposes exactly the
            // reported bytes, including after an aligned prefix read before the request.
            (4196, 50, &[page], 0, Served::Direct),
            (8192 + 10, 100, &[110], 0, Served::Direct),
            (100, long, &[page, 2 * page], 1, Served::Direct),
            (100, long, &[page, page, page - 100], 2, Served::Direct),
            // Anything else under a cancellation request ends the read without output, even
            // a retry, aligned progress, or a short completion that leaves the cursor unaligned.
            (7, 10, &[-libc::EAGAIN], 0, Served::TimedOut),
            (100, long, &[page], 0, Served::TimedOut),
            (100, long, &[page, page - 1], 1, Served::TimedOut),
            (100, long, &[page, page, page - 101], 2, Served::TimedOut),
            (8192 + 10, 100, &[109], 0, Served::TimedOut),
            (100, long, &[page, 0], 1, Served::TimedOut),
            (100, long, &[page, -libc::EAGAIN], 1, Served::TimedOut),
            (7, 10, &[-libc::EINVAL], 0, Served::TimedOut),
            (7, 10, &[-libc::ECANCELED], 0, Served::Failed),
        ];

        // Fresh buffers expose any unwritten byte to Miri. Seeded buffers expose a stale byte to
        // the comparison. Bytes are compared before outcomes, so an early success reaches both.
        for seed in [None, Some(0xEE), Some(0x00)] {
            for (offset, len, completions, cancel_from, outcome) in cases {
                let (served, bytes) = serve(*offset, *len, seed, completions, *cancel_from);

                if let Some(bytes) = bytes {
                    let expected: Vec<u8> = (*offset..*offset + *len as u64).map(byte).collect();
                    assert_eq!(bytes, expected, "{offset} {len} {completions:?} {seed:?}");
                }

                assert_eq!(
                    &served, outcome,
                    "{offset} {len} {completions:?} {cancel_from}"
                );
            }
        }

        // A completion longer than its submission is an invariant failure, for the first chunk
        // and after aligned progress.
        let (file, fd) = make_direct_file();

        for (prefix, result) in [(0, 8193), (4096, 4097)] {
            let mut read = make_direct_request(file.clone(), fd);

            if prefix > 0 {
                assert!(read.on_cqe(ACTIVE, prefix).is_none());
            }

            let overflow = catch_unwind(AssertUnwindSafe(|| read.on_cqe(ACTIVE, result)));
            assert!(overflow.is_err());
        }
    }

    /// A fallback rereads the whole range as a buffered read with the hint, and keeps its own
    /// progress when a buffered rejection of the hint clears the open's RWF_DONTCACHE support.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_direct_fallback_rereads_the_range_and_keeps_buffered_progress() {
        let (file, fd) = make_direct_file();
        let buffered_fd = file.as_raw_fd();
        let mut read = make_direct_request(file.clone(), fd);
        let base = read.buf.as_mut_ptr() as u64;

        // A direct prefix, then a rejected direct read, switches to a buffered read of the
        // whole range with the hint.
        assert!(read.on_cqe(ACTIVE, 4096).is_none());
        assert!(read.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert_eq!(
            read_fields(&read.build_sqe()),
            (
                opcode::Read::CODE,
                buffered_fd,
                4196,
                base + 100,
                4096,
                libc::RWF_DONTCACHE
            )
        );

        // A buffered prefix, then a buffered rejection of the hint, which clears the open's
        // support. The retry continues from the prefix without the hint.
        assert!(read.on_cqe(ACTIVE, 3).is_none());
        assert_eq!(read_fields(&read.build_sqe()).2, 4199);
        assert!(read.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(!file.dont_cache_supported.load(Ordering::Relaxed));
        assert_eq!(read.read, 3);
        assert_eq!(
            read_fields(&read.build_sqe()),
            (opcode::Read::CODE, buffered_fd, 4199, base + 103, 4093, 0)
        );

        // The rest of the range completes the read in the narrowed buffer.
        assert!(matches!(read.on_cqe(ACTIVE, 4093), Some(Ok(()))));
        assert_eq!(read.buf.len(), 4096);
    }

    #[test]
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
            let mut write = WriteAtRequest::new(
                make_file(),
                17,
                IoBufs::from(buf.clone()).into(),
                state,
                Cache::Enabled,
            );

            // A signed CQE cannot report the entire u32-sized prefix at once.
            for _ in 0..2 {
                assert_eq!(write.build_sqe().get_opcode(), opcode::Write::CODE as u32);
                assert!(write.on_cqe(ACTIVE, i32::MAX).is_none());
            }

            assert_eq!(write.write.remaining_len(), 2);
            assert_eq!(write.build_sqe().get_opcode(), opcode::Write::CODE as u32);
            let mut result = write.on_cqe(ACTIVE, 2);
            assert_eq!(write.offset, 17 + len as u64);
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
        let mut write = make_write_request(make_file(), Cache::Enabled);
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
        let mut write = make_write_request(make_file(), Cache::Enabled);
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
            let request = Request::WriteAt(make_write_request(make_file(), Cache::Enabled));
            assert!(matches!(
                complete(request, ACTIVE, result),
                RequestOutput::WriteAt(Err(Error::WriteFailed))
            ));
        }

        let mut write = make_write_request(make_file(), Cache::Enabled);
        write.state = WriteAtState::WritingBeforeSync;
        assert!(matches!(
            complete(Request::WriteAt(write), ACTIVE, -libc::EIO),
            RequestOutput::WriteAt(Err(Error::WriteFailed))
        ));

        // A fused write retains the kernel errno through its durability failure.
        let mut write = make_write_request(make_file(), Cache::Enabled);
        write.state = WriteAtState::WritingSync;
        assert_eq!(write.rw_flags(), libc::RWF_DSYNC);
        let file = write.file.clone();
        assert!(matches!(
            complete(Request::WriteAt(write), ACTIVE, -libc::EINVAL),
            RequestOutput::WriteAt(Err(Error::Io(error)))
                if error.raw_os_error() == Some(libc::EINVAL)
        ));
        assert!(matches!(
            file.tracker.failure(),
            Some(Error::BlobSyncFailed(_, _, error))
                if error.raw_os_error() == Some(libc::EINVAL)
        ));

        for (state, result) in [
            (ACTIVE, 0),
            (WaiterState::CancelRequested, -libc::ECANCELED),
        ] {
            let mut write = make_write_request(make_file(), Cache::Enabled);
            write.state = WriteAtState::WritingSync;
            assert!(matches!(
                complete(Request::WriteAt(write), state, result),
                RequestOutput::WriteAt(Err(Error::WriteFailed))
            ));
        }
    }

    #[test]
    fn test_uncached_sync_write_retries_without_hint_when_unsupported() {
        let mut request = WriteAtRequest::new(
            make_file(),
            0,
            IoBufs::from(IoBuf::from(b"hello")).into(),
            WriteAtState::WritingSync,
            Cache::Disabled,
        );

        assert_eq!(request.rw_flags(), libc::RWF_DSYNC | libc::RWF_DONTCACHE);
        assert!(request.on_cqe(ACTIVE, -libc::EOPNOTSUPP).is_none());
        assert!(!request.file.dont_cache_supported.load(Ordering::Relaxed));
        request.cache = Cache::Disabled;
        assert_eq!(request.rw_flags(), libc::RWF_DSYNC);
        assert!(
            !request
                .cache
                .fallback(&request.file.dont_cache_supported, -libc::EOPNOTSUPP)
        );
    }

    #[test]
    fn test_active_sync_paths() {
        let mut request = Request::Sync(SyncRequest::new(make_file()));
        assert!(request.on_cqe(ACTIVE, -libc::EINTR).is_none());

        // A sync exposes the kernel error code, including unsolicited ECANCELED.
        for code in [libc::ECANCELED, libc::EIO] {
            let request = Request::Sync(SyncRequest::new(make_file()));
            let RequestOutput::Sync(Err(Error::Io(error))) = complete(request, ACTIVE, -code)
            else {
                panic!("expected sync I/O error");
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }

        for result in [0, 1] {
            let request = Request::Sync(SyncRequest::new(make_file()));
            assert!(matches!(
                complete(request, ACTIVE, result),
                RequestOutput::Sync(Ok(()))
            ));
        }
    }

    #[test]
    fn test_sync_completion_credits_only_its_successful_barrier() {
        for trailing in [false, true] {
            for success in [false, true] {
                for later_write in [false, true] {
                    let file = make_file();
                    file.tracker.write();
                    file.tracker.complete();

                    // A multi-batch write reaches its trailing sync after its last batch.
                    let mut request = if trailing {
                        Request::WriteAt(WriteAtRequest::new(
                            file.clone(),
                            0,
                            IoBufs::from(IoBuf::from(b"hello")).into(),
                            WriteAtState::WritingBeforeSync,
                            Cache::Enabled,
                        ))
                    } else {
                        Request::Sync(SyncRequest::new(file.clone()))
                    };
                    if trailing {
                        assert!(request.on_cqe(ACTIVE, 5).is_none());
                    }

                    // A write completing during the barrier stays dirty.
                    if later_write {
                        file.tracker.write();
                        file.tracker.complete();
                    }
                    let result = if success { Ok(()) } else { Err(Error::Timeout) };
                    let (_, retired) = request.complete(result);
                    drop(retired);
                    assert_eq!(file.tracker.is_dirty(), !success || later_write);
                }
            }
        }
    }

    #[test]
    fn test_durability_completion_retains_failure() {
        for state in [
            None,
            Some(WriteAtState::WritingSync),
            Some(WriteAtState::Syncing),
        ] {
            for failure_first in [false, true] {
                let file = make_file();
                file.tracker.write();
                file.tracker.complete();
                let mut failed = Request::Sync(SyncRequest::new(file.clone()));
                let mut successful = state.as_ref().map_or_else(
                    || Request::Sync(SyncRequest::new(file.clone())),
                    |state| {
                        Request::WriteAt(WriteAtRequest::new(
                            file.clone(),
                            0,
                            IoBufs::from(IoBuf::from(b"hello")).into(),
                            if *state == WriteAtState::Syncing {
                                WriteAtState::WritingBeforeSync
                            } else {
                                WriteAtState::WritingSync
                            },
                            Cache::Enabled,
                        ))
                    },
                );
                if state == Some(WriteAtState::Syncing) {
                    assert!(successful.on_cqe(ACTIVE, 5).is_none());
                }

                // Exercise terminal accounting directly, independently of driver admission.
                // Discarding the output cannot discard a retained durability failure.
                let finish_failure = || {
                    let result = failed.on_cqe(ACTIVE, -libc::EIO).unwrap();
                    let (output, retired) = failed.complete(result);
                    assert!(matches!(output, RequestOutput::Sync(Err(Error::Io(_)))));
                    assert!(matches!(
                        file.tracker.failure(),
                        Some(Error::BlobSyncFailed(_, _, error))
                            if error.raw_os_error() == Some(libc::EIO)
                    ));
                    drop(retired);
                };
                let finish_success = || {
                    let result = successful
                        .on_cqe(
                            ACTIVE,
                            if state == Some(WriteAtState::WritingSync) {
                                5
                            } else {
                                0
                            },
                        )
                        .unwrap();
                    let (output, retired) = successful.complete(result);
                    let result = match output {
                        RequestOutput::Sync(result) | RequestOutput::WriteAt(result) => result,
                        _ => unreachable!(),
                    };
                    if failure_first {
                        assert!(
                            matches!(&result, Err(Error::BlobSyncFailed(_, _, error))
                                if error.raw_os_error() == Some(libc::EIO)),
                            "acknowledged after a retained failure: {result:?}"
                        );
                        assert!(file.tracker.is_dirty());
                    } else {
                        result.unwrap();

                        // A trailing sync credits the write completed before the request. A
                        // fused write covers only its own range.
                        assert_eq!(
                            file.tracker.is_dirty(),
                            state == Some(WriteAtState::WritingSync)
                        );
                    }
                    drop(retired);
                };
                if failure_first {
                    finish_failure();
                    finish_success();
                } else {
                    finish_success();
                    finish_failure();
                }
            }
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

        // A failed read's buffer keeps its owner but exposes nothing it may not hold.
        let mut read = make_read_request(make_file(), Cache::Enabled);
        let pointer = read.buf.as_mut_ptr();
        let capacity = read.buf.capacity();
        let (output, retired) = Request::ReadAt(read).complete(Err(Error::Timeout));
        let RequestOutput::ReadAt(Err((mut buf, Error::Timeout))) = output else {
            panic!("expected read timeout and buffer");
        };
        assert_eq!(buf.as_mut_ptr(), pointer);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), capacity);
        drop(retired);

        let request = Request::WriteAt(make_write_request(make_file(), Cache::Enabled));
        let (output, retired) = request.complete(Err(Error::Timeout));
        assert!(matches!(
            output,
            RequestOutput::WriteAt(Err(Error::Timeout))
        ));
        drop(retired);

        let request = Request::Sync(SyncRequest::new(make_file()));
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
