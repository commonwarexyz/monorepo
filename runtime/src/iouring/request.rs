//! Request ownership and progress state machines for each worker's ring.
//!
//! An admitted [`Request`] owns every descriptor, buffer, and stable scratch
//! allocation referenced by its SQEs. Only the owning worker changes progress.
//! Completions return typed [`RequestOutput`] values and [`RetiredResources`],
//! allowing the driver to recycle capacity before invoking any caller code.
//!
//! ```text
//! operation -> waiter -> Request -> SQE -> kernel
//!                           ^                |
//!                           +----- CQE ------+
//!                                  |
//!                  terminal completion
//!                     /            \
//!              RequestOutput   RetiredResources
//!              operation slab  drop outside Local
//! ```
//!
//! Consumed write chunks remain owned until terminal retirement. Progress never
//! drops external buffer owners while local runtime state is borrowed. A cancel
//! acknowledgement does not retire resources, only the operation's own CQE can
//! establish that the kernel has stopped accessing them.

use super::{
    callbacks::Panics,
    sockaddr::SockAddr,
    waiter::{WaiterId, WaiterState},
};
use crate::{Error, IoBuf, IoBufMut, IoBufs, storage::hold::Hold};
use io_uring::{opcode, squeue::Entry as SqueueEntry, types::Fd};
use std::{
    fs::File,
    net::TcpListener,
    ops::Deref,
    os::fd::{AsRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
/// span as few submissions as possible.
pub(crate) const IOVEC_BATCH_SIZE: usize = 1024;

/// Normalized write buffer for [SendRequest] and [WriteAtRequest].
///
/// Preserves a single-buffer fast path and a vectored path with reusable
/// iovec scratch space.
pub(crate) enum WriteBuffers {
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
    /// Release external owners one at a time after leaving the worker borrow.
    fn retire(self, panics: &mut Panics) {
        match self {
            Self::Single { buf, .. } => {
                panics.run(|| drop(buf));
            }
            Self::Vectored { bufs, iovecs, .. } => {
                // Scratch no longer has kernel users. Drop it before invoking
                // owners, each of which may independently panic or reenter.
                drop(iovecs);
                bufs.retire_chunks(|buf| {
                    panics.run(|| drop(buf));
                });
            }
        }
    }

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
/// Each variant owns all buffers and FDs needed by the
/// kernel, and progress cursors. The loop calls [build_sqe](Self::build_sqe)
/// to produce the next SQE, [on_cqe](Self::on_cqe) to evaluate completions,
/// and [complete](Self::complete) or [timeout](Self::timeout) to
/// return results without invoking observers.
pub(crate) enum Request {
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
    /// Returns `true` when the request reached a terminal state, or `false`
    /// when another SQE is needed.
    pub fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
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
    /// The driver calls this only after the operation CQE or before staging its
    /// first SQE. Both returned values must leave the local borrow before they
    /// can be destroyed or delivered to an observer.
    pub fn complete(self) -> (RequestOutput, RetiredResources) {
        match self {
            Self::Send(r) => (
                RequestOutput::Send(r.result.unwrap_or(Err(Error::SendFailed))),
                RetiredResources::Send {
                    fd: r.fd,
                    write: r.write,
                },
            ),
            Self::Recv(r) => {
                let result = match r.result.unwrap_or(Err(Error::RecvFailed)) {
                    Ok(read) => Ok((r.buf, read)),
                    Err(err) => Err((r.buf, err)),
                };
                (
                    RequestOutput::Recv(result),
                    RetiredResources::Socket { fd: r.fd },
                )
            }
            Self::ReadAt(r) => {
                let result = match r.result.unwrap_or(Err(Error::ReadFailed)) {
                    Ok(()) => Ok(r.buf),
                    Err(err) => Err((r.buf, err)),
                };
                (
                    RequestOutput::ReadAt(result),
                    RetiredResources::File {
                        file: r.file,
                        cache: Some(r.cache),
                        write: None,
                    },
                )
            }
            Self::WriteAt(r) => (
                RequestOutput::WriteAt(r.result.unwrap_or(Err(Error::WriteFailed))),
                RetiredResources::File {
                    file: r.file,
                    cache: Some(r.cache),
                    write: Some(r.write),
                },
            ),
            Self::Sync(r) => (
                RequestOutput::Sync(r.result.unwrap_or(Err(Error::Closed))),
                RetiredResources::File {
                    file: r.file,
                    cache: None,
                    write: None,
                },
            ),
            Self::Connect(r) => (
                RequestOutput::Connect(r.result.unwrap_or(Err(Error::ConnectionFailed))),
                RetiredResources::Connect {
                    fd: r.fd,
                    address: r.address,
                },
            ),
            Self::Poll(r) => (
                RequestOutput::Poll(r.result.unwrap_or(Err(Error::ConnectionFailed))),
                RetiredResources::Listener { listener: r.fd },
            ),
        }
    }

    /// Complete a request whose deadline expired before another SQE was staged.
    pub fn timeout(self) -> (RequestOutput, RetiredResources) {
        self.fail(Error::Timeout)
    }

    /// Record a local rejection and return its typed result without dropping owners.
    pub fn fail(mut self, error: Error) -> (RequestOutput, RetiredResources) {
        match &mut self {
            Self::Send(r) => r.result = Some(Err(error)),
            Self::Recv(r) => r.result = Some(Err(error)),
            Self::ReadAt(r) => r.result = Some(Err(error)),
            Self::WriteAt(r) => r.result = Some(Err(error)),
            Self::Sync(r) => r.result = Some(Err(error)),
            Self::Connect(r) => r.result = Some(Err(error)),
            Self::Poll(r) => r.result = Some(Err(error)),
        }
        self.complete()
    }
}

/// Typed terminal results retained separately from active waiter capacity.
#[derive(Debug)]
pub(crate) enum RequestOutput {
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

/// Owners detached at terminal completion and destroyed outside local state.
///
/// The concrete variants preserve the backing resources through cancellation
/// and move them without invoking buffer destructors or observer callbacks.
pub(crate) enum RetiredResources {
    /// Listener retained while an accept readiness observation is outstanding.
    Listener {
        /// Shared listener whose accept queue remains observable.
        listener: Arc<TcpListener>,
    },
    /// Socket retained by a receive operation.
    Socket {
        /// Descriptor no longer referenced by an operation SQE.
        fd: Arc<OwnedFd>,
    },
    /// Socket and all write owners retained by a logical send.
    Send {
        /// Descriptor used by the completed send sequence.
        fd: Arc<OwnedFd>,
        /// Original byte owners, including consumed chunks.
        write: WriteBuffers,
    },
    /// File, directory hold, and any positioned I/O buffer/cache owners.
    File {
        /// File owner carrying its original storage directory hold.
        file: Arc<Held>,
        /// Shared capability state retained by positioned I/O.
        cache: Option<Cache>,
        /// Original write owners, absent for reads and standalone sync.
        write: Option<WriteBuffers>,
    },
    /// Socket and stable address retained by a connection attempt.
    Connect {
        /// Descriptor used by the connection attempt.
        fd: Arc<OwnedFd>,
        /// Boxed native address whose kernel access has ended.
        address: Box<SockAddr>,
    },
}

impl RetiredResources {
    /// Release each runtime-owned buffer chunk under independent panic isolation.
    ///
    /// Calling `drop` on the whole vectored container could run a second owner
    /// destructor during the first owner's unwind, aborting mandatory cleanup.
    pub(super) fn retire(self, panics: &mut Panics) {
        match self {
            Self::Send { fd, write } => {
                write.retire(panics);
                drop(fd);
            }
            Self::File { file, cache, write } => {
                if let Some(write) = write {
                    write.retire(panics);
                }
                drop(cache);
                drop(file);
            }
            Self::Connect { fd, address } => {
                drop(address);
                drop(fd);
            }
            Self::Socket { fd } => drop(fd),
            Self::Listener { listener } => drop(listener),
        }
    }
}

/// A blob's file bundled with the hold on its storage directory.
///
/// Every request must retain this owner to access the file. Moving a blob to a
/// different worker or runner therefore carries its original directory hold
/// through that worker's eventual kernel retirement.
pub(crate) struct Held {
    /// File shared through this owner, including synchronous metadata access.
    file: File,
    /// Directory exclusion retained until every file and request is released.
    _hold: Arc<Hold>,
}

impl Held {
    /// Retain a file and the directory hold that protects its storage.
    pub(crate) fn new(file: File, hold: Arc<Hold>) -> Arc<Self> {
        Arc::new(Self { file, _hold: hold })
    }
}

impl Deref for Held {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
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
pub(crate) struct SendRequest {
    /// Socket used by the current send SQE.
    pub(crate) fd: Arc<OwnedFd>,
    /// Write cursor and buffers that still need to be sent.
    pub(crate) write: WriteBuffers,
    /// Absolute deadline for the whole logical request.
    pub(crate) deadline: Option<Instant>,
    /// Terminal result captured by `on_cqe` and returned by `complete`.
    pub(crate) result: Option<Result<(), Error>>,
}

/// Submit the representable prefix, leaving the remainder for a later SQE.
fn scalar_len(remaining: usize) -> u32 {
    remaining.min(u32::MAX as usize) as u32
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
pub(crate) struct RecvRequest {
    /// Socket used by the current recv SQE.
    pub(crate) fd: Arc<OwnedFd>,
    /// Destination buffer owned by the request.
    pub(crate) buf: IoBufMut,
    /// Byte offset into `buf` where the next recv should write.
    pub(crate) offset: usize,
    /// Total recv target, including any existing filled prefix before `offset`.
    pub(crate) len: usize,
    /// Whether the recv must fill the full target before succeeding.
    pub(crate) exact: bool,
    /// Absolute deadline for the whole logical request.
    pub(crate) deadline: Option<Instant>,
    /// Terminal result captured by `on_cqe` and returned by `complete`.
    pub(crate) result: Option<Result<usize, Error>>,
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
pub(crate) struct ReadAtRequest {
    /// File used by the current read SQE.
    pub(crate) file: Arc<Held>,
    /// Starting file offset for the logical read.
    pub(crate) offset: u64,
    /// Total number of bytes requested.
    pub(crate) len: usize,
    /// Bytes already read into `buf`.
    pub(crate) read: usize,
    /// Destination buffer owned by the request.
    pub(crate) buf: IoBufMut,
    /// Page-cache policy for this request.
    pub(crate) cache: Cache,
    /// Terminal result captured by `on_cqe` and returned by `complete`.
    pub(crate) result: Option<Result<(), Error>>,
}

impl ReadAtRequest {
    /// Return the flags for the next positioned read.
    fn rw_flags(&mut self) -> i32 {
        self.cache.rw_flag()
    }

    /// Fall back to normal caching when the cache-bypass hint is unsupported.
    fn retry_cached(&mut self, code: i32) -> bool {
        code == -libc::EOPNOTSUPP && self.cache.fallback()
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
        opcode::Read::new(fd, ptr, scalar_len(remaining))
            .offset(offset)
            .rw_flags(rw_flags)
            .build()
    }

    /// Classify one read CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => false,
            CqeResult::Error(code) if self.retry_cached(code) => false,
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

/// Page-cache policy for a positioned I/O request.
pub(crate) enum Cache {
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

    /// Record that cache bypass is unsupported and use normal caching when retried.
    fn fallback(&mut self) -> bool {
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
pub(crate) enum WriteAtState {
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

/// Classify one data-sync CQE and store its terminal result.
fn on_sync_cqe(output: &mut Option<Result<(), Error>>, state: WaiterState, result: i32) -> bool {
    match CqeResult::from_raw(result, state) {
        CqeResult::Retry => false,
        CqeResult::Cancelled => {
            let err = std::io::Error::from_raw_os_error(libc::ECANCELED);
            *output = Some(Err(Error::Io(err.into())));
            true
        }
        CqeResult::Error(code) => {
            let err = std::io::Error::from_raw_os_error(-code);
            *output = Some(Err(Error::Io(err.into())));
            true
        }
        CqeResult::Zero | CqeResult::Positive(_) => {
            *output = Some(Ok(()));
            true
        }
    }
}

/// Logical positioned file write request and its in-loop state.
pub(crate) struct WriteAtRequest {
    /// File used by the current write SQE.
    pub(crate) file: Arc<Held>,
    /// Starting file offset for the logical write.
    pub(crate) offset: u64,
    /// Bytes already written successfully.
    pub(crate) written: usize,
    /// Write cursor and buffers that still need to be written.
    pub(crate) write: WriteBuffers,
    /// Current write and durability phase.
    pub(crate) state: WriteAtState,
    /// Page-cache policy for this request.
    pub(crate) cache: Cache,
    /// Terminal result captured by `on_cqe` and returned by `complete`.
    pub(crate) result: Option<Result<(), Error>>,
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

    /// Fall back to normal caching when the cache-bypass hint is unsupported.
    fn retry_cached(&mut self, code: i32) -> bool {
        code == -libc::EOPNOTSUPP && self.cache.fallback()
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
                // A logical write can exceed the SQE length field. Submit its
                // representable prefix and retain the remainder for later CQEs.
                let len = bytes.len().min(u32::MAX as usize) as u32;
                opcode::Write::new(fd, ptr, len)
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
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        if self.state == WriteAtState::Syncing {
            return on_sync_cqe(&mut self.result, state, result);
        }

        match CqeResult::from_raw(result, state) {
            CqeResult::Retry => false,
            CqeResult::Error(code) if self.retry_cached(code) => false,
            CqeResult::Cancelled | CqeResult::Error(_) | CqeResult::Zero => {
                self.result = Some(Err(Error::WriteFailed));
                true
            }
            CqeResult::Positive(n) => {
                self.written += n;
                self.write.advance(n);
                if self.write.is_complete() {
                    if self.state == WriteAtState::WritingBeforeSync {
                        self.state = WriteAtState::Syncing;
                        false
                    } else {
                        self.result = Some(Ok(()));
                        true
                    }
                } else {
                    false
                }
            }
        }
    }
}

/// Logical fsync request and its in-loop state.
pub(crate) struct SyncRequest {
    /// File descriptor to sync.
    pub(crate) file: Arc<Held>,
    /// Terminal result captured by `on_cqe` and returned by `complete`.
    pub(crate) result: Option<Result<(), Error>>,
}

impl SyncRequest {
    /// Build the fsync SQE for this request.
    fn build_sqe(&self) -> SqueueEntry {
        build_datasync_sqe(&self.file)
    }

    /// Classify one fsync CQE and decide whether the logical request completes
    /// or needs another SQE.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        on_sync_cqe(&mut self.result, state, result)
    }
}

/// Socket connection request with stable kernel address storage.
pub(crate) struct ConnectRequest {
    /// Socket retained through its operation CQE.
    pub(crate) fd: Arc<OwnedFd>,
    /// Native address that cannot move after its pointer is staged.
    pub(crate) address: Box<SockAddr>,
    /// Absolute deadline covering admission and every retry.
    pub(crate) deadline: Option<Instant>,
    /// Terminal connection result.
    pub(crate) result: Option<Result<(), Error>>,
}

impl ConnectRequest {
    /// Build a connection SQE pointing into the boxed native address.
    fn build_sqe(&self) -> SqueueEntry {
        let (address, len) = self.address.as_raw();
        opcode::Connect::new(Fd(self.fd.as_raw_fd()), address, len).build()
    }

    /// Preserve connection success when it races a cancellation request.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        if result == -libc::EISCONN || result == 0 {
            self.result = Some(Ok(()));
            return true;
        }
        let result = if result == -libc::EALREADY {
            -libc::EAGAIN
        } else {
            result
        };
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if !matches!(state, WaiterState::CancelRequested) => false,
            CqeResult::Retry | CqeResult::Cancelled => {
                self.result = Some(Err(Error::Timeout));
                true
            }
            CqeResult::Error(code) => {
                self.result = Some(Err(Error::Io(
                    std::io::Error::from_raw_os_error(-code).into(),
                )));
                true
            }
            CqeResult::Zero | CqeResult::Positive(_) => {
                self.result = Some(Err(Error::ConnectionFailed));
                true
            }
        }
    }
}

/// Single-shot readiness observation that never consumes an accepted socket.
pub(crate) struct PollRequest {
    /// Descriptor retained until readiness completes or cancellation retires.
    pub(crate) fd: Arc<TcpListener>,
    /// Native poll flags identifying the readiness event of interest.
    pub(crate) flags: u32,
    /// Absolute deadline for this readiness observation.
    pub(crate) deadline: Option<Instant>,
    /// Terminal readiness result.
    pub(crate) result: Option<Result<(), Error>>,
}

impl PollRequest {
    /// Build one readiness SQE, leaving multishot mode disabled.
    fn build_sqe(&self) -> SqueueEntry {
        opcode::PollAdd::new(Fd(self.fd.as_raw_fd()), self.flags).build()
    }

    /// Treat readiness as a hint, allowing the caller to retry the actual syscall.
    fn on_cqe(&mut self, state: WaiterState, result: i32) -> bool {
        match CqeResult::from_raw(result, state) {
            CqeResult::Retry if !matches!(state, WaiterState::CancelRequested) => false,
            CqeResult::Retry | CqeResult::Cancelled => {
                self.result = Some(Err(Error::Timeout));
                true
            }
            CqeResult::Error(code) => {
                self.result = Some(Err(Error::Io(
                    std::io::Error::from_raw_os_error(-code).into(),
                )));
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
    use bytes::Bytes;
    use std::{
        os::{
            fd::{FromRawFd, IntoRawFd},
            unix::net::UnixStream,
        },
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{OnceLock, atomic::AtomicUsize},
    };

    fn make_socket_fd() -> Arc<OwnedFd> {
        let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
        Arc::new(left.into())
    }

    fn make_file_fd() -> Arc<Held> {
        let (left, _right) = UnixStream::pair().expect("failed to create unix socket pair");
        // SAFETY: `left` is a valid owned fd and is transferred into `File`.
        let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
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

    fn make_read_request(cache: Cache) -> ReadAtRequest {
        ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache,
            result: None,
        }
    }

    fn make_write_request(cache: Cache) -> WriteAtRequest {
        WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache,
            result: None,
        }
    }

    #[test]
    fn test_write_cursor_retains_owners_across_batches() {
        struct Owner {
            dropped: Arc<AtomicUsize>,
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
        inspect(&mut write, b"abc", IOVEC_BATCH_SIZE as u32);
        write.advance(1);
        inspect(&mut write, b"bc", IOVEC_BATCH_SIZE as u32);
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
        assert!(catch_unwind(AssertUnwindSafe(|| write.advance(3))).is_err());
        assert_eq!(write.remaining_len(), 2);
        write.advance(2);
        assert!(write.is_complete());
    }

    #[test]
    fn test_connect_and_poll_completion_rules() {
        let active = WaiterState::Active { target_tick: None };
        for result in [-libc::EALREADY, -libc::EAGAIN, -libc::EINTR] {
            let connect = ConnectRequest {
                fd: make_socket_fd(),
                address: Box::new(
                    "127.0.0.1:1234"
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                        .into(),
                ),
                deadline: None,
                result: None,
            };
            let pointer = connect.address.as_raw();
            connect.build_sqe();
            let mut connect = std::hint::black_box(connect);
            assert_eq!(connect.address.as_raw(), pointer);
            assert!(!connect.on_cqe(active, result));
            assert!(connect.on_cqe(WaiterState::CancelRequested, result));
            assert!(matches!(connect.result, Some(Err(Error::Timeout))));
        }
        for result in [0, -libc::EISCONN] {
            let mut connect = ConnectRequest {
                fd: make_socket_fd(),
                address: Box::new("[::1]:1234".parse::<std::net::SocketAddr>().unwrap().into()),
                deadline: None,
                result: None,
            };
            assert!(connect.on_cqe(WaiterState::CancelRequested, result));
            assert!(matches!(connect.result, Some(Ok(()))));
        }
        for state in [active, WaiterState::CancelRequested] {
            let mut poll = PollRequest {
                fd: Arc::new(TcpListener::bind("127.0.0.1:0").unwrap()),
                flags: libc::POLLIN as u32,
                deadline: None,
                result: None,
            };
            assert!(poll.on_cqe(state, -libc::ECANCELED));
            match poll.result.unwrap().unwrap_err() {
                Error::Io(error) if matches!(state, WaiterState::Active { .. }) => {
                    assert_eq!(error.raw_os_error(), Some(libc::ECANCELED));
                }
                Error::Timeout if matches!(state, WaiterState::CancelRequested) => {}
                error => panic!("unexpected cancellation result: {error:?}"),
            }
        }
        let mut poll = PollRequest {
            fd: Arc::new(TcpListener::bind("127.0.0.1:0").unwrap()),
            flags: libc::POLLIN as u32,
            deadline: None,
            result: None,
        };
        assert!(!poll.on_cqe(active, -libc::EINTR));
        assert!(poll.on_cqe(WaiterState::CancelRequested, libc::POLLIN as i32));
        assert!(matches!(poll.result, Some(Ok(()))));
    }

    #[test]
    fn test_partial_progress_isolates_reentrant_panicking_owners() {
        struct Owner {
            local: Arc<commonware_utils::sync::Mutex<usize>>,
            bytes: [u8; 3],
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
                panic!("external owner panic");
            }
        }

        let local = Arc::new(commonware_utils::sync::Mutex::new(0));
        let mut bufs = IoBufs::from(IoBuf::from(Bytes::from_owner(Owner {
            local: local.clone(),
            bytes: *b"abc",
        })));
        bufs.append(IoBuf::from(Bytes::from_owner(Owner {
            local: local.clone(),
            bytes: *b"def",
        })));
        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: bufs.into(),
            deadline: None,
            result: None,
        });
        let guard = local.lock();
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        let (output, retired) = request.timeout();
        assert!(matches!(output, RequestOutput::Send(Err(Error::Timeout))));
        assert_eq!(*guard, 0);
        drop(guard);
        let mut panics = Panics::default();
        retired.retire(&mut panics);
        assert!(panics.is_pending());
        assert_eq!(*local.lock(), 2);
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
        });
        assert_eq!(send.deadline(), Some(send_deadline));

        let recv_deadline = Instant::now();
        let recv = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(8),
            offset: 0,
            len: 8,
            exact: true,
            deadline: Some(recv_deadline),
            result: None,
        });
        assert_eq!(recv.deadline(), Some(recv_deadline));

        let read = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 4,
            read: 0,
            buf: IoBufMut::with_capacity(4),
            cache: Cache::Enabled,
            result: None,
        });
        assert_eq!(read.deadline(), None);

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
                result: None,
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
                result: None,
            });
            let _ = request.build_sqe(WaiterId::new(0, 0));
        });
        assert!(read_overread.is_err());
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
        let active = WaiterState::Active { target_tick: None };
        let mut send = SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline,
            result: None,
        };
        let mut recv = RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline,
            result: None,
        };
        let mut read = make_read_request(Cache::Enabled);
        read.offset = 7;
        // Real buffers remain valid while each builder advances to its suffix.
        for progress in [2, 3] {
            assert_eq!(send.build_sqe().get_opcode(), opcode::Send::CODE as u32);
            assert_eq!(recv.build_sqe().get_opcode(), opcode::Recv::CODE as u32);
            assert_eq!(read.build_sqe().get_opcode(), opcode::Read::CODE as u32);
            assert_eq!(send.on_cqe(active, progress), progress == 3);
            assert_eq!(recv.on_cqe(active, progress), progress == 3);
            assert_eq!(read.on_cqe(active, progress), progress == 3);
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
        // Verify send state handling across retry, timeout, success, and hard-failure CQEs.

        // Retryable CQEs should simply requeue while the request is still active.

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Partial progress followed by a retry after timeout should resolve to timeout.

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::EAGAIN));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::Timeout)));

        // Partial progress after timeout must also resolve to timeout rather than requeueing.

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::CancelRequested, 1));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::Timeout)));

        // A canceled send that comes back as ECANCELED should also resolve to timeout.

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::Timeout)));

        // Vectored writes should advance across multiple CQEs and complete once all bytes are sent.
        let mut vectored = IoBufs::default();
        vectored.append(IoBuf::from(b"abc"));
        vectored.append(IoBuf::from(b"de"));

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: vectored.into(),
            deadline: None,
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("send should complete successfully");

        // Zero-byte and hard-error CQEs should both surface as send failures.

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::SendFailed)));

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::SendFailed)));

        // A fully successful CQE still wins even if timeout was already requested.

        let mut request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, 5));
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("send should complete successfully");
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
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Non-exact recv should complete as soon as any positive byte count arrives.

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: false,
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        let (_buf, read) = result.expect("recv should complete successfully");
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
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        assert!(request.on_cqe(WaiterState::CancelRequested, 1));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::Timeout))));

        // Retryable and ECANCELED completions after timeout should both resolve to timeout.

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::EINTR));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::Timeout))));

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::Timeout))));

        // A fully successful CQE still wins after timeout was requested.

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, 5));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        let (_buf, read) = result.expect("recv should complete successfully");
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
            result: None,
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
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::RecvFailed))));

        let mut request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::RecvFailed))));
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
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Partial reads should requeue until the full logical length is satisfied.

        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        let (output, retired) = request.complete();
        let RequestOutput::ReadAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("read should complete successfully");

        // EOF and hard-error CQEs should map to the storage read error surface.

        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        let (output, retired) = request.complete();
        let RequestOutput::ReadAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::BlobInsufficientLength))));

        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        let (output, retired) = request.complete();
        let RequestOutput::ReadAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::ReadFailed))));

        // Timeout cancellation should also surface as a read failure.

        let mut request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        let (output, retired) = request.complete();
        let RequestOutput::ReadAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::ReadFailed))));
    }

    #[test]
    fn test_uncached_read_fallback_preserves_progress_and_is_shared_with_writes() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut read = make_read_request(Cache::Disabled(supported.clone()));

        // Preserve completed bytes while retrying without the rejected cache hint.
        assert_eq!(read.rw_flags(), libc::RWF_DONTCACHE);
        assert!(!read.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert_eq!(read.read, 2);
        assert_eq!(read.rw_flags(), libc::RWF_DONTCACHE);

        assert!(!read.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP));
        assert_eq!(read.read, 2);
        assert!(!supported.load(Ordering::Relaxed));
        assert_eq!(read.rw_flags(), 0);

        // Capability loss is shared in both directions across sibling requests.
        let mut sibling_write = make_write_request(Cache::Disabled(supported));
        assert_eq!(sibling_write.rw_flags(), 0);

        let supported = Arc::new(AtomicBool::new(true));
        let mut write = make_write_request(Cache::Disabled(supported.clone()));
        assert_eq!(write.rw_flags(), libc::RWF_DONTCACHE);
        assert!(!write.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP));
        let mut sibling_read = make_read_request(Cache::Disabled(supported));
        assert_eq!(sibling_read.rw_flags(), 0);

        // Unrelated I/O failures must not disable the hint for future requests.
        let supported = Arc::new(AtomicBool::new(true));
        let mut failing_read = make_read_request(Cache::Disabled(supported.clone()));
        assert_eq!(failing_read.rw_flags(), libc::RWF_DONTCACHE);
        assert!(failing_read.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        assert!(supported.load(Ordering::Relaxed));
        assert!(matches!(failing_read.result, Some(Err(Error::ReadFailed))));
    }

    #[test]
    fn test_queued_cache_fallbacks_retry() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut first = make_read_request(Cache::Disabled(supported.clone()));
        let mut second = make_read_request(Cache::Disabled(supported.clone()));

        // Requests queued before the shared downgrade must each requeue without the hint.
        assert_eq!(first.rw_flags(), libc::RWF_DONTCACHE);
        assert_eq!(second.rw_flags(), libc::RWF_DONTCACHE);
        assert!(!first.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP));
        assert!(!second.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP));
        assert!(!supported.load(Ordering::Relaxed));
        assert_eq!(first.rw_flags(), 0);
        assert_eq!(second.rw_flags(), 0);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_large_single_write_preserves_progress_and_durability() {
        // Keep one demand-paged zero allocation across the durability variants.
        // Simulated CQEs advance cursors without reading the large payload.
        let len = u32::MAX as usize + 1;
        let buf = IoBuf::from(vec![0; len]);
        let active = WaiterState::Active { target_tick: None };
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
                result: None,
            };
            for _ in 0..2 {
                assert_eq!(write.build_sqe().get_opcode(), opcode::Write::CODE as u32);
                assert!(!write.on_cqe(active, i32::MAX));
            }
            assert_eq!(write.write.remaining_len(), 2);
            assert_eq!(write.build_sqe().get_opcode(), opcode::Write::CODE as u32);
            assert_eq!(write.on_cqe(active, 2), !trailing_sync);
            assert_eq!(write.written, len);
            assert!(write.write.is_complete());
            if trailing_sync {
                assert!(write.result.is_none());
                assert_eq!(write.build_sqe().get_opcode(), opcode::Fsync::CODE as u32);
                assert!(write.on_cqe(active, 0));
            }
            assert!(matches!(write.result, Some(Ok(()))));
        }
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
            result: None,
        };
        assert_eq!(write.rw_flags(), 0);
        let mut request = Request::WriteAt(write);
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EAGAIN));

        // Single-buffer writes should track partial progress until complete.

        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 2));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 3));
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("write should complete successfully");

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
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, 4));
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 1));
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("vectored write should complete successfully");

        // Zero-byte and hard-error CQEs should surface as write failures.

        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::WriteFailed)));

        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::WriteFailed)));

        // Single-submission synchronous writes use the same logical error
        // surface as regular writes and add `RWF_DSYNC` to the SQE flags.

        let mut write = WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::WritingSync,
            cache: Cache::Enabled,
            result: None,
        };
        assert_eq!(write.rw_flags(), libc::RWF_DSYNC);
        let mut request = Request::WriteAt(write);
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EINVAL));
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::WriteFailed)));

        // Timeout cancellation should also surface as a write failure.

        let mut request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::WriteFailed)));
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
            result: None,
        };

        assert_eq!(request.rw_flags(), libc::RWF_DSYNC | libc::RWF_DONTCACHE);
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EOPNOTSUPP));
        assert!(!dont_cache_supported.load(Ordering::Relaxed));
        request.cache = Cache::Disabled(dont_cache_supported);
        assert_eq!(request.rw_flags(), libc::RWF_DSYNC);
        assert!(!request.cache.fallback());
    }

    #[test]
    fn test_active_sync_paths() {
        // Verify sync state handling across retry, timeout-cancel, error conversion, and success.

        // Retryable CQEs should requeue the fsync request.

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        assert!(!request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EINTR));

        // Timeout cancellation should preserve the kernel ECANCELED surface for sync callers.

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        assert!(request.on_cqe(WaiterState::CancelRequested, -libc::ECANCELED));
        let (output, retired) = request.complete();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        let err = result.expect_err("expected timeout cancel error");
        match err {
            Error::Io(err) => assert_eq!(err.raw_os_error(), Some(libc::ECANCELED)),
            other => panic!("expected io error, got {other:?}"),
        }

        // Hard errors should round-trip as std::io::Error values.

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, -libc::EIO));
        let (output, retired) = request.complete();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        let err = result.expect_err("expected hard error");
        match err {
            Error::Io(err) => assert_eq!(err.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected io error, got {other:?}"),
        }

        // Both zero and positive CQE results should count as sync success.

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 0));
        let (output, retired) = request.complete();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("sync should succeed on zero");

        let mut request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        assert!(request.on_cqe(WaiterState::Active { target_tick: None }, 1));
        let (output, retired) = request.complete();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        result.expect("sync should succeed on positive");

        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        let (output, retired) = request.timeout();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        let err = result.expect_err("expected timeout error");
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn test_finish_without_cqe_uses_fallback_results() {
        // Verify unstarted requests preserve their kind-specific failure results.
        // Network and storage requests each have their own fallback error surface.

        // Network sends and recvs should preserve their wrapper-specific fallback errors.

        let request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        let (output, retired) = request.complete();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::SendFailed)));

        let request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
        });
        let (output, retired) = request.complete();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::RecvFailed))));

        // Storage reads and writes should surface the corresponding storage wrapper errors.

        let request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
            result: None,
        });
        let (output, retired) = request.complete();
        let RequestOutput::ReadAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::ReadFailed))));

        let request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
            result: None,
        });
        let (output, retired) = request.complete();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::WriteFailed)));

        // A sync that never executed must not falsely report durability.

        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        let (output, retired) = request.complete();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::Closed)));
    }

    #[test]
    fn test_finish_timeout_delivers_timeout_results() {
        // Verify the loop's immediate-timeout path delivers timeout to each request variant.
        // Network and storage requests should each receive their type-specific
        // timeout surface when no CQE was processed yet.

        // Network operations should map directly to the shared logical timeout.

        let request = Request::Send(SendRequest {
            fd: make_socket_fd(),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: None,
            result: None,
        });
        let (output, retired) = request.timeout();
        let RequestOutput::Send(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::Timeout)));

        let request = Request::Recv(RecvRequest {
            fd: make_socket_fd(),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: true,
            deadline: None,
            result: None,
        });
        let (output, retired) = request.timeout();
        let RequestOutput::Recv(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::Timeout))));

        // Storage reads and writes also use the common logical timeout surface.

        let request = Request::ReadAt(ReadAtRequest {
            file: make_file_fd(),
            offset: 0,
            len: 5,
            read: 0,
            buf: IoBufMut::with_capacity(5),
            cache: Cache::Enabled,
            result: None,
        });
        let (output, retired) = request.timeout();
        let RequestOutput::ReadAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err((_, Error::Timeout))));

        let request = Request::WriteAt(WriteAtRequest {
            file: make_file_fd(),
            offset: 0,
            written: 0,
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            state: WriteAtState::Writing,
            cache: Cache::Enabled,
            result: None,
        });
        let (output, retired) = request.timeout();
        let RequestOutput::WriteAt(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        assert!(matches!(result, Err(Error::Timeout)));

        let request = Request::Sync(SyncRequest {
            file: make_file_fd(),
            result: None,
        });
        let (output, retired) = request.timeout();
        let RequestOutput::Sync(result) = output else {
            panic!("unexpected request output");
        };
        drop(retired);
        let err = result.expect_err("sync timeout should be an error");
        assert!(matches!(err, Error::Timeout));
    }
}
