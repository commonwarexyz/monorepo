//! Asynchronous io_uring event loop implementation.
//!
//! This module provides a high-level interface for submitting operations to Linux's io_uring
//! subsystem and receiving their results asynchronously. The design centers around a single
//! event loop that manages the submission queue (SQ) and completion queue (CQ) of an io_uring
//! instance.
//!
//! # Architecture
//!
//! ## Event Loop
//!
//! The core of this implementation is the [run] function, which operates an event loop that:
//! 1. Receives operation requests via an MPSC channel
//! 2. Assigns unique IDs to each operation and submits them to io_uring's submission queue (SQE)
//! 3. Polls io_uring's completion queue (CQE) for completed operations
//! 4. Routes completion results back to the original requesters via oneshot channels
//!
//! ## Operation Flow
//!
//! ```text
//! Client Code ─[Op]→ MPSC Channel ─→ Event Loop ─[SQE]→ io_uring Kernel
//!      ↑                                                 ↓
//! Oneshot Channel ←─ Waiter Tracking ←[CQE]─ io_uring Kernel
//! ```
//!
//! ## Work Tracking
//!
//! Each submitted operation is assigned a unique work ID that serves as the `user_data` field
//! in the SQE. The event loop maintains a `waiters` HashMap that maps each work ID to:
//! - A oneshot sender for returning results to the caller
//! - An optional buffer that must be kept alive for the duration of the operation
//! - An optional timespec, if operation timeouts are enabled, that must be kept
//!   alive for the duration of the operation
//!
//! ## Timeout Handling
//!
//! Operations can be configured with timeouts using `Config::op_timeout`. When enabled:
//! - Each operation is linked to a timeout using io_uring's `IOSQE_IO_LINK` flag
//! - If the timeout fires first, the operation is canceled and returns `ETIMEDOUT`
//! - Reserved work IDs distinguish timeout completions from regular operations
//!
//! ## Deadlock Prevention
//!
//! The [Config::force_poll] interval prevents deadlocks in scenarios where:
//! - Multiple tasks use the same io_uring instance
//! - One task's completion depends on another task's submission
//! - The event loop is blocked waiting for completions and can't process new submissions
//!
//! The event loop uses a bounded wait time when waiting for completions,
//! ensuring forward progress even when no completions are immediately available.
//!
//! ## Shutdown Process
//!
//! When the operation channel closes, the event loop enters a drain phase:
//! 1. Stops accepting new operations
//! 2. Waits for all in-flight operations to complete
//! 3. If `shutdown_timeout` is configured, abandons remaining operations after the timeout
//! 4. Cleans up and exits

#[cfg(feature = "iouring-network")]
use bytes::Bytes;
use commonware_utils::StableBuf;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt as _,
};
use io_uring::{
    cqueue::Entry as CqueueEntry,
    opcode::LinkTimeout,
    squeue::Entry as SqueueEntry,
    types::{SubmitArgs, Timespec},
    IoUring,
};
use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use std::{collections::HashMap, sync::Arc, time::Duration};

/// Returns the maximum number of iovecs per sendmsg call.
/// Queries the kernel via sysconf(_SC_IOV_MAX), falling back to 1024 (Linux default).
#[cfg(feature = "iouring-network")]
fn iov_max() -> usize {
    static IOV_MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *IOV_MAX.get_or_init(|| {
        // SAFETY: sysconf is safe to call with _SC_IOV_MAX
        let result = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        if result > 0 {
            result as usize
        } else {
            1024 // Fallback to Linux default (UIO_MAXIOV)
        }
    })
}

/// Buffer(s) kept alive during io_uring operations.
///
/// The io_uring kernel interface requires buffer pointers to remain valid until
/// the operation completes. This enum allows the event loop to store different
/// buffer types while maintaining their lifetime.
#[derive(Debug)]
pub enum OpBuf {
    /// Single contiguous buffer (used by storage and simple network ops).
    Single(StableBuf),
    /// Vectored buffer containing multiple chunks and their iovec metadata.
    /// Used for scatter-gather I/O operations (network only).
    #[cfg(feature = "iouring-network")]
    Vectored(IoVecBuf),
}

impl OpBuf {
    /// Extracts the inner `StableBuf` if this is a `Single` variant.
    pub fn into_single(self) -> Option<StableBuf> {
        match self {
            Self::Single(buf) => Some(buf),
            #[cfg(feature = "iouring-network")]
            Self::Vectored(_) => None,
        }
    }

    /// Extracts the inner `IoVecBuf` if this is a `Vectored` variant.
    #[cfg(feature = "iouring-network")]
    pub fn into_vectored(self) -> Option<IoVecBuf> {
        match self {
            Self::Single(_) => None,
            Self::Vectored(v) => Some(v),
        }
    }
}

/// Owns buffer chunks and their iovec metadata for vectored I/O operations.
///
/// All fields must remain at stable memory addresses while io_uring uses them.
/// When `msghdr` is present, it references `iovecs`, and `iovecs` reference `chunks`.
///
/// # Safety Invariant
///
/// This type contains raw pointers that are passed to the kernel via io_uring.
/// The fields must NOT be modified while an io_uring operation using this buffer
/// is in flight. Only call [`advance`](Self::advance) after the corresponding CQE
/// has been received, indicating the kernel is done with the previous pointers.
#[cfg(feature = "iouring-network")]
pub struct IoVecBuf {
    /// Buffer chunks kept alive for pointer validity.
    /// For Bytes-backed buffers, this is cheap (Arc clone).
    chunks: Vec<Bytes>,
    /// iovec array pointing into chunks. Must not move.
    /// Capped at `iov_max()` entries to respect kernel limits.
    iovecs: Box<[libc::iovec]>,
    /// msghdr pointing to iovecs. Must not move.
    /// Only used by network SendMsg operations; None for storage vectored I/O.
    msghdr: Option<Box<libc::msghdr>>,
    /// Index of first chunk with remaining data (for partial I/O retries).
    first_chunk_idx: usize,
    /// Offset into first partially-sent chunk (for partial I/O retries).
    first_chunk_offset: usize,
    /// Total bytes remaining.
    remaining: usize,
}

#[cfg(feature = "iouring-network")]
// SAFETY: IoVecBuf owns all data it references. The raw pointers in iovecs
// point into the owned `chunks` Vec, which is Send/Sync. The struct is only
// accessed by a single io_uring thread at a time, and the kernel only reads
// from the pointers during the operation.
unsafe impl Send for IoVecBuf {}

#[cfg(feature = "iouring-network")]
impl std::fmt::Debug for IoVecBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoVecBuf")
            .field("chunks", &self.chunks.len())
            .field("iovecs", &self.iovecs.len())
            .field("first_chunk_idx", &self.first_chunk_idx)
            .field("first_chunk_offset", &self.first_chunk_offset)
            .field("remaining", &self.remaining)
            .finish()
    }
}

#[cfg(feature = "iouring-network")]
impl IoVecBuf {
    /// Creates a new IoVecBuf from buffer chunks for network SendMsg operations.
    /// Initializes the msghdr for use with io_uring SendMsg.
    ///
    /// The iovec array is capped at `IOV_MAX` entries to respect kernel limits.
    /// If there are more chunks, subsequent batches are handled via `advance()`.
    pub fn new(chunks: Vec<Bytes>) -> Self {
        let remaining: usize = chunks.iter().map(|c| c.len()).sum();

        // Cap iovecs at iov_max to avoid EINVAL from kernel
        let iov_count = chunks.len().min(iov_max());
        let iovecs: Box<[libc::iovec]> = chunks[..iov_count]
            .iter()
            .map(|c| libc::iovec {
                iov_base: c.as_ptr() as *mut libc::c_void,
                iov_len: c.len(),
            })
            .collect();

        // SAFETY: msghdr is a POD type with no invalid bit patterns. All fields
        // are initialized to zero, which is valid. We immediately set msg_iov
        // and msg_iovlen to valid values below.
        let mut msghdr = Box::new(unsafe { std::mem::zeroed::<libc::msghdr>() });
        msghdr.msg_iov = iovecs.as_ptr() as *mut libc::iovec;
        msghdr.msg_iovlen = iovecs.len();

        Self {
            chunks,
            iovecs,
            msghdr: Some(msghdr),
            first_chunk_idx: 0,
            first_chunk_offset: 0,
            remaining,
        }
    }

    /// Returns a pointer to the msghdr for use with SendMsg.
    /// Panics if msghdr was not initialized (e.g., for storage-only IoVecBuf).
    pub fn msghdr_ptr(&self) -> *const libc::msghdr {
        self.msghdr
            .as_ref()
            .map(|m| &**m as *const _)
            .expect("msghdr not initialized")
    }

    /// Returns true if all data has been processed.
    pub const fn is_complete(&self) -> bool {
        self.remaining == 0
    }

    /// Returns the number of bytes remaining to be sent.
    #[cfg(test)]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Returns the index of the first chunk with remaining data.
    #[cfg(test)]
    pub const fn first_chunk_idx(&self) -> usize {
        self.first_chunk_idx
    }

    /// Returns the offset into the first chunk.
    #[cfg(test)]
    pub const fn first_chunk_offset(&self) -> usize {
        self.first_chunk_offset
    }

    /// Returns the number of iovecs in the current batch.
    #[cfg(test)]
    pub fn iovec_count(&self) -> usize {
        self.iovecs.len()
    }

    /// Advance past processed bytes, rebuilding iovecs for remaining data.
    ///
    /// # Safety Requirement
    ///
    /// This method must only be called after the io_uring CQE for the previous
    /// operation has been received. The kernel must be done reading from the
    /// previous iovec pointers before they are invalidated by this call.
    pub fn advance(&mut self, mut bytes_done: usize) {
        self.remaining = self.remaining.saturating_sub(bytes_done);

        // Skip fully-processed chunks
        while bytes_done > 0 && self.first_chunk_idx < self.chunks.len() {
            let chunk = &self.chunks[self.first_chunk_idx];
            let chunk_remaining = chunk.len() - self.first_chunk_offset;

            if bytes_done >= chunk_remaining {
                // Fully processed this chunk
                bytes_done -= chunk_remaining;
                self.first_chunk_idx += 1;
                self.first_chunk_offset = 0;
            } else {
                // Partially processed this chunk
                self.first_chunk_offset += bytes_done;
                bytes_done = 0;
            }
        }

        // Rebuild iovecs for remaining chunks
        self.rebuild_iovecs();
    }

    /// Rebuilds iovecs starting from current position, capped at iov_max.
    fn rebuild_iovecs(&mut self) {
        let remaining_chunks = &self.chunks[self.first_chunk_idx..];
        let iov_count = remaining_chunks.len().min(iov_max());

        let new_iovecs: Box<[libc::iovec]> = remaining_chunks[..iov_count]
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let offset = if i == 0 { self.first_chunk_offset } else { 0 };
                // Defensive check: offset must not exceed chunk length
                debug_assert!(
                    offset <= c.len(),
                    "offset {} exceeds chunk length {}",
                    offset,
                    c.len()
                );
                libc::iovec {
                    // SAFETY: offset is always <= c.len() because:
                    // - first_chunk_offset is only incremented by bytes_done which never
                    //   exceeds the chunk's remaining length
                    // - For i > 0, offset is 0
                    // The debug_assert above catches violations in debug builds.
                    iov_base: unsafe { c.as_ptr().add(offset) as *mut libc::c_void },
                    iov_len: c.len() - offset,
                }
            })
            .collect();

        self.iovecs = new_iovecs;

        // Update msghdr if present (only for network SendMsg operations)
        if let Some(ref mut msghdr) = self.msghdr {
            msghdr.msg_iov = self.iovecs.as_ptr() as *mut libc::iovec;
            msghdr.msg_iovlen = self.iovecs.len();
        }
    }
}

/// Reserved ID for a CQE that indicates an operation timed out.
const TIMEOUT_WORK_ID: u64 = u64::MAX;

/// Active operations keyed by their work id.
///
/// Each entry keeps the caller's oneshot sender, the buffer(s) that must stay
/// alive until the kernel finishes touching them, and when op_timeout is enabled,
/// the boxed `Timespec` used when we link in an IOSQE_IO_LINK timeout.
type Waiters = HashMap<
    u64,
    (
        oneshot::Sender<(i32, Option<OpBuf>)>,
        Option<OpBuf>,
        Option<Box<Timespec>>,
    ),
>;

#[derive(Debug)]
/// Tracks io_uring metrics.
pub struct Metrics {
    /// Number of operations submitted to the io_uring whose CQEs haven't
    /// yet been processed. Note this metric doesn't include timeouts,
    /// which are generated internally by the io_uring event loop.
    /// It's only updated before `submit_and_wait` is called, so it may
    /// temporarily vary from the actual number of pending operations.
    pending_operations: Gauge,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            pending_operations: Gauge::default(),
        };
        registry.register(
            "pending_operations",
            "Number of operations submitted to the io_uring whose CQEs haven't yet been processed",
            metrics.pending_operations.clone(),
        );
        metrics
    }
}

#[derive(Clone, Debug)]
/// Configuration for an io_uring instance.
/// See `man io_uring`.
pub struct Config {
    /// Size of the ring.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub io_poll: bool,
    /// If true, use single issuer mode.
    /// Warning: when enabled, user must guarantee that the same thread
    /// that creates the io_uring instance is the only thread that submits
    /// work to it. Since the `run` event loop is a future that may move
    /// between threads, this means in practice that `single_issuer` should
    /// only be used in a single-threaded context.
    /// See IORING_SETUP_SINGLE_ISSUER in <https://man7.org/linux/man-pages/man2/io_uring_setup.2.html>.
    pub single_issuer: bool,
    /// In the io_uring event loop (`run`), wait at most this long for a new
    /// completion before checking for new work to submit to the io_ring. This
    /// periodic wake-up prevents deadlocks where one task depends on completions
    /// that won't arrive until another task submits additional work. Avoid
    /// setting this to very low values, or the loop may burn CPU by waking
    /// continuously even when no completions are available.
    pub force_poll: Duration,
    /// If None, operations submitted to the io_uring will not time out.
    /// In this case, the caller should be careful to ensure that the
    /// operations submitted to the io_uring will eventually complete.
    /// If Some, each submitted operation will time out after this duration.
    /// If an operation times out, its result will be -[libc::ETIMEDOUT].
    pub op_timeout: Option<Duration>,
    /// The maximum time the io_uring event loop will wait for in-flight operations
    /// to complete before abandoning them during shutdown.
    /// If None, the event loop will wait indefinitely for in-flight operations
    /// to complete before shutting down. In this case, the caller should be careful
    /// to ensure that the operations submitted to the io_uring will eventually complete.
    pub shutdown_timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 128,
            io_poll: false,
            single_issuer: false,
            force_poll: Duration::from_secs(1),
            op_timeout: None,
            shutdown_timeout: None,
        }
    }
}

fn new_ring(cfg: &Config) -> Result<IoUring, std::io::Error> {
    let mut builder = &mut IoUring::builder();
    if cfg.io_poll {
        builder = builder.setup_iopoll();
    }
    if cfg.single_issuer {
        builder = builder.setup_single_issuer();
        // Enable `DEFER_TASKRUN` to defer work processing until `io_uring_enter` is
        // called with `IORING_ENTER_GETEVENTS`. By default, io_uring processes work at
        // the end of any system call or thread interrupt, which can delay application
        // progress. With `DEFER_TASKRUN`, completions are only processed when explicitly
        // requested, reducing overhead and improving CPU cache locality.
        //
        // This is safe in our implementation since we always call `submit_and_wait()`
        // (which sets `IORING_ENTER_GETEVENTS`), and we are also enabling
        // `IORING_SETUP_SINGLE_ISSUER` here, which is a pre-requisite.
        //
        // This is available since kernel 6.1.
        //
        // See IORING_SETUP_DEFER_TASKRUN in <https://man7.org/linux/man-pages/man2/io_uring_setup.2.html>.
        builder = builder.setup_defer_taskrun();
    }

    // When `op_timeout` is set, each operation uses 2 SQ entries (op + linked
    // timeout). We double the ring size to ensure users get the number of
    // concurrent operations they configured.
    let ring_size = if cfg.op_timeout.is_some() {
        cfg.size * 2
    } else {
        cfg.size
    };

    builder.build(ring_size)
}

/// An operation submitted to the io_uring event loop which will be processed
/// asynchronously by the event loop in `run`.
pub struct Op {
    /// The submission queue entry to be submitted to the ring.
    /// Its user data field will be overwritten. Users shouldn't rely on it.
    pub work: SqueueEntry,
    /// Sends the result of the operation and `buffers`.
    pub sender: oneshot::Sender<(i32, Option<OpBuf>)>,
    /// The buffer(s) used for the operation, if any.
    /// E.g. For read, this is the buffer being read into.
    /// For vectored sends, this holds the chunks and iovecs.
    /// If None, the operation doesn't use a buffer (e.g. a sync operation).
    /// We hold the buffer here so it's guaranteed to live until the operation
    /// completes, preventing write-after-free issues.
    pub buffers: Option<OpBuf>,
}

// Returns false iff we received a shutdown timeout
// and we should stop processing completions.
fn handle_cqe(waiters: &mut Waiters, cqe: CqueueEntry, cfg: &Config) {
    let work_id = cqe.user_data();
    match work_id {
        TIMEOUT_WORK_ID => {
            assert!(
                cfg.op_timeout.is_some(),
                "received TIMEOUT_WORK_ID with op_timeout disabled"
            );
        }
        _ => {
            let result = cqe.result();
            let result = if result == -libc::ECANCELED && cfg.op_timeout.is_some() {
                // This operation timed out
                -libc::ETIMEDOUT
            } else {
                result
            };

            let (result_sender, buffers, _) = waiters.remove(&work_id).expect("missing sender");
            let _ = result_sender.send((result, buffers));
        }
    }
}

/// Creates a new io_uring instance that listens for incoming work on `receiver`.
/// This function will block until `receiver` is closed or an error occurs.
/// It should be run in a separate task.
pub(crate) async fn run(cfg: Config, metrics: Arc<Metrics>, mut receiver: mpsc::Receiver<Op>) {
    let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
    let mut next_work_id: u64 = 0;
    // Maps a work ID to the sender that we will send the result to
    // and the buffer used for the operation.
    let mut waiters = Waiters::with_capacity(cfg.size as usize);

    loop {
        // Try to get a completion
        while let Some(cqe) = ring.completion().next() {
            handle_cqe(&mut waiters, cqe, &cfg);
        }

        // Try to fill the submission queue with incoming work.
        // Stop if we are at the max number of processing work.
        //
        // NOTE: We can safely use `cfg.size` directly as the limit here, even
        // when `op_timeout` is enabled, because we already doubled the ring
        // size in `new_ring()` to account for the fact that each operation
        // needs 2 SQ entries (op + timeout). This ensures users get the number
        // of concurrent operations they configured.
        while waiters.len() < cfg.size as usize {
            // Wait for more work
            let op = if waiters.is_empty() {
                // Block until there is something to do
                match receiver.next().await {
                    // Got work
                    Some(work) => work,
                    // Channel closed, shut down
                    None => {
                        drain(&mut ring, &mut waiters, &cfg);
                        return;
                    }
                }
            } else {
                // Handle incoming work
                match receiver.try_next() {
                    // Got work without blocking
                    Ok(Some(work_item)) => work_item,
                    // Channel closed, shut down
                    Ok(None) => {
                        drain(&mut ring, &mut waiters, &cfg);
                        return;
                    }
                    // No new work available, wait for a completion
                    Err(_) => break,
                }
            };
            let Op {
                mut work,
                sender,
                buffers,
            } = op;

            // Assign a unique id
            let work_id = next_work_id;
            next_work_id += 1;
            if next_work_id == TIMEOUT_WORK_ID {
                // Wrap back to 0
                next_work_id = 0;
            }
            work = work.user_data(work_id);

            // Submit the operation to the ring, with timeout if configured
            let timespec = if let Some(timeout) = &cfg.op_timeout {
                // Link the operation to the (following) timeout
                work = work.flags(io_uring::squeue::Flags::IO_LINK);

                // The timespec needs to be allocated on the heap and kept alive
                // for the duration of the operation so that the pointer stays
                // valid
                let timespec = Box::new(
                    Timespec::new()
                        .sec(timeout.as_secs())
                        .nsec(timeout.subsec_nanos()),
                );

                // Create the timeout
                let timeout = LinkTimeout::new(&*timespec)
                    .build()
                    .user_data(TIMEOUT_WORK_ID);

                // Submit the op and timeout.
                //
                // SAFETY: Both `buffers` and `timespec` are stored in `waiters`
                // until the CQE is processed, ensuring memory referenced by the
                // SQEs remains valid. The ring was doubled in size for timeout
                // support, and `waiters.len() < cfg.size` guarantees space for
                // both entries.
                unsafe {
                    let mut sq = ring.submission();
                    sq.push(&work).expect("unable to push to queue");
                    sq.push(&timeout).expect("unable to push timeout to queue");
                }

                Some(timespec)
            } else {
                // No timeout, submit the operation normally.
                //
                // SAFETY: The `buffers` are stored in `waiters` until the CQE is
                // processed, ensuring memory referenced by the SQE remains valid.
                // The loop condition `waiters.len() < cfg.size` guarantees space
                // in the submission queue.
                unsafe {
                    ring.submission()
                        .push(&work)
                        .expect("unable to push to queue");
                }

                None
            };

            // We'll send the result of this operation to `sender`.
            waiters.insert(work_id, (sender, buffers, timespec));
        }

        // Submit and wait for at least 1 item to be in the completion queue.
        // Note that we block until anything is in the completion queue,
        // even if it's there before this call. That is, a completion
        // that arrived before this call will be counted and cause this
        // call to return. Note that waiters.len() > 0 here.
        //
        // Bound the wait so we periodically check for new work or shutdown,
        // ensuring we don't block indefinitely (e.g. if in the meantime waiters
        // has become 0).
        metrics.pending_operations.set(waiters.len() as _);
        submit_and_wait(&mut ring, 1, Some(cfg.force_poll)).expect("unable to submit to ring");
    }
}

/// Process `ring` completions until all pending operations are complete or
/// until `cfg.shutdown_timeout` fires. If `cfg.shutdown_timeout` is None, wait
/// indefinitely.
fn drain(ring: &mut IoUring, waiters: &mut Waiters, cfg: &Config) {
    // When op_timeout is set, each operation uses 2 SQ entries
    // (op + linked timeout).
    let pending = if cfg.op_timeout.is_some() {
        waiters.len() * 2
    } else {
        waiters.len()
    };

    submit_and_wait(ring, pending, cfg.shutdown_timeout).expect("unable to submit to ring");
    while let Some(cqe) = ring.completion().next() {
        handle_cqe(waiters, cqe, cfg);
    }
}

/// Submits pending operations and waits for completions.
///
/// This function submits all pending SQEs to the kernel and waits for at least
/// `want` completions to arrive. It can optionally use a timeout to bound the
/// wait time, which is useful for implementing periodic wake-ups.
///
/// When a timeout is provided, this uses `submit_with_args` with the EXT_ARG
/// feature to implement a bounded wait without injecting a timeout SQE
/// (available since kernel 5.11+). Without a timeout, it falls back to the
/// standard `submit_and_wait`.
///
/// # Returns
/// * `Ok(true)` - Successfully received `want` completions
/// * `Ok(false)` - Timed out waiting for completions (only when timeout is set)
/// * `Err(e)` - An error occurred during submission or waiting
fn submit_and_wait(
    ring: &mut IoUring,
    want: usize,
    timeout: Option<Duration>,
) -> Result<bool, std::io::Error> {
    timeout.map_or_else(
        || ring.submit_and_wait(want).map(|_| true),
        |timeout| {
            let ts = Timespec::new()
                .sec(timeout.as_secs())
                .nsec(timeout.subsec_nanos());

            let args = SubmitArgs::new().timespec(&ts);

            match ring.submitter().submit_with_args(want, &args) {
                Ok(_) => Ok(true),
                Err(err) if err.raw_os_error() == Some(libc::ETIME) => Ok(false),
                Err(err) => Err(err),
            }
        },
    )
}

/// Returns whether some result should be retried due to a transient error.
///
/// Errors considered transient:
/// * EAGAIN: There is no data ready. Try again later.
/// * EWOULDBLOCK: Operation would block.
pub const fn should_retry(return_value: i32) -> bool {
    return_value == -libc::EAGAIN || return_value == -libc::EWOULDBLOCK
}

#[cfg(test)]
mod tests {
    use crate::iouring::{Config, Op, OpBuf};
    use futures::{
        channel::{
            mpsc::channel,
            oneshot::{self, Canceled},
        },
        executor::block_on,
        SinkExt as _,
    };
    use io_uring::{
        opcode,
        types::{Fd, Timespec},
    };
    use prometheus_client::registry::Registry;
    use std::{
        os::{fd::AsRawFd, unix::net::UnixStream},
        sync::Arc,
        time::Duration,
    };

    async fn recv_then_send(cfg: Config, should_succeed: bool) {
        // Create a new io_uring instance
        let (mut submitter, receiver) = channel(0);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics.clone(), receiver));

        let (left_pipe, right_pipe) = UnixStream::pair().unwrap();

        // Submit a read
        let msg = b"hello".to_vec();
        let mut buf = vec![0; msg.len()];
        let recv =
            opcode::Recv::new(Fd(left_pipe.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _).build();
        let (recv_tx, recv_rx) = oneshot::channel();
        submitter
            .send(crate::iouring::Op {
                work: recv,
                sender: recv_tx,
                buffers: Some(OpBuf::Single(buf.into())),
            })
            .await
            .expect("failed to send work");

        while metrics.pending_operations.get() == 0 {
            // Wait for the read to be submitted
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Submit a write that satisfies the read.
        let write =
            opcode::Write::new(Fd(right_pipe.as_raw_fd()), msg.as_ptr(), msg.len() as _).build();
        let (write_tx, write_rx) = oneshot::channel();
        submitter
            .send(crate::iouring::Op {
                work: write,
                sender: write_tx,
                buffers: Some(OpBuf::Single(msg.into())),
            })
            .await
            .expect("failed to send work");

        // Wait for the read and write operations to complete.
        if should_succeed {
            let (result, _) = recv_rx.await.expect("failed to receive result");
            assert!(result > 0, "recv failed: {result}");
            let (result, _) = write_rx.await.expect("failed to receive result");
            assert!(result > 0, "write failed: {result}");
        } else {
            let _ = recv_rx.await;
            let _ = write_rx.await;
        }
        drop(submitter);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_force_poll_short_interval_prevents_deadlock() {
        // With a short force_poll interval, the event loop should wake up
        // frequently to check for new work, preventing the deadlock.
        let cfg = Config {
            force_poll: Duration::from_millis(10),
            ..Default::default()
        };
        recv_then_send(cfg, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_force_poll_long_interval_deadlock() {
        // With a long force_poll interval, the event loop may block on recv
        // long enough that the matching write isn't observed within our test
        // timeout.
        let cfg = Config {
            force_poll: Duration::from_secs(60),
            ..Default::default()
        };
        // recv_then_send should block for 60 seconds (i.e. force_poll duration).
        // Set a timeout and make sure it doesn't complete.
        let timeout = tokio::time::timeout(Duration::from_secs(2), recv_then_send(cfg, false));
        assert!(
            timeout.await.is_err(),
            "recv_then_send completed unexpectedly"
        );
    }

    #[tokio::test]
    async fn test_timeout() {
        // Create an io_uring instance
        let cfg = super::Config {
            op_timeout: Some(std::time::Duration::from_secs(1)),
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit a work item that will time out (because we don't write to the pipe)
        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let mut buf = vec![0; 8];
        let work =
            opcode::Recv::new(Fd(pipe_left.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(crate::iouring::Op {
                work,
                sender: tx,
                buffers: Some(OpBuf::Single(buf.into())),
            })
            .await
            .expect("failed to send work");
        // Wait for the timeout
        let (result, _) = rx.await.expect("failed to receive result");
        assert_eq!(result, -libc::ETIMEDOUT);
        drop(submitter);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_no_timeout() {
        // Create an io_uring instance with shutdown timeout disabled
        let cfg = super::Config {
            shutdown_timeout: None,
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit an operation that will complete after shutdown
        let timeout = Timespec::new().sec(3);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffers: None,
            })
            .await
            .unwrap();

        // Drop submission channel to trigger io_uring shutdown
        drop(submitter);

        // Wait for the operation `timeout` to fire.
        let (result, _) = rx.await.unwrap();
        assert_eq!(result, -libc::ETIME);
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_timeout() {
        // Create an io_uring instance with shutdown timeout enabled
        let cfg = super::Config {
            shutdown_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit an operation that will complete long after shutdown starts
        let timeout = Timespec::new().sec(5_000);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffers: None,
            })
            .await
            .unwrap();

        // Give the event loop a chance to enter the blocking submit and wait before shutdown
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Drop submission channel to trigger io_uring shutdown
        drop(submitter);

        // The event loop should shut down before the `timeout` fires,
        // dropping `tx` and causing `rx` to return Canceled.
        let err = rx.await.unwrap_err();
        assert!(matches!(err, Canceled { .. }));
        handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_linked_timeout_ensure_enough_capacity() {
        // This is a regression test for a bug where we don't reserve enough SQ
        // space for operations with linked timeouts. Each op needs 2 SQEs (op +
        // timeout) but the code only ensured 1 slot is available before pushing
        // both.
        let cfg = super::Config {
            size: 8,
            op_timeout: Some(Duration::from_millis(5)),
            ..Default::default()
        };
        let (mut submitter, receiver) = channel(8);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));
        let handle = tokio::spawn(super::run(cfg, metrics, receiver));

        // Submit more operations than the SQ size to force batching.
        let total = 64usize;
        let mut rxs = Vec::with_capacity(total);
        for _ in 0..total {
            let nop = opcode::Nop::new().build();
            let (tx, rx) = oneshot::channel();
            submitter
                .send(Op {
                    work: nop,
                    sender: tx,
                    buffers: None,
                })
                .await
                .unwrap();
            rxs.push(rx);
        }

        // All NOPs should complete successfully
        for rx in rxs {
            let (res, _) = rx.await.unwrap();
            assert_eq!(res, 0, "NOP op failed: {res}");
        }

        drop(submitter);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_single_issuer() {
        // Test that SINGLE_ISSUER with DEFER_TASKRUN works correctly.
        // The simplest test: just submit a no-op and verify it completes.
        let cfg = super::Config {
            single_issuer: true,
            ..Default::default()
        };

        let (mut sender, receiver) = channel(1);
        let metrics = Arc::new(super::Metrics::new(&mut Registry::default()));

        // Run io_uring in a dedicated thread
        let uring_thread = std::thread::spawn(move || block_on(super::run(cfg, metrics, receiver)));

        // Submit a no-op
        let (tx, rx) = oneshot::channel();
        sender
            .send(Op {
                work: opcode::Nop::new().build(),
                sender: tx,
                buffers: None,
            })
            .await
            .unwrap();

        // Verify it completes successfully
        let (result, _) = rx.await.unwrap();
        assert_eq!(result, 0);

        // Clean shutdown
        drop(sender);
        uring_thread.join().unwrap();
    }

    #[cfg(feature = "iouring-network")]
    mod iovec_buf_tests {
        use super::super::IoVecBuf;
        use bytes::Bytes;

        #[test]
        fn test_new_initializes_correctly() {
            let chunks = vec![Bytes::from_static(b"hello"), Bytes::from_static(b"world")];
            let buf = IoVecBuf::new(chunks);

            assert_eq!(buf.remaining(), 10);
            assert!(!buf.is_complete());
        }

        #[test]
        fn test_advance_partial_first_chunk() {
            let chunks = vec![Bytes::from_static(b"hello"), Bytes::from_static(b"world")];
            let mut buf = IoVecBuf::new(chunks);

            // Advance 3 bytes into first chunk
            buf.advance(3);

            assert_eq!(buf.remaining(), 7);
            assert_eq!(buf.first_chunk_idx(), 0);
            assert_eq!(buf.first_chunk_offset(), 3);
            assert!(!buf.is_complete());
        }

        #[test]
        fn test_advance_exactly_first_chunk() {
            let chunks = vec![Bytes::from_static(b"hello"), Bytes::from_static(b"world")];
            let mut buf = IoVecBuf::new(chunks);

            // Advance exactly first chunk length
            buf.advance(5);

            assert_eq!(buf.remaining(), 5);
            assert_eq!(buf.first_chunk_idx(), 1);
            assert_eq!(buf.first_chunk_offset(), 0);
            assert!(!buf.is_complete());
        }

        #[test]
        fn test_advance_across_chunk_boundary() {
            let chunks = vec![Bytes::from_static(b"hello"), Bytes::from_static(b"world")];
            let mut buf = IoVecBuf::new(chunks);

            // Advance past first chunk into second
            buf.advance(7);

            assert_eq!(buf.remaining(), 3);
            assert_eq!(buf.first_chunk_idx(), 1);
            assert_eq!(buf.first_chunk_offset(), 2);
            assert!(!buf.is_complete());
        }

        #[test]
        fn test_advance_complete() {
            let chunks = vec![Bytes::from_static(b"hello"), Bytes::from_static(b"world")];
            let mut buf = IoVecBuf::new(chunks);

            // Advance all bytes
            buf.advance(10);

            assert_eq!(buf.remaining(), 0);
            assert!(buf.is_complete());
        }

        #[test]
        fn test_advance_multiple_times() {
            let chunks = vec![
                Bytes::from_static(b"aaa"),
                Bytes::from_static(b"bbb"),
                Bytes::from_static(b"ccc"),
            ];
            let mut buf = IoVecBuf::new(chunks);

            // Simulate partial sends
            buf.advance(2); // 2 bytes into first chunk
            assert_eq!(buf.remaining(), 7);
            assert_eq!(buf.first_chunk_idx(), 0);
            assert_eq!(buf.first_chunk_offset(), 2);

            buf.advance(3); // Finish first chunk, 2 bytes into second
            assert_eq!(buf.remaining(), 4);
            assert_eq!(buf.first_chunk_idx(), 1);
            assert_eq!(buf.first_chunk_offset(), 2);

            buf.advance(4); // Finish all
            assert_eq!(buf.remaining(), 0);
            assert!(buf.is_complete());
        }

        #[test]
        fn test_advance_zero_bytes() {
            let chunks = vec![Bytes::from_static(b"hello")];
            let mut buf = IoVecBuf::new(chunks);

            buf.advance(0);

            assert_eq!(buf.remaining(), 5);
            assert_eq!(buf.first_chunk_idx(), 0);
            assert_eq!(buf.first_chunk_offset(), 0);
        }

        #[test]
        fn test_advance_saturates_on_overflow() {
            let chunks = vec![Bytes::from_static(b"hello")];
            let mut buf = IoVecBuf::new(chunks);

            // Advance more than available (should saturate)
            buf.advance(100);

            assert_eq!(buf.remaining(), 0);
            assert!(buf.is_complete());
        }

        #[test]
        fn test_empty_chunks() {
            let chunks: Vec<Bytes> = vec![];
            let buf = IoVecBuf::new(chunks);

            assert_eq!(buf.remaining(), 0);
            assert!(buf.is_complete());
        }

        #[test]
        fn test_msghdr_ptr_valid() {
            let chunks = vec![Bytes::from_static(b"test")];
            let buf = IoVecBuf::new(chunks);

            // Should not panic
            let ptr = buf.msghdr_ptr();
            assert!(!ptr.is_null());
        }

        #[test]
        fn test_iov_max_capping() {
            use super::super::iov_max;

            let max = iov_max();
            // Create more chunks than iov_max
            let chunk_count = max + 100;
            let chunks: Vec<Bytes> = (0..chunk_count)
                .map(|i| Bytes::from(vec![i as u8; 10]))
                .collect();
            let total_bytes = chunk_count * 10;

            let buf = IoVecBuf::new(chunks);

            // Should cap iovecs at iov_max
            assert_eq!(buf.iovec_count(), max);
            // But remaining should reflect total bytes
            assert_eq!(buf.remaining(), total_bytes);
        }

        #[test]
        fn test_iov_max_batching_across_advance() {
            use super::super::iov_max;

            let max = iov_max();
            // Create exactly 2 * iov_max chunks (2 batches)
            let chunk_count = max * 2;
            let chunk_size = 10;
            let chunks: Vec<Bytes> = (0..chunk_count)
                .map(|i| Bytes::from(vec![i as u8; chunk_size]))
                .collect();

            let mut buf = IoVecBuf::new(chunks);

            // First batch: iov_max iovecs
            assert_eq!(buf.iovec_count(), max);

            // Advance through first batch completely
            let first_batch_bytes = max * chunk_size;
            buf.advance(first_batch_bytes);

            // Now should have second batch: iov_max iovecs
            assert_eq!(buf.iovec_count(), max);
            assert_eq!(buf.first_chunk_idx(), max);
            assert_eq!(buf.remaining(), first_batch_bytes); // Half remaining

            // Advance through second batch
            buf.advance(first_batch_bytes);
            assert!(buf.is_complete());
        }

        #[test]
        fn test_iov_max_partial_final_batch() {
            use super::super::iov_max;

            let max = iov_max();
            // Create iov_max + 50 chunks (full batch + partial)
            let extra_chunks = 50;
            let chunk_count = max + extra_chunks;
            let chunk_size = 10;
            let chunks: Vec<Bytes> = (0..chunk_count)
                .map(|i| Bytes::from(vec![i as u8; chunk_size]))
                .collect();

            let mut buf = IoVecBuf::new(chunks);

            // First batch: iov_max iovecs
            assert_eq!(buf.iovec_count(), max);

            // Advance through first batch
            buf.advance(max * chunk_size);

            // Second batch should be the remaining 50 chunks
            assert_eq!(buf.iovec_count(), extra_chunks);
            assert_eq!(buf.remaining(), extra_chunks * chunk_size);
        }
    }
}
