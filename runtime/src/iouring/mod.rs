//! io_uring event loop implementation.
//!
//! This module provides a high-level interface for submitting operations to Linux's io_uring
//! subsystem and receiving their results. The design centers around a single event loop that
//! manages the submission queue (SQ) and completion queue (CQ) of an io_uring instance.
//!
//! Work is submitted via [Submitter], which pushes operations into an MPSC queue and signals
//! an internal `eventfd` wake source. The event loop blocks in `io_uring_enter` and is woken by:
//! - normal CQE progress in the ring
//! - `eventfd` readiness when new work is queued or all submitters are dropped
//!
//! # Kernel Requirements
//!
//! - Baseline: Linux kernel 5.13 or newer (required for io_uring multishot poll
//!   used by the internal `eventfd` wake path).
//! - With [`Config::single_issuer`] enabled: Linux kernel 6.1 or newer, because
//!   this implementation also enables `IORING_SETUP_DEFER_TASKRUN`.
//! - Effective requirement for runtime io_uring network/storage backends: 6.1+,
//!   since those backends enable [`Config::single_issuer`].
//!
//! # Architecture
//!
//! ## Event Loop
//!
//! The core of this implementation is [IoUringLoop::run], which blocks its calling thread while
//! operating an event loop that:
//! 1. Drains operation requests from a bounded MPSC channel fed by [Submitter]
//! 2. Assigns unique IDs to each operation and submits them to io_uring's submission queue (SQE)
//! 3. Processes io_uring completion queue entries (CQEs), including internal wake CQEs
//! 4. Routes completion results back to the original requesters via oneshot channels
//!
//! ## Operation Flow
//!
//! ```text
//! Data path:
//!   Client task -> Submitter -> bounded MPSC -> IoUringLoop -> SQE -> io_uring
//!   Client task <- oneshot <- IoUringLoop <- CQE <- io_uring
//!
//! Wake path:
//!   Submitter --write(eventfd)--> wake_fd --POLLIN CQE (WAKE_WORK_ID)--> IoUringLoop
//!
//! Loop behavior:
//!   1) Drain CQEs.
//!   2) Drain MPSC and stage SQEs.
//!   3) Submit and block in io_uring_enter until a CQE (data or wake) arrives.
//! ```
//!
//! ## Work Tracking
//!
//! Each submitted operation is assigned a unique work ID that serves as the `user_data` field
//! in the SQE. The event loop maintains a `waiters` HashMap that maps each work ID to:
//! - A oneshot sender for returning results to the caller
//! - An optional buffer that must be kept alive for the duration of the operation
//! - An optional FD handle to prevent descriptor reuse while the operation is in flight
//! - An optional timespec, if operation timeouts are enabled, that must be kept
//!   alive for the duration of the operation
//!
//! ## Timeout Handling
//!
//! Operations can be configured with timeouts using `Config::op_timeout`. When enabled:
//! - Each operation is linked to a timeout using io_uring's `IOSQE_IO_LINK` flag
//! - If the timeout fires first, the operation is canceled and returns `ETIMEDOUT`
//! - Reserved work IDs distinguish internal timeout/wake completions from regular operations
//!
//! ## Wake Handling
//!
//! To avoid submission latency while the loop is blocked in `submit_and_wait`, the loop maintains
//! a multishot `PollAdd` on an internal `eventfd`.
//! - [Submitter::send] coalesces wake writes with an atomic wake-pending latch
//! - Wake CQEs drain the `eventfd` counter and re-arm when `IORING_CQE_F_MORE` is not set
//!
//! ## Shutdown Process
//!
//! When the operation channel closes, the event loop enters a drain phase:
//! 1. Stops accepting new operations
//! 2. Waits for all in-flight operations to complete
//! 3. If `shutdown_timeout` is configured, abandons remaining operations after the timeout
//! 4. Cleans up and exits. Dropping the last submitter signals `eventfd` so shutdown is observed
//!    promptly even if the loop is blocked.

use crate::{IoBuf, IoBufMut};
use commonware_utils::channel::{
    mpsc::{self, error::TryRecvError},
    oneshot,
};
use io_uring::{
    cqueue::Entry as CqueueEntry,
    opcode::{LinkTimeout, PollAdd},
    squeue::{Entry as SqueueEntry, SubmissionQueue},
    types::{Fd, SubmitArgs, Timespec},
    IoUring,
};
use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use std::{
    collections::HashMap,
    fs::File,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// Reserved ID for a CQE that indicates an operation timed out.
const TIMEOUT_WORK_ID: u64 = u64::MAX;
/// Reserved ID for internal wake poll completions.
const WAKE_WORK_ID: u64 = u64::MAX - 1;

/// Buffer for io_uring operations.
///
/// The variant must match the operation type:
/// - `Read`: For operations where the kernel writes INTO the buffer (e.g., recv, read)
/// - `Write`: For operations where the kernel reads FROM the buffer (e.g., send, write)
#[derive(Debug)]
pub enum OpBuffer {
    /// Buffer for read operations - kernel writes into this.
    Read(IoBufMut),
    /// Buffer for write operations - kernel reads from this.
    Write(IoBuf),
}

impl From<IoBufMut> for OpBuffer {
    fn from(buf: IoBufMut) -> Self {
        Self::Read(buf)
    }
}

impl From<IoBuf> for OpBuffer {
    fn from(buf: IoBuf) -> Self {
        Self::Write(buf)
    }
}

/// File descriptor for io_uring operations.
///
/// The variant must match the descriptor type:
/// - `Fd`: For network sockets and other OS file descriptors
/// - `File`: For file-backed descriptors
#[allow(dead_code)]
pub enum OpFd {
    /// A socket or other OS file descriptor.
    Fd(Arc<OwnedFd>),
    /// A file-backed descriptor.
    File(Arc<File>),
}

/// Active operations keyed by their work id.
///
/// Each entry keeps the caller's oneshot sender, the buffer that must stay
/// alive until the kernel finishes touching it, and when op_timeout is enabled,
/// the boxed `Timespec` used when we link in an IOSQE_IO_LINK timeout.
type Waiters = HashMap<
    u64,
    (
        oneshot::Sender<(i32, Option<OpBuffer>)>,
        Option<OpBuffer>,
        Option<OpFd>,
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
    /// Warning: when enabled, the same thread that creates the ring must be
    /// the only thread that submits work to it.
    ///
    /// This loop creates the ring inside [IoUringLoop::run] and performs all
    /// ring submissions from that same thread, so it is compatible with
    /// `single_issuer` when `run` is executed on a dedicated thread.
    /// See IORING_SETUP_SINGLE_ISSUER in <https://man7.org/linux/man-pages/man2/io_uring_setup.2.html>.
    pub single_issuer: bool,
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
            op_timeout: None,
            shutdown_timeout: None,
        }
    }
}

/// An operation submitted to [IoUringLoop], processed by [IoUringLoop::run].
pub struct Op {
    /// The submission queue entry to be submitted to the ring.
    /// Its user data field will be overwritten. Users shouldn't rely on it.
    pub work: SqueueEntry,
    /// Sends the result of the operation and `buffer`.
    pub sender: oneshot::Sender<(i32, Option<OpBuffer>)>,
    /// The buffer used for the operation, if any.
    /// - For reads: `OpBuffer::Read(IoBufMut)` - kernel writes into this
    /// - For writes: `OpBuffer::Write(IoBuf)` - kernel reads from this
    /// - None for operations that don't use a buffer (e.g. sync, timeout)
    ///
    /// We hold the buffer here so it's guaranteed to live until the operation
    /// completes, preventing use-after-free issues.
    pub buffer: Option<OpBuffer>,
    /// The file descriptor used for the operation, if any.
    ///
    /// We hold the descriptor here so the OS cannot reuse the FD number
    /// while the operation is queued or in-flight.
    pub fd: Option<OpFd>,
}

struct WakerInner {
    wake_fd: OwnedFd,
    wake_pending: AtomicBool,
}

/// Internal eventfd-backed wake source for the io_uring loop.
///
/// Producers signal this after enqueueing work. The loop consumes wake
/// notifications from CQEs and re-arms multishot poll when needed.
#[derive(Clone)]
struct Waker {
    inner: Arc<WakerInner>,
}

impl Waker {
    /// Create a non-blocking eventfd wake source.
    fn new() -> Result<Self, std::io::Error> {
        // SAFETY: `eventfd` is called with valid flags and no aliasing pointers.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `eventfd` returned a new owned descriptor.
        let wake_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self {
            inner: Arc::new(WakerInner {
                wake_fd,
                wake_pending: AtomicBool::new(false),
            }),
        })
    }

    /// Signal wake by incrementing the eventfd counter.
    fn signal(&self) {
        let value: u64 = 1;
        loop {
            // SAFETY: `wake_fd` is a valid eventfd descriptor and `value` points
            // to an initialized 8-byte integer for the duration of the call.
            let ret = unsafe {
                libc::write(
                    self.inner.wake_fd.as_raw_fd(),
                    &value as *const u64 as *const libc::c_void,
                    size_of::<u64>(),
                )
            };
            if ret == size_of::<u64>() as isize {
                return;
            }
            if ret == -1 {
                match std::io::Error::last_os_error().raw_os_error() {
                    // Retry if interrupted by a signal before completion.
                    Some(libc::EINTR) => continue,
                    // Non-blocking write would block because the counter is
                    // saturated: a wake is already pending, so no retry is needed.
                    Some(libc::EAGAIN) => return,
                    _ => return,
                }
            }
            return;
        }
    }

    /// Wake once per producer burst using the pending latch.
    ///
    /// The first caller in a burst flips `wake_pending` and writes to eventfd.
    /// Subsequent callers skip the syscall.
    fn wake(&self) {
        if !self.inner.wake_pending.swap(true, Ordering::AcqRel) {
            self.signal();
        }
    }

    /// Clear and return the previous pending state.
    fn clear(&self) -> bool {
        self.inner.wake_pending.swap(false, Ordering::AcqRel)
    }

    /// Consume wake notifications from the eventfd counter.
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "nothing to drain". Without
    /// `EFD_SEMAPHORE`, one successful read drains the full counter to zero.
    fn consume(&self) {
        let mut value: u64 = 0;
        loop {
            // SAFETY: `wake_fd` is a valid eventfd descriptor and `value` points
            // to writable 8-byte storage for the duration of the call.
            let ret = unsafe {
                libc::read(
                    self.inner.wake_fd.as_raw_fd(),
                    &mut value as *mut u64 as *mut libc::c_void,
                    size_of::<u64>(),
                )
            };
            if ret == size_of::<u64>() as isize {
                // eventfd (without EFD_SEMAPHORE) returns the full counter and
                // resets it to zero in one read.
                return;
            }
            if ret == -1 {
                match std::io::Error::last_os_error().raw_os_error() {
                    // Retry if interrupted by a signal before completion.
                    Some(libc::EINTR) => continue,
                    // Non-blocking read would block because the counter is zero,
                    // there is nothing left to drain right now.
                    Some(libc::EAGAIN) => return,
                    _ => return,
                }
            }
            return;
        }
    }

    /// Rearm the wake poll request.
    ///
    /// This uses multishot poll and is called when a wake CQE indicates the
    /// previous multishot arm is no longer active.
    fn rearm(&self, submission_queue: &mut SubmissionQueue<'_>) {
        let wake_poll = PollAdd::new(Fd(self.inner.wake_fd.as_raw_fd()), libc::POLLIN as u32)
            .multi(true)
            .build()
            .user_data(WAKE_WORK_ID);

        // SAFETY: The poll SQE owns no user pointers and references a valid FD.
        unsafe {
            submission_queue
                .push(&wake_poll)
                .expect("wake poll SQE should always fit in the ring");
        }
    }
}

struct SubmitterInner {
    sender: Option<mpsc::Sender<Op>>,
    waker: Waker,
}

impl Drop for SubmitterInner {
    fn drop(&mut self) {
        // Disconnect first, then wake. This avoids a race where the loop
        // handles a wake CQE before channel closure becomes observable.
        drop(self.sender.take());

        // Wake the loop so shutdown observes disconnect promptly.
        self.waker.signal();
    }
}

/// Handle for submitting operations to an [IoUringLoop].
#[derive(Clone)]
pub struct Submitter {
    inner: Arc<SubmitterInner>,
}

impl Submitter {
    /// Submit an operation to the io_uring loop.
    ///
    /// On success, this may signal the loop's `eventfd` wake source. Wake writes are coalesced
    /// with an atomic wake-pending latch so bursts of submissions usually trigger a single wake.
    pub async fn send(&self, op: Op) -> Result<(), mpsc::error::SendError<Op>> {
        self.inner
            .sender
            .as_ref()
            .expect("submitter sender is only taken on drop")
            .send(op)
            .await?;

        // Only the first send in a burst performs the eventfd write.
        self.inner.waker.wake();

        Ok(())
    }
}

/// io_uring event loop state.
pub(crate) struct IoUringLoop {
    cfg: Config,
    metrics: Arc<Metrics>,
    receiver: mpsc::Receiver<Op>,
    waiters: Waiters,
    waker: Waker,
    wake_rearm_needed: bool,
    next_work_id: u64,
}

impl IoUringLoop {
    /// Create a new io_uring loop and submit handle.
    ///
    /// The loop allocates its own metrics, operation channel, and internal `eventfd` wake source.
    pub(crate) fn new(cfg: Config, registry: &mut Registry) -> (Submitter, Self) {
        let size = cfg.size as usize;
        let metrics = Arc::new(Metrics::new(registry));
        let (sender, receiver) = mpsc::channel(size);
        let waker = Waker::new().expect("unable to create wake eventfd");

        let submitter = Submitter {
            inner: Arc::new(SubmitterInner {
                sender: Some(sender),
                waker: waker.clone(),
            }),
        };

        (
            submitter,
            Self {
                cfg,
                metrics,
                receiver,
                waiters: Waiters::with_capacity(size),
                waker,
                wake_rearm_needed: true,
                next_work_id: 0,
            },
        )
    }

    /// Runs the io_uring event loop until all submitters are dropped and in-flight work drains.
    ///
    /// This method blocks the current thread.
    pub(crate) fn run(mut self) {
        let mut ring = new_ring(&self.cfg).expect("unable to create io_uring instance");

        // Hybrid flush policy for the wake-fast path:
        // - flush immediately once a small batch is staged
        // - otherwise allow a small number of deferrals for batching
        let batch_threshold = (self.cfg.size / 32).clamp(1, 32) as usize;
        let max_defer_loops = 2;

        let mut defer_loops = 0;
        loop {
            // Process available completions.
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            // Fill submission queue with inbound work.
            let (submissions, disconnected) = self.fill_submission_queue(&mut ring);

            if disconnected {
                // All submitters are gone, drain in-flight ops and shutdown.
                self.drain(&mut ring);
                return;
            }

            self.metrics.pending_operations.set(self.waiters.len() as _);

            // If producers queued more work since our last channel drain, loop
            // again without blocking.
            if self.waker.clear() {
                if submissions == 0 {
                    defer_loops = 0;
                } else if submissions >= batch_threshold || defer_loops >= max_defer_loops {
                    // Submit staged SQEs to cap tail latency under steady
                    // wakeups while still allowing small-batch coalescing.
                    ring.submit().expect("unable to submit to ring");
                    defer_loops = 0;
                } else {
                    defer_loops += 1;
                }

                continue;
            }

            // Sleep until either a completion arrives or wake_fd poll fires.
            self.submit_and_wait(&mut ring, 1, None)
                .expect("unable to submit to ring");

            defer_loops = 0;
        }
    }

    /// Rearm wake poll (if needed) and stage inbound work into the SQ.
    ///
    /// Returns `(submissions, disconnected)` where:
    /// - `submissions` is the number of SQEs currently staged in the ring.
    /// - `disconnected` indicates the inbound channel closed during staging.
    ///
    /// Staging is limited by `cfg.size` active waiters. This remains correct
    /// when `op_timeout` is enabled because `new_ring` doubles ring size to
    /// accommodate `op + linked timeout` SQE pairs.
    fn fill_submission_queue(&mut self, ring: &mut IoUring) -> (usize, bool) {
        let mut disconnected = false;
        let mut submission_queue = ring.submission();

        if std::mem::take(&mut self.wake_rearm_needed) {
            self.waker.rearm(&mut submission_queue);
        }

        while self.waiters.len() < self.cfg.size as usize {
            let op = match self.receiver.try_recv() {
                Ok(work) => work,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
            };

            let Op {
                mut work,
                sender,
                buffer,
                fd,
            } = op;

            // Assign a unique ID, skipping reserved IDs.
            let work_id = self.next_work_id;
            self.next_work_id += 1;
            if self.next_work_id >= WAKE_WORK_ID {
                self.next_work_id = 0;
            }
            work = work.user_data(work_id);

            // Submit the operation to the ring, with timeout if configured.
            let timespec = if let Some(timeout) = &self.cfg.op_timeout {
                // Link the operation to the (following) timeout.
                work = work.flags(io_uring::squeue::Flags::IO_LINK);

                // The timespec needs to be allocated on the heap and kept
                // alive for the duration of the operation so that the pointer
                // stays valid.
                let timespec = Box::new(
                    Timespec::new()
                        .sec(timeout.as_secs())
                        .nsec(timeout.subsec_nanos()),
                );

                // Create the timeout.
                let timeout = LinkTimeout::new(&*timespec)
                    .build()
                    .user_data(TIMEOUT_WORK_ID);

                // Submit the op and timeout.
                //
                // SAFETY: `buffer`, `timespec`, and `fd` are stored in `self.waiters`
                // until the CQE is processed, ensuring memory referenced by the SQEs
                // remains valid and the FD cannot be reused. The ring was doubled in
                // size for timeout support, and `self.waiters.len() < cfg.size`
                // guarantees space for both entries.
                unsafe {
                    submission_queue
                        .push(&work)
                        .expect("unable to push to queue");
                    submission_queue
                        .push(&timeout)
                        .expect("unable to push timeout to queue");
                }

                Some(timespec)
            } else {
                // No timeout, submit the operation normally.
                //
                // SAFETY: `buffer` and `fd` are stored in `self.waiters` until the
                // CQE is processed, ensuring memory referenced by the SQE remains
                // valid and the FD cannot be reused. The loop condition
                // `self.waiters.len() < cfg.size` guarantees space in the submission
                // queue.
                unsafe {
                    submission_queue
                        .push(&work)
                        .expect("unable to push to queue");
                }

                None
            };

            // We'll send the result of this operation to `sender`.
            // `fd` is retained to prevent FD reuse until completion.
            self.waiters.insert(work_id, (sender, buffer, fd, timespec));
        }

        (submission_queue.len(), disconnected)
    }

    /// Handle a single CQE from the ring.
    ///
    /// Internal wake and timeout CQEs are handled in-place, normal operation
    /// CQEs are matched to `waiters` and forwarded to the original requester.
    fn handle_cqe(&mut self, cqe: CqueueEntry) {
        let work_id = cqe.user_data();
        match work_id {
            WAKE_WORK_ID => {
                assert!(
                    cqe.result() >= 0,
                    "wake poll CQE failed: requires multishot poll (Linux 5.13+)"
                );

                // Clear eventfd readiness so future wake signals can trigger
                // notifications.
                self.waker.consume();

                // Multishot can terminate, so we must re-arm to keep the wake
                // path live.
                if !io_uring::cqueue::more(cqe.flags()) {
                    self.wake_rearm_needed = true;
                }
            }
            TIMEOUT_WORK_ID => {
                assert!(
                    self.cfg.op_timeout.is_some(),
                    "received TIMEOUT_WORK_ID with op_timeout disabled"
                );
            }
            _ => {
                let result = cqe.result();
                let result = if result == -libc::ECANCELED && self.cfg.op_timeout.is_some() {
                    // This operation timed out.
                    -libc::ETIMEDOUT
                } else {
                    result
                };

                let (result_sender, buffer, _, _) =
                    self.waiters.remove(&work_id).expect("missing sender");
                let _ = result_sender.send((result, buffer));
            }
        }
    }

    /// Drain in-flight operations during shutdown.
    ///
    /// - If `shutdown_timeout` is `None`, this waits until all waiters complete.
    /// - If `shutdown_timeout` is `Some`, this waits until all waiters complete
    ///   or the timeout elapses, then abandons any remaining waiters.
    fn drain(&mut self, ring: &mut IoUring) {
        let deadline = self
            .cfg
            .shutdown_timeout
            .map(|timeout| Instant::now() + timeout);

        while !self.waiters.is_empty() {
            let timeout =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));

            if timeout.is_some_and(|t| t.is_zero()) {
                break;
            }

            let got_completion = self
                .submit_and_wait(ring, 1, timeout)
                .expect("unable to submit to ring");

            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            if !got_completion {
                // Shutdown timeout elapsed before all in-flight work completed.
                break;
            }
        }
    }

    /// Submits pending operations and waits for completions.
    ///
    /// This submits all pending SQEs to the kernel and waits for at least
    /// `want` completions to arrive. It can optionally use a timeout to bound
    /// the wait time.
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
        &self,
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
}

/// Build and configure an `io_uring` instance.
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
    // concurrent operations they configured. We also reserve one extra SQE for
    // the internal wake poll.
    let ring_size = if cfg.op_timeout.is_some() {
        cfg.size
            .checked_mul(2)
            .and_then(|size| size.checked_add(1))
            .expect("ring size overflow")
    } else {
        cfg.size.checked_add(1).expect("ring size overflow")
    };

    builder.build(ring_size)
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
    use super::*;
    use commonware_utils::channel::oneshot::{self, error::RecvError};
    use io_uring::{
        opcode,
        types::{Fd, Timespec},
    };
    use prometheus_client::registry::Registry;
    use std::{
        os::{fd::AsRawFd, unix::net::UnixStream},
        time::Duration,
    };

    async fn recv_then_send(cfg: Config, should_succeed: bool) {
        // Create a new io_uring instance
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        let (left_pipe, right_pipe) = UnixStream::pair().unwrap();

        // Submit a read
        let msg = IoBuf::from(b"hello");
        let mut buf = IoBufMut::with_capacity(msg.len());
        let recv =
            opcode::Recv::new(Fd(left_pipe.as_raw_fd()), buf.as_mut_ptr(), msg.len() as _).build();
        let (recv_tx, recv_rx) = oneshot::channel();
        submitter
            .send(Op {
                work: recv,
                sender: recv_tx,
                buffer: Some(buf.into()),
                fd: None,
            })
            .await
            .expect("failed to send work");

        // Submit a write that satisfies the read.
        let write =
            opcode::Write::new(Fd(right_pipe.as_raw_fd()), msg.as_ptr(), msg.len() as _).build();
        let (write_tx, write_rx) = oneshot::channel();
        submitter
            .send(Op {
                work: write,
                sender: write_tx,
                buffer: Some(msg.into()),
                fd: None,
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
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_wake_path_makes_progress() {
        let timeout = tokio::time::timeout(
            Duration::from_secs(2),
            recv_then_send(Default::default(), true),
        );
        assert!(
            timeout.await.is_ok(),
            "recv_then_send timed out unexpectedly"
        );
    }

    #[tokio::test]
    async fn test_timeout() {
        // Create an io_uring instance
        let cfg = Config {
            op_timeout: Some(std::time::Duration::from_secs(1)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit a work item that will time out (because we don't write to the pipe)
        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let mut buf = IoBufMut::with_capacity(8);
        let work = opcode::Recv::new(
            Fd(pipe_left.as_raw_fd()),
            buf.as_mut_ptr(),
            buf.capacity() as _,
        )
        .build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work,
                sender: tx,
                buffer: Some(buf.into()),
                fd: None,
            })
            .await
            .expect("failed to send work");
        // Wait for the timeout
        let (result, _) = rx.await.expect("failed to receive result");
        assert_eq!(result, -libc::ETIMEDOUT);
        drop(submitter);
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_no_timeout() {
        // Create an io_uring instance with shutdown timeout disabled
        let cfg = Config {
            shutdown_timeout: None,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit an operation that will complete after shutdown
        let timeout = Timespec::new().sec(3);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffer: None,
                fd: None,
            })
            .await
            .unwrap();

        // Drop submission channel to trigger io_uring shutdown
        drop(submitter);

        // With `shutdown_timeout = None`, shutdown waits until all in-flight
        // operations complete.
        let (result, _) = rx.await.unwrap();
        assert_eq!(result, -libc::ETIME);
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_timeout() {
        // Create an io_uring instance with shutdown timeout enabled
        let cfg = Config {
            shutdown_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit an operation that will complete long after shutdown starts
        let timeout = Timespec::new().sec(5_000);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffer: None,
                fd: None,
            })
            .await
            .unwrap();

        // Give the event loop a chance to enter the blocking submit and wait before shutdown
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Drop submission channel to trigger io_uring shutdown
        drop(submitter);

        // The event loop should shut down before the `timeout` fires,
        // dropping `tx` and causing `rx` to return RecvError.
        let err = rx.await.unwrap_err();
        assert!(matches!(err, RecvError { .. }));
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_linked_timeout_ensure_enough_capacity() {
        // This is a regression test for a bug where we don't reserve enough SQ
        // space for operations with linked timeouts. Each op needs 2 SQEs (op +
        // timeout) but the code only ensured 1 slot is available before pushing
        // both.
        let cfg = Config {
            size: 8,
            op_timeout: Some(Duration::from_millis(5)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

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
                    buffer: None,
                    fd: None,
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
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_single_issuer() {
        // Test that SINGLE_ISSUER with DEFER_TASKRUN works correctly.
        // The simplest test: just submit a no-op and verify it completes.
        let cfg = Config {
            single_issuer: true,
            ..Default::default()
        };

        let mut registry = Registry::default();
        let (sender, iouring) = IoUringLoop::new(cfg, &mut registry);

        // Run io_uring in a dedicated thread
        let uring_thread = std::thread::spawn(move || iouring.run());

        // Submit a no-op
        let (tx, rx) = oneshot::channel();
        sender
            .send(Op {
                work: opcode::Nop::new().build(),
                sender: tx,
                buffer: None,
                fd: None,
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
}
