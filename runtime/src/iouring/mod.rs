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
//!   Submitter --write(eventfd)--> wake_fd --POLLIN CQE (WAKE_USER_DATA)--> IoUringLoop
//!
//! Loop behavior:
//!   1) Drain CQEs.
//!   2) Drain MPSC and stage SQEs.
//!   3) Submit and block in io_uring_enter until a CQE (data or wake) arrives.
//! ```
//!
//! ## Work Tracking
//!
//! Each submitted operation is assigned a waiter slot index that serves as the
//! `user_data` field in the SQE. The event loop maintains a flat `Waiters` store where
//! each slot maps to:
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
//! - Reserved `user_data` values distinguish internal timeout/wake completions from
//!   regular operations
//!
//! ## Wake Handling
//!
//! To avoid submission latency while the loop is blocked in `submit_and_wait`, the loop maintains
//! a multishot `PollAdd` on an internal `eventfd`.
//! - [Submitter::send] increments an atomic submission sequence
//! - Wake CQEs drain `eventfd` readiness and re-install poll when `IORING_CQE_F_MORE` is not set
//! - The loop uses an arm-and-recheck sleep handshake (`submitted_seq` vs `processed_seq`)
//! - Submitters ring `eventfd` only while sleep intent is armed
//!
//! ## Shutdown Process
//!
//! When the operation channel closes, the event loop enters a drain phase:
//! 1. Stops accepting new operations
//! 2. Waits for all in-flight operations to complete
//! 3. If `shutdown_timeout` is configured, abandons remaining operations after the timeout
//! 4. Cleans up and exits. Dropping the last submitter signals `eventfd` so shutdown is observed
//!    promptly even if the loop is blocked.
//!
//! ## Liveness Model
//!
//! This loop enforces a configured upper bound on in-flight operations, and submissions are staged
//! from a FIFO MPSC queue.
//!
//! This implies a bounded-liveness caveat: if all in-flight operations are waiting on operations
//! that are still queued behind the capacity limit, the loop cannot make progress until some
//! in-flight operation completes or is canceled.
//!
//! Concrete example with `cfg.size = 2`:
//!
//! 1. Queue `read(fd1)`, `read(fd2)`, `write(fd1)`, `write(fd2)` in that order.
//! 2. The loop stages the first two reads and reaches waiter capacity.
//! 3. If each read depends on its corresponding write being submitted through the same loop, both
//!    reads remain blocked.
//! 4. The writes stay queued behind the capacity limit, so no completion is produced and the loop
//!    cannot free capacity on its own.
//!
//! The runtime cannot infer dependency relationships between arbitrary queued and in-flight
//! operations, so it cannot implement dependency-aware admission (and doing so generically would
//! add substantial overhead).
//!
//! The practical way to recover from this condition is cancellation via per-op timeouts. When
//! timed-out in-flight operations are canceled, waiter capacity is eventually released and queued
//! operations can be staged. Without cancellation, liveness depends on workload structure: callers
//! must avoid submission patterns where in-flight operations require later queued operations to
//! run.
//!
//! Operational guidance:
//! - Workloads that may create causal dependencies across queued and in-flight operations must use
//!   per-op timeouts.
//! - If cancellation is disabled, callers must guarantee that in-flight operations never depend on
//!   later queued operations, otherwise the loop can deadlock.

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
    fs::File,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tracing::warn;

/// Reserved `user_data` value for a CQE that indicates an operation timed out.
const TIMEOUT_USER_DATA: u64 = u64::MAX;
/// Reserved `user_data` value for internal wake poll completions.
const WAKE_USER_DATA: u64 = u64::MAX - 1;

/// Bit used to mark that the loop is armed for sleep.
const SLEEP_INTENT_BIT: u64 = 1;
/// Packed-state increment for one submitted operation (bit 0 is reserved).
const SUBMISSION_INCREMENT: u64 = 2;
/// Sequence domain used by the packed submission counter (state >> 1).
const SUBMISSION_SEQ_MASK: u64 = u64::MAX >> 1;

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

#[derive(Debug)]
/// Tracks io_uring metrics.
pub struct Metrics {
    /// Number of operations submitted to the io_uring whose CQEs haven't
    /// yet been processed. Note this metric doesn't include timeouts,
    /// which are generated internally by the io_uring event loop.
    /// This is updated in the main loop and at shutdown drain exit, so it may
    /// temporarily vary from the exact in-flight count between update points.
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

/// Shared wake state used by submitters and the io_uring loop.
///
/// `state` packs two values:
/// - bit 0: sleep intent flag (`1` means the loop may block in `submit_and_wait`)
/// - bits 1..: submitted sequence (`submitted_seq`)
///
/// Submitters always increment `submitted_seq` after enqueueing onto the MPSC. The
/// loop tracks how many submissions it has drained from the MPSC (`processed_seq`,
/// stored in loop-local state). The loop may block only when:
/// - sleep intent is armed, and
/// - `submitted_seq == processed_seq`.
///
/// Blocking follows an arm-and-recheck protocol:
/// - The loop first verifies `submitted_seq == processed_seq`, then arms sleep intent.
/// - `arm()` returns a submission-sequence snapshot from the same atomic state transition.
/// - The loop blocks only if that post-arm snapshot still equals `processed_seq`.
/// - Submitters ring `eventfd` only when they observe sleep intent armed.
///
/// This makes submissions racing with the sleep transition observable either by
/// sequence mismatch in the loop or by an eventfd wakeup.
struct WakerInner {
    wake_fd: OwnedFd,
    state: AtomicU64,
}

/// Internal eventfd-backed wake source for the io_uring loop.
///
/// - Publish submissions from producers via [`Waker::publish`]
/// - Expose submitted sequence snapshots via [`Waker::submitted`]
/// - Coordinate sleep intent transitions via [`Waker::arm`] and [`Waker::disarm`]
/// - Drain `eventfd` readiness on wake CQEs via [`Waker::acknowledge`]
/// - Re-arm the multishot poll request when needed via [`Waker::reinstall`]
///
/// This type intentionally separates:
/// - sequence publication (`state` high bits)
/// - sleep gating (`state` bit 0)
/// - kernel readiness consumption (`eventfd` read path)
///
/// Keeping these concerns separate makes the wake protocol explicit and avoids
/// coupling correctness to exact eventfd coalescing behavior.
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
                state: AtomicU64::new(0),
            }),
        })
    }

    /// Ring the eventfd doorbell.
    fn ring(&self) {
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
                    // Non-blocking write would block because the eventfd
                    // counter is saturated. A wake is already queued, so no
                    // retry is needed.
                    Some(libc::EAGAIN) => return,
                    _ => {
                        warn!("eventfd write failed");
                        return;
                    }
                }
            }
            return;
        }
    }

    /// Publish one submitted operation and optionally ring `eventfd`.
    ///
    /// Callers must invoke this only after successfully enqueueing work into
    /// the MPSC channel. That ordering guarantees that when the loop observes
    /// an updated sequence, there is corresponding work to drain.
    ///
    /// We ring `eventfd` only when sleep intent was armed in the previous
    /// state. This ensures submissions that race with the sleep transition
    /// are visible to the loop without requiring submitters to ring on every
    /// enqueue.
    fn publish(&self) {
        let prev = self
            .inner
            .state
            .fetch_add(SUBMISSION_INCREMENT, Ordering::Release);

        if (prev & SLEEP_INTENT_BIT) != 0 {
            self.ring();
        }
    }

    /// Return the current submitted sequence.
    ///
    /// The sequence domain is masked to 63 bits and compared against the
    /// loop-local `processed_seq` in the same domain.
    fn submitted(&self) -> u64 {
        (self.inner.state.load(Ordering::Acquire) >> 1) & SUBMISSION_SEQ_MASK
    }

    /// Arm sleep intent before attempting to block.
    ///
    /// After this point, any successful submission that races with sleep will
    /// observe sleep intent and ring eventfd.
    ///
    /// Returns the current submitted sequence snapshot from the same atomic
    /// operation that arms sleep intent. If this differs from loop-local
    /// `processed_seq`, the loop skips blocking and disarms immediately.
    fn arm(&self) -> u64 {
        let prev = self
            .inner
            .state
            .fetch_or(SLEEP_INTENT_BIT, Ordering::Acquire);
        (prev >> 1) & SUBMISSION_SEQ_MASK
    }

    /// Disarm sleep intent after we resume running.
    ///
    /// Keeping sleep intent clear while actively running avoids redundant
    /// eventfd writes during bursts. This is done both after a real wake and
    /// after a post-arm recheck decides not to block.
    fn disarm(&self) {
        self.inner
            .state
            .fetch_and(!SLEEP_INTENT_BIT, Ordering::Release);
    }

    /// Drain eventfd readiness acknowledged by a wake CQE.
    ///
    /// This acknowledges kernel-visible wake readiness. Sleep gating is tracked
    /// separately in the packed `state` atomic and is managed by
    /// [`Waker::arm`] / [`Waker::disarm`].
    ///
    /// Retries on `EINTR`. Treats `EAGAIN` as "nothing to drain". Without
    /// `EFD_SEMAPHORE`, one successful read drains the full counter to zero.
    fn acknowledge(&self) {
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
                    _ => {
                        tracing::warn!("eventfd read failed");
                        return;
                    }
                }
            }
            return;
        }
    }

    /// Install the wake poll request into the SQ.
    ///
    /// This uses multishot poll and is called on startup and whenever a wake
    /// CQE indicates the previous multishot request is no longer active.
    fn reinstall(&self, submission_queue: &mut SubmissionQueue<'_>) {
        let wake_poll = PollAdd::new(Fd(self.inner.wake_fd.as_raw_fd()), libc::POLLIN as u32)
            .multi(true)
            .build()
            .user_data(WAKE_USER_DATA);

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

        // Wake the loop so shutdown observes disconnect promptly. This is an
        // out-of-band wake for channel closure, so we ring directly rather
        // than publish a synthetic submission.
        self.waker.ring();
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
    /// On success, this publishes one submission and conditionally rings the loop's
    /// `eventfd` wake source if sleep intent is armed.
    pub async fn send(&self, op: Op) -> Result<(), mpsc::error::SendError<Op>> {
        self.inner
            .sender
            .as_ref()
            .expect("submitter sender is only taken on drop")
            .send(op)
            .await?;

        // Publish submission and ring eventfd only if loop sleep intent is armed.
        self.inner.waker.publish();

        Ok(())
    }
}

/// State for one in-flight operation.
///
/// Holds the sender used for completion delivery and resources that must remain alive
/// until CQE delivery.
struct Waiter {
    /// The oneshot sender used to deliver the operation result and buffer back to the
    /// caller.
    sender: oneshot::Sender<(i32, Option<OpBuffer>)>,
    /// The buffer associated with this operation, if any.
    buffer: Option<OpBuffer>,
    /// The file descriptor associated with this operation, if any. Used to keep the file
    /// descriptor alive and prevent reuse while the operation is in-flight.
    _fd: Option<OpFd>,
    /// The linked timeout timespec associated with this operation, if any. Used to keep
    /// the timespec alive and prevent use-after-free while the operation is in-flight.
    timespec: Option<Timespec>,
}

/// Tracks in-flight operations and the state needed to complete them.
struct Waiters {
    /// Waiters indexed by slot index.
    ///
    /// Free slots have no waiter (`None`).
    entries: Vec<Option<Waiter>>,
    /// Stack of reusable free slot indices.
    free: Vec<usize>,
    /// Number of active waiters currently stored in `entries`.
    len: usize,
}

impl Waiters {
    /// Create an empty waiter set that can track at most `capacity` in-flight operations
    /// at once.
    fn new(capacity: usize) -> Self {
        let mut entries = Vec::with_capacity(capacity);
        entries.resize_with(capacity, || None);

        let mut free = Vec::with_capacity(capacity);
        free.extend((0..capacity).rev());

        Self {
            entries,
            free,
            len: 0,
        }
    }

    /// Return the number of currently in-flight waiters.
    const fn len(&self) -> usize {
        self.len
    }

    /// Return whether there are no in-flight waiters.
    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the waiter for `slot_index`.
    ///
    /// Panics if `slot_index` is out of range or not currently in use.
    fn get(&self, slot_index: u64) -> &Waiter {
        let index = usize::try_from(slot_index).expect("slot index should fit in usize");
        let slot = self.entries.get(index).expect("missing waiter");
        slot.as_ref().expect("missing waiter")
    }

    /// Store a waiter and return its slot index.
    ///
    /// Panics if no free slot is available.
    fn insert(&mut self, waiter: Waiter) -> u64 {
        let index = self
            .free
            .pop()
            .expect("waiters should not exceed configured capacity");
        let replaced = self.entries[index].replace(waiter);
        assert!(replaced.is_none(), "free slot should not contain waiter");
        self.len += 1;
        index as u64
    }

    /// Remove and return the waiter for `slot_index`.
    ///
    /// Panics if `slot_index` is out of range or not currently in use.
    fn remove(&mut self, slot_index: u64) -> Waiter {
        let index = usize::try_from(slot_index).expect("slot index should fit in usize");
        let slot = self.entries.get_mut(index).expect("missing waiter");
        let waiter = slot.take().expect("missing waiter");
        self.free.push(index);
        self.len -= 1;
        waiter
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
    processed_seq: u64,
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
                waiters: Waiters::new(size),
                waker,
                wake_rearm_needed: true,
                processed_seq: 0,
            },
        )
    }

    /// Runs the io_uring event loop until all submitters are dropped and in-flight work drains.
    ///
    /// This method blocks the current thread.
    pub(crate) fn run(mut self) {
        let mut ring = new_ring(&self.cfg).expect("unable to create io_uring instance");
        loop {
            // Process available completions.
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            // Stage as much inbound work as capacity allows.
            let Some(at_capacity) = self.fill_submission_queue(&mut ring) else {
                // Producer side disconnected. Drain in-flight operations and exit.
                self.drain(&mut ring);
                return;
            };

            // Update pending operations metric.
            self.metrics.pending_operations.set(self.waiters.len() as _);

            // If submissions are still pending, do not arm sleep.
            //
            // `submitted != processed_seq` means producers have published work we
            // have not yet drained. Sleep here could park with pending work and
            // no guaranteed eventfd wake, because publish only rings after sleep
            // intent is armed.
            if self.waker.submitted() != self.processed_seq {
                if at_capacity {
                    // Pending submissions exist and staging stopped at capacity.
                    //
                    // Enter the kernel to submit pending SQEs and wait for at
                    // least one completion so capacity can open up.
                    self.submit_and_wait(&mut ring, 1, None)
                        .expect("unable to submit to ring");
                }

                continue;
            }

            // Idle path. No pending submissions are visible.
            //
            // Arm sleep intent and capture a post-arm sequence snapshot from the
            // same atomic operation. Block only if still idle. Any submission that
            // arrives after `arm()` observes sleep intent and rings eventfd, so the
            // loop is woken instead of sleeping through newly published work.
            if self.waker.arm() == self.processed_seq {
                self.submit_and_wait(&mut ring, 1, None)
                    .expect("unable to submit to ring");
            }
            // Disarm sleep intent as soon as we resume running. While disarmed,
            // producers do not ring eventfd for each publish.
            self.waker.disarm();
        }
    }

    /// Stage inbound work into the SQ, reinstalling wake poll if needed.
    ///
    /// Advances `processed_seq` by exactly the number of drained submissions.
    ///
    /// Returns whether staging ended at waiter or SQ capacity, or `None` if
    /// producer channel disconnected.
    fn fill_submission_queue(&mut self, ring: &mut IoUring) -> Option<bool> {
        let mut drained = 0u64;
        let mut submission_queue = ring.submission();
        let mut at_sq_capacity = false;

        // Reinstall wake poll only when a prior wake CQE indicated multishot
        // termination. Otherwise keep the existing poll registration.
        if std::mem::take(&mut self.wake_rearm_needed) {
            self.waker.reinstall(&mut submission_queue);
        }

        // Stage until we either run out of channel work or hit waiter capacity.
        //
        // Capacity is bounded by `cfg.size` active waiters. This remains correct
        // when `op_timeout` is enabled because each operation consumes 2 SQEs
        // (`op + linked timeout`) and staging is budgeted by SQ entries.
        while self.waiters.len() < self.cfg.size as usize {
            // Check SQ capacity before staging each operation.
            let available = submission_queue.capacity() - submission_queue.len();
            let needed = if self.cfg.op_timeout.is_some() { 2 } else { 1 };
            if available < needed {
                at_sq_capacity = true;
                break;
            }

            // Try to drain one operation from the channel. If the channel is empty, we're
            // done for now.
            let op = match self.receiver.try_recv() {
                Ok(work) => work,
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => break,
            };

            // Count exactly how many published submissions we consumed so
            // `processed_seq` stays in sync with the published sequence domain.
            drained += 1;

            let Op {
                mut work,
                sender,
                buffer,
                fd,
            } = op;

            // Prepare op timeout timespec. We build the linked timeout SQE later, after
            // waiter insertion, so its pointer comes from stable waiter-backed storage.
            let timespec = self.cfg.op_timeout.map(|timeout| {
                Timespec::new()
                    .sec(timeout.as_secs())
                    .nsec(timeout.subsec_nanos())
            });

            // Store in-flight operation state before submission.
            let slot_index = self.waiters.insert(Waiter {
                sender,
                buffer,
                _fd: fd,
                timespec,
            });

            // Tag SQE with waiter slot index for completion matching.
            work = work.user_data(slot_index);

            if self.cfg.op_timeout.is_some() {
                // Link this operation to the timeout SQE that will be pushed afterwards.
                work = work.flags(io_uring::squeue::Flags::IO_LINK);
            }

            // Submit the operation.
            //
            // SAFETY:
            // - `buffer` and `fd` are stored in `self.waiters` until CQE processing, so
            //   SQE pointers remain valid and FD numbers cannot be reused early.
            // - `IO_LINK` is set on `work` before pushing it, so the following timeout
            //   SQE applies to this operation.
            // - `available >= needed` was checked above, so this push fits.
            unsafe {
                submission_queue
                    .push(&work)
                    .expect("unable to push to queue");
            }

            if self.cfg.op_timeout.is_some() {
                // Build linked timeout op from waiter-owned timespec storage.
                let timeout = LinkTimeout::new(
                    self.waiters
                        .get(slot_index)
                        .timespec
                        .as_ref()
                        .expect("missing timespec"),
                )
                .build()
                .user_data(TIMEOUT_USER_DATA);

                // SAFETY:
                // - `timeout` was built from the waiter's stored `timespec`, and that
                //   waiter entry stays alive until CQE handling, so the kernel `Timespec`
                //   pointer remains valid.
                // - `available >= needed` was checked above, so this push fits.
                unsafe {
                    submission_queue
                        .push(&timeout)
                        .expect("unable to push timeout to queue");
                }
            }
        }

        // Track which submitted sequence has been consumed.
        self.processed_seq = self.processed_seq.wrapping_add(drained) & SUBMISSION_SEQ_MASK;

        let at_waiter_capacity = self.waiters.len() == self.cfg.size as usize;
        Some(at_waiter_capacity || at_sq_capacity)
    }

    /// Handle a single CQE from the ring.
    ///
    /// Internal wake and timeout CQEs are handled in-place, normal operation
    /// CQEs are matched to `waiters` and forwarded to the original requester.
    fn handle_cqe(&mut self, cqe: CqueueEntry) {
        let user_data = cqe.user_data();
        match user_data {
            WAKE_USER_DATA => {
                assert!(
                    cqe.result() >= 0,
                    "wake poll CQE failed: requires multishot poll (Linux 5.13+)"
                );

                // Drain wake readiness from eventfd for this wake CQE.
                self.waker.acknowledge();

                // Multishot can terminate, so we must re-arm to keep the wake
                // path live.
                if !io_uring::cqueue::more(cqe.flags()) {
                    self.wake_rearm_needed = true;
                }
            }
            TIMEOUT_USER_DATA => {
                assert!(
                    self.cfg.op_timeout.is_some(),
                    "received TIMEOUT_USER_DATA with op_timeout disabled"
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

                let Waiter {
                    sender: result_sender,
                    buffer,
                    ..
                } = self.waiters.remove(user_data);
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
        let mut remaining = self.cfg.shutdown_timeout;

        while !self.waiters.is_empty() {
            if remaining.is_some_and(|t| t.is_zero()) {
                break;
            }

            let start = Instant::now();
            let got_completion = self
                .submit_and_wait(ring, 1, remaining)
                .expect("unable to submit to ring");

            // Always drain CQEs, even after timeout: completions can race with
            // timeout expiry and still be pending in the queue
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            if !got_completion {
                // Shutdown timeout elapsed before all in-flight work completed.
                break;
            }

            if let Some(remaining) = remaining.as_mut() {
                *remaining = remaining.saturating_sub(start.elapsed());
            }
        }

        self.metrics.pending_operations.set(self.waiters.len() as _);
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
        // This is safe in our implementation since we eventually call `submit_and_wait()`
        // (which sets `IORING_ENTER_GETEVENTS`) even on the wake fast-path, and we are
        // also enabling `IORING_SETUP_SINGLE_ISSUER` here, which is a pre-requisite.
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
        cfg.size.checked_mul(2).expect("ring size overflow")
    } else {
        cfg.size
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
