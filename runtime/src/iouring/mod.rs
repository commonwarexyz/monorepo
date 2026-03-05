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
//! Each submitted operation is assigned a waiter id that serves as the
//! `user_data` field in the SQE. The event loop maintains a flat `Waiters` store where
//! each slot maps to:
//! - A oneshot sender for returning results to the caller
//! - An optional buffer that must be kept alive for the duration of the operation
//! - An optional FD handle to prevent descriptor reuse while the operation is in flight
//! - Timeout lifecycle state for deadline tracking and cancellation
//!
//! ## Timeout Handling
//!
//! Operations can optionally carry an absolute deadline via [Op::deadline]. When present:
//! - The loop tracks deadline ticks in a userspace timing wheel
//! - Already-expired operations complete immediately with `ETIMEDOUT` before SQE submission
//! - In-flight operations that expire submit an async-cancel SQE
//! - A timed-out waiter is removed only after both original-op and cancel CQEs arrive
//! - If the original op CQE result is `ECANCELED`, the caller sees `ETIMEDOUT`
//! - If the original op CQE result arrives before cancel completion, that original
//!   result is returned
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

mod timeout;
mod waiter;
mod waker;

use crate::{IoBuf, IoBufMut, IoBufs};
use commonware_utils::channel::{
    mpsc::{self, error::TryRecvError},
    oneshot,
};
use io_uring::{
    cqueue::Entry as CqueueEntry,
    opcode::AsyncCancel,
    squeue::{Entry as SqueueEntry, SubmissionQueue},
    types::{SubmitArgs, Timespec},
    IoUring,
};
use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use std::{
    collections::VecDeque,
    fs::File,
    os::fd::OwnedFd,
    sync::Arc,
    time::{Duration, Instant},
};
use timeout::{Tick, TimeoutWheel};
use waiter::{CompletedWaiter, WaiterId, Waiters};
use waker::{Waker, SUBMISSION_SEQ_MASK, WAKE_USER_DATA};

/// Packed `io_uring` `user_data` value.
pub type UserData = u64;

/// Buffer for io_uring operations.
///
/// The variant must match the operation type:
/// - `Read`: For operations where the kernel writes INTO the buffer (e.g., recv, read)
/// - `Write`: For operations where the kernel reads FROM a single contiguous buffer (e.g., send, write)
/// - `WriteVectored`: For operations where the kernel reads FROM multiple buffers (e.g., writev)
#[derive(Debug)]
pub enum OpBuffer {
    /// Buffer for read operations - kernel writes into this.
    Read(IoBufMut),
    /// Buffer for write operations - kernel reads from this.
    Write(IoBuf),
    /// Buffers for vectored write operations - kernel reads from these.
    WriteVectored(IoBufs),
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

impl From<IoBufs> for OpBuffer {
    fn from(bufs: IoBufs) -> Self {
        Self::WriteVectored(bufs)
    }
}

/// File descriptor for io_uring operations.
///
/// The variant must match the descriptor type:
/// - `Fd`: For network sockets and other OS file descriptors
/// - `File`: For file-backed descriptors
pub enum OpFd {
    /// A socket or other OS file descriptor.
    ///
    /// NOTE: this is only used by the network backend, hence the allow dead
    /// code. The field itself is never read regardless, since this only exists
    /// to keep the FD alive until operation completion.
    #[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
    Fd(#[allow(dead_code)] Arc<OwnedFd>),
    /// A file-backed descriptor.
    ///
    /// NOTE: this is only used by the storage backend, hence the allow dead
    /// code. The field itself is never read regardless, since this only exists
    /// to keep the FD alive until operation completion.
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    File(#[allow(dead_code)] Arc<File>),
}

/// Owned iovecs that back a vectored io_uring operation.
///
/// This wrapper allows transferring iovec arrays through channels while keeping
/// the pointed-to buffer memory alive through [`OpBuffer`].
///
/// The field is never read directly, since this only exists to keep the iovecs
/// alive until operation completion.
pub struct OpIovecs(#[allow(dead_code)] Box<[libc::iovec]>);

impl OpIovecs {
    pub const fn new(iovecs: Box<[libc::iovec]>) -> Self {
        Self(iovecs)
    }

    pub fn as_ptr(&self) -> *const libc::iovec {
        self.0.as_ptr()
    }
}

// SAFETY: `OpIovecs` only carries raw iovec descriptors. The pointed-to memory
// is owned by `OpBuffer` and retained for the operation lifetime by the
// io_uring waiter map.
unsafe impl Send for OpIovecs {}

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
    /// Requested size of the ring.
    ///
    /// This value is rounded up to the next power of two when constructing
    /// [IoUringLoop], so the configured in-flight waiter capacity matches the
    /// effective ring sizing behavior.
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
    /// Maximum operation timeout supported by the userspace timeout wheel.
    ///
    /// Deadlines are clamped to this horizon. This value should be set to the
    /// largest expected per-operation deadline budget.
    pub max_op_timeout: Duration,
    /// The maximum time the io_uring event loop will wait for in-flight operations
    /// to complete before abandoning them during shutdown.
    /// If None, the event loop will wait indefinitely for in-flight operations
    /// to complete before shutting down. In this case, the caller should be careful
    /// to ensure that the operations submitted to the io_uring will eventually complete.
    pub shutdown_timeout: Option<Duration>,
    /// Tick granularity used by the userspace timeout wheel.
    ///
    /// Smaller values increase timing precision but increase wakeup and wheel
    /// processing frequency.
    pub timeout_wheel_tick: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size: 128,
            io_poll: false,
            single_issuer: false,
            max_op_timeout: Duration::from_secs(60),
            shutdown_timeout: None,
            timeout_wheel_tick: Duration::from_millis(5),
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
    /// Absolute deadline for this operation, if any.
    ///
    /// If present and the operation has not completed by this deadline, the
    /// loop issues an async cancel SQE.
    pub deadline: Option<Instant>,
    /// The buffer used for the operation, if any.
    /// - For reads: `OpBuffer::Read(IoBufMut)` - kernel writes into this
    /// - For writes: `OpBuffer::Write(IoBuf)` - kernel reads from this
    /// - For vectored writes: `OpBuffer::WriteVectored(IoBufs)` - kernel reads from these
    /// - None for operations that don't use a buffer (e.g. sync, timeout)
    ///
    /// We hold the buffer(s) here so it's guaranteed to live until the operation
    /// completes, preventing use-after-free issues.
    pub buffer: Option<OpBuffer>,
    /// The file descriptor used for the operation, if any.
    ///
    /// We hold the descriptor here so the OS cannot reuse the FD number
    /// while the operation is queued or in-flight.
    pub fd: Option<OpFd>,
    /// Owned iovecs used by vectored operations, if any.
    ///
    /// We hold these iovecs here so they're guaranteed to live until the operation
    /// completes, preventing use-after-free issues.
    pub iovecs: Option<OpIovecs>,
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

/// io_uring event loop state.
pub(crate) struct IoUringLoop {
    cfg: Config,
    metrics: Arc<Metrics>,
    receiver: mpsc::Receiver<Op>,
    waiters: Waiters,
    timeout_wheel: TimeoutWheel,
    waker: Waker,
    wake_rearm_needed: bool,
    processed_seq: u64,
}

impl IoUringLoop {
    /// Create a new io_uring loop and submit handle.
    ///
    /// The loop allocates its own metrics, operation channel, and internal `eventfd` wake source.
    pub(crate) fn new(mut cfg: Config, registry: &mut Registry) -> (Submitter, Self) {
        assert!(
            !cfg.max_op_timeout.is_zero(),
            "max_op_timeout must be non-zero for timeout wheel"
        );
        assert!(
            !cfg.timeout_wheel_tick.is_zero(),
            "timeout_wheel_tick must be non-zero for timeout wheel"
        );
        cfg.size = cfg
            .size
            .checked_next_power_of_two()
            .expect("ring size exceeds u32::MAX");
        let size = cfg.size as usize;
        let metrics = Arc::new(Metrics::new(registry));
        let (sender, receiver) = mpsc::channel(size);
        let waker = Waker::new().expect("unable to create wake eventfd");
        let timeout_wheel =
            TimeoutWheel::new(cfg.max_op_timeout, cfg.timeout_wheel_tick, Instant::now());
        let waiters = Waiters::new(size);

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
                waiters,
                timeout_wheel,
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
        let mut pending_cancels = VecDeque::with_capacity(self.cfg.size as usize);
        loop {
            // Process available completions.
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            // Process due deadlines before staging new submissions so timed-out
            // waiters move to cancellation promptly and free capacity sooner.
            self.advance_timeouts(&mut pending_cancels);

            // Stage as much inbound work as capacity allows.
            let Some(at_capacity) = self.fill_submission_queue(&mut ring, &mut pending_cancels)
            else {
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
                    self.submit_and_wait(&mut ring, 1, self.timeout_wheel.next_deadline())
                        .expect("unable to submit to ring");
                }

                continue;
            }

            // No pending submissions are currently visible.
            //
            // If staging hit capacity, force a submit and wait cycle to open
            // space, even though the sequence snapshot looks idle here.
            //
            // Otherwise, arm sleep intent and capture a post-arm sequence
            // snapshot from the same atomic operation. Block only if still idle.
            // Any submission that arrives after `arm()` observes sleep intent
            // and rings eventfd, so the loop is woken instead of sleeping
            // through newly published work.
            if at_capacity || self.waker.arm() == self.processed_seq {
                self.submit_and_wait(&mut ring, 1, self.timeout_wheel.next_deadline())
                    .expect("unable to submit to ring");
            }
            // Disarm sleep intent as soon as we resume running. While disarmed,
            // producers do not ring eventfd for each publish.
            self.waker.disarm();
        }
    }

    /// Stage inbound operations into the SQ.
    ///
    /// In the same pass, it rearms wake polling if needed and stages pending
    /// cancellations before new operations.
    ///
    /// Advances `processed_seq` by exactly the number of drained submissions.
    ///
    /// Returns whether staging ended at waiter or SQ capacity, or `None` if the
    /// producer channel disconnected.
    fn fill_submission_queue(
        &mut self,
        ring: &mut IoUring,
        pending_cancels: &mut VecDeque<WaiterId>,
    ) -> Option<bool> {
        let mut drained = 0u64;
        let mut submission_queue = ring.submission();
        let mut advanced = self.timeout_wheel.next_deadline().is_some();

        // Reinstall wake poll only when a prior wake CQE indicated multishot
        // termination. Otherwise keep the existing poll registration.
        if std::mem::take(&mut self.wake_rearm_needed) {
            self.waker.reinstall(&mut submission_queue);
        }

        // Stage pending cancel SQEs first so timed-out operations are canceled promptly.
        if self.stage_cancellations(&mut submission_queue, pending_cancels) {
            // If cancels alone filled the SQ, submit them first.
            return Some(true);
        }

        // Stage operations until the channel is empty, waiter capacity is hit,
        // or the SQ is full. Waiter capacity is bounded by `cfg.size`.
        while self.waiters.len() < self.cfg.size as usize && !submission_queue.is_full() {
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
                iovecs,
                deadline,
            } = op;

            let target_tick = if let Some(deadline) = deadline {
                // Avoid per-loop clock reads when no deadlines are active.
                // When the first deadline arrives after an idle period, align
                // wheel time once before converting deadlines to ticks.
                if !advanced {
                    assert!(self.timeout_wheel.advance(Instant::now()).is_none());
                    advanced = true;
                }

                match self.timeout_wheel.target_tick(deadline) {
                    Some(target_tick) => Some(target_tick),
                    None => {
                        // Deadline already expired before this operation reached staging.
                        // Return result immediately to caller.
                        let _ = sender.send((-libc::ETIMEDOUT, buffer));
                        continue;
                    }
                }
            } else {
                None
            };

            // Store in-flight operation state before submission.
            let waiter_id = self.waiters.insert(sender, buffer, fd, iovecs, target_tick);
            if let Some(target_tick) = target_tick {
                self.timeout_wheel.schedule(waiter_id, target_tick);
            }

            // Tag SQE with waiter id for completion matching.
            work = work.user_data(waiter_id.user_data());

            // Submit the operation.
            //
            // SAFETY:
            // - `buffer` and `fd` are stored in `self.waiters` until CQE processing, so
            //   SQE pointers remain valid and FD numbers cannot be reused early.
            // - SQ capacity was checked above, so this push fits.
            unsafe {
                submission_queue
                    .push(&work)
                    .expect("unable to push to queue");
            }
        }

        // Track which submitted sequence has been consumed.
        self.processed_seq = self.processed_seq.wrapping_add(drained) & SUBMISSION_SEQ_MASK;

        let at_sq_capacity = submission_queue.is_full();
        let at_waiter_capacity = self.waiters.len() == self.cfg.size as usize;
        Some(at_waiter_capacity || at_sq_capacity)
    }

    /// Stage queued cancellation SQEs from `pending_cancels` in FIFO order.
    ///
    /// Stops when all queued cancellations are staged or the SQ reaches
    /// capacity. Returns `true` when SQ capacity is hit and at least one
    /// cancellation remains queued.
    fn stage_cancellations(
        &mut self,
        submission_queue: &mut SubmissionQueue<'_>,
        pending_cancels: &mut VecDeque<WaiterId>,
    ) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = pending_cancels.pop_front() else {
                return false;
            };

            let cancel = AsyncCancel::new(waiter_id.user_data())
                .build()
                .user_data(waiter_id.cancel_user_data());

            // SAFETY: AsyncCancel SQE uses stable user_data only.
            unsafe {
                submission_queue
                    .push(&cancel)
                    .expect("unable to push cancel to queue");
            }
        }

        !pending_cancels.is_empty()
    }

    /// Handle a single CQE from the ring.
    ///
    /// Internal wake CQEs are handled in-place. All other CQEs are forwarded to
    /// waiter lifecycle tracking and may complete a waiter.
    fn handle_cqe(&mut self, cqe: CqueueEntry) {
        let user_data = cqe.user_data();
        if user_data == WAKE_USER_DATA {
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
            return;
        }

        // Route op/cancel completions through waiter state. Only terminal
        // transitions return a completed waiter to deliver to the caller.
        if let Some(completed) = self.waiters.on_completion(user_data, cqe.result()) {
            let CompletedWaiter {
                sender,
                buffer,
                mut result,
                cancelled,
                target_tick,
            } = completed;

            // Remove active deadline tracking when this waiter completes.
            if let Some(target_tick) = target_tick {
                self.timeout_wheel.remove(target_tick);
            }

            // Surface timeout as ETIMEDOUT when cancellation succeeded.
            if cancelled && result == -libc::ECANCELED {
                result = -libc::ETIMEDOUT;
            }

            let _ = sender.send((result, buffer));
        }
    }

    /// Advance the timeout wheel and enqueue cancellations for newly expired waiters.
    ///
    /// This is a no-op when no active deadlines exist. Expired stale wheel
    /// entries are ignored when waiter generation no longer matches.
    fn advance_timeouts(&mut self, pending_cancels: &mut VecDeque<WaiterId>) {
        // Fast path: no active deadlines means no clock read and no wheel scan.
        if self.timeout_wheel.next_deadline().is_none() {
            return;
        }

        // No newly expired entries at this tick.
        let Some(expired) = self.timeout_wheel.advance(Instant::now()) else {
            return;
        };

        // Mark expired waiters as cancel-requested and queue their IDs for
        // later cancel SQE staging.
        for entry in expired {
            // `None` means stale timeout entry (slot reused) or waiter already
            // transitioned to cancelled/completed.
            if let Some(cancel_user_data) = self.waiters.cancel(entry.waiter_id) {
                assert_eq!(cancel_user_data, entry.waiter_id.cancel_user_data());

                // Once cancel is requested, this waiter is no longer deadline-active.
                self.timeout_wheel.remove(entry.target_tick);
                pending_cancels.push_back(entry.waiter_id);
            }
        }
    }

    /// Drain in-flight operations during shutdown.
    ///
    /// Keeps draining CQEs until all waiters complete or shutdown budget is
    /// exhausted.
    ///
    /// If `shutdown_timeout` is `None`, this waits until all waiters complete.
    /// If `shutdown_timeout` is `Some`, this waits until completion or timeout,
    /// then abandons any remaining waiters.
    ///
    /// This path does not advance timeout deadlines or stage new cancellation
    /// SQEs after shutdown starts.
    fn drain(&mut self, ring: &mut IoUring) {
        let mut remaining = self.cfg.shutdown_timeout;

        // Keep driving completions until all in-flight waiters finish or the
        // shutdown budget is exhausted.
        while !self.waiters.is_empty() {
            if remaining.is_some_and(|t| t.is_zero()) {
                break;
            }

            let start = Instant::now();
            self.submit_and_wait(ring, 1, remaining)
                .expect("unable to submit to ring");

            // Always drain CQEs, even after timeout: completions can race with
            // timeout expiry and still be pending in the queue
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            // Charge elapsed wall time against the shutdown budget.
            if let Some(remaining) = remaining.as_mut() {
                *remaining = remaining.saturating_sub(start.elapsed());
            }
        }

        self.metrics.pending_operations.set(self.waiters.len() as _);
    }

    /// Submits pending SQEs and waits for completions.
    ///
    /// Attempts to wait for at least `want` completions but may return early on
    /// timeout or transient errors.
    ///
    /// When a timeout is provided, this uses `submit_with_args` with the EXT_ARG
    /// feature to implement a bounded wait without injecting a timeout SQE
    /// (available since kernel 5.11+). Without a timeout, it falls back to the
    /// standard `submit_and_wait`.
    ///
    /// Transient `io_uring_enter(2)` errors (`EINTR`, `EAGAIN`, `EBUSY`) return
    /// `Ok(true)` so the caller can drain CQEs and re-enter through its event
    /// loop.
    ///
    /// # Returns
    /// * `Ok(true)` - Completions may be available (caller should drain CQEs)
    /// * `Ok(false)` - Timed out waiting for completions (only when timeout is set)
    /// * `Err(e)` - An unrecoverable error occurred during submission or waiting
    fn submit_and_wait(
        &self,
        ring: &mut IoUring,
        want: usize,
        timeout: Option<Duration>,
    ) -> Result<bool, std::io::Error> {
        let result = timeout.map_or_else(
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
        );

        match result {
            Ok(v) => Ok(v),
            Err(err) => match err.raw_os_error() {
                // Transient errors: return so the caller can drain
                // CQEs and re-enter through its event loop.
                Some(libc::EINTR | libc::EAGAIN | libc::EBUSY) => Ok(true),
                _ => Err(err),
            },
        }
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

    builder.build(cfg.size)
}

/// Returns whether some result should be retried due to a transient error.
///
/// Errors considered transient:
/// * EAGAIN: There is no data ready. Try again later.
/// * EWOULDBLOCK: Operation would block.
/// * EINTR: A signal interrupted the operation before any data was transferred.
pub const fn should_retry(return_value: i32) -> bool {
    return_value == -libc::EAGAIN
        || return_value == -libc::EWOULDBLOCK
        || return_value == -libc::EINTR
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

    #[test]
    fn test_iouring_loop_rounds_ring_size_up_to_power_of_two() {
        // Ring size is rounded to the next power of two.
        let mut registry = Registry::default();
        let cfg = Config {
            size: 1_000,
            ..Default::default()
        };
        let (_, iouring) = IoUringLoop::new(cfg, &mut registry);

        assert_eq!(iouring.cfg.size, 1_024);

        // Already-power-of-two size is preserved.
        let cfg = Config {
            size: 1_024,
            ..Default::default()
        };
        let (_, iouring) = IoUringLoop::new(cfg, &mut registry);
        assert_eq!(iouring.cfg.size, 1_024);
    }

    #[test]
    fn test_should_retry_classification() {
        // Transient retryable codes.
        for code in [-libc::EAGAIN, -libc::EWOULDBLOCK, -libc::EINTR] {
            assert!(should_retry(code));
        }

        // Non-transient examples.
        for code in [0, -libc::EINVAL, -libc::ETIMEDOUT] {
            assert!(!should_retry(code));
        }
    }

    #[test]
    fn test_submit_and_wait_non_etime_error_is_not_misclassified() {
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_submitter, iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Force a deterministic kernel error path by closing the ring FD first.
        // SAFETY: `ring.as_raw_fd()` is a valid owned fd at this point.
        let close_result = unsafe { libc::close(ring.as_raw_fd()) };
        assert_eq!(close_result, 0, "failed to close ring fd in test");
        let err = iouring
            .submit_and_wait(&mut ring, 1, Some(Duration::from_millis(1)))
            .expect_err("submit_and_wait should fail on closed ring fd");
        assert_ne!(err.raw_os_error(), Some(libc::ETIME));

        // Ring fd is already closed above; avoid running Drop cleanup on invalid fd.
        std::mem::forget(ring);
    }

    #[test]
    fn test_opbuffer_write_vectored_and_opiovecs_helpers() {
        let write_vectored =
            OpBuffer::from(IoBufs::from(vec![IoBuf::from(b"a"), IoBuf::from(b"b")]));
        match write_vectored {
            OpBuffer::WriteVectored(_) => {}
            _ => panic!("expected write-vectored buffer variant"),
        }

        let iovecs = vec![libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }]
        .into_boxed_slice();
        let expected = iovecs.as_ptr();
        let owned = OpIovecs::new(iovecs);
        assert_eq!(owned.as_ptr(), expected);
    }

    #[test]
    fn test_fill_submission_queue_returns_true_when_cancel_staging_fills_sq() {
        let cfg = Config {
            size: 8,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Queue enough cancellations to overflow one staging pass once wake poll
        // rearm also consumes an SQE.
        let mut pending_cancels = VecDeque::new();
        for _ in 0..cfg.size as usize {
            let (tx, _rx) = oneshot::channel();
            let waiter_id = iouring.waiters.insert(tx, None, None, None, None);
            let cancel_user_data = iouring
                .waiters
                .cancel(waiter_id)
                .expect("cancel should transition waiter to cancel-requested");
            assert_eq!(cancel_user_data, waiter_id.cancel_user_data());
            pending_cancels.push_back(waiter_id);
        }

        // Staging should stop at SQ capacity and leave some cancels queued.
        let at_capacity = iouring
            .fill_submission_queue(&mut ring, &mut pending_cancels)
            .expect("channel should remain connected");
        assert!(at_capacity);
        assert!(!pending_cancels.is_empty());
    }

    #[tokio::test]
    async fn test_fill_submission_queue_expired_deadline_completes_immediately() {
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
        let mut pending_cancels = VecDeque::new();

        // Keep this test focused on operation staging, not wake rearm behavior.
        iouring.wake_rearm_needed = false;

        let (tx, rx) = oneshot::channel();
        let past_deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        submitter
            .send(Op {
                work: opcode::Nop::new().build(),
                sender: tx,
                buffer: None,
                fd: None,
                iovecs: None,
                deadline: Some(past_deadline),
            })
            .await
            .expect("failed to enqueue op");

        let at_capacity = iouring
            .fill_submission_queue(&mut ring, &mut pending_cancels)
            .expect("channel should remain connected");

        assert!(!at_capacity);
        assert!(pending_cancels.is_empty());
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);

        let (result, buffer) = rx.await.expect("missing timeout completion");
        assert_eq!(result, -libc::ETIMEDOUT);
        assert!(buffer.is_none());
    }

    #[tokio::test]
    async fn test_timeout_slot_reuse_does_not_cancel_new_waiter_early() {
        let cfg = Config {
            // Keep ring size realistic; size=1 can deadlock progress in some setups.
            // Waiter slot reuse is still exercised because we complete op1 before op2.
            size: 8,
            max_op_timeout: Duration::from_millis(200),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // First operation completes quickly but still carries a generous deadline,
        // leaving a stale timeout entry that should be ignored later after slot reuse.
        let (tx1, rx1) = oneshot::channel();
        submitter
            .send(Op {
                work: opcode::Nop::new().build(),
                sender: tx1,
                buffer: None,
                fd: None,
                iovecs: None,
                deadline: Some(Instant::now() + Duration::from_millis(200)),
            })
            .await
            .expect("failed to submit first operation");
        let (result1, _) = tokio::time::timeout(Duration::from_secs(2), rx1)
            .await
            .expect("first completion timed out")
            .expect("missing first completion");
        assert_eq!(result1, 0);

        // Second operation reuses the only waiter slot and blocks until timeout.
        let (left, _right) = UnixStream::pair().expect("failed to create unix stream pair");
        let mut buf = IoBufMut::with_capacity(8);
        let recv =
            opcode::Recv::new(Fd(left.as_raw_fd()), buf.as_mut_ptr(), buf.capacity() as _).build();
        let (tx2, rx2) = oneshot::channel();
        submitter
            .send(Op {
                work: recv,
                sender: tx2,
                buffer: Some(buf.into()),
                fd: None,
                iovecs: None,
                deadline: Some(Instant::now() + Duration::from_millis(80)),
            })
            .await
            .expect("failed to submit second operation");

        // If stale timeout entries were not ignored, this could time out around the first
        // operation's deadline (~15ms) instead of the second one (~80ms).
        let start = Instant::now();
        let (result2, _) = tokio::time::timeout(Duration::from_secs(2), rx2)
            .await
            .expect("second completion timed out")
            .expect("missing second completion");
        let elapsed = start.elapsed();
        assert_eq!(result2, -libc::ETIMEDOUT);
        assert!(
            elapsed >= Duration::from_millis(50),
            "timeout fired too early after slot reuse: {elapsed:?}"
        );

        drop(submitter);
        handle.join().expect("io_uring loop thread panicked");
    }

    #[test]
    fn test_advance_timeouts_ignores_stale_entry_after_slot_reuse() {
        let cfg = Config {
            max_op_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg, &mut registry);
        let mut pending_cancels = VecDeque::new();

        // Schedule an old waiter at tick 1, then complete it early so the wheel
        // retains a stale entry for this slot/tick pair.
        let (old_tx, _old_rx) = oneshot::channel();
        let old_slot = iouring.waiters.insert(old_tx, None, None, None, Some(1));
        iouring.timeout_wheel.schedule(old_slot, 1);
        let completed = iouring
            .waiters
            .on_completion(old_slot.user_data(), 0)
            .expect("missing waiter completion");
        let CompletedWaiter {
            sender,
            buffer,
            mut result,
            cancelled,
            target_tick,
        } = completed;
        if let Some(target_tick) = target_tick {
            iouring.timeout_wheel.remove(target_tick);
        }
        if cancelled && result == -libc::ECANCELED {
            result = -libc::ETIMEDOUT;
        }
        let _ = sender.send((result, buffer));

        // Reuse the same slot for a new waiter with a later timeout.
        let (tx, _rx) = oneshot::channel();
        let slot_index = iouring.waiters.insert(tx, None, None, None, Some(3));
        assert_eq!(slot_index.index(), old_slot.index());
        iouring.timeout_wheel.schedule(slot_index, 3);

        // At tick 1, only the stale old entry should expire. The new waiter must
        // stay active and no cancel should be queued.
        std::thread::sleep(iouring.cfg.timeout_wheel_tick + Duration::from_millis(2));
        iouring.advance_timeouts(&mut pending_cancels);
        assert!(pending_cancels.is_empty());

        // At tick 3, the real timeout should queue cancellation.
        std::thread::sleep((iouring.cfg.timeout_wheel_tick * 2) + Duration::from_millis(2));
        iouring.advance_timeouts(&mut pending_cancels);
        assert_eq!(pending_cancels.len(), 1);
    }

    #[test]
    fn test_cancel_completion_returns_saved_op_result() {
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg, &mut registry);
        let (tx, rx) = oneshot::channel();
        let slot_index = iouring.waiters.insert(tx, None, None, None, Some(2));
        let cancel = iouring
            .waiters
            .cancel(slot_index)
            .expect("cancel should transition active waiter");
        assert_eq!(cancel, slot_index.cancel_user_data());
        iouring.timeout_wheel.schedule(slot_index, 2);
        iouring.timeout_wheel.remove(2);

        // Simulate op CQE first, then cancel CQE.
        // The op result should be delivered immediately and the late cancel CQE ignored.
        let completed = iouring
            .waiters
            .on_completion(slot_index.user_data(), 123)
            .expect("missing completion");
        let CompletedWaiter {
            sender,
            buffer,
            mut result,
            cancelled,
            target_tick,
        } = completed;
        if let Some(target_tick) = target_tick {
            iouring.timeout_wheel.remove(target_tick);
        }
        if cancelled && result == -libc::ECANCELED {
            result = -libc::ETIMEDOUT;
        }
        let _ = sender.send((result, buffer));
        let completed = iouring
            .waiters
            .on_completion(slot_index.cancel_user_data(), -libc::ECANCELED);
        assert!(completed.is_none());

        let (result, _) = futures::executor::block_on(rx).expect("missing completion");
        assert_eq!(result, 123);
        assert_eq!(iouring.waiters.len(), 0);
    }

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
                iovecs: None,
                deadline: None,
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
                iovecs: None,
                deadline: None,
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
    async fn test_wake_path_progress_scenarios() {
        for should_succeed in [true, false] {
            // Run both wake-path scenarios:
            // - strict success assertions enabled
            // - branch-only progress check (no success assertions)
            let timeout = tokio::time::timeout(
                Duration::from_secs(2),
                recv_then_send(Default::default(), should_succeed),
            );
            assert!(
                timeout.await.is_ok(),
                "recv_then_send timed out unexpectedly (should_succeed={should_succeed})"
            );
        }
    }

    #[tokio::test]
    async fn test_timeout() {
        // Create an io_uring instance
        let cfg = Config {
            max_op_timeout: std::time::Duration::from_secs(1),
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
        let deadline = Instant::now() + Duration::from_secs(1);
        submitter
            .send(Op {
                work,
                sender: tx,
                buffer: Some(buf.into()),
                fd: None,
                iovecs: None,
                deadline: Some(deadline),
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
                iovecs: None,
                deadline: None,
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
                iovecs: None,
                deadline: None,
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
    async fn test_shutdown_timeout_with_completion() {
        let cfg = Config {
            shutdown_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Complete during shutdown drain to exercise the `got_completion` branch.
        let timeout = Timespec::new().sec(1);
        let timeout = opcode::Timeout::new(&timeout).build();
        let (tx, rx) = oneshot::channel();
        submitter
            .send(Op {
                work: timeout,
                sender: tx,
                buffer: None,
                fd: None,
                iovecs: None,
                deadline: None,
            })
            .await
            .unwrap();

        drop(submitter);
        let (result, _) = rx.await.expect("missing completion");
        assert_eq!(result, -libc::ETIME);
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_deadline_timeout_ensure_enough_capacity() {
        // Regression test: many operations with deadlines should batch without
        // requiring linked timeout SQEs or ring-size doubling.
        let cfg = Config {
            size: 8,
            max_op_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit more operations than the SQ size to force batching.
        let total = 64usize;
        let mut rxs = Vec::with_capacity(total);
        let deadline = Instant::now() + Duration::from_millis(50);
        for _ in 0..total {
            let nop = opcode::Nop::new().build();
            let (tx, rx) = oneshot::channel();
            submitter
                .send(Op {
                    work: nop,
                    sender: tx,
                    buffer: None,
                    fd: None,
                    iovecs: None,
                    deadline: Some(deadline),
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
                iovecs: None,
                deadline: None,
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
