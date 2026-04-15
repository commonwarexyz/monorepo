//! io_uring event loop implementation.
//!
//! This module provides a high-level interface for submitting logical requests to Linux's io_uring
//! subsystem and receiving their results. The design centers around a single event loop that
//! manages the submission queue (SQ) and completion queue (CQ) of an io_uring instance.
//!
//! Work is submitted via [Handle], which pushes [Request]s into an MPSC queue and signals
//! an internal wake source. The event loop blocks either in userspace futex wait
//! (when the ring is truly idle) or in `io_uring_enter` (when the ring has active
//! waiters), and is woken by:
//! - normal CQE progress in the ring
//! - futex wake when new work is queued while fully idle
//! - `eventfd` readiness when new work is queued or all submitters are dropped while
//!   blocked in `submit_and_wait`
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
//! 1. Drains logical requests from a bounded MPSC channel fed by [Handle]
//! 2. Admits requests into the waiter table and submits their first SQE
//! 3. Processes io_uring completion queue entries (CQEs), including internal wake CQEs
//! 4. Handles partial progress and retryable errors by requeuing requests
//! 5. Routes typed completion results back to the original requesters via oneshot channels
//!
//! ## Request Flow
//!
//! ```text
//! Data path:
//!   Client task -> Handle -> bounded MPSC -> IoUringLoop -> SQE -> io_uring
//!   Client task <- typed oneshot <- IoUringLoop <- CQE <- io_uring
//!
//! Wake paths:
//!   Handle --futex wake--> packed wake state --> IoUringLoop
//!   Handle --write(eventfd)--> wake_fd --POLLIN CQE (WAKE_USER_DATA)--> IoUringLoop
//!
//! Loop behavior:
//!   1) Drain CQEs.
//!   2) Advance timeouts.
//!   3) Rarely rearm wake polling, then stage cancels, ready-queue requests,
//!      and new inbound requests into SQ.
//!   4) If work is pending or active waiters remain, submit and possibly block in
//!      io_uring_enter until a CQE (data or wake) arrives.
//!   5) If the ring is fully idle, arm the shared wake word and sleep in futex
//!      wait until a producer publishes work or latches an out-of-band wake.
//! ```
//!
//! ## Work Tracking
//!
//! Each admitted request is assigned a waiter id that serves as the `user_data` field in its
//! SQEs. The event loop maintains a flat `Waiters` store where each slot maps to an
//! [Request] that owns all resources (buffers, FDs, progress state, completion sender)
//! needed for the request's lifetime.
//!
//! ## Timeout Handling
//!
//! Requests can optionally carry an absolute deadline. When present:
//! - The loop tracks deadline ticks in a userspace timing wheel
//! - Already-expired requests complete immediately with timeout before SQE submission
//! - Requests that still have an SQE in flight submit an async-cancel SQE on expiry
//! - Requests parked only in the ready queue time out locally without staging cancel SQEs
//! - Timeouts apply to the whole logical request, not individual SQEs
//! - If the original op CQE completes the whole request, the caller sees success
//! - If the original op CQE only makes partial/retryable progress after timeout, the caller
//!   sees timeout and no follow-up SQE is issued
//!
//! ## Submission Policy
//!
//! A logical request may need multiple SQEs before it completes. The loop keeps
//! such requests on a FIFO ready queue and stages work in this order:
//! 1. Rarely, a wake poll rearm SQE when a prior multishot wake CQE ended the
//!    existing poll registration.
//! 2. Cancellation SQEs for timed-out requests.
//! 3. Ready-queue requests that were already admitted and need another SQE.
//! 4. Fresh requests drained from the channel, until waiter or SQ capacity is hit.
//!
//! During shutdown, there is no new channel work, so the drain phase continues
//! servicing cancellations and the ready queue until requests complete, time
//! out, or are abandoned by `shutdown_timeout`.
//!
//! ## Wake Handling
//!
//! The wake path uses one shared atomic state word plus an internal `eventfd`.
//! - [Handle::enqueue] increments an atomic submission sequence
//! - When the loop has no waiters, it sleeps in futex wait on that shared word
//! - When the loop blocks in `submit_and_wait`, it keeps a multishot `PollAdd`
//!   on the internal `eventfd`
//! - Wake CQEs drain `eventfd` readiness and re-install poll when `IORING_CQE_F_MORE`
//!   is not set
//! - The loop uses an arm-and-recheck sleep handshake (`submitted_seq` vs `processed_seq`)
//! - A dedicated signalled bit coalesces repeated wake attempts while a wait is armed
//!
//! ## Shutdown Process
//!
//! When the request channel closes, the event loop enters a drain phase:
//! 1. Stops accepting new requests
//! 2. Waits for all in-flight requests to complete or be cancelled
//! 3. If `shutdown_timeout` is configured, abandons remaining requests after the timeout
//! 4. Cleans up and exits. Dropping the last submitter latches one wake and, if a
//!    target is currently armed, signals it immediately so shutdown is observed
//!    promptly whether the loop is already blocked or about to sleep.
//!
//! ## Liveness Model
//!
//! This loop enforces a configured upper bound on in-flight requests. New submissions arrive
//! through a FIFO MPSC queue, but already-admitted requests may be restaged ahead of that queue
//! according to the submission policy above.
//!
//! This implies a bounded-liveness caveat: if all in-flight requests are waiting on operations
//! that are still queued behind the capacity limit, the loop cannot make progress until some
//! in-flight request completes or is canceled.
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
//! requests, so it cannot implement dependency-aware admission (and doing so generically would
//! add substantial overhead).
//!
//! The practical way to recover from this condition is cancellation via per-request timeouts.
//! When timed-out in-flight requests are canceled, waiter capacity is eventually released and
//! queued requests can be staged. Without cancellation, liveness depends on workload structure:
//! callers must avoid submission patterns where in-flight requests require later queued requests
//! to run.
//!
//! Operational guidance:
//! - Workloads that may create causal dependencies across queued and in-flight requests must use
//!   per-request timeouts.
//! - If cancellation is disabled, callers must guarantee that in-flight requests never depend on
//!   later queued requests, otherwise the loop can deadlock.

use crate::{Error, IoBufMut, IoBufs};
use commonware_utils::channel::{
    mpsc::{self, error::TryRecvError},
    oneshot,
};
use io_uring::{
    cqueue::Entry as CqueueEntry,
    opcode::AsyncCancel,
    squeue::SubmissionQueue,
    types::{SubmitArgs, Timespec},
    IoUring,
};
use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use request::{ReadAtRequest, RecvRequest, Request, SendRequest, SyncRequest, WriteAtRequest};
use std::{
    collections::VecDeque,
    fs::File,
    os::fd::OwnedFd,
    sync::Arc,
    time::{Duration, Instant},
};

mod request;
mod timeout;
use timeout::{Tick, TimeoutWheel};
mod waiter;
use waiter::{CompletionOutcome, StageOutcome, WaiterId, Waiters};
mod waker;
use waker::{Waker, SUBMISSION_SEQ_MASK, WAKE_USER_DATA};

/// Packed `io_uring` `user_data` value.
type UserData = u64;

/// Tracks io_uring metrics.
#[derive(Debug)]
pub struct Metrics {
    /// Number of active logical requests whose CQEs haven't yet been fully
    /// processed. Note this metric doesn't include timeouts, which are
    /// generated internally by the io_uring event loop.
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
            "Number of active logical requests in the io_uring loop",
            metrics.pending_operations.clone(),
        );
        metrics
    }
}

/// Configuration for an io_uring instance.
/// See `man io_uring`.
#[derive(Clone, Debug)]
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
    /// Maximum request timeout supported by the userspace timeout wheel.
    ///
    /// Deadlines are clamped to this horizon. This value should be set to the
    /// largest expected per-request deadline budget.
    pub max_request_timeout: Duration,
    /// The maximum time the io_uring event loop will wait for in-flight requests
    /// to complete before abandoning them during shutdown.
    /// If None, the event loop will wait indefinitely for in-flight requests
    /// to complete before shutting down. In this case, the caller should be careful
    /// to ensure that the requests submitted to the io_uring will eventually complete.
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
            max_request_timeout: Duration::from_secs(60),
            shutdown_timeout: None,
            timeout_wheel_tick: Duration::from_millis(5),
        }
    }
}

struct HandleInner {
    sender: Option<mpsc::Sender<Request>>,
    waker: Waker,
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        // Disconnect first, then wake. This avoids a race where the loop
        // handles a wake CQE before channel closure becomes observable.
        drop(self.sender.take());

        // Wake the loop so shutdown observes disconnect promptly. This is an
        // out-of-band wake for channel closure, so do not publish a synthetic
        // submission sequence increment.
        self.waker.wake();
    }
}

/// Handle for submitting requests to an [IoUringLoop].
#[derive(Clone)]
pub struct Handle {
    inner: Arc<HandleInner>,
}

impl Handle {
    /// Enqueue a request for the io_uring loop.
    ///
    /// On success, this publishes one submission and conditionally wakes the
    /// loop if a futex or eventfd wait target is currently armed.
    async fn enqueue(&self, request: Request) -> Result<(), mpsc::error::SendError<Request>> {
        self.inner
            .sender
            .as_ref()
            .expect("handle sender is only taken on drop")
            .send(request)
            .await?;

        // Publish submission and wake the armed wait target, if any.
        self.inner.waker.publish();

        Ok(())
    }

    /// Submit a logical send request and wait for its completion.
    #[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
    pub async fn send(
        &self,
        fd: Arc<OwnedFd>,
        bufs: IoBufs,
        deadline: Instant,
    ) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(Request::Send(SendRequest {
            fd,
            write: bufs.into(),
            deadline: Some(deadline),
            result: None,
            sender: tx,
        }))
        .await
        .map_err(|_| Error::SendFailed)?;
        rx.await.map_err(|_| Error::SendFailed)?
    }

    /// Submit a logical recv request and wait for its completion.
    #[cfg_attr(not(feature = "iouring-network"), allow(dead_code))]
    pub async fn recv(
        &self,
        fd: Arc<OwnedFd>,
        buf: IoBufMut,
        offset: usize,
        len: usize,
        exact: bool,
        deadline: Instant,
    ) -> Result<(IoBufMut, usize), (IoBufMut, Error)> {
        assert!(
            offset <= len && len <= buf.capacity(),
            "recv invariant violated: need offset <= len <= capacity"
        );
        let (tx, rx) = oneshot::channel();
        let request = Request::Recv(RecvRequest {
            fd,
            buf,
            offset,
            len,
            exact,
            deadline: Some(deadline),
            result: None,
            sender: tx,
        });
        if let Err(err) = self.enqueue(request).await {
            let Request::Recv(request) = err.0 else {
                unreachable!("recv enqueue returned wrong request variant");
            };
            return Err((request.buf, Error::RecvFailed));
        }

        rx.await.unwrap_or_else(|_| {
            // Once the request is admitted, ownership of `buf` moves into the
            // loop. If the loop dies before replying, there is no owned buffer
            // left to recover here, so return an empty placeholder.
            Err((IoBufMut::default(), Error::RecvFailed))
        })
    }

    /// Submit a logical positioned read request and wait for its completion.
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    pub async fn read_at(
        &self,
        file: Arc<File>,
        offset: u64,
        len: usize,
        buf: IoBufMut,
    ) -> Result<IoBufMut, (IoBufMut, Error)> {
        assert!(len <= buf.capacity(), "read_at len exceeds buffer capacity");
        let (tx, rx) = oneshot::channel();
        let request = Request::ReadAt(ReadAtRequest {
            file,
            offset,
            len,
            read: 0,
            buf,
            result: None,
            sender: tx,
        });
        if let Err(err) = self.enqueue(request).await {
            let Request::ReadAt(request) = err.0 else {
                unreachable!("read_at enqueue returned wrong request variant");
            };
            return Err((request.buf, Error::ReadFailed));
        }

        rx.await.unwrap_or_else(|_| {
            // Once the request is admitted, ownership of `buf` moves into the
            // loop. If the loop dies before replying, there is no owned buffer
            // left to recover here, so return an empty placeholder.
            Err((IoBufMut::default(), Error::ReadFailed))
        })
    }

    /// Submit a logical positioned write request and wait for its completion.
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    pub async fn write_at(&self, file: Arc<File>, offset: u64, bufs: IoBufs) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(Request::WriteAt(WriteAtRequest {
            file,
            offset,
            written: 0,
            write: bufs.into(),
            result: None,
            sender: tx,
        }))
        .await
        .map_err(|_| Error::WriteFailed)?;
        rx.await.map_err(|_| Error::WriteFailed)?
    }

    /// Submit a logical fsync request and wait for its completion.
    #[cfg_attr(not(feature = "iouring-storage"), allow(dead_code))]
    pub async fn sync(&self, file: Arc<File>) -> std::io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(Request::Sync(SyncRequest {
            file,
            result: None,
            sender: tx,
        }))
        .await
        .map_err(|_| std::io::Error::other("failed to send work"))?;
        rx.await
            .map_err(|_| std::io::Error::other("failed to read result"))?
    }
}

/// io_uring event loop state.
pub(crate) struct IoUringLoop {
    cfg: Config,
    metrics: Arc<Metrics>,
    receiver: mpsc::Receiver<Request>,
    waiters: Waiters,
    ready_queue: VecDeque<WaiterId>,
    pending_cancels: VecDeque<WaiterId>,
    timeout_wheel: TimeoutWheel,
    waker: Waker,
    wake_rearm_needed: bool,
    processed_seq: u32,
}

impl IoUringLoop {
    /// Create a new io_uring loop and submit handle.
    ///
    /// The loop allocates its own metrics, request channel, and internal `eventfd` wake source.
    pub(crate) fn new(mut cfg: Config, registry: &mut Registry) -> (Handle, Self) {
        assert!(
            !cfg.max_request_timeout.is_zero(),
            "max_request_timeout must be non-zero for timeout wheel"
        );
        assert!(
            !cfg.timeout_wheel_tick.is_zero(),
            "timeout_wheel_tick must be non-zero for timeout wheel"
        );
        cfg.size = cfg
            .size
            .checked_next_power_of_two()
            .expect("ring size exceeds u32::MAX");
        assert!(
            cfg.size < (1 << 29),
            "rounded ring size must stay below 1<<29 to preserve the 29-bit wake sequence bound"
        );
        let size = cfg.size as usize;
        let metrics = Arc::new(Metrics::new(registry));
        let (sender, receiver) = mpsc::channel(size);
        let waker = Waker::new().expect("unable to create wake eventfd");
        let timeout_wheel = TimeoutWheel::new(
            cfg.max_request_timeout,
            cfg.timeout_wheel_tick,
            Instant::now(),
        );
        let waiters = Waiters::new(size);

        let handle = Handle {
            inner: Arc::new(HandleInner {
                sender: Some(sender),
                waker: waker.clone(),
            }),
        };

        (
            handle,
            Self {
                cfg,
                metrics,
                receiver,
                waiters,
                ready_queue: VecDeque::with_capacity(size),
                pending_cancels: VecDeque::with_capacity(size),
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
        loop {
            // Process available completions.
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            // Process due deadlines before staging new submissions so timed-out
            // requests move to cancellation promptly and free capacity sooner.
            self.advance_timeouts();

            // Stage as much inbound work as capacity allows.
            let Some(at_capacity) = self.fill_submission_queue(&mut ring) else {
                // Producer side disconnected. Drain in-flight requests and exit.
                self.drain(&mut ring);
                return;
            };

            // Update pending operations metric.
            self.metrics.pending_operations.set(self.waiters.len() as _);

            // If submissions are still pending, do not arm idle sleep.
            //
            // `pending(processed_seq)` means producers have published work we
            // have not yet drained. Sleep here could park with pending work and
            // no guaranteed wake, because publish only signals once a wait target
            // is armed.
            if self.waker.pending(self.processed_seq) {
                if at_capacity {
                    // Pending submissions exist and staging stopped at capacity.
                    //
                    // Enter the kernel to submit pending SQEs and wait for at
                    // least one completion so capacity can open up. Arm the
                    // eventfd wait so producer disconnect is still observed
                    // promptly while blocked in `submit_and_wait`.
                    let _arm = self.waker.arm(self.processed_seq);
                    self.submit_and_wait(&mut ring, 1, self.timeout_wheel.next_deadline())
                        .expect("unable to submit to ring");
                }

                continue;
            }

            // No pending submissions are currently visible.
            //
            // If the ring is truly idle, avoid `io_uring_enter` entirely and
            // wait on the shared wake state via futex until a producer changes
            // it. This bypasses the eventfd wake path when there are no active
            // waiters.
            if self.waiters.is_empty() {
                self.waker.park_idle(self.processed_seq);
                continue;
            }

            // Otherwise, active waiters remain in the ring, so sleep by
            // blocking in `submit_and_wait`.
            //
            // If staging hit capacity, force a submit-and-wait cycle to open
            // space, even though the sequence snapshot looks idle here.
            //
            // Otherwise, arm the blocking wake path. If the post-arm snapshot
            // still looks idle, we may enter `submit_and_wait`. Any submission
            // that arrives after `arm()` observes the wait target and rings
            // eventfd, so the loop is woken instead of sleeping through newly
            // published work.
            let arm = self.waker.arm(self.processed_seq);
            if at_capacity || arm.should_block() {
                self.submit_and_wait(&mut ring, 1, self.timeout_wheel.next_deadline())
                    .expect("unable to submit to ring");
            }
        }
    }

    /// Admit a request into the waiter table and schedule its timeout.
    ///
    /// Returns the waiter id if the request was admitted, or `None` if the
    /// deadline already expired (in which case the request is completed
    /// immediately with a timeout error).
    fn admit_request(&mut self, request: Request) -> Option<WaiterId> {
        let deadline = request.deadline();
        let target_tick = match deadline {
            Some(deadline) => match self.timeout_wheel.target_tick(deadline) {
                Some(target_tick) => Some(target_tick),
                None => {
                    request.timeout();
                    return None;
                }
            },
            None => None,
        };

        let waiter_id = self.waiters.insert(request, target_tick);
        if let Some(target_tick) = target_tick {
            self.timeout_wheel.schedule(waiter_id, target_tick);
        }

        Some(waiter_id)
    }

    /// Build and push the SQE for a request in the waiter table.
    ///
    /// If the request was marked for cancellation while sitting in the ready
    /// queue (timeout fired between requeue and staging), it is completed with
    /// a timeout error instead of issuing a follow-up SQE. If the original
    /// caller dropped its wait handle before staging, the request is retired
    /// locally without issuing another SQE.
    fn stage_request(&mut self, waiter_id: WaiterId, submission_queue: &mut SubmissionQueue<'_>) {
        match self.waiters.stage(waiter_id) {
            StageOutcome::Timeout(request) => request.timeout(),
            StageOutcome::Orphaned { target_tick } => {
                // The caller disappeared before another SQE was issued, so all that
                // remains is to release deadline tracking (the waiter, and associated
                // resources, were already dropped inside `Waiters`).
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
            }
            StageOutcome::Submit(sqe) => {
                // SAFETY:
                // - All resources are stored in `self.waiters` until CQE processing, so
                //   SQE pointers remain valid and FD numbers cannot be reused early.
                // - SQ capacity was checked by caller.
                unsafe {
                    submission_queue
                        .push(&sqe)
                        .expect("unable to push to queue");
                }
            }
        }
    }

    /// Stage requeued requests from `ready_queue` in FIFO order.
    ///
    /// Stops when all queued requests are staged or the SQ reaches capacity.
    /// Returns `true` when SQ capacity is hit and at least one ready request
    /// remains queued.
    fn stage_ready_requests(&mut self, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = self.ready_queue.pop_front() else {
                return false;
            };
            self.stage_request(waiter_id, submission_queue);
        }

        !self.ready_queue.is_empty()
    }

    /// Stage pending submission work into the SQ.
    ///
    /// In one pass, this may rearm wake polling, stage cancellations, restage
    /// ready-queue requests, and admit new requests.
    ///
    /// Advances `processed_seq` by exactly the number of drained submissions.
    ///
    /// Returns whether staging ended at waiter or SQ capacity, or `None` if the
    /// producer channel disconnected.
    fn fill_submission_queue(&mut self, ring: &mut IoUring) -> Option<bool> {
        let mut drained = 0u32;
        let mut submission_queue = ring.submission();
        let mut wheel_aligned = self.timeout_wheel.next_deadline().is_some();

        // Reinstall wake poll only when a prior wake CQE indicated multishot
        // termination. Otherwise keep the existing poll registration.
        if std::mem::take(&mut self.wake_rearm_needed) {
            self.waker.reinstall(&mut submission_queue);
        }

        // Stage pending cancel SQEs first so timed-out requests are canceled promptly.
        if self.stage_cancellations(&mut submission_queue) {
            // If cancels alone filled the SQ, submit them first.
            return Some(true);
        }

        // Requeued work already owns waiter capacity, so restage it before
        // admitting fresh channel requests.
        if self.stage_ready_requests(&mut submission_queue) {
            return Some(true);
        }

        // Stage operations until the channel is empty, waiter capacity is hit,
        // or the SQ is full. Waiter capacity is bounded by `cfg.size`.
        while self.waiters.len() < self.cfg.size as usize && !submission_queue.is_full() {
            // Try to drain one operation from the channel. If the channel is empty, we're
            // done for now.
            let request = match self.receiver.try_recv() {
                Ok(request) => request,
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => break,
            };

            // Count exactly how many published submissions we consumed so
            // `processed_seq` stays in sync with the published sequence domain.
            drained += 1;

            // Avoid per-loop clock reads when no deadlines are active. When the
            // first deadline arrives after an idle period, align wheel time once
            // before converting deadlines to ticks.
            if !wheel_aligned && request.has_deadline() {
                assert!(self.timeout_wheel.advance(Instant::now()).is_none());
                wheel_aligned = true;
            }

            if let Some(waiter_id) = self.admit_request(request) {
                self.stage_request(waiter_id, &mut submission_queue);
            }
        }

        // Track which submitted sequence has been consumed.
        self.processed_seq = self.processed_seq.wrapping_add(drained) & SUBMISSION_SEQ_MASK;

        let at_sq_capacity = submission_queue.is_full();
        let at_waiter_capacity = self.waiters.len() == self.cfg.size as usize;
        Some(at_sq_capacity || at_waiter_capacity)
    }

    /// Stage queued cancellation SQEs from `pending_cancels` in FIFO order.
    ///
    /// Stops when all queued cancellations are staged or the SQ reaches
    /// capacity. Returns `true` when SQ capacity is hit and at least one
    /// cancellation remains queued.
    fn stage_cancellations(&mut self, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = self.pending_cancels.pop_front() else {
                return false;
            };

            // This waiter timed out earlier, but its queued cancel may have
            // gone stale before we got around to staging it. If the original
            // op CQE already retired the outstanding SQE, there is nothing
            // left for the kernel to cancel.
            if !self.waiters.is_in_flight(waiter_id) {
                continue;
            }

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

        !self.pending_cancels.is_empty()
    }

    /// Handle a single CQE from the ring.
    ///
    /// Internal wake CQEs are handled in-place. All other CQEs are forwarded to
    /// the request state machine for progress evaluation.
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

        match self.waiters.on_completion(user_data, cqe.result()) {
            CompletionOutcome::Cancel => {
                // Async-cancel CQEs are handled entirely inside `Waiters` they do
                // not directly complete or requeue a logical request here.
            }
            CompletionOutcome::Requeue(waiter_id) => {
                // Request needs another SQE. Add it to the ready queue.
                self.ready_queue.push_back(waiter_id);
            }
            CompletionOutcome::Complete {
                request,
                target_tick,
            } => {
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
                request.complete();
            }
        }
    }

    /// Advance the timeout wheel and enqueue cancellations for newly expired requests.
    ///
    /// This is a no-op when no active deadlines exist. Expired stale wheel
    /// entries are ignored when waiter generation no longer matches.
    fn advance_timeouts(&mut self) {
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
            // `false` means stale timeout entry (slot reused) or waiter already
            // transitioned to cancel-requested/completed.
            if self.waiters.cancel(entry.waiter_id) {
                // Once cancel is requested, this waiter is no longer deadline-active.
                self.timeout_wheel.remove(entry.target_tick);
                // Only timed-out waiters with an outstanding op SQE need
                // AsyncCancel. Waiters parked in the ready queue have no
                // kernel op to cancel and will time out locally when restaged.
                if self.waiters.is_in_flight(entry.waiter_id) {
                    self.pending_cancels.push_back(entry.waiter_id);
                }
            }
        }
    }

    /// Drain in-flight requests during shutdown.
    ///
    /// Keeps draining CQEs until all waiters complete or shutdown budget is
    /// exhausted.
    ///
    /// If `shutdown_timeout` is `None`, this waits until all waiters complete or are cancelled.
    /// If `shutdown_timeout` is `Some`, this waits until completion or timeout,
    /// then abandons any remaining waiters.
    fn drain(&mut self, ring: &mut IoUring) {
        let mut remaining = self.cfg.shutdown_timeout;

        // Keep driving completions until all in-flight waiters finish or the
        // shutdown budget is exhausted.
        loop {
            // Always drain CQEs first, even after a timed wait: completions can
            // race with timeout expiry and still be pending in the queue.
            for cqe in ring.completion() {
                self.handle_cqe(cqe);
            }

            // CQE draining can finish the last waiter, so stop before another
            // submit-and-wait cycle.
            if self.waiters.is_empty() {
                break;
            }

            // Once shutdown budget is exhausted, abandon any remaining waiters
            // immediately instead of advancing more deadlines or staging new cancels.
            if remaining.is_some_and(|t| t.is_zero()) {
                break;
            }

            // Keep userspace deadline processing alive during shutdown so
            // in-flight timed operations preserve their ETIMEDOUT semantics,
            // and continue staging requeued requests so partially-complete or
            // retrying requests can keep making progress.
            self.advance_timeouts();
            {
                let mut submission_queue = ring.submission();
                self.stage_cancellations(&mut submission_queue);
                self.stage_ready_requests(&mut submission_queue);
            }

            // Staging can directly complete the last waiter (for example, when a
            // timed-out requeued request is removed instead of reissued).
            if self.waiters.is_empty() {
                break;
            }

            let timeout = match (remaining, self.timeout_wheel.next_deadline()) {
                (Some(remaining), Some(deadline)) => Some(remaining.min(deadline)),
                (Some(remaining), None) => Some(remaining),
                (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            };

            // Wait for at least one completion or timeout.
            let start = Instant::now();
            self.submit_and_wait(ring, 1, timeout)
                .expect("unable to submit to ring");

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IoBuf, IoBufMut};
    use commonware_utils::channel::oneshot::{self, error::RecvError};
    use futures::future::{join, join_all};
    use prometheus_client::registry::Registry;
    use request::{RecvRequest, SendRequest, SyncRequest};
    use std::{
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd, IntoRawFd},
            unix::net::UnixStream,
        },
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
    #[should_panic(expected = "rounded ring size must stay below 1<<29")]
    fn test_iouring_loop_rejects_sizes_that_exceed_wake_sequence_domain() {
        // The wake state reserves only 29 bits for the submission sequence, so
        // the bounded request channel must stay strictly below that domain even
        // after ring-size round-up.
        let mut registry = Registry::default();
        let cfg = Config {
            size: (1 << 28) + 1,
            ..Default::default()
        };
        let _ = IoUringLoop::new(cfg, &mut registry);
    }

    #[test]
    fn test_submit_and_wait_non_etime_error_is_not_misclassified() {
        // Verify `submit_and_wait` only treats `ETIME` as the bounded-wait timeout case.
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
    fn test_new_ring_iopoll_builder_path_is_exercised() {
        // Verify the optional IOPOLL builder branch is reachable even on hosts
        // where the kernel rejects the resulting configuration.
        let cfg = Config {
            io_poll: true,
            ..Default::default()
        };

        match new_ring(&cfg) {
            Ok(_ring) => {}
            Err(err) => assert!(err.raw_os_error().is_some()),
        }
    }

    #[test]
    fn test_fill_submission_queue_returns_true_when_cancel_staging_fills_sq() {
        // Verify cancel staging reports SQ saturation so the loop drains completions
        // before trying to enqueue more work.
        let cfg = Config {
            size: 8,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Queue enough in-flight cancellations to overflow one staging pass once
        // wake poll rearm also consumes an SQE.
        for _ in 0..cfg.size as usize {
            let (sock_left, _sock_right) =
                UnixStream::pair().expect("failed to create unix socket pair");
            // SAFETY: sock_left is a valid fd that we own.
            let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
            let (tx, _rx) = oneshot::channel();
            let request = Request::Sync(SyncRequest {
                file: Arc::new(file),
                result: None,
                sender: tx,
            });
            let waiter_id = iouring.waiters.insert(request, None);
            assert!(matches!(
                iouring.waiters.stage(waiter_id),
                StageOutcome::Submit(_)
            ));
            assert!(
                iouring.waiters.cancel(waiter_id),
                "cancel should transition waiter to cancel-requested"
            );
            iouring.pending_cancels.push_back(waiter_id);
        }

        // Staging should stop at SQ capacity and leave some cancels queued.
        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");
        assert!(at_capacity);
        assert!(!iouring.pending_cancels.is_empty());
    }

    #[test]
    fn test_fill_submission_queue_returns_true_when_ready_staging_fills_sq() {
        // Verify requeued work can also saturate the SQ and force the loop to
        // return early with ready-queue work still pending.
        let cfg = Config {
            size: 8,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Leave wake rearm enabled so the wake poll consumes one SQE and the
        // ready queue cannot fully drain in a single staging pass.
        for _ in 0..cfg.size as usize {
            let (sock_left, _sock_right) =
                UnixStream::pair().expect("failed to create unix socket pair");
            // SAFETY: sock_left is a valid fd that we own.
            let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
            let (tx, _rx) = oneshot::channel();
            let request = Request::Sync(SyncRequest {
                file: Arc::new(file),
                result: None,
                sender: tx,
            });
            let waiter_id = iouring.waiters.insert(request, None);
            iouring.ready_queue.push_back(waiter_id);
        }

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        assert!(at_capacity);
        assert!(!iouring.ready_queue.is_empty());
    }

    #[test]
    fn test_fill_submission_queue_returns_true_when_fresh_staging_fills_sq() {
        // Verify newly submitted work can fill the SQ before waiter capacity is exhausted.
        let cfg = Config {
            size: 8,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Leave wake rearm enabled so it consumes one SQE up front. The fresh
        // request staging loop should then stop because the SQ fills first,
        // while waiter capacity still has room left.
        futures::executor::block_on(async {
            for _ in 0..cfg.size as usize {
                let (sock_left, _sock_right) =
                    UnixStream::pair().expect("failed to create unix socket pair");
                // SAFETY: sock_left is a valid fd that we own.
                let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
                let (tx, _rx) = oneshot::channel();
                submitter
                    .enqueue(Request::Sync(SyncRequest {
                        file: Arc::new(file),
                        result: None,
                        sender: tx,
                    }))
                    .await
                    .expect("failed to enqueue request");
            }
        });

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        assert!(at_capacity);
        assert!(ring.submission().is_full());
        assert!(iouring.waiters.len() < cfg.size as usize);
    }

    #[test]
    fn test_fill_submission_queue_skips_cancel_for_ready_queue_timeout() {
        // Verify pending cancel entries are discarded once the waiter no longer
        // has an operation SQE in flight.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Keep the test focused on cancel staging instead of wake rearm.
        iouring.wake_rearm_needed = false;

        // Insert a waiter that is already marked cancel-requested but was never
        // staged, matching the "timed out while parked in ready_queue" shape.
        let (sock_left, _sock_right) =
            UnixStream::pair().expect("failed to create unix socket pair");
        // SAFETY: sock_left is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (tx, _rx) = oneshot::channel();
        let request = Request::Sync(SyncRequest {
            file: Arc::new(file),
            result: None,
            sender: tx,
        });
        let waiter_id = iouring.waiters.insert(request, None);
        assert!(iouring.waiters.cancel(waiter_id));
        iouring.pending_cancels.push_back(waiter_id);

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        // No cancel SQE should be staged because there is no in-flight op left to cancel.
        assert!(!at_capacity);
        assert!(iouring.pending_cancels.is_empty());
        assert_eq!(ring.submission().len(), 0);
        assert!(matches!(
            iouring.waiters.stage(waiter_id),
            StageOutcome::Timeout(_)
        ));
    }

    #[tokio::test]
    async fn test_fill_submission_queue_expired_deadline_completes_immediately() {
        // Verify already-expired requests are completed locally instead of being staged.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Keep this test focused on request staging, not wake rearm behavior.
        iouring.wake_rearm_needed = false;

        let (tx, rx) = oneshot::channel();
        let past_deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        submitter
            .enqueue(Request::Send(SendRequest {
                // SAFETY: pair() returns valid fds; we own the left end.
                fd: Arc::new(UnixStream::pair().unwrap().0.into()),
                write: IoBufs::from(IoBuf::from(b"hello")).into(),
                deadline: Some(past_deadline),
                result: None,
                sender: tx,
            }))
            .await
            .expect("failed to enqueue request");

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        assert!(!at_capacity);
        assert!(iouring.pending_cancels.is_empty());
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);

        let result = rx.await.expect("missing timeout completion");
        assert!(matches!(result, Err(crate::Error::Timeout)));
    }

    #[test]
    fn test_handle_recv_panics_on_invalid_buffer_bounds() {
        // Verify the public recv helper rejects impossible offset/len shapes
        // before it can enqueue a malformed request.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (handle, io_loop) = IoUringLoop::new(cfg, &mut registry);
        drop(io_loop);

        let offset_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (left, _right) = UnixStream::pair().unwrap();
            let _ = futures::executor::block_on(handle.recv(
                Arc::new(left.into()),
                IoBufMut::with_capacity(4),
                5,
                4,
                true,
                Instant::now() + Duration::from_secs(1),
            ));
        }));
        assert!(offset_panic.is_err());

        let capacity_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (left, _right) = UnixStream::pair().unwrap();
            let _ = futures::executor::block_on(handle.recv(
                Arc::new(left.into()),
                IoBufMut::with_capacity(4),
                0,
                5,
                true,
                Instant::now() + Duration::from_secs(1),
            ));
        }));
        assert!(capacity_panic.is_err());
    }

    #[tokio::test]
    async fn test_timeout_slot_reuse_does_not_cancel_new_waiter_early() {
        // Verify stale timeout-wheel entries from an earlier generation do not
        // cancel a newly inserted waiter that reused the same slot.
        let cfg = Config {
            // Keep ring size realistic; size=1 can deadlock progress in some setups.
            // Waiter slot reuse is still exercised because we complete op1 before op2.
            size: 8,
            max_request_timeout: Duration::from_millis(200),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // First operation completes quickly but still carries a generous deadline,
        // leaving a stale timeout entry that should be ignored later after slot reuse.
        let (left1, right1) = UnixStream::pair().unwrap();
        // Write a byte so the recv completes immediately.
        (&right1).write_all(&[42]).unwrap();

        let (_buf1, read1) = submitter
            .recv(
                Arc::new(left1.into()),
                IoBufMut::with_capacity(1),
                0,
                1,
                false,
                Instant::now() + Duration::from_millis(200),
            )
            .await
            .expect("first recv should succeed");
        assert!(read1 > 0);

        // Second request reuses the slot and blocks until timeout.
        let (left2, _right2) = UnixStream::pair().expect("failed to create unix stream pair");
        let start = Instant::now();
        let result2 = submitter
            .recv(
                Arc::new(left2.into()),
                IoBufMut::with_capacity(8),
                0,
                8,
                false,
                Instant::now() + Duration::from_millis(80),
            )
            .await;
        let elapsed = start.elapsed();
        assert!(matches!(result2, Err((_, crate::Error::Timeout))));
        assert!(
            elapsed >= Duration::from_millis(50),
            "timeout fired too early after slot reuse: {elapsed:?}"
        );

        drop(submitter);
        handle.join().expect("io_uring loop thread panicked");
    }

    #[test]
    fn test_stage_request_panics_on_stale_ready_queue_entry() {
        // A stale ready-queue id should be treated as an internal logic error:
        // once a waiter is queued for restaging, no production path should
        // remove and reuse that slot before the queue entry is revisited.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Create and complete one waiter so the ready queue can later point at
        // a stale generation.
        let (sock_left, _sock_right) = UnixStream::pair().unwrap();
        // SAFETY: sock_left is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (tx, _rx) = oneshot::channel();
        let stale = iouring.waiters.insert(
            Request::Sync(SyncRequest {
                file: Arc::new(file),
                result: None,
                sender: tx,
            }),
            None,
        );
        assert!(matches!(
            iouring.waiters.stage(stale),
            StageOutcome::Submit(_)
        ));
        match iouring.waiters.on_completion(stale.user_data(), 0) {
            CompletionOutcome::Complete { request, .. } => request.complete(),
            _ => panic!("sync waiter should complete immediately"),
        }

        // Reuse the same slot with a new generation to prove `stage_request`
        // matches on the full waiter id, not just the slot index.
        let (sock_left, _sock_right) = UnixStream::pair().unwrap();
        // SAFETY: sock_left is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (tx, _rx) = oneshot::channel();
        let reused = iouring.waiters.insert(
            Request::Sync(SyncRequest {
                file: Arc::new(file),
                result: None,
                sender: tx,
            }),
            None,
        );
        assert_eq!(reused.index(), stale.index());
        assert_ne!(reused, stale);

        let stale_ready = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sq = ring.submission();
            iouring.stage_request(stale, &mut sq);
        }));
        assert!(stale_ready.is_err());
        assert!(!iouring.waiters.is_in_flight(reused));
    }

    #[test]
    fn test_advance_timeouts_ignores_stale_entry_after_slot_reuse() {
        // Verify timeout-wheel advancement ignores stale entries from a reused waiter slot.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg, &mut registry);

        // Schedule an old waiter at tick 1, then complete it early so the wheel
        // retains a stale entry for this slot/tick pair.
        let (sock_left, _) = UnixStream::pair().unwrap();
        // SAFETY: sock_left is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (old_tx, _old_rx) = oneshot::channel();
        let old_req = Request::Sync(SyncRequest {
            file: Arc::new(file),
            result: None,
            sender: old_tx,
        });
        let old_slot = iouring.waiters.insert(old_req, Some(1));
        iouring.timeout_wheel.schedule(old_slot, 1);
        // Simulate completion after the waiter had an op staged.
        assert!(matches!(
            iouring.waiters.stage(old_slot),
            StageOutcome::Submit(_)
        ));
        if let CompletionOutcome::Complete {
            request,
            target_tick: Some(tick),
        } = iouring.waiters.on_completion(old_slot.user_data(), 0)
        {
            iouring.timeout_wheel.remove(tick);
            request.complete();
        }

        // Reuse the same slot for a new waiter with a later timeout.
        let (sock_left2, _) = UnixStream::pair().unwrap();
        // SAFETY: sock_left2 is a valid fd that we own.
        let file2 = unsafe { std::fs::File::from_raw_fd(sock_left2.into_raw_fd()) };
        let (tx, _rx) = oneshot::channel();
        let req = Request::Sync(SyncRequest {
            file: Arc::new(file2),
            result: None,
            sender: tx,
        });
        let slot_index = iouring.waiters.insert(req, Some(3));
        assert_eq!(slot_index.index(), old_slot.index());
        assert!(matches!(
            iouring.waiters.stage(slot_index),
            StageOutcome::Submit(_)
        ));
        iouring.timeout_wheel.schedule(slot_index, 3);

        // At tick 1, only the stale old entry should expire. The new waiter must
        // stay active and no cancel should be queued.
        std::thread::sleep(iouring.cfg.timeout_wheel_tick + Duration::from_millis(2));
        iouring.advance_timeouts();
        assert!(iouring.pending_cancels.is_empty());

        // At tick 3, the real timeout should queue cancellation.
        std::thread::sleep((iouring.cfg.timeout_wheel_tick * 2) + Duration::from_millis(2));
        iouring.advance_timeouts();
        assert_eq!(iouring.pending_cancels.len(), 1);
    }

    #[test]
    fn test_cancel_completion_returns_saved_op_result() {
        // Verify a successful operation CQE still wins if it races with a timeout cancel.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg, &mut registry);

        let (left, right) = UnixStream::pair().unwrap();
        // Write data so a recv would succeed.
        (&right).write_all(b"hello").unwrap();

        let (tx, rx) = oneshot::channel();
        let req = Request::Recv(RecvRequest {
            fd: Arc::new(left.into()),
            buf: IoBufMut::with_capacity(5),
            offset: 0,
            len: 5,
            exact: false,
            deadline: Some(Instant::now() + Duration::from_secs(1)),
            result: None,
            sender: tx,
        });
        let slot_index = iouring.waiters.insert(req, Some(2));
        assert!(matches!(
            iouring.waiters.stage(slot_index),
            StageOutcome::Submit(_)
        ));
        assert!(
            iouring.waiters.cancel(slot_index),
            "cancel should transition active waiter"
        );
        iouring.timeout_wheel.schedule(slot_index, 2);
        iouring.timeout_wheel.remove(2);

        // Simulate op CQE arriving with positive result (5 bytes read).
        // Even though cancel was requested, a complete positive result wins.
        if let CompletionOutcome::Complete { request, .. } =
            iouring.waiters.on_completion(slot_index.user_data(), 5)
        {
            request.complete();
        }

        // Late cancel CQE should be ignored.
        assert!(matches!(
            iouring
                .waiters
                .on_completion(slot_index.cancel_user_data(), -libc::ECANCELED),
            CompletionOutcome::Cancel
        ));

        let (_, result) = futures::executor::block_on(rx)
            .expect("missing completion")
            .expect("recv should succeed");
        // exact=false recv with 5 bytes should succeed.
        assert_eq!(result, 5);
        assert_eq!(iouring.waiters.len(), 0);
    }

    #[test]
    fn test_staged_cancel_cqe_is_ignored_after_timeout_completion() {
        // Drive the "cancel SQE already staged" race explicitly:
        //
        // 1. Stage an exact recv with a deadline and register it with the wheel.
        // 2. Advance time so the waiter becomes cancel-requested and queues an
        //    AsyncCancel.
        // 3. Stage that cancel SQE into the ring, but do not complete it yet.
        // 4. Deliver a partial op CQE after cancellation was requested. For an
        //    exact recv, that must complete locally as Timeout instead of
        //    requeueing.
        // 5. Finally, deliver the late cancel CQE and confirm it is ignored
        //    because the waiter was already removed by step 4.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(100),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        let (left, _right) = UnixStream::pair().unwrap();
        let (tx, rx) = oneshot::channel();
        let req = Request::Recv(RecvRequest {
            fd: Arc::new(left.into()),
            buf: IoBufMut::with_capacity(8),
            offset: 0,
            len: 8,
            exact: true,
            deadline: Some(Instant::now() + Duration::from_millis(25)),
            result: None,
            sender: tx,
        });
        let waiter_id = iouring.waiters.insert(req, Some(1));
        assert!(matches!(
            iouring.waiters.stage(waiter_id),
            StageOutcome::Submit(_)
        ));
        iouring.timeout_wheel.schedule(waiter_id, 1);

        // Expire the deadline so the waiter transitions to cancel-requested and
        // the loop queues an AsyncCancel for the in-flight recv SQE.
        std::thread::sleep(iouring.cfg.timeout_wheel_tick + Duration::from_millis(2));
        iouring.advance_timeouts();
        assert_eq!(iouring.pending_cancels.len(), 1);

        // Stage the queued AsyncCancel. It is now in the SQ, but there is still
        // no cancel CQE, so the operation CQE can still win the race.
        {
            let mut submission_queue = ring.submission();
            assert!(!iouring.stage_cancellations(&mut submission_queue));
            assert_eq!(submission_queue.len(), 1);
        }
        assert!(iouring.pending_cancels.is_empty());

        // A partial result after cancellation was requested must complete this
        // exact recv as Timeout rather than parking it back in the ready queue.
        match iouring.waiters.on_completion(waiter_id.user_data(), 4) {
            CompletionOutcome::Complete {
                request,
                target_tick: None,
            } => request.complete(),
            _ => panic!("missing timeout completion from op CQE"),
        }

        // The cancel CQE arrives after the waiter was already removed, so it
        // should be treated as stale and ignored.
        assert!(matches!(
            iouring
                .waiters
                .on_completion(waiter_id.cancel_user_data(), -libc::ECANCELED),
            CompletionOutcome::Cancel
        ));

        assert!(matches!(
            futures::executor::block_on(rx).expect("missing completion"),
            Err((_, crate::Error::Timeout))
        ));
        assert_eq!(iouring.waiters.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_wake_path_progress_scenarios() {
        // Run both wake-path variants: one with strict success assertions and
        // one that only checks for forward progress without inspecting results.
        for should_succeed in [true, false] {
            let cfg = Config::default();
            let mut registry = Registry::default();
            let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
            let handle = std::thread::spawn(move || iouring.run());

            let (left_pipe, right_pipe) = UnixStream::pair().unwrap();

            // Submit a recv.
            let recv = submitter.recv(
                Arc::new(left_pipe.into()),
                IoBufMut::with_capacity(5),
                0,
                5,
                false,
                Instant::now() + Duration::from_secs(5),
            );
            let send = submitter.send(
                Arc::new(right_pipe.into()),
                IoBufs::from(IoBuf::from(b"hello")),
                Instant::now() + Duration::from_secs(5),
            );

            let timeout = tokio::time::timeout(Duration::from_secs(2), async {
                let (recv_result, send_result) = join(recv, send).await;
                if should_succeed {
                    let (_, read) = recv_result.expect("recv should succeed");
                    assert!(read > 0);
                    send_result.expect("send should succeed");
                } else {
                    let _ = recv_result;
                    let _ = send_result;
                }
            });
            assert!(
                timeout.await.is_ok(),
                "wake path test timed out (should_succeed={should_succeed})"
            );

            drop(submitter);
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_idle_shutdown_wakes_futex_wait() {
        // Verify dropping the last submitter wakes an otherwise idle loop that
        // is sleeping on the futex-backed idle path.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let idle_waker = iouring.waker.clone();
        let handle = std::thread::spawn(move || iouring.run());

        // Wait until the loop has armed its futex-backed idle path before
        // dropping the final submitter.
        waker::tests::wait_until_futex_armed(&idle_waker);
        drop(submitter);

        handle.join().expect("io_uring loop thread panicked");
    }

    #[tokio::test]
    async fn test_timeout() {
        // Verify a timed recv completes with timeout once its deadline expires.
        let cfg = Config {
            max_request_timeout: Duration::from_secs(1),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit a recv that will time out (because we don't write to the pipe).
        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();

        assert!(matches!(
            submitter
                .recv(
                    Arc::new(pipe_left.into()),
                    IoBufMut::with_capacity(8),
                    0,
                    8,
                    false,
                    Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err((_, crate::Error::Timeout))
        ));

        drop(submitter);
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_no_timeout() {
        // Verify shutdown waits for the last in-flight request when no cutoff is configured.
        let cfg = Config {
            shutdown_timeout: None,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit a low-level nop-equivalent: a sync on a real fd.
        let (sock_left, _) = UnixStream::pair().unwrap();
        // SAFETY: sock_left is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (tx, rx) = oneshot::channel();
        submitter
            .enqueue(Request::Sync(SyncRequest {
                file: Arc::new(file),
                result: None,
                sender: tx,
            }))
            .await
            .unwrap();

        // With `shutdown_timeout = None`, shutdown waits until all in-flight
        // requests complete. Fsync on a socket should complete quickly.
        drop(submitter);
        let result = rx.await.unwrap();
        // Socket fsync may succeed or fail, either is fine for this test.
        let _ = result;
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_no_timeout_continues_deadline_processing() {
        // Verify shutdown-without-cutoff still advances deadlines until timed requests resolve.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(250),
            timeout_wheel_tick: Duration::from_millis(5),
            shutdown_timeout: None,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let (tx, rx) = oneshot::channel();
        submitter
            .enqueue(Request::Recv(RecvRequest {
                fd: Arc::new(pipe_left.into()),
                buf: IoBufMut::with_capacity(8),
                offset: 0,
                len: 8,
                exact: false,
                deadline: Some(Instant::now() + Duration::from_millis(50)),
                result: None,
                sender: tx,
            }))
            .await
            .unwrap();

        drop(submitter);

        let result = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("deadline completion timed out");
        assert!(matches!(
            result.expect("missing deadline completion"),
            Err((_, crate::Error::Timeout))
        ));
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_timeout() {
        // Verify a bounded shutdown abandons requests that never complete.
        let cfg = Config {
            shutdown_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit a recv that will never complete (nobody writes to the pipe).
        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let (tx, rx) = oneshot::channel();
        submitter
            .enqueue(Request::Recv(RecvRequest {
                fd: Arc::new(pipe_left.into()),
                buf: IoBufMut::with_capacity(8),
                offset: 0,
                len: 8,
                exact: false,
                deadline: None,
                result: None,
                sender: tx,
            }))
            .await
            .unwrap();

        // Give the event loop a chance to enter the blocking submit and wait.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Drop submission channel to trigger shutdown.
        drop(submitter);

        // The event loop should shut down before the recv completes,
        // dropping `tx` and causing `rx` to return RecvError.
        let err = rx.await.unwrap_err();
        assert!(matches!(err, RecvError { .. }));
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_timeout_preserves_deadline_result() {
        // Verify a bounded shutdown still lets an already-expiring request report timeout
        // when the deadline wins the race against the shutdown cutoff.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(250),
            timeout_wheel_tick: Duration::from_millis(5),
            shutdown_timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let (tx, rx) = oneshot::channel();
        submitter
            .enqueue(Request::Recv(RecvRequest {
                fd: Arc::new(pipe_left.into()),
                buf: IoBufMut::with_capacity(8),
                offset: 0,
                len: 8,
                exact: false,
                deadline: Some(Instant::now() + Duration::from_millis(50)),
                result: None,
                sender: tx,
            }))
            .await
            .unwrap();

        drop(submitter);

        let result = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("deadline completion timed out");
        assert!(matches!(
            result.expect("missing deadline completion"),
            Err((_, crate::Error::Timeout))
        ));
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_timeout_abandons_timed_op_after_cutoff() {
        // Verify a bounded shutdown abandons even deadline-bearing requests
        // once the shutdown cutoff expires before the request deadline.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(750),
            timeout_wheel_tick: Duration::from_millis(5),
            shutdown_timeout: Some(Duration::from_millis(50)),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        let (pipe_left, _pipe_right) = UnixStream::pair().unwrap();
        let (tx, rx) = oneshot::channel();
        submitter
            .enqueue(Request::Recv(RecvRequest {
                fd: Arc::new(pipe_left.into()),
                buf: IoBufMut::with_capacity(8),
                offset: 0,
                len: 8,
                exact: false,
                deadline: Some(Instant::now() + Duration::from_millis(500)),
                result: None,
                sender: tx,
            }))
            .await
            .unwrap();

        // Trigger shutdown well before the request deadline so shutdown, not
        // deadline processing, is responsible for completing the test.
        // Give the loop a chance to submit the long-running op before shutdown.
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(submitter);

        // The request should be abandoned once shutdown times out, which drops
        // the oneshot sender instead of returning a logical timeout result.
        let err = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("shutdown abandonment timed out")
            .unwrap_err();
        assert!(matches!(err, RecvError { .. }));
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_deadline_timeout_ensure_enough_capacity() {
        // Verify timed requests are still drained correctly when timeout-driven
        // cancel traffic exceeds the ring's SQ capacity in a single pass.
        let cfg = Config {
            size: 8,
            max_request_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Submit more timed requests than the SQ size to force batching.
        let total = 64usize;
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut peers = Vec::with_capacity(total);
        let mut recvs = Vec::with_capacity(total);
        for _ in 0..total {
            let (left, right) = UnixStream::pair().unwrap();
            peers.push(right);
            recvs.push({
                let submitter = submitter.clone();
                async move {
                    submitter
                        .recv(
                            Arc::new(left.into()),
                            IoBufMut::with_capacity(8),
                            0,
                            8,
                            false,
                            deadline,
                        )
                        .await
                }
            });
        }

        // All requests should complete with timeout rather than getting stuck
        // behind waiter capacity.
        for result in tokio::time::timeout(Duration::from_secs(2), join_all(recvs))
            .await
            .expect("deadline completion timed out")
        {
            assert!(matches!(result, Err((_, crate::Error::Timeout))));
        }

        drop(peers);
        drop(submitter);
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_exact_recv_partial_progress() {
        // Exercise the exact=true recv path where the kernel returns partial
        // data and the loop must requeue for a follow-up SQE.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        let (left, right) = UnixStream::pair().unwrap();
        // Set the socket to non-blocking so partial writes are possible.
        left.set_nonblocking(true).unwrap();
        right.set_nonblocking(true).unwrap();

        let total = 100;
        let recv = submitter.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(total),
            0,
            total,
            true,
            Instant::now() + Duration::from_secs(5),
        );

        // Write data in two chunks so the recv must make partial progress.
        let writer = async {
            (&right).write_all(&[1u8; 40]).unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            (&right).write_all(&[2u8; 60]).unwrap();
        };

        let (recv_result, ()) = tokio::time::timeout(Duration::from_secs(5), join(recv, writer))
            .await
            .expect("recv timed out");
        let (_, result) = recv_result.expect("recv should succeed");
        assert_eq!(result, total);

        drop(submitter);
        handle.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_shutdown_no_timeout_processes_ready_queue() {
        // Verify shutdown draining continues staging ready-queue work until a partially
        // completed logical request reaches its terminal result.
        let cfg = Config {
            shutdown_timeout: None,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        // Use a socket pair so we can feed the recv in two phases and control
        // exactly when the request is requeued.
        let (left, right) = UnixStream::pair().unwrap();
        left.set_nonblocking(true).unwrap();
        right.set_nonblocking(true).unwrap();

        let total = 100usize;
        let (tx, rx) = oneshot::channel();

        // Submit an exact recv large enough that the first short write cannot
        // complete it. After the first CQE, the request must requeue itself.
        submitter
            .enqueue(Request::Recv(RecvRequest {
                fd: Arc::new(left.into()),
                buf: IoBufMut::with_capacity(total),
                offset: 0,
                len: total,
                exact: true,
                deadline: None,
                result: None,
                sender: tx,
            }))
            .await
            .unwrap();

        // Deliver only part of the payload so the recv makes progress and lands
        // in the ready queue awaiting a follow-up SQE.
        (&right).write_all(&[1u8; 10]).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Trigger shutdown after the request has been requeued but before it
        // has necessarily been restaged. Drain must continue servicing the
        // ready queue from this point onward.
        drop(submitter);

        // Finish the request after shutdown has started. Drain must continue
        // staging ready-queue work or this recv will hang forever.
        tokio::time::sleep(Duration::from_millis(20)).await;
        (&right).write_all(&[2u8; 90]).unwrap();

        // The recv should still complete successfully even though shutdown was
        // initiated between the first and second stages of the logical request.
        let (_, result) = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("shutdown recv timed out")
            .expect("missing shutdown recv completion")
            .expect("recv should succeed during shutdown");
        assert_eq!(result, total);

        handle.join().unwrap();
    }

    #[tokio::test]
    async fn test_timeout_fires_while_request_in_ready_queue() {
        // Regression test: a request that made partial progress and was
        // requeued must be completed with timeout if the deadline expires
        // before the ready queue entry is staged. Without this fix, the
        // request would leak in the waiter table forever.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(200),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (submitter, iouring) = IoUringLoop::new(cfg, &mut registry);
        let handle = std::thread::spawn(move || iouring.run());

        let (left, right) = UnixStream::pair().unwrap();

        // Submit an exact recv for 100 bytes with a short deadline.
        let recv = submitter.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(100),
            0,
            100,
            true,
            Instant::now() + Duration::from_millis(80),
        );

        // Write partial data so the recv makes progress and gets requeued,
        // then let the deadline expire before sending the rest.
        let writer = async {
            (&right).write_all(&[1u8; 10]).unwrap();
        };

        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), join(recv, writer))
            .await
            .expect("recv should not hang");
        assert!(
            matches!(result, Err((_, crate::Error::Timeout))),
            "expected timeout, got {result:?}"
        );

        drop(submitter);
        handle.join().unwrap();
    }

    #[test]
    fn test_ready_queue_timeout_skips_cancel_staging() {
        // Verify timeout processing does not enqueue AsyncCancel for requests
        // that already retired their last SQE and are only waiting in ready_queue.
        let cfg = Config {
            max_request_timeout: Duration::from_millis(100),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg, &mut registry);

        let (left, _right) = UnixStream::pair().unwrap();
        let (tx, _rx) = oneshot::channel();
        let request = Request::Recv(RecvRequest {
            fd: Arc::new(left.into()),
            buf: IoBufMut::with_capacity(8),
            offset: 0,
            len: 8,
            exact: true,
            deadline: Some(Instant::now() + Duration::from_millis(25)),
            result: None,
            sender: tx,
        });
        let waiter_id = iouring.waiters.insert(request, Some(1));
        assert!(matches!(
            iouring.waiters.stage(waiter_id),
            StageOutcome::Submit(_)
        ));
        iouring.timeout_wheel.schedule(waiter_id, 1);

        // Simulate a short recv CQE so the logical request requeues itself but
        // no longer has a kernel op outstanding.
        let waiter_id = match iouring.waiters.on_completion(waiter_id.user_data(), 4) {
            CompletionOutcome::Requeue(waiter_id) => waiter_id,
            _ => panic!("missing partial recv completion"),
        };
        iouring.ready_queue.push_back(waiter_id);

        std::thread::sleep(iouring.cfg.timeout_wheel_tick + Duration::from_millis(2));
        iouring.advance_timeouts();

        // Timeout should mark the waiter canceled locally without staging `AsyncCancel`.
        assert!(iouring.pending_cancels.is_empty());
        assert!(matches!(
            iouring.waiters.stage(waiter_id),
            StageOutcome::Timeout(_)
        ));
    }

    #[test]
    fn test_drain_breaks_after_local_ready_queue_timeout_finishes_last_waiter() {
        // Verify shutdown drain exits immediately once ready-queue staging
        // finishes the final waiter locally instead of restaging another SQE.
        let cfg = Config {
            shutdown_timeout: None,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");
        iouring.wake_rearm_needed = false;

        // Seed drain with exactly one waiter that is already canceled and only
        // remains in the ready queue.
        let (tx, rx) = oneshot::channel();
        let waiter_id = iouring.waiters.insert(
            Request::Send(SendRequest {
                fd: Arc::new(UnixStream::pair().unwrap().0.into()),
                write: IoBufs::from(IoBuf::from(b"hello")).into(),
                deadline: Some(Instant::now() + Duration::from_secs(1)),
                result: None,
                sender: tx,
            }),
            Some(1),
        );
        assert!(iouring.waiters.cancel(waiter_id));
        iouring.ready_queue.push_back(waiter_id);

        iouring.drain(&mut ring);

        // Drain should finish the waiter locally and exit without staging more SQEs.
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);
        let result = futures::executor::block_on(rx).expect("missing timeout completion");
        assert!(matches!(result, Err(crate::Error::Timeout)));
    }

    #[tokio::test]
    async fn test_fill_submission_queue_completes_cancelled_ready_queue_entry_locally() {
        // Verify a cancel-requested waiter parked in the ready queue completes
        // immediately with timeout instead of restaging another SQE.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_submitter, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Keep the test focused on ready-queue staging instead of wake rearm.
        iouring.wake_rearm_needed = false;

        // Insert a canceled waiter whose next transition should be a local timeout completion.
        let (tx, rx) = oneshot::channel();
        let request = Request::Send(SendRequest {
            fd: Arc::new(UnixStream::pair().unwrap().0.into()),
            write: IoBufs::from(IoBuf::from(b"hello")).into(),
            deadline: Some(Instant::now() + Duration::from_secs(1)),
            result: None,
            sender: tx,
        });
        let waiter_id = iouring.waiters.insert(request, Some(1));
        assert!(iouring.waiters.cancel(waiter_id));
        iouring.ready_queue.push_back(waiter_id);

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        // Ready-queue staging should retire the waiter locally and leave the SQ untouched.
        assert!(!at_capacity);
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);
        let result = rx.await.expect("missing timeout completion");
        assert!(matches!(result, Err(crate::Error::Timeout)));
    }

    #[tokio::test]
    async fn test_fill_submission_queue_orphans_closed_request_before_first_submit() {
        // Verify dropping the caller before the loop stages the first SQE
        // retires both send and read-at requests locally instead of issuing
        // any I/O.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (handle, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Keep the test focused on request staging instead of wake rearm.
        iouring.wake_rearm_needed = false;

        let (tx, rx) = oneshot::channel();
        drop(rx);
        handle
            .enqueue(Request::Send(SendRequest {
                fd: Arc::new(UnixStream::pair().unwrap().0.into()),
                write: IoBufs::from(IoBuf::from(b"hello")).into(),
                deadline: Some(Instant::now() + Duration::from_secs(1)),
                result: None,
                sender: tx,
            }))
            .await
            .expect("request should enqueue");

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        // The request should retire locally without consuming waiter or SQ
        // capacity, and its scheduled deadline should disappear as well.
        assert!(!at_capacity);
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);
        assert_eq!(iouring.timeout_wheel.next_deadline(), None);

        let (sock_left, _sock_right) = UnixStream::pair().unwrap();
        // SAFETY: sock_left is a valid fd that we own. This request is
        // orphaned before staging, so the file descriptor is never submitted.
        let file = unsafe { std::fs::File::from_raw_fd(sock_left.into_raw_fd()) };
        let (tx, rx) = oneshot::channel();
        drop(rx);
        handle
            .enqueue(Request::ReadAt(ReadAtRequest {
                file: Arc::new(file),
                offset: 0,
                len: 8,
                read: 0,
                buf: IoBufMut::with_capacity(8),
                result: None,
                sender: tx,
            }))
            .await
            .expect("request should enqueue");

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        // The read request should take the same orphan path as send.
        assert!(!at_capacity);
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);
        assert_eq!(iouring.timeout_wheel.next_deadline(), None);
    }

    #[tokio::test]
    async fn test_fill_submission_queue_orphans_closed_ready_queue_entry_locally() {
        // Verify an orphaned waiter parked in the ready queue retires
        // locally instead of staging another SQE.
        let cfg = Config::default();
        let mut registry = Registry::default();
        let (_handle, mut iouring) = IoUringLoop::new(cfg.clone(), &mut registry);
        let mut ring = new_ring(&cfg).expect("unable to create io_uring instance");

        // Keep the test focused on ready-queue staging instead of wake rearm.
        iouring.wake_rearm_needed = false;

        let (tx, rx) = oneshot::channel();
        drop(rx);
        let waiter_id = iouring.waiters.insert(
            Request::Recv(RecvRequest {
                fd: Arc::new(UnixStream::pair().unwrap().0.into()),
                buf: IoBufMut::with_capacity(8),
                offset: 4,
                len: 8,
                exact: true,
                deadline: None,
                result: None,
                sender: tx,
            }),
            Some(1),
        );
        iouring.timeout_wheel.schedule(waiter_id, 1);
        iouring.ready_queue.push_back(waiter_id);

        let at_capacity = iouring
            .fill_submission_queue(&mut ring)
            .expect("channel should remain connected");

        // Restaging should notice the closed caller, drop the request locally,
        // and clean up its deadline tracking without touching the SQ.
        assert!(!at_capacity);
        assert!(iouring.waiters.is_empty());
        assert_eq!(ring.submission().len(), 0);
        assert_eq!(iouring.timeout_wheel.next_deadline(), None);
    }

    #[tokio::test]
    async fn test_single_issuer() {
        // Verify SINGLE_ISSUER still allows normal request submission and completion.
        let cfg = Config {
            single_issuer: true,
            ..Default::default()
        };

        let mut registry = Registry::default();
        let (sender, iouring) = IoUringLoop::new(cfg, &mut registry);
        let uring_thread = std::thread::spawn(move || iouring.run());

        // Use a real request/response pair instead of a nop-style operation so
        // the test proves that submissions and completions still work with the
        // SINGLE_ISSUER ring configuration enabled.
        let (sock_left, sock_right) = UnixStream::pair().unwrap();
        // Queue the recv first so the send has a real consumer and we exercise
        // the normal cross-request wake/completion path.
        let recv = sender.recv(
            Arc::new(sock_left.into()),
            IoBufMut::with_capacity(5),
            0,
            5,
            true,
            Instant::now() + Duration::from_secs(5),
        );
        let send = sender.send(
            Arc::new(sock_right.into()),
            IoBufs::from(IoBuf::from(b"hello")),
            Instant::now() + Duration::from_secs(5),
        );

        // The recv must observe the full payload, which shows that the request
        // made it through submission, wakeup, and completion successfully.
        let (recv_result, send_result) =
            tokio::time::timeout(Duration::from_secs(2), join(recv, send))
                .await
                .expect("recv/send timed out");
        let (_, read) = recv_result.expect("recv should succeed");
        assert_eq!(read, 5);

        // The paired send must also complete cleanly.
        send_result.expect("send should succeed");

        drop(sender);
        uring_thread.join().unwrap();
    }
}
