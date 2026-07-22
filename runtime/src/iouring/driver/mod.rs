//! The io_uring driver: the owned event loop and ring ([Driver]) and the
//! shared op state that futures submit through ([Handle]).
//!
//! See [crate::iouring] for the full request flow and liveness discussion.

mod handle;
pub(crate) use handle::{AcceptTicket, Affine, Handle, Shared};
mod request;
pub(crate) use request::RawSocketAddr;
mod timeout;
use timeout::{Tick, TimeoutWheel};
mod waiter;
use waiter::{CompletionOutcome, StageOutcome, WaiterId};
pub(crate) mod waker;
use waker::{HALF_SUBMISSION_SEQUENCE_DOMAIN, WAKE_USER_DATA, Waker};
pub(crate) mod spinner;
use super::RingConfig;
use crate::telemetry::metrics::{Gauge, Register, raw};
use io_uring::{
    IoUring,
    cqueue::Entry as CqueueEntry,
    opcode::AsyncCancel,
    squeue::SubmissionQueue,
    types::{SubmitArgs, Timespec},
};
use spinner::Spinner;
use std::{
    sync::Arc,
    task::Waker as TaskWaker,
    time::{Duration, Instant},
};

/// Maximum rounded ring size accepted by [`RingConfig::size`].
///
/// Requested sizes are rounded up to the next power of two before validation.
pub const MAX_RING_SIZE: u32 = HALF_SUBMISSION_SEQUENCE_DOMAIN / 2;

/// Packed `io_uring` `user_data` value.
type UserData = u64;

/// Tracks io_uring metrics.
#[derive(Debug)]
pub(crate) struct Metrics {
    /// Number of active logical requests whose CQEs haven't yet been fully
    /// processed. Note this metric doesn't include timeouts, which are
    /// generated internally by the io_uring event loop.
    /// This is updated in the main loop and at shutdown drain exit, so it may
    /// temporarily vary from the exact in-flight count between update points.
    pending_operations: Gauge,
}

impl Metrics {
    pub(crate) fn new(registry: &mut impl Register) -> Self {
        Self {
            pending_operations: registry.register(
                "pending_operations",
                "Number of active logical requests in the io_uring loop",
                raw::Gauge::default(),
            ),
        }
    }
}

/// io_uring event loop state.
pub(crate) struct IoUringLoop {
    cfg: RingConfig,
    metrics: Arc<Metrics>,
    /// Shared op state, also reachable from the front-ends' op futures.
    handle: Handle,
    timeout_wheel: TimeoutWheel,
    idle_spinner: Spinner,
    waker: Waker,
    wake_rearm_needed: bool,
    /// Sequence position of the retained (currently unexercised) submission
    /// publish protocol. Stays at zero: submissions are staged on the loop
    /// thread itself, so no producer ever publishes ahead.
    processed_seq: u32,
    /// Scratch list of task wakers collected under the state borrow and
    /// invoked after it is released.
    pending_wakers: Vec<TaskWaker>,
}

/// Outcome of one `fill_submission_queue()` staging pass.
///
/// This tells the outer loop whether staging drained all currently visible
/// work, hit submission-queue pressure, or hit waiter-capacity pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FillResult {
    /// Staging drained all currently visible work without hitting a hard limit.
    Drained,
    /// The submission queue filled before waiter capacity was exhausted.
    AtSubmissionQueueCapacity,
    /// The waiter table filled, regardless of whether the submission queue also filled.
    AtWaiterCapacity,
}

impl FillResult {
    /// Derive the staging outcome from the current fill state.
    ///
    /// Submission-queue saturation dominates while stageable work remains:
    /// the loop must flush and restage or admitted requests never reach the
    /// kernel (ops are admitted into the slab by their futures before any
    /// staging pass, so a full slab does not imply the kernel has work).
    /// Otherwise waiter saturation is reported so the park path knows
    /// completions must free capacity before admissions resume.
    #[inline]
    fn from_fill_state(shared: &Shared, submission_queue: &SubmissionQueue<'_>) -> Self {
        if submission_queue.is_full()
            && (!shared.staged.is_empty() || !shared.pending_cancels.is_empty())
        {
            return Self::AtSubmissionQueueCapacity;
        }
        if shared.waiters.is_full() {
            Self::AtWaiterCapacity
        } else if submission_queue.is_full() {
            Self::AtSubmissionQueueCapacity
        } else {
            Self::Drained
        }
    }
}

impl IoUringLoop {
    /// Create a new io_uring loop and its shared submission handle.
    ///
    /// The loop allocates its own metrics and internal `eventfd` wake source.
    /// The calling thread becomes the handle's owning (runtime) thread.
    pub(crate) fn new(mut cfg: RingConfig, registry: &mut impl Register) -> (Handle, Self) {
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
        // The retained wake protocol's `pending()` interprets packed
        // submission-sequence deltas with half-range modular ordering. After
        // rounding to a power of two, that means the maximum admissible ring
        // size is `MAX_RING_SIZE`.
        assert!(
            cfg.size <= MAX_RING_SIZE,
            "rounded ring size must be at most {}",
            MAX_RING_SIZE
        );
        let size = cfg.size as usize;
        let metrics = Arc::new(Metrics::new(registry));
        let waker = Waker::new().expect("unable to create wake eventfd");
        let timeout_wheel = TimeoutWheel::new(
            cfg.max_request_timeout,
            cfg.timeout_wheel_tick,
            Instant::now(),
        );
        let idle_spinner = Spinner::new(&cfg.idle_spinner, || waker.pending(0));
        let handle = Handle::new(size);

        (
            handle.clone(),
            Self {
                cfg,
                metrics,
                handle,
                timeout_wheel,
                idle_spinner,
                waker,
                wake_rearm_needed: true,
                processed_seq: 0,
                pending_wakers: Vec::new(),
            },
        )
    }

    /// Invoke every collected task waker.
    ///
    /// Must be called outside any borrow of the driver state: wakers reenter
    /// executor scheduling but never the loop state itself.
    fn flush_wakers(&mut self) {
        for waker in self.pending_wakers.drain(..) {
            waker.wake();
        }
    }

    /// Release every task waiting for a free waiter slot.
    ///
    /// Called whenever a slot frees. Woken futures re-register if they lose
    /// the admission race.
    fn notify_capacity(&mut self, shared: &mut Shared) {
        self.pending_wakers.append(&mut shared.capacity);
    }

    /// Make progress on the ring without blocking.
    ///
    /// Drains available CQEs (parking or requeuing their requests), advances
    /// userspace deadlines, stages as much admitted work as capacity allows,
    /// and flushes staged SQEs to the kernel. Never blocks: the runtime
    /// executor calls this between task-poll batches so completions wake tasks
    /// promptly while submissions reach the kernel before the executor parks.
    pub(crate) fn turn(&mut self, ring: &mut IoUring) {
        let handle = self.handle.clone();
        loop {
            let (fill_result, kernel_idle) = handle.with(|shared| {
                // Process available completions.
                for cqe in ring.completion() {
                    self.handle_cqe(shared, cqe);
                }

                // Process due deadlines before staging new submissions so timed-out
                // requests move to cancellation promptly and free capacity sooner.
                self.advance_timeouts(shared);

                // Stage as much admitted work as capacity allows.
                let fill_result = self.fill_submission_queue(shared, ring);

                // Update pending operations metric.
                self.metrics
                    .pending_operations
                    .set(shared.waiters.len() as _);

                (fill_result, shared.waiters.pending() == 0)
            });

            // Wake tasks whose results were parked, outside the state borrow.
            self.flush_wakers();

            match fill_result {
                FillResult::AtSubmissionQueueCapacity => {
                    // Flush the staged batch into the kernel and stage more work.
                    self.submit(ring).expect("unable to submit to ring");
                    continue;
                }
                FillResult::AtWaiterCapacity | FillResult::Drained => {}
            }

            // Without progressing waiters there is nothing to flush or reap:
            // staged wake-poll rearms (the only waiter-less SQEs) are submitted
            // by the next blocking park, and the futex park path does not need
            // them.
            if kernel_idle {
                return;
            }

            // Flush staged SQEs and reap completions without blocking. With
            // `DEFER_TASKRUN`, completions are only posted during an
            // `io_uring_enter` that requests events, so a zero-timeout wait
            // doubles as the reap.
            self.submit_and_wait(ring, 1, Some(Duration::ZERO))
                .expect("unable to submit to ring");

            // Process any completions the flush surfaced before returning.
            if ring.completion().is_empty() {
                return;
            }
        }
    }

    /// Park the calling thread until progress is possible or the earliest
    /// deadline elapses.
    ///
    /// `limit` bounds the wait in addition to the loop's own timeout wheel; the
    /// runtime executor passes the delay until its next sleeper alarm. Callers
    /// must invoke [Self::turn] immediately before parking so the wake poll is
    /// armed and staged work has been flushed.
    ///
    /// Wakes on CQE arrival or on an out-of-band wake (e.g. a task woken from
    /// another thread).
    pub(crate) fn park(&mut self, ring: &mut IoUring, limit: Option<Duration>) {
        let deadline = match (self.timeout_wheel.next_deadline(), limit) {
            (Some(wheel), Some(limit)) => Some(wheel.min(limit)),
            (wheel, limit) => wheel.or(limit),
        };

        let (fully_idle, waiters_full) = self.handle.with(|shared| {
            (
                shared.waiters.pending() == 0
                    && shared.staged.is_empty()
                    && shared.pending_cancels.is_empty(),
                shared.waiters.is_full(),
            )
        });

        // If the ring is truly idle and no deadline is pending, avoid
        // `io_uring_enter` entirely and wait on the shared wake state via
        // futex until another thread latches a wake. Before parking, spin
        // briefly to avoid the futex round-trip when work is imminent.
        if fully_idle && deadline.is_none() {
            if self
                .idle_spinner
                .spin(|| self.waker.pending(self.processed_seq))
            {
                return;
            }
            if let Some(park_duration) = self.waker.park_idle(self.processed_seq) {
                self.idle_spinner.on_wake(park_duration);
            }
            return;
        }

        // Otherwise, arm the eventfd-backed blocking path. Under
        // waiter-capacity pressure, admissions cannot proceed until
        // completions free capacity, so block unless an out-of-band wake
        // (e.g. a task wake) is latched. Otherwise block only if the post-arm
        // snapshot still looks idle (no latched wake).
        let arm = self.waker.arm(self.processed_seq);
        let may_block = if waiters_full {
            !arm.wake_latched()
        } else {
            arm.still_idle()
        };
        if may_block {
            self.submit_and_wait(ring, 1, deadline)
                .expect("unable to submit to ring");
        }
    }

    /// Build and push the SQE for a request in the waiter table.
    ///
    /// If the request was marked for cancellation while sitting in the staged
    /// queue (timeout or ticket drop between requeue and staging), it is
    /// completed with a timeout error or retired instead of issuing a
    /// follow-up SQE.
    fn stage_request(
        &mut self,
        shared: &mut Shared,
        waiter_id: WaiterId,
        submission_queue: &mut SubmissionQueue<'_>,
    ) {
        match shared.waiters.stage(waiter_id) {
            StageOutcome::Timeout { waker, freed } => {
                self.pending_wakers.extend(waker);
                if freed {
                    self.notify_capacity(shared);
                }
            }
            StageOutcome::Orphaned { target_tick } => {
                // The ticket disappeared before another SQE was issued, so all
                // that remains is to release deadline tracking (the waiter, and
                // associated resources, were already dropped inside `Waiters`).
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
                self.notify_capacity(shared);
            }
            StageOutcome::Submit(sqe) => {
                // SAFETY:
                // - All resources are stored in the waiter slab until CQE processing, so
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

    /// Stage admitted requests from the staged queue in FIFO order.
    ///
    /// The first staging of a request that carries a deadline converts it to
    /// a wheel tick (aligning the wheel when it was previously idle);
    /// already-expired deadlines complete immediately with timeout before any
    /// SQE is issued.
    ///
    /// Stops when all queued requests are staged or the SQ reaches capacity.
    /// Returns `true` when SQ capacity is hit and at least one staged request
    /// remains queued.
    fn stage_staged(
        &mut self,
        shared: &mut Shared,
        submission_queue: &mut SubmissionQueue<'_>,
    ) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = shared.staged.pop_front() else {
                return false;
            };

            if let Some(deadline) = shared.waiters.deadline_to_schedule(waiter_id) {
                // Avoid per-request clock reads when no deadlines are active.
                // When the first deadline arrives after an idle period, align
                // wheel time once before converting deadlines to ticks.
                if self.timeout_wheel.next_deadline().is_none() {
                    assert!(self.timeout_wheel.advance(Instant::now()).is_none());
                }
                match self.timeout_wheel.target_tick(deadline) {
                    Some(tick) => {
                        shared.waiters.set_target_tick(waiter_id, tick);
                        self.timeout_wheel.schedule(waiter_id, tick);
                    }
                    // The deadline already expired: transition to cancellation
                    // so staging below completes the request with timeout.
                    None => assert!(shared.waiters.cancel(waiter_id)),
                }
            }

            self.stage_request(shared, waiter_id, submission_queue);
        }

        !shared.staged.is_empty()
    }

    /// Stage pending submission work into the SQ.
    ///
    /// In one pass, this may rearm wake polling, stage cancellations, and
    /// stage admitted requests.
    ///
    /// Returns why staging stopped.
    fn fill_submission_queue(&mut self, shared: &mut Shared, ring: &mut IoUring) -> FillResult {
        let mut submission_queue = ring.submission();

        // Reinstall wake poll only when a prior wake CQE indicated multishot
        // termination. Otherwise keep the existing poll registration.
        //
        // This check runs before every possible transition into the eventfd-backed
        // blocking path. The fully idle futex path does not need the poll to be
        // live, so an iteration that parks in futex may skip kernel entry
        // entirely. If multishot termination was observed earlier, the next
        // iteration that might block in `submit_and_wait` stages the rearm SQE
        // here before entering the kernel again.
        if self.wake_rearm_needed {
            // If the SQ is already full from a previous iteration, submit them first.
            if !self.waker.reinstall(&mut submission_queue) {
                // Even if waiter capacity is also exhausted, we must not take
                // the blocking path yet: the wake poll is not rearmed, so
                // `submit_and_wait` would sleep without the eventfd wake path
                // being live. Flush staged SQEs first, then retry rearm in the
                // next pass.
                return FillResult::AtSubmissionQueueCapacity;
            }
            self.wake_rearm_needed = false;
        }

        // Stage pending cancel SQEs first so timed-out requests are canceled promptly.
        if self.stage_cancellations(shared, &mut submission_queue) {
            return FillResult::from_fill_state(shared, &submission_queue);
        }

        // Stage admitted requests in FIFO order.
        if self.stage_staged(shared, &mut submission_queue) {
            return FillResult::from_fill_state(shared, &submission_queue);
        }

        FillResult::from_fill_state(shared, &submission_queue)
    }

    /// Stage queued cancellation SQEs from `pending_cancels` in FIFO order.
    ///
    /// Stops when all queued cancellations are staged or the SQ reaches
    /// capacity. Returns `true` when SQ capacity is hit and at least one
    /// cancellation remains queued.
    fn stage_cancellations(
        &mut self,
        shared: &mut Shared,
        submission_queue: &mut SubmissionQueue<'_>,
    ) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = shared.pending_cancels.pop_front() else {
                return false;
            };

            // This waiter was cancelled earlier, but its queued cancel may
            // have gone stale before we got around to staging it. If the
            // original op CQE already retired the outstanding SQE, there is
            // nothing left for the kernel to cancel.
            if !shared.waiters.is_in_flight(waiter_id) {
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

        !shared.pending_cancels.is_empty()
    }

    /// Handle a single CQE from the ring.
    ///
    /// Internal wake CQEs are handled in-place. All other CQEs are forwarded to
    /// the request state machine for progress evaluation.
    fn handle_cqe(&mut self, shared: &mut Shared, cqe: CqueueEntry) {
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

        match shared.waiters.on_completion(user_data, cqe.result()) {
            CompletionOutcome::Cancel => {
                // Async-cancel CQEs are handled entirely inside `Waiters` they do
                // not directly complete or requeue a logical request here.
            }
            CompletionOutcome::Requeue(waiter_id) => {
                // Request needs another SQE. Add it back to the staged queue.
                shared.staged.push_back(waiter_id);
            }
            CompletionOutcome::Complete {
                waker,
                target_tick,
                freed,
            } => {
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
                self.pending_wakers.extend(waker);
                if freed {
                    self.notify_capacity(shared);
                }
            }
        }
    }

    /// Advance the timeout wheel and enqueue cancellations for newly expired requests.
    ///
    /// This is a no-op when no active deadlines exist. Expired stale wheel
    /// entries are ignored when waiter generation no longer matches.
    fn advance_timeouts(&mut self, shared: &mut Shared) {
        // Release deadline accounting for ops whose tickets were dropped: the
        // wheel is loop-owned, so drop paths queue removals instead. Without
        // this the wheel would report the stale tick as the next deadline
        // forever once it elapsed.
        for tick in shared.released_deadlines.drain(..) {
            self.timeout_wheel.remove(tick);
        }

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
            if shared.waiters.cancel(entry.waiter_id) {
                // Once cancel is requested, this waiter is no longer deadline-active.
                self.timeout_wheel.remove(entry.target_tick);
                // Only timed-out waiters with an outstanding op SQE need
                // AsyncCancel. Waiters parked in the staged queue have no
                // kernel op to cancel and will time out locally when restaged.
                if shared.waiters.is_in_flight(entry.waiter_id) {
                    shared.pending_cancels.push_back(entry.waiter_id);
                }
            }
        }
    }

    /// Request cancellation of every progressing waiter.
    ///
    /// Cancelled waiters leave the timeout wheel, in-flight waiters get an
    /// async-cancel SQE queued, and waiters parked in the staged queue retire
    /// locally when restaged.
    fn cancel_all(&mut self, shared: &mut Shared) {
        for (waiter_id, target_tick, in_flight) in shared.waiters.cancel_active() {
            if let Some(tick) = target_tick {
                self.timeout_wheel.remove(tick);
            }
            if in_flight {
                shared.pending_cancels.push_back(waiter_id);
            }
        }
    }

    /// Drain in-flight requests during shutdown.
    ///
    /// Keeps draining CQEs until all progressing waiters finish. Parked
    /// results owned by escaped tickets hold no kernel resources and are left
    /// in place: they are reclaimed when their ticket is polled or dropped.
    ///
    /// If `shutdown_timeout` is `None`, this waits until all waiters complete
    /// or are cancelled by their own deadlines. If `shutdown_timeout` is
    /// `Some`, every request still outstanding when the budget expires is
    /// cancelled, and the drain then waits for the kernel to retire it: a
    /// request must never be dropped while the kernel may still reference its
    /// buffers, so operations that cannot be cancelled (e.g. an executing disk
    /// write) are awaited regardless of the budget.
    fn drain(&mut self, ring: &mut IoUring) {
        let handle = self.handle.clone();
        let mut remaining = self.cfg.shutdown_timeout;

        // Keep driving completions until all progressing waiters finish.
        loop {
            // Always drain CQEs first, even after a timed wait: completions can
            // race with timeout expiry and still be pending in the queue.
            let pending = handle.with(|shared| {
                for cqe in ring.completion() {
                    self.handle_cqe(shared, cqe);
                }
                shared.waiters.pending()
            });
            self.flush_wakers();

            // CQE draining can finish the last waiter, so stop before another
            // submit-and-wait cycle.
            if pending == 0 {
                break;
            }

            // Once the shutdown budget is exhausted, request cancellation of
            // every remaining operation instead of abandoning it: an abandoned
            // request would free buffers the kernel may still write into.
            if remaining.is_some_and(|t| t.is_zero()) {
                remaining = None;
                handle.with(|shared| self.cancel_all(shared));
            }

            // Keep userspace deadline processing alive during shutdown so
            // in-flight timed operations preserve their ETIMEDOUT semantics,
            // and continue staging requeued requests so partially-complete or
            // retrying requests can keep making progress.
            let pending = handle.with(|shared| {
                self.advance_timeouts(shared);
                {
                    let mut submission_queue = ring.submission();
                    self.stage_cancellations(shared, &mut submission_queue);
                    self.stage_staged(shared, &mut submission_queue);
                }
                shared.waiters.pending()
            });
            self.flush_wakers();

            // Staging can directly complete the last waiter (for example, when a
            // timed-out requeued request is retired instead of reissued).
            if pending == 0 {
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

        let handle = self.handle.clone();
        handle.with(|shared| {
            self.metrics
                .pending_operations
                .set(shared.waiters.len() as _);
        });
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

    /// Submit pending SQEs without waiting for a completion.
    #[inline]
    fn submit(&self, ring: &mut IoUring) -> Result<(), std::io::Error> {
        self.submit_and_wait(ring, 0, None).map(|_| ())
    }
}

/// Build and configure an `io_uring` instance.
pub(crate) fn new_ring(cfg: &RingConfig) -> Result<IoUring, std::io::Error> {
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

/// Owned half of the io_uring driver: the ring plus the loop state that
/// services it.
///
/// Op futures reach the driver's shared op state through [Handle]s, while the
/// worker that owns the [Driver] is the only place SQEs are built and CQEs
/// are reaped. The ring and loop state live in separate fields so the
/// delegating methods below can borrow them disjointly.
pub(crate) struct Driver {
    ring: IoUring,
    inner: IoUringLoop,
}

impl Driver {
    /// Create the driver and its shared submission handle.
    ///
    /// The calling thread becomes the ring's owner and only submitter.
    pub(crate) fn new(
        cfg: RingConfig,
        registry: &mut impl Register,
    ) -> Result<(Self, Handle), std::io::Error> {
        let (handle, inner) = IoUringLoop::new(cfg, registry);
        let ring = new_ring(&inner.cfg)?;
        Ok((Self { ring, inner }, handle))
    }

    /// Clone the driver's cross-thread wake source.
    pub(crate) fn waker(&self) -> Waker {
        self.inner.waker.clone()
    }

    /// Service the ring: build and submit staged SQEs, then reap CQEs and
    /// wake the tasks whose results parked.
    pub(crate) fn turn(&mut self) {
        self.inner.turn(&mut self.ring);
    }

    /// Park until a completion arrives, a wake is published, or the next
    /// timer (ring timeout wheel or `limit`) is due.
    pub(crate) fn park(&mut self, limit: Option<Duration>) {
        self.inner.park(&mut self.ring, limit);
    }

    /// Close the shared op state so late admissions fail with their
    /// kind-specific error. Returns the capacity waiters so the caller can
    /// wake them outside the borrow.
    pub(crate) fn close(&self) -> Vec<TaskWaker> {
        self.inner.handle.close()
    }

    /// Drain in-flight ring work so kernel-owned buffers and descriptors are
    /// released, consuming the driver: the ring is destroyed afterwards.
    pub(crate) fn drain(mut self) {
        self.inner.drain(&mut self.ring);
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Shared single-threaded harness for tests that drive the loop
    //! directly (loop, network, and storage unit tests).

    use super::*;
    use crate::telemetry::metrics::Registry;
    use futures::task::{ArcWake, waker as arc_waker};
    use std::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll},
    };

    /// Task waker that latches the loop's out-of-band wake, mirroring how the
    /// runtime executor's task wakers unpark the loop.
    pub(crate) struct Unpark(Waker);

    impl ArcWake for Unpark {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.wake();
        }
    }

    /// Single-threaded loop harness driving `turn`/`park` interleaved with
    /// polling a future, mirroring the runtime executor's structure.
    pub(crate) struct TestLoop {
        pub(crate) handle: Handle,
        /// The owned driver, taken by [TestLoop::shutdown] (drain consumes it).
        driver: Option<Driver>,
    }

    impl TestLoop {
        pub(crate) fn new(mut cfg: RingConfig) -> Self {
            // Mirror the runtime's startup behavior: production always runs
            // with single issuer (and thus deferred task running), so the
            // harness must exercise the same completion-delivery mode.
            cfg.single_issuer = true;
            let mut registry = Registry::default();
            let (driver, handle) =
                Driver::new(cfg, &mut registry).expect("unable to create io_uring instance");
            Self {
                handle,
                driver: Some(driver),
            }
        }

        /// Access the owned driver.
        ///
        /// Panics after [TestLoop::shutdown].
        pub(crate) fn driver(&mut self) -> &mut Driver {
            self.driver.as_mut().expect("driver already drained")
        }

        /// Build a waker that latches the loop's out-of-band wake, or a noop
        /// waker once the driver is drained (parked results resolve without
        /// one).
        fn waker(&self) -> TaskWaker {
            self.driver
                .as_ref()
                .map_or_else(futures::task::noop_waker, |driver| {
                    arc_waker(Arc::new(Unpark(driver.waker())))
                })
        }

        /// Drive `fut` to completion, servicing the ring between polls.
        pub(crate) fn block_on<F: Future>(&mut self, fut: F) -> F::Output {
            let waker = self.waker();
            let mut cx = Context::from_waker(&waker);
            let mut fut = pin!(fut);
            loop {
                if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                    return output;
                }
                let driver = self.driver.as_mut().expect("future pending after shutdown");
                driver.turn();
                driver.park(None);
            }
        }

        /// Close the driver and drain in-flight work, as runtime teardown does.
        pub(crate) fn shutdown(&mut self) {
            let Some(driver) = self.driver.take() else {
                return;
            };
            for waker in driver.close() {
                waker.wake();
            }
            driver.drain();
        }

        /// Number of tracked waiters (including parked results).
        pub(crate) fn tracked(&self) -> usize {
            self.handle.with(|shared| shared.waiters.len())
        }

        /// Number of waiters still progressing.
        pub(crate) fn pending(&self) -> usize {
            self.handle.with(|shared| shared.waiters.pending())
        }
    }

    impl Drop for TestLoop {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// Poll `fut` exactly once with a loop-latching waker.
    pub(crate) fn poll_once<F: Future + Unpin>(harness: &TestLoop, fut: &mut F) -> Poll<F::Output> {
        let waker = harness.waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(fut).poll(&mut cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};
    use crate::{Error, IoBuf, IoBufMut, IoBufs, telemetry::metrics::Registry};
    use std::{
        io::Write,
        os::{
            fd::{FromRawFd, IntoRawFd, OwnedFd},
            unix::net::UnixStream,
        },
        task::Poll,
        time::{Duration, Instant},
    };

    #[test]
    fn test_iouring_loop_rounds_ring_size_up_to_power_of_two() {
        let cfg = RingConfig {
            size: 100,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_driver, ioloop) = IoUringLoop::new(cfg, &mut registry);
        assert_eq!(ioloop.cfg.size, 128);
    }

    #[test]
    fn test_iouring_loop_rejects_sizes_that_exceed_max_ring_size() {
        let cfg = RingConfig {
            size: MAX_RING_SIZE + 1,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = IoUringLoop::new(cfg, &mut registry);
        }));
        assert!(rejected.is_err());
    }

    #[test]
    fn test_new_ring_iopoll_builder_path_is_exercised() {
        // IOPOLL requires files opened with O_DIRECT to do useful work, so this
        // only verifies the builder path constructs (or cleanly fails to
        // construct) a ring with the flag.
        let cfg = RingConfig {
            io_poll: true,
            ..Default::default()
        };
        let _ = new_ring(&cfg);
    }

    #[test]
    fn test_submit_and_wait_non_etime_error_is_not_misclassified() {
        // Verify only ETIME maps to a timed-out wait: other errno values from
        // `io_uring_enter` must propagate as real errors rather than being
        // swallowed as transient.
        let mut harness = TestLoop::new(RingConfig::default());

        // Closing the ring fd out from under the loop makes the next enter
        // fail with EBADF.
        let driver = harness.driver();
        // SAFETY: the fd is intentionally invalidated; the harness issues no
        // further ring operations after the failed wait.
        unsafe {
            libc::close(std::os::fd::AsRawFd::as_raw_fd(&driver.ring));
        }
        let err = driver
            .inner
            .submit_and_wait(&mut driver.ring, 1, Some(Duration::from_millis(1)))
            .expect_err("enter on a closed ring must fail");
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));

        // The ring fd is gone, so skip the harness drain.
        std::mem::forget(harness);
    }

    #[test]
    fn test_recv_completes_and_frees_slot() {
        // Verify a recv with available data completes and its slot frees once
        // the result is taken.
        let mut harness = TestLoop::new(RingConfig::default());
        let (left, right) = UnixStream::pair().unwrap();
        (&right).write_all(&[42]).unwrap();

        let driver = harness.handle.clone();
        let (mut buf, read) = harness
            .block_on(driver.recv(
                Arc::new(left.into()),
                IoBufMut::with_capacity(1),
                0,
                1,
                false,
                Instant::now() + Duration::from_secs(5),
            ))
            .expect("recv should succeed");
        assert_eq!(read, 1);
        // SAFETY: the kernel filled `read` bytes before completion.
        unsafe { buf.set_len(read) };
        assert_eq!(buf.as_ref(), &[42]);
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_recv_timeout() {
        // Verify a timed recv completes with timeout once its deadline expires.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(1),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let start = Instant::now();
        let result = harness.block_on(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_millis(80),
        ));
        assert!(matches!(result, Err((_, Error::Timeout))));
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "timeout fired too early: {:?}",
            start.elapsed()
        );
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_timeout_slot_reuse_does_not_cancel_new_waiter_early() {
        // Verify stale timeout-wheel entries from an earlier generation do not
        // cancel a newly inserted waiter that reused the same slot.
        let mut harness = TestLoop::new(RingConfig {
            size: 8,
            max_request_timeout: Duration::from_millis(200),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        });

        // First operation completes quickly but still carries a generous
        // deadline, leaving a stale timeout entry that should be ignored later
        // after slot reuse.
        let (left1, right1) = UnixStream::pair().unwrap();
        (&right1).write_all(&[42]).unwrap();
        let driver = harness.handle.clone();
        let (_buf1, read1) = harness
            .block_on(driver.recv(
                Arc::new(left1.into()),
                IoBufMut::with_capacity(1),
                0,
                1,
                false,
                Instant::now() + Duration::from_millis(200),
            ))
            .expect("first recv should succeed");
        assert!(read1 > 0);

        // Second request reuses the slot and blocks until timeout.
        let (left2, _right2) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let result2 = harness.block_on(driver.recv(
            Arc::new(left2.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_millis(80),
        ));
        let elapsed = start.elapsed();
        assert!(matches!(result2, Err((_, Error::Timeout))));
        assert!(
            elapsed >= Duration::from_millis(50),
            "timeout fired too early after slot reuse: {elapsed:?}"
        );
    }

    #[test]
    fn test_exact_recv_partial_progress() {
        // Verify an exact recv keeps requeuing until the full length arrives.
        let mut harness = TestLoop::new(RingConfig::default());
        let (left, right) = UnixStream::pair().unwrap();
        (&right).write_all(&[1, 2, 3]).unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(5),
            0,
            5,
            true,
            Instant::now() + Duration::from_secs(5),
        ));

        // Drive until the partial bytes are consumed, then supply the rest.
        for _ in 0..10 {
            if poll_once(&harness, &mut recv).is_ready() {
                panic!("exact recv completed before all bytes arrived");
            }
            harness.driver().turn();
        }
        (&right).write_all(&[4, 5]).unwrap();

        let (mut buf, read) = harness
            .block_on(recv)
            .expect("exact recv should complete after remaining bytes");
        assert_eq!(read, 5);
        // SAFETY: the kernel filled `read` bytes before completion.
        unsafe { buf.set_len(read) };
        assert_eq!(buf.as_ref(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_expired_deadline_completes_immediately() {
        // Verify a request admitted with an already-expired deadline completes
        // with timeout before any SQE is issued.
        let mut harness = TestLoop::new(RingConfig::default());
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let start = Instant::now();
        let result = harness.block_on(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() - Duration::from_millis(10),
        ));
        assert!(matches!(result, Err((_, Error::Timeout))));
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "expired deadline should complete locally, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    #[should_panic(expected = "recv invariant violated")]
    fn test_recv_panics_on_invalid_buffer_bounds() {
        let mut harness = TestLoop::new(RingConfig::default());
        let (left, _right) = UnixStream::pair().unwrap();
        let driver = harness.handle.clone();
        let _ = harness.block_on(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(4),
            0,
            5,
            false,
            Instant::now() + Duration::from_secs(1),
        ));
    }

    #[test]
    fn test_drop_cancels_inflight_recv() {
        // Verify dropping an op future mid-flight eagerly cancels the
        // operation and frees its slot without waiting for the deadline.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();
        let fd = Arc::new(OwnedFd::from(left));

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(fd.try_clone().unwrap()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(60),
        ));

        // Admit and submit the recv.
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();
        assert_eq!(harness.pending(), 1);

        // Dropping the future orphans the slot and requests cancellation. The
        // next turn stages the async cancel and the kernel retires the op.
        drop(recv);
        let start = Instant::now();
        while harness.tracked() != 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "orphaned recv still tracked after {:?}",
                start.elapsed()
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
    }

    #[test]
    fn test_drop_before_first_submit_retires_locally() {
        // Verify dropping an op future that was admitted but never staged
        // retires the slot without issuing an SQE.
        let mut harness = TestLoop::new(RingConfig::default());
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(60),
        ));

        // Admit without turning the loop, then drop.
        assert!(poll_once(&harness, &mut recv).is_pending());
        assert_eq!(harness.tracked(), 1);
        drop(recv);

        // The staged entry is retired locally on the next turn.
        harness.driver().turn();
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_write_detaches_on_drop() {
        // Verify a dropped write keeps running to completion for durability
        // parity with the tokio backend.
        let dir = std::env::temp_dir().join(format!(
            "commonware_iouring_write_detach_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("detached_write");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let mut harness = TestLoop::new(RingConfig::default());
        let driver = harness.handle.clone();
        let payload = vec![7u8; 1 << 20];
        let mut write = Box::pin(driver.write_at_sync(
            Arc::new(file),
            0,
            IoBufs::from(IoBuf::from(payload.clone())),
        ));

        // Admit the write, then drop the future before it completes.
        assert!(poll_once(&harness, &mut write).is_pending());
        drop(write);

        // Drain runs the detached write to completion.
        harness.shutdown();
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, payload);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_capacity_wake_all_admits_waiting_op() {
        // Verify an op parked on the capacity wait list admits once a slot
        // frees.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let (left_a, right_a) = UnixStream::pair().unwrap();
        let (left_b, right_b) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let recv_a = driver.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(5),
        );
        let recv_b = driver.recv(
            Arc::new(left_b.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(5),
        );

        // Feed both sockets so each recv completes as soon as it is admitted.
        (&right_a).write_all(&[1]).unwrap();
        (&right_b).write_all(&[2]).unwrap();

        let (result_a, result_b) = harness.block_on(futures::future::join(recv_a, recv_b));
        let (mut buf_a, read_a) = result_a.expect("first recv should succeed");
        let (mut buf_b, read_b) = result_b.expect("second recv should succeed");
        // SAFETY: the kernel filled the reported bytes before completion.
        unsafe { buf_a.set_len(read_a) };
        // SAFETY: the kernel filled the reported bytes before completion.
        unsafe { buf_b.set_len(read_b) };
        assert_eq!(buf_a.as_ref(), &[1]);
        assert_eq!(buf_b.as_ref(), &[2]);
    }

    #[test]
    fn test_closed_driver_fails_admission() {
        // Verify ops staged after close resolve with their kind-specific
        // failures without touching the ring.
        let mut harness = TestLoop::new(RingConfig::default());
        for waker in harness.driver().close() {
            waker.wake();
        }

        let (left, _right) = UnixStream::pair().unwrap();
        let driver = harness.handle.clone();
        let result = harness.block_on(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(1),
        ));
        assert!(matches!(result, Err((_, Error::RecvFailed))));

        let (sock, _keep) = UnixStream::pair().unwrap();
        // SAFETY: sock is a valid fd that we own.
        let file = unsafe { std::fs::File::from_raw_fd(sock.into_raw_fd()) };
        let ticket = harness.block_on(driver.start_sync(Arc::new(file)));
        let result = harness.block_on(ticket);
        assert!(matches!(result, Err(Error::Closed)));
    }

    #[test]
    fn test_shutdown_waits_for_inflight_write() {
        // Verify shutdown without a budget waits for the last in-flight
        // request instead of abandoning it.
        let dir = std::env::temp_dir().join(format!(
            "commonware_iouring_shutdown_write_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("shutdown_write");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let mut harness = TestLoop::new(RingConfig {
            shutdown_timeout: None,
            ..Default::default()
        });
        let driver = harness.handle.clone();
        let payload = vec![9u8; 1 << 20];
        let mut write = Box::pin(driver.write_at_sync(
            Arc::new(file),
            0,
            IoBufs::from(IoBuf::from(payload.clone())),
        ));
        assert!(poll_once(&harness, &mut write).is_pending());

        // Shutdown drains the write; the future then observes success.
        harness.shutdown();
        match poll_once(&harness, &mut write) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected completed write after drain, got {other:?}"),
        }
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, payload);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shutdown_timeout_cancels_stuck_recv() {
        // Verify a bounded shutdown cancels requests that never complete and
        // the abandoned future observes the timeout result.
        let mut harness = TestLoop::new(RingConfig {
            shutdown_timeout: Some(Duration::from_millis(200)),
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();
        assert_eq!(harness.pending(), 1);

        let start = Instant::now();
        harness.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "bounded shutdown took {:?}",
            start.elapsed()
        );

        // The cancelled recv parked its timeout result for the live future.
        match poll_once(&harness, &mut recv) {
            Poll::Ready(Err((_, Error::Timeout))) => {}
            other => panic!("expected cancelled recv timeout, got {other:?}"),
        }
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_shutdown_preserves_deadline_result() {
        // Verify an op whose own deadline expires during the drain reports
        // timeout even when the shutdown budget is longer.
        let mut harness = TestLoop::new(RingConfig {
            shutdown_timeout: Some(Duration::from_secs(10)),
            max_request_timeout: Duration::from_secs(60),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_millis(100),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();

        let start = Instant::now();
        harness.shutdown();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "deadline-driven drain took {elapsed:?}"
        );

        match poll_once(&harness, &mut recv) {
            Poll::Ready(Err((_, Error::Timeout))) => {}
            other => panic!("expected recv deadline timeout, got {other:?}"),
        }
    }

    #[test]
    fn test_dropped_op_releases_wheel_deadline() {
        // Verify dropping a deadline-carrying op future after first staging
        // releases its timeout-wheel accounting: a leaked tick would make the
        // wheel report an elapsed deadline forever, degrading park into a
        // busy loop.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(1),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_millis(50),
        ));

        // Admit and submit the recv (first staging schedules the deadline).
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();
        assert_eq!(harness.pending(), 1);

        // Drop the future: orphan plus eager async-cancel.
        drop(recv);
        let start = Instant::now();
        while harness.tracked() != 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "orphaned recv still tracked after {:?}",
                start.elapsed()
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }

        // No waiters remain, so once the original deadline elapses the wheel
        // must not report an active deadline.
        std::thread::sleep(Duration::from_millis(100));
        harness.driver().turn();
        assert_eq!(
            harness.driver().inner.timeout_wheel.next_deadline(),
            None,
            "dropped op leaked its timeout-wheel deadline"
        );
    }

    #[test]
    fn test_cross_thread_wake_lands_with_saturated_submission_queue() {
        // Verify the wake poll wins its rearm retry against a single-slot SQ
        // (where it competes with op SQEs for the only entry) so an
        // out-of-band wake still unparks a blocked loop.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        // Keep a recv in flight so park blocks in the eventfd-backed path.
        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();
        assert_eq!(harness.pending(), 1);

        // Wake from a foreign thread after the loop has had time to block.
        let waker = harness.driver().waker();
        let start = Instant::now();
        let wake_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            waker.wake();
        });
        harness.driver().park(None);
        let elapsed = start.elapsed();
        wake_thread.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(5),
            "cross-thread wake did not unpark the loop: {elapsed:?}"
        );

        // Drop the recv before the harness so shutdown cancels it eagerly.
        drop(recv);
    }

    #[test]
    fn test_fill_reports_sq_pressure_over_waiter_pressure() {
        // Verify the staging-pressure dominance rule directly: a full SQ with
        // staged work remaining must report submission-queue pressure (so the
        // turn loop flushes and restages) even when the slab is also full,
        // and only a full slab with nothing left to stage reports waiter
        // pressure.
        let mut harness = TestLoop::new(RingConfig {
            size: 2,
            ..Default::default()
        });
        let (left_a, _right_a) = UnixStream::pair().unwrap();
        let (left_b, _right_b) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv_a = Box::pin(driver.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let mut recv_b = Box::pin(driver.recv(
            Arc::new(left_b.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut recv_a).is_pending());
        assert!(poll_once(&harness, &mut recv_b).is_pending());

        // First pass: the wake-poll rearm plus one op fill the two-slot SQ
        // while the second op stays staged, so SQ pressure must dominate the
        // (also true) waiter-capacity pressure.
        let driver_state = harness.handle.clone();
        let driver = harness.driver();
        let fill = driver_state
            .with(|shared| driver.inner.fill_submission_queue(shared, &mut driver.ring));
        assert_eq!(fill, FillResult::AtSubmissionQueueCapacity);

        // After flushing, the second op stages and nothing remains queued, so
        // the full slab now reports waiter pressure.
        driver.inner.submit(&mut driver.ring).unwrap();
        let fill = driver_state
            .with(|shared| driver.inner.fill_submission_queue(shared, &mut driver.ring));
        assert_eq!(fill, FillResult::AtWaiterCapacity);

        drop(recv_a);
        drop(recv_b);
    }

    #[test]
    fn test_drain_retires_staged_cancelled_op_without_blocking() {
        // Verify drain breaks after staging locally retires the last waiter:
        // an op admitted but never submitted whose ticket dropped must not
        // leave drain blocked in a kernel wait that nothing will complete.
        let mut harness = TestLoop::new(RingConfig {
            shutdown_timeout: None,
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        // Admit without turning the loop, then drop: the entry stays in the
        // staged queue in cancel-requested state.
        assert!(poll_once(&harness, &mut recv).is_pending());
        drop(recv);

        let start = Instant::now();
        harness.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "drain blocked on a locally-retired op: {:?}",
            start.elapsed()
        );
        assert_eq!(harness.pending(), 0);
    }

    #[test]
    fn test_drain_restages_partial_recv_to_completion() {
        // Verify requeued partial progress keeps advancing inside the drain
        // loop: an exact recv that has consumed part of its target must be
        // restaged by drain until the remaining bytes complete it.
        let mut harness = TestLoop::new(RingConfig {
            shutdown_timeout: None,
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, right) = UnixStream::pair().unwrap();
        (&right).write_all(&[1]).unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(2),
            0,
            2,
            true,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();

        // Supply the rest before shutdown so drain can finish the requeue.
        (&right).write_all(&[2]).unwrap();

        let start = Instant::now();
        harness.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "drain did not restage the partial recv: {:?}",
            start.elapsed()
        );

        match poll_once(&harness, &mut recv) {
            Poll::Ready(Ok((_, read))) => assert_eq!(read, 2),
            other => panic!("expected completed exact recv after drain, got {other:?}"),
        }
    }

    #[test]
    fn test_off_thread_drop_leaks_slot_until_shutdown() {
        // Verify the documented off-thread drop behavior: the slot leaks
        // (rather than freeing kernel-referenced buffers) and a bounded
        // shutdown reclaims it.
        let mut harness = TestLoop::new(RingConfig {
            shutdown_timeout: Some(Duration::from_millis(200)),
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv = Box::pin(driver.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();
        assert_eq!(harness.tracked(), 1);

        // Drop the admitted future on a foreign thread: the affinity check
        // rejects the orphan path, so the slot must stay tracked.
        std::thread::scope(|scope| {
            scope.spawn(move || drop(recv)).join().unwrap();
        });
        harness.driver().turn();
        assert_eq!(
            harness.tracked(),
            1,
            "off-thread drop must leak the slot, not free it"
        );

        // The shutdown budget force-cancels the leaked op promptly.
        let start = Instant::now();
        harness.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "shutdown did not reclaim the leaked slot: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_closed_driver_fails_capacity_parked_admission() {
        // Verify an admission parked on the capacity wait list observes a
        // driver close and resolves with its kind-specific error instead of
        // re-parking.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left_a, _right_a) = UnixStream::pair().unwrap();
        let (left_b, _right_b) = UnixStream::pair().unwrap();

        let driver = harness.handle.clone();
        let mut recv_a = Box::pin(driver.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let mut recv_b = Box::pin(driver.recv(
            Arc::new(left_b.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));

        // Fill the single slot, then park the second admission.
        assert!(poll_once(&harness, &mut recv_a).is_pending());
        harness.driver().turn();
        assert!(poll_once(&harness, &mut recv_b).is_pending());

        // Close the driver: the parked admission must fail on its next poll.
        for waker in harness.driver().close() {
            waker.wake();
        }
        match poll_once(&harness, &mut recv_b) {
            Poll::Ready(Err((_, Error::RecvFailed))) => {}
            other => panic!("expected closed-driver recv failure, got {other:?}"),
        }

        drop(recv_a);
    }

    #[test]
    fn test_mass_timeout_cancel_burst_exceeds_sq_capacity() {
        // Verify a timeout burst whose cancel SQEs exceed one SQ pass batches
        // across submit cycles instead of stranding in-flight waiters.
        let mut harness = TestLoop::new(RingConfig {
            size: 8,
            max_request_timeout: Duration::from_secs(1),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        });

        let driver = harness.handle.clone();
        let mut sockets = Vec::new();
        let mut recvs = Vec::new();
        for _ in 0..8 {
            let (left, right) = UnixStream::pair().unwrap();
            sockets.push(right);
            recvs.push(Box::pin(driver.recv(
                Arc::new(left.into()),
                IoBufMut::with_capacity(1),
                0,
                1,
                false,
                Instant::now() + Duration::from_millis(60),
            )));
        }
        for recv in &mut recvs {
            assert!(poll_once(&harness, recv).is_pending());
        }
        harness.driver().turn();

        // Let every deadline expire, then drive all ops to their timeout
        // results: the cancel burst plus the wake-poll rearm exceeds the
        // eight-slot SQ and must batch.
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        let results = harness.block_on(futures::future::join_all(recvs));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancel burst did not batch: {:?}",
            start.elapsed()
        );
        for result in results {
            assert!(matches!(result, Err((_, Error::Timeout))));
        }
    }

    #[test]
    fn test_single_issuer_ring_construction() {
        // Verify the single-issuer + defer-taskrun configuration constructs on
        // the calling thread (the runtime always enables it).
        let cfg = RingConfig {
            single_issuer: true,
            ..Default::default()
        };
        let ring = new_ring(&cfg).expect("single issuer ring should construct");
        drop(ring);
    }
}
