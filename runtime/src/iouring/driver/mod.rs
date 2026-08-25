//! The io_uring driver: the owned event loop and ring ([Driver]) and the
//! shared op state that futures submit through ([Handle]).
//!
//! See [crate::iouring] for the full request flow and liveness discussion.

mod handle;
pub(crate) use handle::{AcceptTicket, Affine, Handle, Ops};
mod request;
pub(crate) use request::{Cache, RawSocketAddr};
mod timeout;
use timeout::{Tick, TimeoutWheel};
mod waiter;
use waiter::{CompletionId, CompletionOutcome, StageOutcome, WaiterId};
pub(crate) mod waker;
use waker::{WAKE_USER_DATA, Waker};
pub(crate) mod spinner;
use super::RingConfig;
use crate::telemetry::metrics::{Gauge, GaugeValue, Register, raw};
use io_uring::{
    IoUring,
    cqueue::Entry as CqueueEntry,
    opcode::AsyncCancel,
    squeue::SubmissionQueue,
    types::{SubmitArgs, Timespec},
};
use spinner::Spinner;
use std::time::{Duration, Instant};

/// Maximum rounded ring size accepted by [`RingConfig::size`].
///
/// Linux limits an io_uring submission queue to 32,768 entries. Requested
/// sizes are rounded up to the next power of two before validation.
pub const MAX_RING_SIZE: u32 = 32_768;

/// Round and validate a requested submission queue size before any
/// size-proportional driver state is allocated.
fn validated_ring_size(size: u32) -> u32 {
    let size = size
        .checked_next_power_of_two()
        .expect("ring size exceeds u32::MAX");
    assert!(
        size <= MAX_RING_SIZE,
        "rounded ring size must be at most {}",
        MAX_RING_SIZE
    );
    size
}

/// Packed `io_uring` `user_data` value.
type UserData = u64;

/// Tracks io_uring metrics.
#[derive(Debug)]
pub(crate) struct Metrics {
    /// Number of logical requests retained by the driver. Internal SQEs (the
    /// wake poll and async cancels) are not counted. Active waiters and Ready
    /// detached ticket completions count once each.
    /// This is updated in the main loop and at shutdown drain exit, so it may
    /// temporarily vary from the exact in-flight count between update points.
    pending_operations: PendingOperations,
}

impl Metrics {
    pub(crate) fn new(registry: &mut impl Register) -> Self {
        Self {
            pending_operations: PendingOperations {
                gauge: registry.register(
                    "pending_operations",
                    "Number of retained logical operations in the io_uring loop",
                    raw::Gauge::default(),
                ),
                reported: 0,
            },
        }
    }
}

/// One driver's contribution to the runtime-wide pending-operations gauge.
///
/// Every worker's driver registers the same gauge (the registry dedups by
/// name and attributes), so absolute `set`s from different workers would
/// overwrite one another. Each driver instead applies the delta since its
/// last report, which sums correctly across workers.
#[derive(Debug)]
struct PendingOperations {
    gauge: Gauge,
    /// The count this driver last folded into the shared gauge.
    reported: GaugeValue,
}

impl PendingOperations {
    /// Fold this driver's current pending count into the shared gauge.
    fn report(&mut self, pending: usize) {
        let pending = pending as GaugeValue;
        if pending > self.reported {
            self.gauge.inc_by(pending - self.reported);
        } else if pending < self.reported {
            self.gauge.dec_by(self.reported - pending);
        }
        self.reported = pending;
    }
}

impl Drop for PendingOperations {
    fn drop(&mut self) {
        // Remove this driver's contribution: the drain can exit with Ready
        // escaped tickets still counted, and a destroyed ring must not leave
        // the shared gauge permanently inflated.
        self.report(0);
    }
}

/// io_uring event loop state.
pub(crate) struct IoUringLoop {
    cfg: RingConfig,
    metrics: Metrics,
    /// Shared op state, also reachable from the front-ends' op futures.
    handle: Handle,
    timeout_wheel: TimeoutWheel,
    idle_spinner: Spinner,
    waker: Waker,
    wake_rearm_needed: bool,
    /// Scratch list of state panics, task-waker drops, and callbacks collected
    /// under the owner-state borrow and handled after it is released.
    pending_waker_actions: Vec<handle::WakerAction>,
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
    fn from_fill_state(ops: &Ops, submission_queue: &SubmissionQueue<'_>) -> Self {
        if submission_queue.is_full()
            && (!ops.backlog.is_empty() || !ops.pending_cancels.is_empty())
        {
            return Self::AtSubmissionQueueCapacity;
        }
        if ops.waiters.is_full() {
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
    pub(crate) fn new(
        mut cfg: RingConfig,
        registry: &mut impl Register,
    ) -> Result<(IoUring, Handle, Self), std::io::Error> {
        assert!(
            !cfg.max_request_timeout.is_zero(),
            "max_request_timeout must be non-zero for timeout wheel"
        );
        assert!(
            !cfg.timeout_wheel_tick.is_zero(),
            "timeout_wheel_tick must be non-zero for timeout wheel"
        );
        cfg.size = validated_ring_size(cfg.size);

        // Ask the kernel to construct the ring before allocating the waiter
        // table whose capacity is proportional to the requested ring size.
        let ring = new_ring(&cfg)?;
        let size = cfg.size as usize;
        let metrics = Metrics::new(registry);
        let waker = Waker::new().expect("unable to create wake eventfd");
        let timeout_wheel = TimeoutWheel::new(
            cfg.max_request_timeout,
            cfg.timeout_wheel_tick,
            Instant::now(),
        );
        let idle_spinner = Spinner::new(&cfg.idle_spinner, || waker.signalled());
        let handle = Handle::new(size, waker.clone());

        Ok((
            ring,
            handle.clone(),
            Self {
                cfg,
                metrics,
                handle,
                timeout_wheel,
                idle_spinner,
                waker,
                wake_rearm_needed: true,
                pending_waker_actions: Vec::new(),
            },
        ))
    }

    /// Invoke every collected task waker.
    ///
    /// Must be called outside any borrow of the driver state: wakers reenter
    /// executor scheduling but never the loop state itself.
    fn flush_wakers(&mut self) {
        handle::wake_batch(self.pending_waker_actions.drain(..));
    }

    /// Reconcile FIFO capacity grants against the waiter table.
    ///
    /// Called after every actual waiter removal. Each granted task owns its
    /// permit until admission or cancellation, so later polls cannot barge.
    fn notify_capacity(&mut self, ops: &mut Ops) {
        ops.capacity
            .reconcile(ops.waiters.free_len(), &mut self.pending_waker_actions);
    }

    /// Wind down work dropped on a foreign thread (see
    /// [handle::OrphanMailbox]): admitted waiters orphan exactly as an
    /// on-thread drop would, and parked admission attempts release their
    /// capacity slots.
    fn process_orphans(&mut self, ops: &mut Ops) {
        for orphan in self.handle.orphans.take() {
            match orphan {
                handle::Orphan::Waiter(id) => {
                    handle::wind_down_orphan(ops, id, &mut self.pending_waker_actions);
                }
                handle::Orphan::Completion(id) => {
                    let mut capacity_actions = handle::CapacityActions::new();
                    let waker = handle::wind_down_ticket(ops, id, &mut capacity_actions);
                    self.pending_waker_actions
                        .extend(waker.map(handle::WakerAction::Drop));
                    self.pending_waker_actions.extend(capacity_actions);
                }
                handle::Orphan::Capacity(slot) => ops.capacity.cancel(
                    slot,
                    ops.waiters.free_len(),
                    &mut self.pending_waker_actions,
                ),
            }
        }
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
            let (fill_result, kernel_idle) = handle.with(|ops| {
                // Wind down foreign-thread drops first: freed slots and
                // cancel SQEs from the mailbox take effect this turn.
                self.process_orphans(ops);

                // Process available completions.
                for cqe in ring.completion() {
                    self.handle_cqe(ops, cqe);
                }

                // Process due deadlines before staging new submissions so timed-out
                // requests move to cancellation promptly and free capacity sooner.
                self.advance_timeouts(ops);

                // Stage as much admitted work as capacity allows.
                let fill_result = self.fill_submission_queue(ops, ring);

                // Update pending operations metric.
                self.metrics
                    .pending_operations
                    .report(ops.operation_count());

                (fill_result, ops.waiters.pending() == 0)
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
    /// `limit` bounds the wait in addition to the loop's own timeout wheel (the
    /// runtime executor passes the delay until its next sleeper alarm). Callers
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

        let (fully_idle, waiters_full) = self.handle.with(|ops| {
            (
                ops.waiters.pending() == 0
                    && ops.backlog.is_empty()
                    && ops.pending_cancels.is_empty(),
                ops.waiters.is_full(),
            )
        });

        // If the ring is truly idle and no deadline is pending, avoid
        // `io_uring_enter` entirely and wait on the shared wake state via
        // futex until another thread latches a wake. Before parking, spin
        // briefly to avoid the futex round-trip when work is imminent.
        if fully_idle && deadline.is_none() {
            // A wake that lands during the spin ends it early, and `park_idle`'s
            // post-arm snapshot then consumes the latch without a futex round
            // trip. The spin must not skip `park_idle` on a hit: only the
            // arm-and-clear cycle consumes the latch, and leaving it set
            // would make every subsequent idle park return instantly.
            self.idle_spinner.spin(|| self.waker.signalled());
            if let Some(park_duration) = self.waker.park_idle() {
                self.idle_spinner.on_wake(park_duration);
            }
            return;
        }

        // Otherwise, arm the eventfd-backed blocking path. Under
        // waiter-capacity pressure, admissions cannot proceed until
        // completions free capacity, so block unless an out-of-band wake
        // (e.g. a task wake) is latched. Otherwise block only if the post-arm
        // snapshot still looks idle (no latched wake).
        let arm = self.waker.arm();
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
    /// If the request was marked for cancellation while sitting in the
    /// backlog (deadline expiry, runtime shutdown, or ticket drop between
    /// requeue and staging), it is completed with the reason's error
    /// (timeout for a deadline, closed for shutdown) or retired for a
    /// dropped ticket instead of issuing a follow-up SQE.
    fn stage_request(
        &mut self,
        ops: &mut Ops,
        waiter_id: WaiterId,
        submission_queue: &mut SubmissionQueue<'_>,
    ) {
        match ops.waiters.stage(waiter_id) {
            StageOutcome::Complete { waker, freed } => {
                self.pending_waker_actions
                    .extend(waker.map(handle::WakerAction::Wake));
                if freed {
                    self.notify_capacity(ops);
                }
            }
            StageOutcome::Ticket {
                waiter_id,
                completion_id,
                output,
            } => self.complete_ticket(ops, waiter_id, completion_id, output, None),
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

    /// Stage admitted requests from the backlog in FIFO order.
    ///
    /// The first staging of a request that carries a deadline converts it to
    /// a wheel tick (aligning the wheel when it was previously idle), and
    /// already-expired deadlines complete immediately with timeout before any
    /// SQE is issued.
    ///
    /// Stops when all queued requests are staged or the SQ reaches capacity.
    /// Returns `true` when SQ capacity is hit and at least one backlog
    /// request remains queued.
    fn stage_backlog(&mut self, ops: &mut Ops, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = ops.backlog.pop_front() else {
                return false;
            };

            if let Some(deadline) = ops.waiters.deadline_to_schedule(waiter_id) {
                // Avoid per-request clock reads when no deadlines are active.
                // When the first deadline arrives after an idle period, align
                // wheel time once before converting deadlines to ticks.
                if self.timeout_wheel.next_deadline().is_none() {
                    assert!(self.timeout_wheel.advance(Instant::now()).is_none());
                }
                match self.timeout_wheel.target_tick(deadline) {
                    Some(tick) => {
                        ops.waiters.set_target_tick(waiter_id, tick);
                        self.timeout_wheel.schedule(waiter_id, tick);
                    }
                    // The deadline already expired: transition to cancellation
                    // so staging below completes the request with timeout.
                    None => assert!(ops.waiters.cancel(waiter_id)),
                }
            }

            self.stage_request(ops, waiter_id, submission_queue);
        }

        !ops.backlog.is_empty()
    }

    /// Stage pending submission work into the SQ.
    ///
    /// In one pass, this may rearm wake polling, stage cancellations, and
    /// stage admitted requests.
    ///
    /// Returns why staging stopped.
    fn fill_submission_queue(&mut self, ops: &mut Ops, ring: &mut IoUring) -> FillResult {
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
        if self.stage_cancellations(ops, &mut submission_queue) {
            return FillResult::from_fill_state(ops, &submission_queue);
        }

        // Stage admitted requests in FIFO order.
        if self.stage_backlog(ops, &mut submission_queue) {
            return FillResult::from_fill_state(ops, &submission_queue);
        }

        FillResult::from_fill_state(ops, &submission_queue)
    }

    /// Stage queued cancellation SQEs from `pending_cancels` in FIFO order.
    ///
    /// Stops when all queued cancellations are staged or the SQ reaches
    /// capacity. Returns `true` when SQ capacity is hit and at least one
    /// cancellation remains queued.
    fn stage_cancellations(
        &mut self,
        ops: &mut Ops,
        submission_queue: &mut SubmissionQueue<'_>,
    ) -> bool {
        while !submission_queue.is_full() {
            let Some(waiter_id) = ops.pending_cancels.pop_front() else {
                return false;
            };

            // This waiter was cancelled earlier, but its queued cancel may
            // have gone stale before we got around to staging it. If the
            // original op CQE already retired the outstanding SQE, there is
            // nothing left for the kernel to cancel.
            if !ops.waiters.is_in_flight(waiter_id) {
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

        !ops.pending_cancels.is_empty()
    }

    /// Handle a single CQE from the ring.
    ///
    /// Internal wake CQEs are handled in-place. All other CQEs are forwarded to
    /// the request state machine for progress evaluation.
    fn handle_cqe(&mut self, ops: &mut Ops, cqe: CqueueEntry) {
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

        match ops.waiters.on_completion(user_data, cqe.result()) {
            CompletionOutcome::Cancel => {
                // Async-cancel CQEs are handled entirely inside `Waiters`. They do
                // not directly complete or requeue a logical request here.
            }
            CompletionOutcome::Requeue(waiter_id) => {
                // Request needs another SQE. Add it back to the backlog.
                ops.backlog.push_back(waiter_id);
            }
            CompletionOutcome::Complete {
                waker,
                target_tick,
                freed,
            } => {
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
                self.pending_waker_actions
                    .extend(waker.map(handle::WakerAction::Wake));
                if freed {
                    self.notify_capacity(ops);
                }
            }
            CompletionOutcome::Ticket {
                waiter_id,
                completion_id,
                output,
                target_tick,
            } => self.complete_ticket(ops, waiter_id, completion_id, output, target_tick),
        }
    }

    /// Transfer a terminal detached-ticket output away from its waiter.
    ///
    /// State publication, timeout removal, and waiter recycling all precede
    /// collection of ticket and capacity wakers. The wakers themselves run
    /// only after the surrounding op-state borrow is released.
    fn complete_ticket(
        &mut self,
        ops: &mut Ops,
        waiter_id: WaiterId,
        completion_id: CompletionId,
        output: request::Output,
        target_tick: Option<Tick>,
    ) {
        let waker = ops
            .completions
            .publish_ready(completion_id, waiter_id, output);
        if let Some(tick) = target_tick {
            self.timeout_wheel.remove(tick);
        }
        ops.waiters.finish_ticket(waiter_id, completion_id);
        self.pending_waker_actions
            .extend(waker.map(handle::WakerAction::Wake));
        self.notify_capacity(ops);
    }

    /// Advance the timeout wheel and enqueue cancellations for newly expired requests.
    ///
    /// This is a no-op when no active deadlines exist. Expired stale wheel
    /// entries are ignored when waiter generation no longer matches.
    fn advance_timeouts(&mut self, ops: &mut Ops) {
        // Release deadline accounting for ops whose tickets were dropped: the
        // wheel is loop-owned, so drop paths queue removals instead. Without
        // this the wheel would report the stale tick as the next deadline
        // forever once it elapsed.
        for tick in ops.released_deadlines.drain(..) {
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
            if ops.waiters.cancel(entry.waiter_id) {
                // Once cancel is requested, this waiter is no longer deadline-active.
                self.timeout_wheel.remove(entry.target_tick);
                // Only timed-out waiters with an outstanding op SQE need
                // AsyncCancel. Waiters parked in the backlog have no kernel
                // op to cancel and will time out locally when restaged.
                if ops.waiters.is_in_flight(entry.waiter_id) {
                    ops.pending_cancels.push_back(entry.waiter_id);
                }
            }
        }
    }

    /// Request cancellation of every progressing waiter.
    ///
    /// Cancelled waiters leave the timeout wheel, in-flight waiters get an
    /// async-cancel SQE queued, and waiters parked in the backlog retire
    /// locally when restaged.
    fn cancel_all(&mut self, ops: &mut Ops) {
        for (waiter_id, target_tick, in_flight) in ops.waiters.cancel_active() {
            if let Some(tick) = target_tick {
                self.timeout_wheel.remove(tick);
            }
            if in_flight {
                ops.pending_cancels.push_back(waiter_id);
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
            let pending = handle.with(|ops| {
                // Foreign-thread drops during shutdown release parked slots
                // and cancel in-flight work, speeding the drain.
                self.process_orphans(ops);
                for cqe in ring.completion() {
                    self.handle_cqe(ops, cqe);
                }
                ops.waiters.pending()
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
                handle.with(|ops| self.cancel_all(ops));
            }

            // Keep userspace deadline processing alive during shutdown so
            // in-flight timed operations preserve their ETIMEDOUT semantics,
            // and continue staging requeued requests so partially-complete or
            // retrying requests can keep making progress.
            let pending = handle.with(|ops| {
                self.advance_timeouts(ops);
                {
                    let mut submission_queue = ring.submission();
                    self.stage_cancellations(ops, &mut submission_queue);
                    self.stage_backlog(ops, &mut submission_queue);
                    // Keep the eventfd wake path live during shutdown: a
                    // foreign-thread drop pushes into the orphan mailbox and
                    // must be able to wake a drain blocked in
                    // `submit_and_wait`. Rearm strictly AFTER staging so the
                    // poll SQE can never displace the staging that retires
                    // waiters (on a size-1 ring it would consume the whole
                    // SQ and deadlock an unbounded wait). If staging filled
                    // the SQ first, the flush below retries before any armed
                    // wait.
                    if self.wake_rearm_needed && self.waker.reinstall(&mut submission_queue) {
                        self.wake_rearm_needed = false;
                    }
                }
                ops.waiters.pending()
            });
            self.flush_wakers();

            // Staging can directly complete the last waiter (for example, when a
            // timed-out requeued request is retired instead of reissued).
            if pending == 0 {
                break;
            }

            // The wake poll must be live before any armed wait: with it
            // terminated, an orphan wake writes the eventfd without
            // producing a CQE and an unbounded wait sleeps through it. If
            // staging filled the SQ before the rearm landed, flush without
            // waiting and retry (each flush drains the SQ, and requeues need
            // a CQE apiece, so the retry converges).
            if self.wake_rearm_needed {
                self.submit(ring).expect("unable to submit to ring");
                continue;
            }

            let timeout = match (remaining, self.timeout_wheel.next_deadline()) {
                (Some(remaining), Some(deadline)) => Some(remaining.min(deadline)),
                (Some(remaining), None) => Some(remaining),
                (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            };

            // Wait for at least one completion or timeout, with the eventfd
            // wake path armed: a foreign-thread drop pushes into the orphan
            // mailbox and must be able to interrupt this wait (an unarmed
            // wake only latches the state word without writing the eventfd).
            // When a wake is already latched, skip blocking and let the next
            // iteration process the mailbox. The guard's drop consumes the
            // latch either way.
            let arm = self.waker.arm();
            if !arm.wake_latched() {
                let start = Instant::now();
                self.submit_and_wait(ring, 1, timeout)
                    .expect("unable to submit to ring");

                // Charge elapsed wall time against the shutdown budget.
                if let Some(remaining) = remaining.as_mut() {
                    *remaining = remaining.saturating_sub(start.elapsed());
                }
            }
            drop(arm);
        }

        let handle = self.handle.clone();
        handle.with(|ops| {
            self.metrics
                .pending_operations
                .report(ops.operation_count());
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
    // Every ring is created and submitted by one worker thread. SINGLE_ISSUER
    // records that invariant for the kernel, while DEFER_TASKRUN processes
    // completions only during io_uring_enter calls with GETEVENTS. Every turn,
    // including the wake fast path, eventually makes such a call.
    //
    // DEFER_TASKRUN requires SINGLE_ISSUER and both flags require Linux 6.1.
    builder = builder.setup_single_issuer();
    builder = builder.setup_defer_taskrun();

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
        let (ring, handle, inner) = IoUringLoop::new(cfg, registry)?;
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

    /// Close the shared op state and wake every parked admission.
    ///
    /// The state is invalidated before callbacks run. All callbacks are
    /// attempted even if one panics, then the earliest panic is resumed.
    pub(crate) fn close(&self) {
        let wakers = self.inner.handle.close();
        handle::wake_batch(wakers.into_iter().map(handle::WakerAction::Wake));
    }

    /// Drain in-flight ring work so kernel-owned buffers and descriptors are
    /// released, consuming the driver: the ring is destroyed afterwards.
    ///
    /// A panic inside the drain aborts the process: unwinding would destroy
    /// the ring and release the driver's op-table reference while the kernel
    /// may still write into request buffers.
    pub(crate) fn drain(mut self) {
        // The guard must live inside this frame: locals drop before
        // parameters during unwind, so the abort fires while `self` (the
        // ring and its op-table reference) is still alive. A guard at any
        // call site would run only after unwinding out of this frame had
        // already dropped them.
        let guard = AbortOnUnwind;
        self.inner.drain(&mut self.ring);
        std::mem::forget(guard);
    }
}

/// Aborts the process when dropped during an unwind (see [Driver::drain]).
struct AbortOnUnwind;

impl Drop for AbortOnUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("io_uring drain panicked with operations in flight, aborting");
            std::process::abort();
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A single-threaded harness for tests that drive the loop
    //! directly (loop, network, and storage unit tests).

    use super::*;
    use crate::telemetry::metrics::Registry;
    use futures::task::{ArcWake, waker as arc_waker};
    use std::{
        future::Future,
        pin::{Pin, pin},
        sync::Arc,
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
        pub(crate) fn new(cfg: RingConfig) -> Self {
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
        fn waker(&self) -> std::task::Waker {
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
            // Mirror the runtime's teardown: a waker panic must not skip the
            // drain (drain panics abort inside [Driver::drain]).
            let wakers =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.close()));
            driver.drain();
            if let Err(payload) = wakers {
                std::panic::resume_unwind(payload);
            }
        }

        /// Number of tracked logical operations, including Ready tickets.
        pub(crate) fn tracked(&self) -> usize {
            self.handle.with(|ops| ops.operation_count())
        }

        /// Number of waiters still progressing.
        pub(crate) fn pending(&self) -> usize {
            self.handle.with(|ops| ops.waiters.pending())
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
    use super::{handle::SyncTicket, testing::*, *};
    use crate::{Error, IoBuf, IoBufMut, IoBufs, WriteOptions, telemetry::metrics::Registry};
    use futures::task::{ArcWake, waker as arc_waker};
    use std::{
        fs::File,
        future::Future,
        io::{Read, Write},
        os::{
            fd::{FromRawFd, IntoRawFd, OwnedFd},
            unix::net::UnixStream,
        },
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker as TaskWaker},
        time::{Duration, Instant},
    };

    #[test]
    fn test_iouring_loop_rounds_ring_size_up_to_power_of_two() {
        let cfg = RingConfig {
            size: 100,
            ..Default::default()
        };
        let mut registry = Registry::default();
        let (_ring, _handle, ioloop) =
            IoUringLoop::new(cfg, &mut registry).expect("io_uring creation should succeed");
        assert_eq!(ioloop.cfg.size, 128);
    }

    #[test]
    fn test_ring_size_accepts_linux_limit_after_rounding() {
        assert_eq!(MAX_RING_SIZE, 32_768);
        assert_eq!(validated_ring_size(MAX_RING_SIZE / 2 + 1), MAX_RING_SIZE);
        assert_eq!(validated_ring_size(MAX_RING_SIZE), MAX_RING_SIZE);
    }

    #[test]
    fn test_ring_size_rejects_rounded_size_above_linux_limit() {
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validated_ring_size(MAX_RING_SIZE + 1);
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
        // SAFETY: the fd is intentionally invalidated, and the harness issues
        // no further ring operations after the failed wait.
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

        let handle = harness.handle.clone();
        let (mut buf, read) = harness
            .block_on(handle.recv(
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

        let handle = harness.handle.clone();
        let start = Instant::now();
        let result = harness.block_on(handle.recv(
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
        let handle = harness.handle.clone();
        let (_buf1, read1) = harness
            .block_on(handle.recv(
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
        let result2 = harness.block_on(handle.recv(
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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

        let handle = harness.handle.clone();
        let start = Instant::now();
        let result = harness.block_on(handle.recv(
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
        let handle = harness.handle.clone();
        let _ = harness.block_on(handle.recv(
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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

        // The backlog entry is retired locally on the next turn.
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
        let handle = harness.handle.clone();
        let payload = vec![7u8; 1 << 20];
        let mut write = Box::pin(handle.write_at(
            Arc::new(file),
            0,
            IoBufs::from(IoBuf::from(payload.clone())),
            WriteOptions::SYNC,
            Cache::Enabled,
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
    fn test_capacity_fifo_grant_admits_waiting_op() {
        // Verify a FIFO-granted op admits once its reserved slot frees.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let (left_a, right_a) = UnixStream::pair().unwrap();
        let (left_b, right_b) = UnixStream::pair().unwrap();

        let handle = harness.handle.clone();
        let recv_a = handle.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(5),
        );
        let recv_b = handle.recv(
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
    fn test_pending_operations_aggregates_across_drivers() {
        // Every worker's driver registers the same pending-operations gauge
        // (the registry dedups by name): drivers must fold deltas into it
        // rather than set absolute values, and a destroyed driver must remove
        // its own contribution, including Ready escaped tickets, which
        // survive the drain without retaining a waiter.
        let mut registry = Registry::default();
        // Registration dedup hands back the same gauge the drivers share.
        let gauge: crate::telemetry::metrics::Gauge = Register::register(
            &mut registry,
            "pending_operations",
            "Number of retained logical operations in the io_uring loop",
            raw::Gauge::default(),
        );
        let (mut driver_a, handle_a) = Driver::new(RingConfig::default(), &mut registry).unwrap();
        let (mut driver_b, _handle_b) = Driver::new(RingConfig::default(), &mut registry).unwrap();

        // Admit a sync whose ticket is never awaited. Its terminal result
        // parks in driver A's completion arena after a socket fd fails fsync.
        let (socket, _peer) = UnixStream::pair().unwrap();
        // SAFETY: `into_raw_fd` transfers ownership of the socket fd into
        // `File`.
        let file = unsafe { std::fs::File::from_raw_fd(socket.into_raw_fd()) };
        let mut admit = Box::pin(handle_a.start_sync(Arc::new(file)));
        let noop = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&noop);
        let Poll::Ready(ticket) = admit.as_mut().poll(&mut cx) else {
            panic!("admission should not park on an empty slab");
        };

        // Driver A reports its pending op, and an idle driver B turn must not
        // clobber that contribution.
        driver_a.turn();
        assert_eq!(gauge.get(), 1);
        driver_b.turn();
        assert_eq!(gauge.get(), 1);

        // Close and drain A: the parked result survives the drain, but
        // destroying the driver removes its contribution from the shared
        // gauge.
        driver_a.close();
        driver_a.drain();
        assert_eq!(gauge.get(), 0);

        drop(ticket);
    }

    #[test]
    fn test_ticket_metric_counts_pending_and_ready_once() {
        let mut registry = Registry::default();
        let gauge: crate::telemetry::metrics::Gauge = Register::register(
            &mut registry,
            "pending_operations",
            "Number of retained logical operations in the io_uring loop",
            raw::Gauge::default(),
        );
        let (mut driver, handle) = Driver::new(
            RingConfig {
                size: 1,
                ..Default::default()
            },
            &mut registry,
        )
        .unwrap();

        // Pending completion entries mirror a live waiter and count once.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut accept_admission = Box::pin(handle.start_accept(
            Arc::new(OwnedFd::from(listener)),
            Instant::now() + Duration::from_secs(60),
        ));
        let noop = futures::task::noop_waker();
        let mut cx = Context::from_waker(&noop);
        let Poll::Ready(accept_ticket) = accept_admission.as_mut().poll(&mut cx) else {
            panic!("accept admission unexpectedly parked");
        };
        driver.turn();
        assert_eq!(gauge.get(), 1);
        handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 1);
        });

        drop(accept_ticket);
        let start = Instant::now();
        while handle.with(|ops| ops.waiters.pending()) != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            driver.turn();
            driver.park(Some(Duration::from_millis(10)));
        }
        driver.turn();
        assert_eq!(gauge.get(), 0);

        // A Ready completion has no waiter and still contributes one until
        // its ticket is consumed.
        let (left, _right) = UnixStream::pair().unwrap();
        // SAFETY: `left` is a valid owned fd and is transferred into `File`.
        let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
        let mut sync_admission = Box::pin(handle.start_sync(Arc::new(file)));
        let Poll::Ready(mut sync_ticket) = sync_admission.as_mut().poll(&mut cx) else {
            panic!("sync admission unexpectedly parked");
        };
        let start = Instant::now();
        while handle.with(|ops| ops.waiters.pending()) != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            driver.turn();
            driver.park(Some(Duration::from_millis(10)));
        }
        driver.turn();
        assert_eq!(gauge.get(), 1);
        handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 1);
            assert_eq!(ops.operation_count(), 1);
        });

        assert!(matches!(
            Pin::new(&mut sync_ticket).poll(&mut cx),
            Poll::Ready(Err(_))
        ));
        driver.turn();
        assert_eq!(gauge.get(), 0);
        driver.close();
        driver.drain();
    }

    #[test]
    fn test_foreign_drop_wakes_unbounded_drain() {
        // A drain blocked in an unbounded `submit_and_wait` must be woken by
        // a foreign-thread ticket drop: the orphan-mailbox push must reach
        // the armed eventfd path and cancel the in-flight accept, instead of
        // latching a wake nothing observes while the drain sleeps toward the
        // distant wheel deadline.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(3600),
            ..Default::default()
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd: Arc<OwnedFd> = Arc::new(OwnedFd::from(listener));

        let handle = harness.handle.clone();
        let mut admit =
            Box::pin(handle.start_accept(fd, Instant::now() + Duration::from_secs(3600)));
        let noop = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&noop);
        let Poll::Ready(ticket) = admit.as_mut().poll(&mut cx) else {
            panic!("accept admission should not park on an empty slab");
        };
        harness.driver().turn();
        assert_eq!(harness.pending(), 1);

        // Drop the ticket on a foreign thread once the drain is underway.
        let dropper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(ticket);
        });

        let start = Instant::now();
        harness.driver().close();
        harness.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "drain slept through the foreign-thread drop: {:?}",
            start.elapsed()
        );
        dropper.join().unwrap();
    }

    #[test]
    fn test_drain_rearms_wake_poll_before_armed_wait() {
        // On a size-1 ring, staging can fill the SQ before the wake-poll
        // rearm lands. The drain must flush and retry until the poll is live
        // before blocking: with the poll terminated, a foreign-thread drop
        // writes the eventfd without producing a CQE, and an unbounded wait
        // sleeps through it toward the distant wheel deadline.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            max_request_timeout: Duration::from_secs(3600),
            ..Default::default()
        });
        let handle = harness.handle.clone();

        // Admit a recv but never turn: at drain entry the request is still
        // in the backlog and the wake poll was never installed, so the
        // drain's first staging pass fills the single-entry SQ before the
        // rearm can land.
        let (left, _right) = UnixStream::pair().unwrap();
        let mut recv = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(3600),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());

        std::thread::scope(|scope| {
            // Drop the recv on a foreign thread once the drain is blocked.
            let dropper = scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                drop(recv);
            });

            let start = Instant::now();
            harness.driver().close();
            harness.shutdown();
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "drain slept behind a dead wake poll: {:?}",
                start.elapsed()
            );
            dropper.join().unwrap();
        });
    }

    #[test]
    fn test_off_thread_drop_releases_capacity_slot() {
        // An admission attempt parked on a full slab and dropped on a
        // foreign thread must release its capacity registration through the
        // orphan mailbox: a saturated ring never drains the wait list, so a
        // retained registration would otherwise persist indefinitely.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();

        let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
        let mut blocker = Box::pin(handle.recv(
            Arc::new(blocker_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut blocker).is_pending());

        let (left, _right) = UnixStream::pair().unwrap();
        let mut parked = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut parked).is_pending());
        harness
            .handle
            .with(|ops| assert_eq!(ops.capacity.registered(), 1));

        // Drop the parked attempt on a foreign thread: the registration
        // routes through the mailbox and the next turn releases it.
        std::thread::scope(|scope| {
            scope.spawn(move || drop(parked)).join().unwrap();
        });
        harness.driver().turn();
        harness
            .handle
            .with(|ops| assert_eq!(ops.capacity.registered(), 0));
    }

    #[test]
    fn test_off_thread_drop_transfers_granted_capacity_slot() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();

        let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
        let mut blocker = Box::pin(handle.recv(
            Arc::new(blocker_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut blocker).is_pending());

        let first_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let first_waker = arc_waker(Arc::clone(&first_count));
        let mut first_cx = Context::from_waker(&first_waker);
        let (first_left, _first_right) = UnixStream::pair().unwrap();
        let mut first = Box::pin(handle.recv(
            Arc::new(first_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(first.as_mut().poll(&mut first_cx).is_pending());

        // The blocker is still in the backlog. Its owner drop and the next
        // turn retire it locally, granting the released slot to `first`.
        drop(blocker);
        harness.driver().turn();
        assert_eq!(first_count.0.load(Ordering::Acquire), 1);
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        let second_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let second_waker = arc_waker(Arc::clone(&second_count));
        let mut second_cx = Context::from_waker(&second_waker);
        let (second_left, _second_right) = UnixStream::pair().unwrap();
        let mut second = Box::pin(handle.recv(
            Arc::new(second_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(second.as_mut().poll(&mut second_cx).is_pending());
        assert_eq!(second_count.0.load(Ordering::Acquire), 0);

        // A foreign drop routes the granted CapacityId through the mailbox.
        // Cancelling it transfers the reserved permit to the queued head.
        std::thread::scope(|scope| {
            scope.spawn(move || drop(first)).join().unwrap();
        });
        harness.driver().turn();
        assert_eq!(second_count.0.load(Ordering::Acquire), 1);
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        drop(second);
        assert_eq!(harness.tracked(), 0);
    }

    /// Park a completed sync ticket's terminal result in its independent
    /// completion entry while retaining the ticket.
    ///
    /// fsync on a socket-backed file fails fast, so the terminal error parks
    /// in the completion entry while the returned ticket is held.
    fn park_sync_ticket(harness: &mut TestLoop, handle: &Handle) -> SyncTicket {
        let (left, _right) = UnixStream::pair().unwrap();
        // SAFETY: `left` is a valid owned fd and is transferred into `File`.
        let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
        let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        // Bounded turn loop: drive the fsync CQE so the result parks.
        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "sync result did not park: {:?}",
                start.elapsed()
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0, "terminal ticket retained a waiter");
            assert_eq!(ops.completions.ready(), 1);
            assert_eq!(ops.operation_count(), 1);
        });
        ticket
    }

    /// Admit and stage an accept that has no peer, leaving its completion
    /// entry Pending and its waiter in flight.
    fn pending_accept_ticket(harness: &mut TestLoop, handle: &Handle) -> AcceptTicket {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = Arc::new(OwnedFd::from(listener));
        let ticket =
            harness.block_on(handle.start_accept(fd, Instant::now() + Duration::from_secs(60)));
        harness.driver().turn();
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 1);
        });
        ticket
    }

    struct WokenFlag(AtomicBool);

    impl ArcWake for WokenFlag {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.store(true, Ordering::Release);
        }
    }

    struct WakeCount(AtomicUsize);

    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn test_ready_ticket_poll_does_not_double_release_capacity() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let (sync_left, _sync_right) = UnixStream::pair().unwrap();
        // SAFETY: `sync_left` is a valid owned fd and is transferred into
        // `File`.
        let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
        let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        // Register a second request while the ticket still owns the only
        // active waiter.
        let (left, _right) = UnixStream::pair().unwrap();
        let mut second = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
        let waker = arc_waker(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        assert!(second.as_mut().poll(&mut cx).is_pending());
        assert_eq!(harness.handle.with(|ops| ops.capacity.registered()), 1);

        // Terminal ticket publication frees the waiter and wakes capacity
        // before the ticket itself is consumed.
        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 1);
            assert_eq!(ops.operation_count(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        assert!(flag.0.load(Ordering::Acquire));

        // The only free waiter is reserved for `second`, so a later poll
        // queues behind it.
        let third_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let third_waker = arc_waker(Arc::clone(&third_count));
        let mut third_cx = Context::from_waker(&third_waker);
        let (third_left, _third_right) = UnixStream::pair().unwrap();
        let mut third = Box::pin(handle.recv(
            Arc::new(third_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(third.as_mut().poll(&mut third_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        // Polling the independently stored Ready output removes no waiter and
        // therefore cannot create or transfer another capacity permit.
        assert!(harness.block_on(ticket).is_err());
        assert_eq!(third_count.0.load(Ordering::Acquire), 0);
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        // The granted request reuses the waiter. Its later terminal removal,
        // not the Ready ticket poll, transfers capacity to `third`.
        assert!(second.as_mut().poll(&mut cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 0);
        });

        drop(second);
        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "second request did not wind down"
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        assert_eq!(third_count.0.load(Ordering::Acquire), 1);
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        drop(third);
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_ready_ticket_drop_does_not_double_release_capacity() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let (sync_left, _sync_right) = UnixStream::pair().unwrap();
        // SAFETY: `sync_left` is a valid owned fd and is transferred into
        // `File`.
        let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
        let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        let (second_left, _second_right) = UnixStream::pair().unwrap();
        let mut second = Box::pin(handle.recv(
            Arc::new(second_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut second).is_pending());
        while harness.pending() != 0 {
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }

        let third_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let third_waker = arc_waker(Arc::clone(&third_count));
        let mut third_cx = Context::from_waker(&third_waker);
        let (third_left, _third_right) = UnixStream::pair().unwrap();
        let mut third = Box::pin(handle.recv(
            Arc::new(third_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(third.as_mut().poll(&mut third_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.completions.ready(), 1);
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        drop(ticket);
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.completions.arena_len(), 1);
            assert_eq!(ops.operation_count(), 0);
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        assert_eq!(third_count.0.load(Ordering::Acquire), 0);

        drop(second);
        assert_eq!(third_count.0.load(Ordering::Acquire), 1);
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        drop(third);
    }

    #[test]
    fn test_ready_ticket_foreign_drop_preserves_reused_waiter() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let ticket = park_sync_ticket(&mut harness, &handle);

        // Reuse the old ticket's waiter with a recv that remains active.
        let (left, _right) = UnixStream::pair().unwrap();
        let mut second = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut second).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 1);
        });

        std::thread::scope(|scope| {
            scope.spawn(move || drop(ticket)).join().unwrap();
        });
        harness.driver().turn();
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1, "Ready drop touched reused waiter");
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 1);
        });

        drop(second);
        while harness.pending() != 0 {
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_pending_accept_owner_drop_cancels_and_reuses_waiter() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let ticket = pending_accept_ticket(&mut harness, &handle);
        drop(ticket);

        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 0);
        });

        // The next accept reuses the freed waiter and retains the exact fd
        // and peer address through its independent completion entry.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();
        let mut reused = harness.block_on(handle.start_accept(
            Arc::new(OwnedFd::from(listener)),
            Instant::now() + Duration::from_secs(60),
        ));
        let mut client = std::net::TcpStream::connect(local_addr).unwrap();
        let expected_remote = client.local_addr().unwrap();
        let (fd, remote) = harness.block_on(&mut reused).unwrap();
        assert_eq!(remote, expected_remote);

        let mut accepted = std::net::TcpStream::from(fd);
        client.write_all(b"x").unwrap();
        let mut byte = [0];
        accepted.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn test_pending_accept_foreign_drop_cancels() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let ticket = pending_accept_ticket(&mut harness, &handle);
        std::thread::scope(|scope| {
            scope.spawn(move || drop(ticket)).join().unwrap();
        });

        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 0);
        });
    }

    #[test]
    fn test_pending_sync_foreign_drop_detaches_until_terminal_completion() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let (sync_left, _sync_right) = UnixStream::pair().unwrap();
        // SAFETY: `sync_left` is a valid owned fd and is transferred into
        // `File`.
        let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
        let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        // Park another admission on the live sync waiter. The counter proves
        // terminal retirement releases this capacity registration once.
        let (waiting_left, _waiting_right) = UnixStream::pair().unwrap();
        let mut waiting = Box::pin(handle.recv(
            Arc::new(waiting_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let count_waker = arc_waker(count.clone());
        let mut count_cx = Context::from_waker(&count_waker);
        assert!(waiting.as_mut().poll(&mut count_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.completions.arena_len(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.operation_count(), 1);
        });

        std::thread::scope(|scope| {
            scope.spawn(move || drop(ticket)).join().unwrap();
        });

        // Process the foreign mailbox before staging so the detach transition
        // is directly observable. Completion state is gone, but sync orphan
        // policy retains the waiter without a cancel SQE or premature
        // capacity release.
        {
            let driver = harness.driver();
            let owner = driver.inner.handle.clone();
            owner.with(|ops| driver.inner.process_orphans(ops));
            driver.inner.flush_wakers();
        }
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 1);
            assert!(ops.pending_cancels.is_empty());
            assert_eq!(ops.capacity.registered(), 1);
        });
        assert_eq!(count.0.load(Ordering::Acquire), 0);

        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            if harness.pending() != 0 {
                harness.driver().park(Some(Duration::from_millis(10)));
            }
        }
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.operation_count(), 0);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        assert_eq!(count.0.load(Ordering::Acquire), 1);

        // Extra loop work cannot notify the granted registration again.
        harness.driver().turn();
        assert_eq!(count.0.load(Ordering::Acquire), 1);
        drop(waiting);
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_accept_ticket_timeout_releases_deadline_before_poll() {
        let mut harness = TestLoop::new(RingConfig {
            timeout_wheel_tick: Duration::from_millis(1),
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ticket = harness.block_on(handle.start_accept(
            Arc::new(OwnedFd::from(listener)),
            Instant::now() + Duration::from_millis(10),
        ));

        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 1);
        });
        assert!(matches!(harness.block_on(ticket), Err(Error::Timeout)));
    }

    /// Waker that panics whenever the driver or a completing op invokes it.
    struct PanicWaker;

    impl ArcWake for PanicWaker {
        fn wake_by_ref(_: &Arc<Self>) {
            panic!("intentional test waker panic");
        }
    }

    /// Counters observed by the clone-panic capacity test waker.
    struct ClonePanicWakerState {
        /// Number of attempted RawWaker clones.
        clones: AtomicUsize,
        /// Number of consuming wake callbacks.
        wakes: AtomicUsize,
    }

    /// Clone the capacity test waker, panicking on its second clone attempt.
    ///
    /// # Safety
    ///
    /// `data` must be an `Arc<ClonePanicWakerState>` pointer owned by this
    /// vtable.
    unsafe fn clone_panicking_capacity_waker(data: *const ()) -> RawWaker {
        // SAFETY: every data pointer in this vtable comes from Arc::into_raw
        // for Arc<ClonePanicWakerState>. ManuallyDrop retains the source
        // RawWaker's reference while a successful clone creates one new
        // reference.
        let state = std::mem::ManuallyDrop::new(unsafe {
            Arc::<ClonePanicWakerState>::from_raw(data.cast())
        });
        if state.clones.fetch_add(1, Ordering::AcqRel) == 1 {
            panic!("capacity waker clone panic");
        }
        let clone = Arc::clone(&state);
        RawWaker::new(
            Arc::into_raw(clone).cast(),
            &CLONE_PANICKING_CAPACITY_WAKER_VTABLE,
        )
    }

    /// Consume one capacity test waker reference and record its wake.
    ///
    /// # Safety
    ///
    /// `data` must be an `Arc<ClonePanicWakerState>` pointer owned by this
    /// vtable.
    unsafe fn wake_clone_panicking_capacity_waker(data: *const ()) {
        // SAFETY: wake consumes the RawWaker reference represented by data.
        let state = unsafe { Arc::<ClonePanicWakerState>::from_raw(data.cast()) };
        state.wakes.fetch_add(1, Ordering::AcqRel);
    }

    /// Observe a capacity test wake without consuming its reference.
    ///
    /// The callback intentionally has no effect because successor progress is
    /// measured with a separate flag waker.
    unsafe fn wake_by_ref_clone_panicking_capacity_waker(_: *const ()) {}

    /// Release one capacity test waker reference.
    ///
    /// # Safety
    ///
    /// `data` must be an `Arc<ClonePanicWakerState>` pointer owned by this
    /// vtable.
    unsafe fn drop_clone_panicking_capacity_waker(data: *const ()) {
        // SAFETY: drop consumes the RawWaker reference represented by data.
        drop(unsafe { Arc::<ClonePanicWakerState>::from_raw(data.cast()) });
    }

    /// Raw-waker callbacks for the clone-panic capacity regressions.
    static CLONE_PANICKING_CAPACITY_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_panicking_capacity_waker,
        wake_clone_panicking_capacity_waker,
        wake_by_ref_clone_panicking_capacity_waker,
        drop_clone_panicking_capacity_waker,
    );

    /// Build a task waker whose second clone resumes a controlled test panic.
    fn clone_panicking_waker(state: Arc<ClonePanicWakerState>) -> TaskWaker {
        // SAFETY: the vtable owns the Arc reference transferred into the raw
        // pointer and balances it in wake or drop. Clone deliberately panics
        // once, before creating a new reference.
        unsafe {
            TaskWaker::from_raw(RawWaker::new(
                Arc::into_raw(state).cast(),
                &CLONE_PANICKING_CAPACITY_WAKER_VTABLE,
            ))
        }
    }

    unsafe fn clone_panicking_drop_waker(_: *const ()) -> std::task::RawWaker {
        std::task::RawWaker::new(std::ptr::null(), &PANICKING_DROP_WAKER_VTABLE)
    }

    unsafe fn wake_panicking_drop_waker(_: *const ()) {}

    unsafe fn wake_by_ref_panicking_drop_waker(_: *const ()) {}

    unsafe fn drop_panicking_drop_waker(_: *const ()) {
        panic!("intentional RawWaker drop panic");
    }

    static PANICKING_DROP_WAKER_VTABLE: std::task::RawWakerVTable = std::task::RawWakerVTable::new(
        clone_panicking_drop_waker,
        wake_panicking_drop_waker,
        wake_by_ref_panicking_drop_waker,
        drop_panicking_drop_waker,
    );

    fn panicking_drop_waker() -> std::task::Waker {
        // SAFETY: the static vtable accepts the null data pointer and every
        // entry treats it as an opaque token. Its drop panic is intentional
        // test behavior exercised behind catch_unwind.
        unsafe {
            std::task::Waker::from_raw(std::task::RawWaker::new(
                std::ptr::null(),
                &PANICKING_DROP_WAKER_VTABLE,
            ))
        }
    }

    #[test]
    fn test_pending_ticket_waker_drop_panics_after_sync_detach_commit() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let (left, _right) = UnixStream::pair().unwrap();
        // SAFETY: `left` is a valid owned fd and is transferred into `File`.
        let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
        let mut ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        let waker = panicking_drop_waker();
        {
            let mut cx = Context::from_waker(&waker);
            assert!(Pin::new(&mut ticket).poll(&mut cx).is_pending());
        }
        // The completion entry owns a clone. Forget the test's original so
        // only owner-side completion removal exercises the panicking drop.
        std::mem::forget(waker);

        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ticket)));
        assert!(dropped.is_err());
        harness.handle.with(|ops| {
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.operation_count(), 1);
            assert!(ops.pending_cancels.is_empty());
        });

        // The sync was already detached before RawWaker destruction ran.
        // Its terminal CQE therefore frees the waiter without addressing the
        // removed completion entry or producing a second panic.
        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            let progressed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                harness.driver().turn();
                if harness.pending() != 0 {
                    harness.driver().park(Some(Duration::from_millis(10)));
                }
            }));
            assert!(progressed.is_ok());
        }
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_panicking_ticket_waker_leaves_committed_completion() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let (left, _right) = UnixStream::pair().unwrap();
        // SAFETY: `left` is a valid owned fd and is transferred into `File`.
        let file = unsafe { File::from_raw_fd(left.into_raw_fd()) };
        let mut ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        let waker = arc_waker(Arc::new(PanicWaker));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut ticket).poll(&mut cx).is_pending());

        // Register a capacity waiter after the panicking ticket waker. Its
        // grant is committed when ticket completion frees the only waiter, so
        // it must still be invoked before the panic resumes.
        let (waiting_left, _waiting_right) = UnixStream::pair().unwrap();
        let mut waiting = Box::pin(handle.recv(
            Arc::new(waiting_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
        let flag_waker = arc_waker(flag.clone());
        let mut flag_cx = Context::from_waker(&flag_waker);
        assert!(waiting.as_mut().poll(&mut flag_cx).is_pending());
        assert_eq!(harness.handle.with(|ops| ops.capacity.registered()), 1);

        let start = Instant::now();
        let panic = loop {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                harness.driver().turn();
                harness.driver().park(Some(Duration::from_millis(10)));
            }));
            if result.is_err() {
                break result;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
        };
        assert!(panic.is_err());
        assert!(flag.0.load(Ordering::SeqCst));
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        // Drop observes Ready by CompletionId. It must not touch the recycled
        // waiter or panic while unwinding from the callback.
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ticket)));
        assert!(dropped.is_ok());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
        });
        drop(waiting);
    }

    #[test]
    fn test_panicking_capacity_waker_observes_done_op() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();

        // Complete an ordinary recv but leave its output parked in the only
        // waiter until the future is polled again.
        let (left, mut right) = UnixStream::pair().unwrap();
        let mut first = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut first).is_pending());
        right.write_all(b"x").unwrap();
        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        assert_eq!(harness.handle.with(|ops| ops.waiters.len()), 1);

        // Register two admissions in order. Only the FIFO head receives the
        // released permit, and its capacity waker panics.
        let (second_left, _second_right) = UnixStream::pair().unwrap();
        let mut second = Box::pin(handle.recv(
            Arc::new(second_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let panic_waker = arc_waker(Arc::new(PanicWaker));
        let mut panic_cx = Context::from_waker(&panic_waker);
        assert!(second.as_mut().poll(&mut panic_cx).is_pending());

        let (third_left, _third_right) = UnixStream::pair().unwrap();
        let mut third = Box::pin(handle.recv(
            Arc::new(third_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let flag = Arc::new(WokenFlag(AtomicBool::new(false)));
        let flag_waker = arc_waker(flag.clone());
        let mut flag_cx = Context::from_waker(&flag_waker);
        assert!(third.as_mut().poll(&mut flag_cx).is_pending());
        assert_eq!(harness.handle.with(|ops| ops.capacity.registered()), 2);

        // Consuming the first op recycles its waiter, changes its local state
        // to Done, then invokes capacity wakers. Drop after the callback panic
        // must therefore be a no-op instead of orphaning a stale waiter ID.
        let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let noop = futures::task::noop_waker();
            let mut cx = Context::from_waker(&noop);
            let _ = first.as_mut().poll(&mut cx);
        }));
        assert!(completed.is_err());
        assert!(!flag.0.load(Ordering::SeqCst));
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(first)));
        assert!(dropped.is_ok());

        // Cancelling the granted head transfers its permit to the next FIFO
        // node and wakes that task exactly once.
        drop(second);
        assert!(flag.0.load(Ordering::SeqCst));
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        drop(third);
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_clone_panicking_capacity_head_after_ready_op_does_not_wedge() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();

        let (first_left, mut first_right) = UnixStream::pair().unwrap();
        let mut first = Box::pin(handle.recv(
            Arc::new(first_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut first).is_pending());
        first_right.write_all(b"x").unwrap();
        let start = Instant::now();
        while harness.pending() != 0 {
            assert!(start.elapsed() < Duration::from_secs(5));
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }

        let panic_state = Arc::new(ClonePanicWakerState {
            clones: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
        });
        let panic_waker = clone_panicking_waker(Arc::clone(&panic_state));
        let mut panic_cx = Context::from_waker(&panic_waker);
        let (failed_left, _failed_right) = UnixStream::pair().unwrap();
        let mut failed = Box::pin(handle.recv(
            Arc::new(failed_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(failed.as_mut().poll(&mut panic_cx).is_pending());

        let valid_flag = Arc::new(WokenFlag(AtomicBool::new(false)));
        let valid_waker = arc_waker(Arc::clone(&valid_flag));
        let mut valid_cx = Context::from_waker(&valid_waker);
        let (valid_left, _valid_right) = UnixStream::pair().unwrap();
        let mut valid = Box::pin(handle.recv(
            Arc::new(valid_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(valid.as_mut().poll(&mut valid_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 2);
            assert_eq!(ops.capacity.reserved(), 0);
            assert_eq!(ops.capacity.arena_len(), 2);
        });

        let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let noop = futures::task::noop_waker();
            let mut cx = Context::from_waker(&noop);
            assert!(first.as_mut().poll(&mut cx).is_ready());
        }));
        let payload = completed.expect_err("capacity clone panic was not resumed");
        assert_eq!(
            payload.downcast_ref::<&'static str>(),
            Some(&"capacity waker clone panic")
        );
        assert_eq!(panic_state.clones.load(Ordering::Acquire), 2);
        assert_eq!(panic_state.wakes.load(Ordering::Acquire), 1);
        assert!(valid_flag.0.load(Ordering::Acquire));
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
            assert_eq!(ops.capacity.arena_len(), 2);
        });
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(first))).is_ok());

        // The failed head owns a stale generation after recovery. Its drop is
        // a no-op and cannot revoke the valid successor's reservation.
        drop(failed);
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        // A fresh admission cannot barge ahead of that reservation.
        let barger_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let barger_waker = arc_waker(Arc::clone(&barger_count));
        let mut barger_cx = Context::from_waker(&barger_waker);
        let (barger_left, _barger_right) = UnixStream::pair().unwrap();
        let mut barger = Box::pin(handle.recv(
            Arc::new(barger_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(barger.as_mut().poll(&mut barger_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 2);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 1);
        });
        assert_eq!(barger_count.0.load(Ordering::Acquire), 0);

        // No manual reconcile is needed. The valid waiter consumes the grant
        // and enters the waiter table while the fresh attempt stays queued.
        assert!(valid.as_mut().poll(&mut valid_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 0);
        });
        assert_eq!(barger_count.0.load(Ordering::Acquire), 0);

        drop(valid);
        harness.driver().turn();
        assert_eq!(barger_count.0.load(Ordering::Acquire), 1);
        drop(barger);
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_ticket_completion_clone_panic_grants_valid_successor_before_resume() {
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();
        let (sync_left, _sync_right) = UnixStream::pair().unwrap();
        // SAFETY: sync_left is a valid owned fd and is transferred into File.
        let file = unsafe { File::from_raw_fd(sync_left.into_raw_fd()) };
        let ticket = harness.block_on(handle.start_sync(Arc::new(file)));

        let panic_state = Arc::new(ClonePanicWakerState {
            clones: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
        });
        let panic_waker = clone_panicking_waker(Arc::clone(&panic_state));
        let mut panic_cx = Context::from_waker(&panic_waker);
        let (failed_left, _failed_right) = UnixStream::pair().unwrap();
        let mut failed = Box::pin(handle.recv(
            Arc::new(failed_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(failed.as_mut().poll(&mut panic_cx).is_pending());

        let valid_flag = Arc::new(WokenFlag(AtomicBool::new(false)));
        let valid_waker = arc_waker(Arc::clone(&valid_flag));
        let mut valid_cx = Context::from_waker(&valid_waker);
        let (valid_left, _valid_right) = UnixStream::pair().unwrap();
        let mut valid = Box::pin(handle.recv(
            Arc::new(valid_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(valid.as_mut().poll(&mut valid_cx).is_pending());

        let start = Instant::now();
        let payload = loop {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                harness.driver().turn();
            }));
            if let Err(payload) = result {
                break payload;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            if harness.pending() != 0 {
                harness.driver().park(Some(Duration::from_millis(10)));
            }
        };
        assert_eq!(
            payload.downcast_ref::<&'static str>(),
            Some(&"capacity waker clone panic")
        );
        assert_eq!(panic_state.clones.load(Ordering::Acquire), 2);
        assert_eq!(panic_state.wakes.load(Ordering::Acquire), 1);
        assert!(valid_flag.0.load(Ordering::Acquire));
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 1);
            assert_eq!(ops.operation_count(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
            assert_eq!(ops.capacity.arena_len(), 2);
        });

        drop(failed);
        drop(ticket);
        assert!(valid.as_mut().poll(&mut valid_cx).is_pending());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.capacity.registered(), 0);
            assert_eq!(ops.capacity.reserved(), 0);
        });
        drop(valid);
        harness.driver().turn();
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_ready_ticket_survives_driver_close() {
        let mut harness = TestLoop::new(RingConfig::default());
        let handle = harness.handle.clone();
        let ticket = park_sync_ticket(&mut harness, &handle);
        harness.shutdown();

        // The ring is gone, but the ticket's Handle keeps the userspace-only
        // Ready completion alive and directly consumable.
        assert!(harness.block_on(ticket).is_err());
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
        });
    }

    #[test]
    fn test_capacity_cancel_releases_slot() {
        // Cancelled admission attempts must release their capacity slots
        // immediately and reuse the arena, so a long-saturated ring retains
        // no wakers (and no growing arena) for attempts that no longer exist.
        let mut harness = TestLoop::new(RingConfig {
            size: 1,
            ..Default::default()
        });
        let handle = harness.handle.clone();

        // Fill the single waiter slot with a recv that stays in flight.
        let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
        let mut blocker = Box::pin(handle.recv(
            Arc::new(blocker_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut blocker).is_pending());

        // Park-and-cancel churn: every attempt holds exactly one slot
        // (re-polls refresh in place), releases it on drop, and the arena
        // recycles that slot instead of growing.
        for _ in 0..64 {
            let (left, _right) = UnixStream::pair().unwrap();
            let mut parked = Box::pin(handle.recv(
                Arc::new(left.into()),
                IoBufMut::with_capacity(1),
                0,
                1,
                false,
                Instant::now() + Duration::from_secs(60),
            ));
            assert!(poll_once(&harness, &mut parked).is_pending());
            assert!(poll_once(&harness, &mut parked).is_pending());
            harness.handle.with(|ops| {
                assert_eq!(ops.capacity.registered(), 1);
                assert_eq!(ops.capacity.arena_len(), 1);
            });
            drop(parked);
            harness
                .handle
                .with(|ops| assert_eq!(ops.capacity.registered(), 0));
        }
        harness
            .handle
            .with(|ops| assert_eq!(ops.capacity.arena_len(), 1));

        // A registration invalidated by close is ignored by a later cancel
        // through its stale generation.
        let (left, _right) = UnixStream::pair().unwrap();
        let mut parked = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        assert!(poll_once(&harness, &mut parked).is_pending());
        harness.driver().close();
        harness
            .handle
            .with(|ops| assert_eq!(ops.capacity.registered(), 0));
        drop(parked);
    }

    #[test]
    fn test_closed_driver_fails_admission() {
        // Verify ops staged after close resolve with their kind-specific
        // failures without touching the ring.
        let mut harness = TestLoop::new(RingConfig::default());
        harness.driver().close();

        let (left, _right) = UnixStream::pair().unwrap();
        let handle = harness.handle.clone();
        let result = harness.block_on(handle.recv(
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
        let ticket = harness.block_on(handle.start_sync(Arc::new(file)));
        let result = harness.block_on(ticket);
        assert!(matches!(result, Err(Error::Closed)));
        harness.handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.completions.ready(), 0);
            assert_eq!(ops.completions.arena_len(), 0);
            assert_eq!(ops.operation_count(), 0);
        });
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
        let handle = harness.handle.clone();
        let payload = vec![9u8; 1 << 20];
        let mut write = Box::pin(handle.write_at(
            Arc::new(file),
            0,
            IoBufs::from(IoBuf::from(payload.clone())),
            WriteOptions::SYNC,
            Cache::Enabled,
        ));
        assert!(poll_once(&harness, &mut write).is_pending());

        // Shutdown drains the write, and the future then observes success.
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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

        // The shutdown-cancelled recv parked a closed result for the live
        // future: shutdown is distinguishable from an operation timeout.
        match poll_once(&harness, &mut recv) {
            Poll::Ready(Err((_, Error::Closed))) => {}
            other => panic!("expected shutdown-cancelled recv to be closed, got {other:?}"),
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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
        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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
        // backlog work remaining must report submission-queue pressure (so the
        // turn loop flushes and restages) even when the slab is also full,
        // and only a full slab with nothing left to stage reports waiter
        // pressure.
        let mut harness = TestLoop::new(RingConfig {
            size: 2,
            ..Default::default()
        });
        let (left_a, _right_a) = UnixStream::pair().unwrap();
        let (left_b, _right_b) = UnixStream::pair().unwrap();

        let handle = harness.handle.clone();
        let mut recv_a = Box::pin(handle.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let mut recv_b = Box::pin(handle.recv(
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
        // while the second op stays in the backlog, so SQ pressure must dominate the
        // (also true) waiter-capacity pressure.
        let driver_state = harness.handle.clone();
        let driver = harness.driver();
        let fill =
            driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
        assert_eq!(fill, FillResult::AtSubmissionQueueCapacity);

        // After flushing, the second op stages and nothing remains queued, so
        // the full slab now reports waiter pressure.
        driver.inner.submit(&mut driver.ring).unwrap();
        let fill =
            driver_state.with(|ops| driver.inner.fill_submission_queue(ops, &mut driver.ring));
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(8),
            0,
            8,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        // Admit without turning the loop, then drop: the entry stays in the
        // backlog in cancel-requested state.
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

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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
    fn test_off_thread_drop_reclaims_slot() {
        // A future dropped on a foreign thread hands its slot to the loop
        // through the orphan mailbox: subsequent turns wind it down
        // (cancelling the in-flight recv) instead of leaking the slot until
        // shutdown.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
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
        // cannot run the wind-down there, so it routes through the mailbox.
        std::thread::scope(|scope| {
            scope.spawn(move || drop(recv)).join().unwrap();
        });

        // The loop winds the orphan down (async-cancelling the recv) and the
        // slot frees without any shutdown budget.
        let start = Instant::now();
        while harness.tracked() != 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "foreign-thread drop did not reclaim the slot: {:?}",
                start.elapsed()
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
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

        let handle = harness.handle.clone();
        let mut recv_a = Box::pin(handle.recv(
            Arc::new(left_a.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(60),
        ));
        let mut recv_b = Box::pin(handle.recv(
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
        harness.driver().close();
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

        let handle = harness.handle.clone();
        let mut sockets = Vec::new();
        let mut recvs = Vec::new();
        for _ in 0..8 {
            let (left, right) = UnixStream::pair().unwrap();
            sockets.push(right);
            recvs.push(Box::pin(handle.recv(
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
    fn test_completion_races_timeout_expiry() {
        // Data arriving in the same window as deadline expiry must resolve
        // to either success or timeout, and never panic, double-remove a
        // wheel tick, or leak the slot.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(1),
            timeout_wheel_tick: Duration::from_millis(1),
            ..Default::default()
        });
        let handle = harness.handle.clone();
        for i in 0..40u64 {
            let (left, right) = UnixStream::pair().unwrap();
            let mut recv = Box::pin(handle.recv(
                Arc::new(left.into()),
                IoBufMut::with_capacity(1),
                0,
                1,
                false,
                Instant::now() + Duration::from_millis(10),
            ));
            assert!(poll_once(&harness, &mut recv).is_pending());
            harness.driver().turn();
            // Race the write against deadline expiry from both sides.
            std::thread::sleep(Duration::from_millis(if i % 2 == 0 { 9 } else { 11 }));
            (&right).write_all(&[7]).unwrap();
            match harness.block_on(recv) {
                Ok((_, 1)) | Err((_, Error::Timeout)) => {}
                other => panic!("unexpected recv result: {other:?}"),
            }
            assert_eq!(harness.tracked(), 0);
        }
        // No deadline accounting may survive the races.
        harness.driver().turn();
        assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
    }

    #[test]
    fn test_exact_recv_partial_then_timeout() {
        // An exact recv that made partial progress (requeued) must resolve
        // with timeout at its deadline and return the buffer.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(1),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        });
        let (left, right) = UnixStream::pair().unwrap();
        (&right).write_all(&[1, 2]).unwrap();

        let handle = harness.handle.clone();
        let recv = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(4),
            0,
            4,
            true,
            Instant::now() + Duration::from_millis(80),
        ));
        let start = Instant::now();
        match harness.block_on(recv) {
            Err((mut buf, Error::Timeout)) => {
                // The partial bytes were received before the deadline.
                // SAFETY: the kernel filled 2 bytes before the requeue.
                unsafe { buf.set_len(2) };
                assert_eq!(buf.as_ref(), &[1, 2]);
            }
            other => panic!("expected timeout after partial progress, got {other:?}"),
        }
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "timeout fired too early: {:?}",
            start.elapsed()
        );
        assert_eq!(harness.tracked(), 0);
    }

    #[test]
    fn test_drop_after_timeout_before_cancel_resolves() {
        // Deadline expiry transitions the waiter to cancel-requested and
        // releases its wheel tick. Dropping the future in that window must
        // not double-release deadline accounting or leak the slot.
        let mut harness = TestLoop::new(RingConfig {
            max_request_timeout: Duration::from_secs(1),
            timeout_wheel_tick: Duration::from_millis(5),
            ..Default::default()
        });
        let (left, _right) = UnixStream::pair().unwrap();

        let handle = harness.handle.clone();
        let mut recv = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_millis(30),
        ));
        assert!(poll_once(&harness, &mut recv).is_pending());
        harness.driver().turn();
        assert_eq!(harness.pending(), 1);

        // Let the deadline elapse, then advance timeouts WITHOUT staging the
        // cancel SQE or reaping its CQE: the waiter is now cancel-requested
        // with its op still in flight.
        std::thread::sleep(Duration::from_millis(50));
        let driver = harness.driver();
        handle.with(|ops| driver.inner.advance_timeouts(ops));
        assert!(driver.inner.timeout_wheel.next_deadline().is_none());

        // Drop the future in the cancel-requested window.
        drop(recv);

        // The slot must wind down through the normal cancel path.
        let start = Instant::now();
        while harness.tracked() != 0 {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "cancel-requested orphan still tracked after {:?}",
                start.elapsed()
            );
            harness.driver().turn();
            harness.driver().park(Some(Duration::from_millis(10)));
        }
        assert_eq!(harness.driver().inner.timeout_wheel.next_deadline(), None);
    }

    #[test]
    fn test_required_ring_flags_construct() {
        // The runtime cannot operate without single-issuer and deferred
        // task-run mode, so every RingConfig must exercise both flags.
        let ring = new_ring(&RingConfig::default()).expect("required ring flags should construct");
        drop(ring);
    }
}
