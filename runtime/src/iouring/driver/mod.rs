//! The io_uring driver: the owned event loop and ring ([Driver]) and the
//! shared op state that futures submit through ([Handle]).
//!
//! See [crate::iouring] for the full request flow and liveness discussion.

mod handle;
pub(crate) use handle::{AcceptTicket, Affine, Handle, Ops, current_thread_id};
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

/// Validate every pure ring invariant before construction has side effects.
///
/// Returns the effective ring size used for kernel and userspace capacity.
pub(crate) fn validate_ring_config(cfg: &RingConfig, max_request_timeout: Duration) -> u32 {
    let size = validated_ring_size(cfg.size);
    TimeoutWheel::validate_layout(max_request_timeout, cfg.timeout_wheel_tick);
    Spinner::validate_config(&cfg.idle_spinner);
    size
}

/// Packed `io_uring` `user_data` value.
type UserData = u64;

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
    fn new(registry: &mut impl Register) -> Self {
        Self {
            gauge: registry.register(
                "pending_operations",
                "Number of retained logical operations in the io_uring loop",
                raw::Gauge::default(),
            ),
            reported: 0,
        }
    }

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

/// State owned by one io_uring event loop.
///
/// [`IoUringLoop`] and its ring remain on one runtime worker. Front-end
/// futures share [`Handle`], whose affinity cell exposes [`Ops`] only on that
/// worker.
///
/// ```text
/// owner runtime thread
/// +-- IoUringLoop: shutdown, metrics, timeouts, idle/wake, scratch
/// `-- Handle -> Ops (thread-affine): waiters, completions, queues, capacity
/// foreign-thread drops -> Handle orphan mailbox -> owner loop
/// ```
///
/// The three `Vec` fields are scratch, not logical state. Each is empty at its
/// stated reuse boundary and draining it preserves capacity for the next batch.
pub(crate) struct IoUringLoop {
    /// Optional cancellation grace measured from shutdown drain entry.
    ///
    /// `None` lets requests finish or reach their own deadlines. Once a grace
    /// elapses, outstanding waiters are cancelled, but kernel retirement is
    /// still awaited, so this is not a total shutdown bound.
    shutdown_timeout: Option<Duration>,
    /// Number of logical requests retained by the driver. Internal SQEs (the
    /// wake poll and async cancels) are not counted. Tracked waiters and Ready
    /// detached ticket completions count once each.
    /// This is updated in the main loop and at shutdown drain exit, so it may
    /// temporarily vary from the exact retained-operation count between update
    /// points.
    pending_operations: PendingOperations,
    /// Loop-owned clone of the shared operation handle.
    ///
    /// This keeps [`Ops`] and its kernel-referenced resources alive through
    /// ring drain. Owner-thread futures borrow the affinity cell directly,
    /// while foreign-thread drops publish only to the orphan mailbox.
    handle: Handle,
    /// Owner-loop index of active admitted-request deadlines.
    ///
    /// It is mutated only while matching waiter state in [`Ops`] is borrowed.
    /// Every scheduled deadline has one active-count removal, while waiter
    /// generation checks reject stale bucket entries.
    timeout_wheel: TimeoutWheel,
    /// Owner-local adaptive controller for deadline-free, fully idle parks.
    ///
    /// Its budget persists across parks and is never applied while ring work
    /// or a deadline requires an eventfd-backed wait.
    idle_spinner: Spinner,
    /// Shared futex and eventfd wake source.
    ///
    /// Producers latch notifications through [`Waker::wake`]. The owner loop
    /// consumes the latch, acknowledges wake CQEs, and manages poll rearming.
    waker: Waker,
    /// Whether a multishot eventfd poll SQE must be staged.
    ///
    /// `true` means no wake poll is known to be live or already staged. It is
    /// set initially and when a wake CQE lacks the kernel `MORE` flag, then
    /// cleared only after [`Waker::reinstall`] accepts a new SQE. It must be
    /// `false` before eventfd-backed blocking. The fully idle futex path does
    /// not require the poll to be armed.
    wake_rearm_needed: bool,
    /// Scratch list of state panics, task-waker drops, and callbacks collected
    /// under the [`Ops`] borrow and handled after it is released.
    ///
    /// Empty at each outer turn or drain iteration boundary. Draining invokes
    /// no callback under the affinity borrow and retains the batch capacity.
    pending_waker_actions: Vec<handle::WakerAction>,
    /// Reusable batch of foreign-thread drop notifications.
    ///
    /// Empty before every mailbox drain and after every orphan-processing
    /// pass. Draining retains capacity up to the largest observed batch.
    pending_orphans: Vec<handle::Orphan>,
    /// Reusable batch of timeout-wheel entries due in one turn.
    ///
    /// Empty before every [`TimeoutWheel::advance_into`] call and after every
    /// expiry scan. Draining retains capacity, and entries are candidates
    /// whose waiter generations still require validation.
    expired_timeouts: Vec<timeout::TimeoutEntry>,
}

impl IoUringLoop {
    /// Create a new io_uring loop and its shared submission handle.
    ///
    /// The loop allocates its own metrics and internal `eventfd` wake source.
    /// The calling thread becomes the handle's owning (runtime) thread.
    /// Ring creation completes before the waiter table and queues whose
    /// capacities are proportional to the effective ring size are allocated.
    /// `max_request_timeout` sets the timeout wheel horizon and must cover
    /// every request deadline.
    ///
    /// # Errors
    ///
    /// Returns the kernel error if the io_uring instance cannot be created.
    /// In that case, no ring-sized waiter or queue state is allocated.
    ///
    /// # Panics
    ///
    /// Panics if either timeout duration is zero, the requested ring size
    /// overflows when rounded or rounds above [`MAX_RING_SIZE`], the timeout
    /// wheel exceeds its slot limit, the wake `eventfd` cannot be created, or
    /// the spinner budget exceeds its configured maximum.
    pub(crate) fn new(
        cfg: RingConfig,
        max_request_timeout: Duration,
        registry: &mut impl Register,
    ) -> Result<(IoUring, Handle, Self), std::io::Error> {
        let size = validate_ring_config(&cfg, max_request_timeout);

        // Ask the kernel to construct the ring before allocating the waiter
        // table whose capacity is proportional to the effective ring size.
        let ring = new_ring(size)?;
        let pending_operations = PendingOperations::new(registry);
        let waker = Waker::new().expect("unable to create wake eventfd");
        let timeout_wheel =
            TimeoutWheel::new(max_request_timeout, cfg.timeout_wheel_tick, Instant::now());
        let idle_spinner = Spinner::new(&cfg.idle_spinner, || waker.signalled());
        let handle = Handle::new(size as usize, waker.clone());

        Ok((
            ring,
            handle.clone(),
            Self {
                shutdown_timeout: cfg.shutdown_timeout,
                pending_operations,
                handle,
                timeout_wheel,
                idle_spinner,
                waker,
                wake_rearm_needed: true,
                pending_waker_actions: Vec::new(),
                pending_orphans: Vec::new(),
                expired_timeouts: Vec::new(),
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

    /// Wind down work routed through [handle::Handle] by a foreign-thread
    /// drop: admitted waiters orphan exactly as an on-thread drop would, and
    /// parked admission attempts release their capacity slots.
    fn process_orphans(&mut self, ops: &mut Ops) {
        self.handle.drain_orphans(&mut self.pending_orphans);
        for orphan in self.pending_orphans.drain(..) {
            match orphan {
                handle::Orphan::Waiter(id) => {
                    handle::wind_down_orphan(ops, id, &mut self.pending_waker_actions);
                }
                handle::Orphan::Completion(id) => {
                    handle::wind_down_ticket(ops, id, &mut self.pending_waker_actions);
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
            let (needs_flush, mut kernel_idle) = handle.with(|ops| {
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
                let needs_flush = self.fill_submission_queue(ops, ring);

                // Update pending operations metric.
                self.pending_operations.report(ops.operation_count());

                (needs_flush, ops.waiters.pending() == 0)
            });

            // Wake tasks whose results were parked, outside the state borrow.
            // RawWaker callbacks are arbitrary code and may synchronously
            // poll another driver operation.
            let invoked_callbacks = !self.pending_waker_actions.is_empty();
            self.flush_wakers();

            if needs_flush {
                // Flush the staged batch into the kernel and stage more work.
                self.submit(ring).expect("unable to submit to ring");
                continue;
            }

            // A callback may admit work or consume enough time for a request
            // deadline to expire after the staging snapshot above. Refresh
            // deadlines and owner-local queues without repeating the complete
            // turn when the callback had no observable driver effect.
            if invoked_callbacks {
                let follow_up = handle.with(|ops| {
                    self.advance_timeouts(ops);
                    kernel_idle = ops.waiters.pending() == 0;
                    self.pending_operations.report(ops.operation_count());
                    !ops.backlog.is_empty() || !ops.pending_cancels.is_empty()
                });
                if follow_up || !self.pending_waker_actions.is_empty() {
                    continue;
                }
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
        let now = Instant::now();
        let capacity_deadline = self.handle.with(|ops| ops.capacity.next_deadline(now));
        let deadline = [self.timeout_wheel.next_deadline(), capacity_deadline, limit]
            .into_iter()
            .flatten()
            .min();

        let fully_idle = self.handle.with(|ops| {
            ops.waiters.pending() == 0 && ops.backlog.is_empty() && ops.pending_cancels.is_empty()
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

        // Otherwise, arm the eventfd-backed blocking path and block only if no
        // out-of-band wake (e.g. a task wake) is latched.
        self.waker.wait_eventfd(|| {
            self.submit_and_wait(ring, 1, deadline)
                .expect("unable to submit to ring");
        });
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
            StageOutcome::Ready { waker } => {
                self.pending_waker_actions
                    .extend(waker.map(handle::WakerAction::Wake));
            }
            StageOutcome::Freed => self.notify_capacity(ops),
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
                    assert!(
                        !self
                            .timeout_wheel
                            .advance_into(Instant::now(), &mut self.expired_timeouts)
                    );
                }
                match self.timeout_wheel.target_tick(deadline) {
                    Some(tick) => {
                        ops.waiters.set_target_tick(waiter_id, tick);
                        self.timeout_wheel.schedule(waiter_id, tick);
                    }
                    // The deadline already expired: transition to cancellation
                    // so staging below completes the request with timeout.
                    None => assert!(ops.waiters.expire(waiter_id)),
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
    /// Returns whether the turn must flush without waiting and stage another
    /// batch before it can reap completions. When the last available waiter
    /// exactly fills the SQ, the caller instead combines that flush with its
    /// zero-timeout completion reap.
    fn fill_submission_queue(&mut self, ops: &mut Ops, ring: &mut IoUring) -> bool {
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
                return true;
            }
            self.wake_rearm_needed = false;
        }

        // Stage pending cancel SQEs first so timed-out requests are canceled promptly.
        if self.stage_cancellations(ops, &mut submission_queue) {
            return true;
        }

        // Stage admitted requests in FIFO order.
        let backlog_remains = self.stage_backlog(ops, &mut submission_queue);

        // With no free waiter and no work left to stage, the zero-timeout
        // submit-and-wait below can flush this exact batch and reap in one
        // kernel entry. Every other full-SQ state needs an immediate flush so
        // staging can continue or a waiter-less internal SQE reaches the
        // kernel before the turn returns.
        submission_queue.is_full() && (backlog_remains || !ops.waiters.is_full())
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
            CompletionOutcome::Ready { waker, target_tick } => {
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
                self.pending_waker_actions
                    .extend(waker.map(handle::WakerAction::Wake));
            }
            CompletionOutcome::Freed { target_tick } => {
                if let Some(tick) = target_tick {
                    self.timeout_wheel.remove(tick);
                }
                self.notify_capacity(ops);
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
    /// The output is published, timeout accounting removed, and the waiter
    /// recycled before capacity reservations are reconciled. Ticket and
    /// capacity callbacks are detached during that transition, then run only
    /// after the surrounding op-state borrow is released.
    fn complete_ticket(
        &mut self,
        ops: &mut Ops,
        waiter_id: WaiterId,
        completion_id: CompletionId,
        output: request::Output,
        target_tick: Option<Tick>,
    ) {
        // Publish Ready while the completion still links to this waiter. The
        // ticket can then observe its output independently of waiter reuse.
        let waker = ops
            .completions
            .publish_ready(completion_id, waiter_id, output);

        // Remove active timeout accounting after publication, while the
        // generation-stamped waiter identity is still current.
        if let Some(tick) = target_tick {
            self.timeout_wheel.remove(tick);
        }

        // Recycle the waiter only after the completion arena owns the output.
        ops.waiters.finish_ticket(waiter_id, completion_id);

        // Queue the ticket callback ahead of capacity callbacks to preserve
        // callback order, without executing it under the Ops borrow.
        self.pending_waker_actions
            .extend(waker.map(handle::WakerAction::Wake));

        // Reconcile reservations against the waiter's authoritative free list.
        self.notify_capacity(ops);
    }

    /// Advance the timeout wheel and enqueue cancellations for newly expired requests.
    ///
    /// This is a no-op when no active deadlines exist. Expired stale wheel
    /// entries are ignored when waiter generation no longer matches.
    fn advance_timeouts(&mut self, ops: &mut Ops) {
        self.advance_timeouts_at(ops, Instant::now());
    }

    /// Advance timeout processing to an explicit monotonic instant.
    fn advance_timeouts_at(&mut self, ops: &mut Ops, now: Instant) {
        // Admission wait is part of the operation budget. Expire capacity
        // registrations before touching admitted requests so a saturated ring
        // cannot hide a network deadline from the event loop.
        ops.capacity
            .expire(now, ops.waiters.free_len(), &mut self.pending_waker_actions);

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
        let (timeout_wheel, expired_timeouts) =
            (&mut self.timeout_wheel, &mut self.expired_timeouts);
        if !timeout_wheel.advance_into(now, expired_timeouts) {
            return;
        }

        // Mark expired waiters as cancel-requested and queue their IDs for
        // later cancel SQE staging.
        for entry in expired_timeouts.drain(..) {
            // `false` means stale timeout entry (slot reused) or waiter already
            // transitioned to cancel-requested/completed.
            if ops.waiters.expire(entry.waiter_id) {
                // Once cancel is requested, this waiter is no longer deadline-active.
                timeout_wheel.remove(entry.target_tick);
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
        for cancelled in ops.waiters.cancel_for_shutdown() {
            if let Some(tick) = cancelled.target_tick {
                self.timeout_wheel.remove(tick);
            }
            if cancelled.needs_cancel_sqe {
                ops.pending_cancels.push_back(cancelled.id);
            }
        }
    }

    /// Drain in-flight requests during shutdown.
    ///
    /// Keeps draining CQEs until all progressing waiters finish. Ready results
    /// retained by escaped tickets hold no kernel resources or waiter slots and
    /// remain in the completion arena until their ticket is polled or dropped.
    ///
    /// If `shutdown_timeout` is `None`, this waits until all waiters complete
    /// or are cancelled by their own deadlines. If `shutdown_timeout` is
    /// `Some`, it is a cancellation grace measured from drain entry. Every
    /// request still outstanding when the grace expires is cancelled, and the
    /// drain then waits for kernel retirement. Operations that cannot be
    /// cancelled (e.g. an executing disk write) may outlive the grace, so it is
    /// not a total shutdown bound.
    fn drain(&mut self, ring: &mut IoUring) {
        let handle = self.handle.clone();
        let started_at = Instant::now();
        let grace = self.shutdown_timeout;
        let mut cancellation_requested = false;

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
            let invoked_callbacks = !self.pending_waker_actions.is_empty();
            self.flush_wakers();

            // Staging can directly complete the last waiter (for example, when a
            // timed-out requeued request is retired instead of reissued).
            if pending == 0 {
                break;
            }

            // Include all shutdown work in the grace, not only time blocked
            // in the kernel. Check it before restarting for callbacks so a
            // sustained callback stream cannot postpone cancellation.
            let remaining_grace = grace
                .filter(|_| !cancellation_requested)
                .map(|grace| grace.saturating_sub(started_at.elapsed()));
            if remaining_grace.is_some_and(|remaining| remaining.is_zero()) {
                cancellation_requested = true;
                handle.with(|ops| self.cancel_all(ops));
                continue;
            }

            // Callback time can cross a request deadline after timeout_now
            // was sampled. Restart so cancellation is staged before deriving
            // a kernel wait from the timeout wheel.
            if invoked_callbacks {
                continue;
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

            let timeout = match (remaining_grace, self.timeout_wheel.next_deadline()) {
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
            // iteration process the mailbox. Ending the wait consumes the
            // latch either way.
            self.waker.wait_eventfd(|| {
                self.submit_and_wait(ring, 1, timeout)
                    .expect("unable to submit to ring");
            });
        }

        handle.with(|ops| {
            self.pending_operations.report(ops.operation_count());
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
    /// Timeouts and transient `io_uring_enter(2)` errors (`EINTR`, `EAGAIN`,
    /// `EBUSY`) return `Ok(())` so the caller can drain CQEs and re-enter through its event
    /// loop.
    fn submit_and_wait(
        &self,
        ring: &mut IoUring,
        want: usize,
        timeout: Option<Duration>,
    ) -> Result<(), std::io::Error> {
        let result = timeout.map_or_else(
            || ring.submit_and_wait(want).map(|_| ()),
            |timeout| {
                let ts = Timespec::new()
                    .sec(timeout.as_secs())
                    .nsec(timeout.subsec_nanos());

                let args = SubmitArgs::new().timespec(&ts);

                match ring.submitter().submit_with_args(want, &args) {
                    Ok(_) => Ok(()),
                    Err(err) if err.raw_os_error() == Some(libc::ETIME) => Ok(()),
                    Err(err) => Err(err),
                }
            },
        );

        match result {
            Ok(()) => Ok(()),
            Err(err) => match err.raw_os_error() {
                // Transient errors: return so the caller can drain
                // CQEs and re-enter through its event loop.
                Some(libc::EINTR | libc::EAGAIN | libc::EBUSY) => Ok(()),
                _ => Err(err),
            },
        }
    }

    /// Submit pending SQEs without waiting for a completion.
    #[inline]
    fn submit(&self, ring: &mut IoUring) -> Result<(), std::io::Error> {
        self.submit_and_wait(ring, 0, None)
    }
}

/// Build and configure an `io_uring` instance.
pub(crate) fn new_ring(size: u32) -> Result<IoUring, std::io::Error> {
    // Every ring is created and submitted by one worker thread. SINGLE_ISSUER
    // records that invariant for the kernel, while DEFER_TASKRUN processes
    // completions only during io_uring_enter calls with GETEVENTS. Every turn,
    // including the wake fast path, eventually makes such a call.
    //
    // DEFER_TASKRUN requires SINGLE_ISSUER and both flags require Linux 6.1.
    IoUring::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .build(size)
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
    /// `max_request_timeout` sets the timeout wheel horizon and must cover
    /// every request deadline admitted by the driver.
    pub(crate) fn new(
        cfg: RingConfig,
        max_request_timeout: Duration,
        registry: &mut impl Register,
    ) -> Result<(Self, Handle), std::io::Error> {
        let (ring, handle, inner) = IoUringLoop::new(cfg, max_request_timeout, registry)?;
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
        /// Create a loop harness with a 60-second timeout horizon.
        pub(crate) fn new(cfg: RingConfig) -> Self {
            Self::new_with_max_request_timeout(cfg, Duration::from_secs(60))
        }

        /// Create a loop harness with the provided timeout horizon.
        pub(crate) fn new_with_max_request_timeout(
            cfg: RingConfig,
            max_request_timeout: Duration,
        ) -> Self {
            let mut registry = Registry::default();
            let (driver, handle) = Driver::new(cfg, max_request_timeout, &mut registry)
                .expect("unable to create io_uring instance");
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
            let wakers = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.close()));
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
#[path = "tests.rs"]
mod tests;
