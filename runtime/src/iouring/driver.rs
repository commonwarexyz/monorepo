//! Worker-local io_uring submission, completion, and deadlines.
//!
//! [`Waiters`] owns each request's descriptors, buffers, progress, and observer.
//! The driver queues only IDs. Durability requests first acquire their open's
//! permit. Eligible requests and partial completions join the ready queue,
//! waiting for both SQ space and an available operation slot.
//! Completion releases that slot even if the local result remains unconsumed
//! in its waiter. Detached sync results leave through [`Deferred`].
//!
//! # Submission and Cancellation
//!
//! Staging keeps every SQE-referenced resource alive until the operation CQE,
//! including when submission returns a transient error. Cancellation CQEs only
//! acknowledge the cancellation attempt. They cannot release those resources.
//!
//! Dropping a local or forwarded observer cancels reads and network operations.
//! Queued requests can finish immediately, while in-flight requests need a cancellation
//! SQE and must await their operation CQE. Writes and syncs continue through all
//! follow-up SQEs after their observers are dropped.
//!
//! Cancellations stage first, followed by operations in FIFO order. The
//! operation limit excludes cancellation and ring wait SQEs. A full SQ needs a
//! flush, but reaching the operation limit requires a CQE to free capacity.
//!
//! # Service and Parking
//!
//! Each service turn reaps completions, advances the timeout wheel, registers new
//! deadlines, and stages queued work. Reaping first lets a terminal completion
//! win a race with expiry. Partial progress after expiry cannot issue another SQE.
//! Queued requests expire even while all operation slots are occupied.
//!
//! The ring uses SINGLE_ISSUER and DEFER_TASKRUN. Unfinished requests need a
//! GETEVENTS enter even when tasks keep the worker busy. An idle turn may defer
//! that enter to [`Driver::park`]. Control SQEs carry no request resources and
//! may remain until later I/O service or ring teardown.
//!
//! Parking arms the worker's [`Parker`] and blocks only while its word
//! still carries the sequence the worker observed before checking its sources.
//! Without a live ring futex wait, it reserves an SQ slot before arming and
//! queues one against the exact post-arm state, so an unpark that lands before
//! the kernel queues the wait fails its compare. A wait stays live across parks
//! until its CQE is reaped. See [`super::idle`] for how pool worker
//! selection fits with this wait.
//!
//! # Cleanup
//!
//! Observer callbacks and request-resource destruction go through [`Deferred`],
//! outside the worker borrow. Closure detaches local and forwarded observers and
//! cancels eligible requests. The worker continues servicing until all requests
//! retire, keeping the driver in place throughout the drain. Dropping the
//! driver on its owner thread synchronously cancels a live ring futex wait, so
//! no stale wait stays queued at the word's address once the word can be freed.

use super::{
    park::{Parker, RING_WAIT_USER_DATA, Unparker},
    registration::Observation,
    request::{Request, RequestOutput},
    runtime::{Deferred, RingConfig},
    timeout::TimeoutWheel,
    waiter::{CompletionOutcome, Observer, UserData, WaiterId, Waiters},
};
use crate::Error;
use commonware_utils::{channel::oneshot, sync::OwnedAsyncMutexGuard};
use futures::{Stream, future::BoxFuture, stream::FuturesUnordered};
use io_uring::{
    EnterFlags, IoUring,
    opcode::AsyncCancel,
    squeue::SubmissionQueue,
    types::{CancelBuilder, SubmitArgs, Timespec},
};
use std::{
    collections::VecDeque,
    io, mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tracing::warn;

/// Shared acknowledgement token for cancellation SQEs.
///
/// Like the ring wait token, this uses the slot index reserved by
/// [`Waiters::insert`].
const CANCEL_USER_DATA: UserData = u32::MAX as UserData;

/// Ring and request state accessed exclusively by the owning worker.
///
/// Drop it on the owner thread, the only thread that can cancel its ring futex
/// wait.
pub struct Driver {
    /// The worker's ring. Closing it only queues its teardown in the kernel, so
    /// cleanup retires every operation that can access request memory before
    /// the driver drops.
    ring: IoUring,
    /// Kept separately to allow batching SQ access while updating request state.
    state: State,
}

/// Request state borrowed independently of the ring's SQ and CQ mappings.
struct State {
    /// Queued requests, in-flight requests, and unconsumed local results.
    waiters: Waiters,
    /// Maximum number of outstanding operation SQEs.
    in_flight_limit: usize,
    /// FIFO of initial and follow-up operation SQEs, with lazily removed stale IDs.
    ready_queue: VecDeque<WaiterId>,
    /// Accepted durability requests awaiting their open's permit, absent from the FIFO.
    acquiring: FuturesUnordered<BoxFuture<'static, (WaiterId, OwnedAsyncMutexGuard<()>)>>,
    /// Permit grants wake ring service even after the ordinary mailbox closes.
    acquisition_waker: Waker,
    /// New requests whose deadlines must be registered after advancing the wheel.
    pending_deadlines: VecDeque<WaiterId>,
    /// Requests awaiting a cancellation SQE, skipped if their operation finishes first.
    pending_cancels: VecDeque<WaiterId>,
    /// Deadlines for queued and in-flight requests, independent of sleepers.
    timeout_wheel: TimeoutWheel,
    /// Unparker of the worker's word, the word every ring wait waits on,
    /// retained through ring destruction.
    unparker: Unparker,
    /// Whether no ring futex wait is live, so the next blocking park queues one.
    ring_wait_needed: bool,
}

/// What [`Driver::enter`] asks of the kernel after submitting queued SQEs.
#[derive(Clone, Copy)]
enum Enter {
    /// Nothing more. Used to make room in a full SQ.
    Flush,
    /// Run deferred task work, which posts finished requests to the CQ, and
    /// return without waiting.
    TaskWork,
    /// Run deferred task work and sleep until a completion arrives.
    Wait {
        /// When to stop waiting, or `None` to wait without a bound. A
        /// deadline that already passed does not sleep.
        deadline: Option<Instant>,
    },
}

impl Driver {
    /// Create a ring on its permanent owner thread after configuration validation.
    ///
    /// Uses the CQ sizing and overflow policy described by [`RingConfig::size`].
    pub fn new(
        cfg: &RingConfig,
        max_timeout: Duration,
        unparker: Unparker,
        now: Instant,
    ) -> io::Result<Self> {
        assert!(cfg.size > 0 && cfg.size.is_power_of_two() && cfg.size <= 32_768);

        TimeoutWheel::validate_layout(max_timeout, cfg.timeout_wheel_tick)
            .expect("validated timeout wheel configuration");

        // Deferred task work runs during GETEVENTS, supplied by service or park.
        let ring = IoUring::builder()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .build(cfg.size)?;
        let size = cfg.size as usize;

        Ok(Self {
            ring,
            state: State {
                waiters: Waiters::new(size),
                in_flight_limit: size,
                ready_queue: VecDeque::with_capacity(size),
                acquiring: FuturesUnordered::new(),
                acquisition_waker: Arc::new(unparker.clone()).into(),
                pending_deadlines: VecDeque::with_capacity(size),
                pending_cancels: VecDeque::with_capacity(size),
                timeout_wheel: TimeoutWheel::new(max_timeout, cfg.timeout_wheel_tick, now),
                unparker,
                ring_wait_needed: true,
            },
        })
    }

    /// Accept an owned request without staging kernel work.
    ///
    /// Cached time can reject expired requests immediately. Service validates
    /// remaining deadlines after the wheel has advanced.
    pub fn admit(
        &mut self,
        request: Request,
        observer: Observer,
        now: Instant,
        deferred: &mut Deferred,
    ) -> WaiterId {
        let deadline = request.deadline();
        let durability = request.durability().cloned();

        // Transfer ownership before any wait for staging capacity or durability.
        let id = self.state.waiters.insert(request, observer);
        if let Some(deadline) = deadline {
            if deadline <= now {
                self.state.complete(id, Err(Error::Timeout), deferred);
                return id;
            }

            // A task poll may have taken long enough to leave the wheel behind.
            // Service refreshes it before assigning this deadline a tick.
            self.state.pending_deadlines.push_back(id);
        }

        // A durability request holds the open's permit through terminal accounting so a later
        // barrier observes any earlier failure. Contended requests wait in `acquiring` outside
        // the ready queue. They have no deadline and finish even if their caller is dropped.
        if let Some(durability) = durability {
            match durability.clone().try_lock_owned() {
                Ok(permit) => self.state.acquired(id, permit, deferred),
                Err(_) => {
                    // The native driver owns this wait, so no cooperative budget
                    // of a task polling the driver may delay it. Admission may
                    // follow the last service turn before parking, so poll now
                    // to register the foreign release's wake target.
                    self.state.acquiring.push(Box::pin(async move {
                        (
                            id,
                            tokio::task::unconstrained(durability.lock_owned()).await,
                        )
                    }));
                    self.state.poll_acquisitions(deferred);
                }
            }
        } else {
            self.state.ready_queue.push_back(id);
        }
        id
    }

    /// Number of active logical requests, excluding retained completed outputs.
    pub const fn len(&self) -> usize {
        self.state.waiters.len()
    }

    /// Whether all logical requests retired, excluding retained completed outputs.
    pub const fn is_empty(&self) -> bool {
        self.state.waiters.is_empty()
    }

    /// Whether actionable staging or deadline registration must run before parking.
    pub fn has_pending_submissions(&self) -> bool {
        (!self.state.ready_queue.is_empty()
            && self.state.waiters.in_flight() < self.state.in_flight_limit)
            || !self.state.pending_deadlines.is_empty()
            || !self.state.pending_cancels.is_empty()
    }

    /// Earliest active deadline registered on the operation wheel.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.timeout_wheel.next_deadline()
    }

    /// Consume a retained result or check whether its waker needs refreshing.
    pub fn observe(&mut self, id: WaiterId, waker: &Waker) -> Observation<RequestOutput> {
        self.state.waiters.observe(id, waker)
    }

    /// Install a waker cloned outside the worker borrow, returning the displaced one.
    pub fn set_waker(&mut self, id: WaiterId, waker: Waker) -> Option<Waker> {
        self.state.waiters.set_waker(id, waker)
    }

    /// Forward local observation while retaining all kernel resources locally.
    pub fn forward(
        &mut self,
        id: WaiterId,
        sender: oneshot::Sender<Result<RequestOutput, Error>>,
        deferred: &mut Deferred,
    ) {
        self.state.waiters.forward(id, sender, deferred);
    }

    /// Detach local or forwarded observation and request eligible cancellation.
    pub fn orphan(&mut self, id: WaiterId, deferred: &mut Deferred) {
        if self.state.waiters.orphan(id, deferred) {
            self.state.cancel(id, deferred);
        }
    }

    /// Clear local and forwarded observation before draining retained writes and syncs.
    pub fn close(&mut self, deferred: &mut Deferred) {
        for id in self.state.waiters.close(deferred) {
            self.state.cancel(id, deferred);
        }
    }

    /// Process completions, deadlines, and queued submissions without callbacks.
    ///
    /// Returns whether this turn deferred GETEVENTS for unfinished requests. The
    /// `defer_kernel_service` argument permits the following idle ring wait to
    /// supply GETEVENTS. It is ignored when callbacks or unfinished staging
    /// already require another busy turn.
    pub fn service(
        &mut self,
        now: Instant,
        defer_kernel_service: bool,
        deferred: &mut Deferred,
    ) -> io::Result<bool> {
        // Finish posted work before expiring requests, then register deadlines
        // against the refreshed wheel so an idle interval cannot shorten them.
        self.state.reap(&mut self.ring, deferred);
        self.state.advance_timeouts(now, deferred);
        self.state.register_deadlines(now, deferred);
        self.state.poll_acquisitions(deferred);
        self.state.compact_ready_queue();

        while self.state.fill_submission_queue(&mut self.ring) {
            let before = self.ring.submission().len();
            Self::enter(&mut self.ring, Enter::Flush)?;
            if self.ring.submission().len() >= before {
                // A transient enter may leave the SQ full. Preserve queued
                // identities and give the kernel a completion-service point
                // before another staging attempt.
                break;
            }
        }

        // Busy turns must run deferred kernel work. An idle turn can leave this
        // enter to park, unless callbacks or more submissions need attention.
        let service_kernel = !self.is_empty()
            && (!defer_kernel_service || !deferred.is_empty() || self.has_pending_submissions());

        if service_kernel {
            Self::enter(&mut self.ring, Enter::TaskWork)?;
        }

        // New CQEs can complete requests or end the ring futex wait, which the
        // next blocking park then queues again.
        self.state.reap(&mut self.ring, deferred);

        #[cfg(test)]
        tests::after_service(&self.ring, &self.state, deferred)?;

        Ok(!service_kernel && !self.is_empty())
    }

    /// Wait for ring activity or the deadline while retaining worker ownership.
    ///
    /// `parker` must be the parker of the word whose unparker this driver was
    /// created with, since permit grants unpark that word. Returns `false` when
    /// submissions still need staging, the SQ has no room for the ring wait,
    /// or a notification since the worker observed `seen` rejects sleeping.
    /// A skipped wait does not satisfy a deferred GETEVENTS requirement, so
    /// the worker must service nonblocking before its next task-polling turn
    /// when kernel work remains.
    pub fn park(
        &mut self,
        parker: &Parker,
        seen: u32,
        deadline: Option<Instant>,
    ) -> io::Result<bool> {
        assert!(
            self.state.unparker.unparks(parker),
            "a driver must park on the word it was created with"
        );
        if self.has_pending_submissions() {
            return Ok(false);
        }

        // Reserve the wait's SQ slot before arming, since only the exact
        // post-arm state rejects a wake that lands before the kernel queues the
        // wait. A transient flush can leave the SQ full, in which case service
        // must run before trying again.
        if self.state.ring_wait_needed && self.ring.submission().is_full() {
            Self::enter(&mut self.ring, Enter::Flush)?;
            if self.ring.submission().is_full() {
                return Ok(false);
            }
        }

        // Keep the arm guard alive through the wait. A notification racing this
        // check either prevents sleeping or wakes the ring wait.
        let arm = parker.arm(seen);
        if !arm.still_idle() {
            return Ok(false);
        }

        if self.state.ring_wait_needed {
            arm.install(&mut self.ring.submission());
            self.state.ring_wait_needed = false;
        }

        Self::enter(&mut self.ring, Enter::Wait { deadline })?;
        Ok(true)
    }

    /// Submit queued SQEs, then do what `mode` asks of the kernel.
    ///
    /// The caller reaps the CQ afterwards. A timeout or a transient error
    /// (`EINTR`, `EAGAIN`, `EBUSY`) returns `Ok` because the next service
    /// turn retries, so `Ok` does not mean the kernel consumed the SQ or posted
    /// a completion. Other errors are permanent, and once the kernel has
    /// dropped a completion every enter fails with `EBADR`.
    fn enter(ring: &mut IoUring, mut mode: Enter) -> io::Result<()> {
        #[cfg(test)]
        if matches!(mode, Enter::Flush) && tests::stall_flush(ring) {
            return Ok(());
        }

        // Read the clock once, right before the syscall. A wait for one
        // completion with a zero timeout arms an expired timer and sleeps until
        // it fires whenever no completion is ready, so a deadline that already
        // passed runs only the task work.
        let mut timeout = Duration::ZERO;
        if let Enter::Wait {
            deadline: Some(deadline),
        } = mode
        {
            timeout = deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                mode = Enter::TaskWork;
            }
        }

        let result = match mode {
            // The crate adds GETEVENTS when the CQ has overflowed, so the kernel
            // also moves its overflow backlog into the CQ.
            Enter::Flush => ring.submit(),
            // GETEVENTS with no minimum completion count runs a batch of
            // deferred task work and returns, as liburing's
            // `io_uring_submit_and_get_events` does. Newer kernels bound the
            // batch and leave the rest for a later enter.
            Enter::TaskWork => {
                let to_submit =
                    u32::try_from(ring.submission().len()).expect("SQ length must fit u32");
                // SAFETY: `to_submit` counts only entries already published to
                // the SQ, whose resources stay alive until their CQEs, and no
                // argument pointer is passed.
                unsafe {
                    ring.submitter().enter::<libc::sigset_t>(
                        to_submit,
                        0,
                        EnterFlags::GETEVENTS.bits(),
                        None,
                    )
                }
            }
            Enter::Wait { deadline: None } => ring.submit_and_wait(1),
            Enter::Wait { deadline: Some(_) } => {
                // EXT_ARG bounds the wait without reserving an SQE for a timeout.
                let ts = Timespec::new()
                    .sec(timeout.as_secs())
                    .nsec(timeout.subsec_nanos());
                let args = SubmitArgs::new().timespec(&ts);
                match ring.submitter().submit_with_args(1, &args) {
                    // This timeout bounds the enter. Request expiry belongs to
                    // the wheel.
                    Err(err) if err.raw_os_error() == Some(libc::ETIME) => Ok(0),
                    result => result,
                }
            }
        };

        // A transient error falls through and returns `Ok`, so the caller
        // reaps before retrying. An immediate retry here could spin while the
        // kernel needs CQ space to make further progress.
        if let Err(err) = result
            && !matches!(
                err.raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN | libc::EBUSY)
            )
        {
            return Err(err);
        }

        // The kernel reports a dropped completion only once, and only from an
        // enter that submitted no SQEs and then waited with no completion
        // ready. An enter that submits discards the wait's result, and a flush,
        // a task-work enter or a wait that finds completions queued never
        // reaches the check. The ring's overflow counter grows only when the
        // kernel drops a CQE and never decreases, so check it after every
        // enter. Every later enter fails too, since the driver cannot tell
        // which request lost its completion and a drain would otherwise wait
        // for it forever.
        let dropped = ring.completion().overflow() != 0;
        #[cfg(test)]
        let dropped = dropped || tests::drop_completion(ring);
        if dropped {
            return Err(io::Error::from_raw_os_error(libc::EBADR));
        }
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // A queued ring wait never reads or writes the word again, since wakes
        // and cancellations find it through its futex key (the address space
        // and the word's address) and kernel-owned nodes. Freeing the word
        // under a queued wait is still a hazard, since a later futex at the
        // same address could have a wake absorbed by the stale wait. So cancel
        // a live wait synchronously, and keep the word allocated if that fails.
        //
        // SINGLE_ISSUER rejects the cancel from any thread but the owner with
        // EEXIST, which would leak the word, so the driver must drop on its
        // owner thread, as worker cleanup does.
        //
        // No wait is live once its completion was reaped.
        if self.state.ring_wait_needed {
            return;
        }

        loop {
            let cancel = CancelBuilder::user_data(RING_WAIT_USER_DATA);
            match self.ring.submitter().register_sync_cancel(None, cancel) {
                Ok(()) => return,
                Err(error) => match error.raw_os_error() {
                    // The wait already completed, or its SQE was never
                    // submitted. Without SQPOLL, an unsubmitted SQE stays
                    // inert through ring destruction.
                    Some(libc::ENOENT) => return,
                    Some(libc::EINTR) => continue,
                    _ => {
                        // The wait may still be queued at the word's address,
                        // so keep the word allocated. Keep it before the
                        // warning, whose subscriber can panic.
                        mem::forget(self.state.unparker.clone());
                        warn!(%error, "failed to cancel the ring futex wait");
                        return;
                    }
                },
            }
        }
    }
}

impl State {
    /// Make a granted request eligible only after checking the open's retained outcome.
    fn acquired(
        &mut self,
        id: WaiterId,
        permit: OwnedAsyncMutexGuard<()>,
        deferred: &mut Deferred,
    ) {
        if let Some(result) = self.waiters.acquire_durability(id, permit) {
            self.complete(id, result, deferred);
        } else {
            self.ready_queue.push_back(id);
        }
    }

    /// Advance only notified permit waits, using a wake path that survives worker closure.
    fn poll_acquisitions(&mut self, deferred: &mut Deferred) {
        while let Poll::Ready(Some((id, permit))) = Pin::new(&mut self.acquiring)
            .poll_next(&mut Context::from_waker(&self.acquisition_waker))
        {
            self.acquired(id, permit, deferred);
        }
    }

    /// Store the terminal result and defer resource destruction and callbacks.
    fn complete(&mut self, id: WaiterId, result: Result<(), Error>, deferred: &mut Deferred) {
        // Finish splits the request into its result and deferred resources.
        // A previously cancelled request has already released its wheel tick.
        if let Some(tick) = self.waiters.finish(id, result, deferred) {
            self.timeout_wheel.remove(tick);
        }
    }

    /// Request cancellation once, finishing locally if no SQE is in flight.
    fn cancel(&mut self, id: WaiterId, deferred: &mut Deferred) {
        // Cancellation clears the waiter's tick. Save it before the transition
        // so the wheel loses its active count exactly once.
        let tick = self.waiters.target_tick(id);
        if !self.waiters.cancel(id) {
            return;
        }
        if let Some(tick) = tick {
            self.timeout_wheel.remove(tick);
        }

        if self.waiters.is_in_flight(id) {
            self.pending_cancels.push_back(id);
        } else {
            // No kernel access remains, including between partial completions.
            self.complete(id, Err(Error::Timeout), deferred);
        }
    }

    /// Advance the wheel even when no active operation deadline remains.
    fn advance_timeouts(&mut self, now: Instant, deferred: &mut Deferred) {
        let Some(expired) = self.timeout_wheel.advance(now) else {
            return;
        };
        for id in expired {
            self.cancel(id, deferred);
        }
    }

    /// Register deadlines for new requests against this turn's refreshed wheel.
    fn register_deadlines(&mut self, now: Instant, deferred: &mut Deferred) {
        while let Some(id) = self.pending_deadlines.pop_front() {
            // Cancellation may have retired the request before registration.
            let Some(deadline) = self.waiters.deadline(id) else {
                continue;
            };

            match self.timeout_wheel.checked_target_tick(deadline, now) {
                Ok(Some(tick)) => {
                    // Remember the same tick in the waiter so completion or
                    // cancellation can remove its active count from the wheel.
                    self.timeout_wheel.schedule(id, tick);
                    self.waiters.set_deadline(id, tick);
                }
                // Time spent waiting for service can exhaust the deadline.
                // Complete before staging, leaving the ready ID for lazy removal.
                Ok(None) => self.complete(id, Err(Error::Timeout), deferred),
                Err(message) => {
                    // An unsupported deadline fails through the request result
                    // path before the kernel can reference this request.
                    let error =
                        Error::Io(io::Error::new(io::ErrorKind::InvalidInput, message).into());
                    self.complete(id, Err(error), deferred);
                }
            }
        }
    }

    /// Remove stale queue IDs once they exceed both 64 and the live queued count.
    fn compact_ready_queue(&mut self) {
        // Requests awaiting a permit have no ready ID. Every other pending
        // request without an in-flight SQE has exactly one. Extra IDs are stale.
        let queued = self.waiters.len() - self.waiters.in_flight() - self.acquiring.len();
        let stale = self
            .ready_queue
            .len()
            .checked_sub(queued)
            .expect("queued request missing from ready queue");
        if stale <= 64 || stale <= queued {
            return;
        }

        // Queued cancellations and expirations leave IDs behind even when no
        // staging capacity opens. Compact in place without disturbing FIFO order.
        self.ready_queue.retain(|id| self.waiters.is_pending(*id));
    }

    /// Stage operation SQEs in FIFO order, returning whether an SQ flush is needed.
    fn stage_ready_requests(&mut self, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        while self.waiters.in_flight() < self.in_flight_limit {
            let Some(id) = self.ready_queue.front().copied() else {
                return false;
            };

            // Cancelled and expired requests leave their IDs behind. Drop them
            // without consuming SQ capacity or reporting a flush.
            if !self.waiters.is_pending(id) {
                self.ready_queue.pop_front();
                continue;
            }
            if submission_queue.is_full() {
                return true;
            }

            self.ready_queue.pop_front();
            let sqe = self.waiters.stage(id);

            // SAFETY: The waiter retains every referenced descriptor and buffer
            // until its operation CQE. The SQ has capacity, and no callback can
            // retire the waiter between constructing and pushing this SQE.
            unsafe {
                submission_queue
                    .push(&sqe)
                    .expect("checked operation SQ capacity");
            }
        }

        // Only a completion can release this limit. A flush cannot, and
        // cancellation SQEs must still be allowed to stage.
        false
    }

    /// Stage cancellation SQEs, returning whether an SQ flush is needed.
    fn stage_cancellations(&mut self, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        while !submission_queue.is_full() {
            let Some(id) = self.pending_cancels.pop_front() else {
                return false;
            };

            // The operation may have finished before its cancellation staged.
            if !self.waiters.is_in_flight(id) {
                continue;
            }

            let cancel = AsyncCancel::new(id.user_data())
                .build()
                .user_data(CANCEL_USER_DATA);

            // SAFETY: AsyncCancel carries only the stable user_data identity.
            // Its target's waiter retains every kernel-visible owner, and the
            // loop checked SQ capacity before taking this queued identity.
            unsafe {
                submission_queue
                    .push(&cancel)
                    .expect("checked cancellation SQ capacity");
            }
        }

        !self.pending_cancels.is_empty()
    }

    /// Fill available SQ slots and report whether more work requires a flush.
    fn fill_submission_queue(&mut self, ring: &mut IoUring) -> bool {
        // One SQ view batches tail publication until it is dropped on return.
        let mut submission_queue = ring.submission();

        // Cancellation must progress even when all operation slots are occupied.
        if self.stage_cancellations(&mut submission_queue) {
            return true;
        }

        self.stage_ready_requests(&mut submission_queue)
    }

    /// Reap every posted CQE without invoking observer callbacks.
    fn reap(&mut self, ring: &mut IoUring, deferred: &mut Deferred) {
        // Dropping this CQ view returns the consumed slots to the kernel.
        // Observer callbacks remain deferred until the worker borrow ends.
        for cqe in ring.completion() {
            self.handle_cqe(cqe.user_data(), cqe.result(), deferred);
        }
    }

    /// Apply a CQE without invoking observer callbacks.
    fn handle_cqe(&mut self, user_data: UserData, result: i32, deferred: &mut Deferred) {
        // The reserved ring wait token is outside the waiter's ID space. A
        // wake, a changed word, or cancellation ends the one-shot ring futex
        // wait, and the next blocking park queues another, even after
        // service's final reap.
        if user_data == RING_WAIT_USER_DATA {
            // The kernel allocates the wait without blocking, so memory
            // pressure can fail it with ENOMEM. That ends the wait like the
            // others, and the next blocking park installs another. Anything
            // else breaks an invariant, such as EINVAL from a kernel without
            // IORING_OP_FUTEX_WAIT.
            assert!(
                matches!(-result, 0 | libc::EAGAIN | libc::ECANCELED | libc::ENOMEM),
                "ring futex wait failed: {result}"
            );
            self.ring_wait_needed = true;
            return;
        }

        // Only the target operation's CQE can retire its resource owners.
        if user_data == CANCEL_USER_DATA {
            if result == 0 {
                // Cancellation successful.
            } else if result == -libc::EALREADY {
                // Cancellation is no longer possible at this stage. The target
                // operation CQE should follow shortly.
            } else if result == -libc::ENOENT {
                // The target may already have completed and vacated its slot.
            } else if result == -libc::EINVAL {
                panic!("async cancel SQE rejected by kernel: EINVAL");
            } else {
                warn!(result, "unexpected async cancel CQE result");
            }

            return;
        }

        // Waiters releases an operation's in-flight count before returning its outcome.
        match self.waiters.on_completion(user_data, result) {
            // Partial progress rejoins the tail behind already queued work.
            CompletionOutcome::Requeue(id) => self.ready_queue.push_back(id),
            CompletionOutcome::Complete(id, result) => self.complete(id, result, deferred),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        IoBuf, IoBufMut, IoBufs,
        iouring::{
            mailbox::Mailbox,
            park::tests::{handles, wait_until_armed, wake},
            request::{
                Cache, DIRECT_ALIGN, IOVEC_BATCH_SIZE, ReadAtRequest, RecvRequest, RequestOutput,
                SyncRequest, WriteAtRequest, WriteAtState,
            },
        },
        storage::{hold::Hold, iouring::Shared},
    };
    use commonware_utils::channel::oneshot;
    use io_uring::opcode::Nop;
    use std::{
        cell::Cell,
        fs::{self, OpenOptions},
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::{fs::OpenOptionsExt as _, net::UnixStream},
        },
        panic::{AssertUnwindSafe, catch_unwind},
        path::PathBuf,
        sync::Arc,
        task::Wake,
        thread,
    };
    use tracing_subscriber::layer::SubscriberExt as _;

    /// Bound of a timed wait that times out. It leaves the deadline in the
    /// future when `Driver::enter` samples the clock on a loaded runner, so
    /// the wait takes the timed path rather than the elapsed one.
    const TIMED_WAIT: Duration = Duration::from_millis(10);

    /// Kernel outcomes that cannot be scheduled reliably with a real ring.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        /// A transient flush leaves every SQ entry untouched.
        StallFlush,
        /// Service fails with retired resources awaiting deferred cleanup.
        AfterCompletion,
        /// The kernel drops a CQE because it cannot allocate an overflow entry.
        DropCompletion,
    }

    thread_local! {
        /// One failure scoped to the calling thread and the selected ring.
        static FAULT: Cell<Option<(RawFd, Fault)>> = const { Cell::new(None) };

        /// Callback run once at the end of this thread's next service turn
        /// that leaves a durability request waiting for its permit.
        static WHILE_ACQUIRING: Cell<Option<Box<dyn FnOnce()>>> = const { Cell::new(None) };
    }

    /// Clear an unused injection when its test scope exits or unwinds.
    pub struct FaultGuard;

    impl Drop for FaultGuard {
        fn drop(&mut self) {
            FAULT.set(None);
        }
    }

    /// Install one failure without changing the driver's production state.
    fn inject(driver: &Driver, fault: Fault) -> FaultGuard {
        assert!(FAULT.get().is_none(), "driver fault already installed");
        FAULT.set(Some((driver.ring.as_raw_fd(), fault)));
        FaultGuard
    }

    /// Fail service after completion ownership has moved to deferred cleanup.
    pub fn fail_after_completion(driver: &Driver) -> FaultGuard {
        inject(driver, Fault::AfterCompletion)
    }

    /// Consume the selected fault once, leaving later cleanup turns unaffected.
    fn take_fault(ring: &IoUring, fault: Fault) -> bool {
        if FAULT.get() != Some((ring.as_raw_fd(), fault)) {
            return false;
        }

        FAULT.set(None);
        true
    }

    /// Model a transient flush before the kernel consumes any SQ entries.
    pub fn stall_flush(ring: &IoUring) -> bool {
        take_fault(ring, Fault::StallFlush)
    }

    /// Model a CQE the kernel dropped, which it counts in the ring's overflow
    /// counter.
    pub fn drop_completion(ring: &IoUring) -> bool {
        take_fault(ring, Fault::DropCompletion)
    }

    /// Fail service when retired resources are awaiting deferred cleanup, and
    /// otherwise run the hook installed by [`on_service_while_acquiring`] if
    /// a durability request still waits for its permit.
    pub(super) fn after_service(
        ring: &IoUring,
        state: &State,
        deferred: &Deferred,
    ) -> io::Result<()> {
        if !deferred.resources.is_empty() && take_fault(ring, Fault::AfterCompletion) {
            return Err(io::Error::other(
                "injected service failure after completion",
            ));
        }

        if !state.acquiring.is_empty()
            && let Some(hook) = WHILE_ACQUIRING.take()
        {
            hook();
        }
        Ok(())
    }

    /// Run `hook` on the calling thread at the end of its next service turn
    /// that leaves a durability request waiting for its permit, after that
    /// turn polled the request's acquisition. The hook runs while the worker's
    /// local state is borrowed, so it must not reach that state.
    pub fn on_service_while_acquiring(hook: impl FnOnce() + 'static) {
        let previous = WHILE_ACQUIRING.replace(Some(Box::new(hook)));
        assert!(previous.is_none(), "service hook already installed");
    }

    /// Duplicate the driver's ring descriptor, so the kernel keeps the ring
    /// until the duplicate closes, even after the driver drops.
    fn hold_ring(driver: &Driver) -> OwnedFd {
        // SAFETY: `dup` only reads the driver's open ring descriptor.
        let fd = unsafe { libc::dup(driver.ring.as_raw_fd()) };
        assert!(
            fd >= 0,
            "failed to duplicate the ring descriptor: {}",
            io::Error::last_os_error()
        );

        // SAFETY: `fd` is a new open descriptor that nothing else owns.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    /// A tracing layer that panics on every event, standing in for a
    /// subscriber that panics while recording a warning.
    struct PanicOnEvent;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PanicOnEvent {
        fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            panic!("subscriber panicked on an event");
        }
    }

    /// Destination of a result collected by the harness.
    enum TestObserver {
        /// Local result identified by a test-assigned tag.
        Local(u64),
        /// Detached sync awaiting explicit publication by the test.
        DetachedSync(oneshot::Sender<Result<(), Error>>),
        /// Discarded result from an orphaned request.
        Orphaned,
    }

    /// Completed request and the observer that would receive its output.
    struct Completed {
        /// Destination retained for assertions or detached publication.
        observer: TestObserver,
        /// Request result removed from its waiter or deferred callbacks.
        output: RequestOutput,
    }

    /// Distinct waker allocation used to identify a local completion.
    struct Notify;

    // Each observer needs a distinct identity for matching its deferred wake.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for Notify {
        fn wake(self: Arc<Self>) {}
    }

    /// Collect results while driving a real ring or injecting operation CQEs.
    struct Harness {
        /// Ring and request state under test.
        driver: Driver,
        /// The word's parker, which the test thread holds as the worker.
        parker: Parker,
        /// Callbacks and resources detached by driver transitions.
        deferred: Deferred,
        /// Local observers matched by waker identity, with test-assigned tags.
        tracked: Vec<(WaiterId, u64, Waker)>,
        /// Collected results retained for assertions.
        completed: Vec<Completed>,
        /// Initial wheel time, also used as the origin for simulated deadlines.
        start: Instant,
    }

    impl Harness {
        /// Create a real ring whose SQ size also bounds in-flight operations.
        fn new(size: u32) -> Self {
            let start = Instant::now();
            let parker = Parker::new();
            Self {
                driver: Driver::new(
                    &RingConfig {
                        size,
                        timeout_wheel_tick: Duration::from_millis(5),
                    },
                    Duration::from_secs(60),
                    parker.unparker(),
                    start,
                )
                .unwrap(),
                parker,
                deferred: Deferred::default(),
                tracked: Vec::new(),
                completed: Vec::new(),
                start,
            }
        }

        /// Queue a local request whose result `collect` will consume automatically.
        fn admit(&mut self, request: Request, tag: u64) -> WaiterId {
            let waker = Waker::from(Arc::new(Notify));
            let id = self.driver.admit(
                request,
                Observer::Local(Some(waker.clone())),
                self.start,
                &mut self.deferred,
            );
            self.tracked.push((id, tag, waker));
            id
        }

        /// Stage a request without submitting its SQE, for simulated completions.
        fn stage(&mut self, request: Request, tick: Option<u64>, tag: u64) -> WaiterId {
            let waker = Waker::from(Arc::new(Notify));
            let id = self
                .driver
                .state
                .waiters
                .insert(request, Observer::Local(Some(waker.clone())));
            if let Some(tick) = tick {
                self.driver.state.timeout_wheel.schedule(id, tick);
                self.driver.state.waiters.set_deadline(id, tick);
            }

            // Keep the fixture out of the ready queue and the kernel. Only
            // simulated_completion may release this operation's in-flight count.
            self.driver.state.waiters.stage(id);
            self.tracked.push((id, tag, waker));
            id
        }

        /// Collect deferred outputs and consume local results in wake order.
        fn collect(&mut self) {
            for output in self.deferred.outputs.drain(..) {
                self.completed.push(Completed {
                    observer: TestObserver::Orphaned,
                    output,
                });
            }

            for waker in self.deferred.wakes.drain(..) {
                // Match by observer identity to preserve completion order even
                // when earlier requests have already vacated and reused slots.
                let index = self
                    .tracked
                    .iter()
                    .position(|(_, _, current)| current.will_wake(&waker))
                    .unwrap();
                let (id, tag, _) = self.tracked.swap_remove(index);
                let Observation::Ready(output) = self.driver.observe(id, &waker) else {
                    panic!("completion wake without retained output");
                };
                self.completed.push(Completed {
                    observer: TestObserver::Local(tag),
                    output,
                });
                waker.wake();
            }

            // Orphaned observers leave a waker to discard without consuming a result.
            for waker in self.deferred.drops.drain(..) {
                if let Some(index) = self
                    .tracked
                    .iter()
                    .position(|(_, _, current)| current.will_wake(&waker))
                {
                    self.tracked.swap_remove(index);
                }
            }
            self.deferred.resources.clear();

            // Let tests delay detached publication until after the driver drains.
            for (sender, output) in self.deferred.completions.drain(..) {
                self.completed.push(Completed {
                    observer: TestObserver::DetachedSync(sender),
                    output: RequestOutput::Sync(output),
                });
            }
        }

        /// Drop a local or forwarded observer and collect any immediately discarded output.
        fn orphan(&mut self, id: WaiterId) {
            self.driver.orphan(id, &mut self.deferred);
            self.collect();
        }

        /// Service at a chosen time and collect results.
        fn service_at(&mut self, now: Instant, defer: bool) {
            self.driver.service(now, defer, &mut self.deferred).unwrap();
            self.collect();
        }

        /// Service using wall-clock time and run deferred kernel work immediately.
        fn service(&mut self) {
            self.service_at(Instant::now(), false);
        }

        /// Fill the one-slot SQ with a control SQE that uses no operation slot.
        fn fill_with_control(&mut self) {
            let nop = Nop::new().build().user_data(CANCEL_USER_DATA);
            // SAFETY: Nop references no memory that the kernel could access.
            unsafe {
                self.driver.ring.submission().push(&nop).unwrap();
            }
        }

        /// Park the driver as the worker would, against `seen`.
        fn park(&mut self, seen: u32, deadline: Option<Instant>) -> io::Result<bool> {
            self.driver.park(&self.parker, seen, deadline)
        }

        /// Require a real ring wait CQE before any further submission can mask
        /// its absence.
        fn reap_ring_wait(&mut self) {
            let cqe = self
                .driver
                .ring
                .completion()
                .next()
                .expect("missing ring wait CQE");
            assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
            self.driver
                .state
                .handle_cqe(cqe.user_data(), cqe.result(), &mut self.deferred);
        }

        /// Drive until `count` results have been collected, failing if progress stalls.
        fn until(&mut self, count: usize) {
            let limit = Instant::now() + Duration::from_secs(10);
            while self.completed.len() < count {
                assert!(Instant::now() < limit, "driver completion stalled");
                self.service();
                thread::yield_now();
            }
        }

        /// Notify observers of closure without trying to consume retained results.
        fn close(&mut self) {
            self.driver.close(&mut self.deferred);
            for waker in self.deferred.wakes.drain(..) {
                waker.wake();
            }
            self.tracked.clear();
            self.collect();
        }

        /// Close local and forwarded observation and wait for request retirement.
        fn drain(&mut self) {
            self.close();

            let limit = Instant::now() + Duration::from_secs(10);
            while !self.driver.is_empty() || self.driver.has_pending_submissions() {
                assert!(Instant::now() < limit, "driver retirement stalled");
                self.service();
                thread::yield_now();
            }
        }

        /// Inject progress only for SQEs deliberately kept out of the real ring.
        ///
        /// This models the completion status and byte count without writing data.
        fn simulated_completion(&mut self, id: WaiterId, result: i32) {
            match self
                .driver
                .state
                .waiters
                .on_completion(id.user_data(), result)
            {
                CompletionOutcome::Complete(id, result) => {
                    self.driver.state.complete(id, result, &mut self.deferred)
                }
                CompletionOutcome::Requeue(id) => self.driver.state.ready_queue.push_back(id),
            }
            self.collect();
        }
    }

    /// Build an exact receive with initialized storage for payload assertions.
    fn recv(fd: UnixStream, len: usize, deadline: Option<Instant>) -> Request {
        Request::Recv(RecvRequest {
            fd: Arc::new(fd.into()),
            buf: IoBufMut::zeroed(len),
            offset: 0,
            len,
            exact: true,
            deadline,
        })
    }

    /// Borrow the initialized prefix reported by a successful receive.
    fn received(output: &Completed) -> &[u8] {
        match &output.output {
            RequestOutput::Recv(Ok((buf, len))) => &buf.as_ref()[..*len],
            _ => panic!("expected successful recv"),
        }
    }

    /// Create an isolated open for tests that control durability completion.
    pub fn make_file(name: &str) -> (PathBuf, Arc<Shared>) {
        let directory =
            std::env::temp_dir().join(format!("commonware_driver_{name}_{}", std::process::id()));
        let hold = Hold::acquire(&directory).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(directory.join("blob"))
            .unwrap();
        (directory, Shared::detached(file, hold))
    }

    #[test]
    fn test_unconsumed_results_leave_staging_and_deadline_tracking() {
        let mut harness = Harness::new(1);
        // Occupy the only operation slot so stale IDs cannot drain by staging.
        let (active, mut peer) = UnixStream::pair().unwrap();
        harness.admit(recv(active, 1, None), 0);
        harness.service();

        assert_eq!(harness.driver.state.waiters.in_flight(), 1);

        // Keep completed results in their slots while the sole operation slot
        // stays occupied. Their queue IDs must still count as stale.
        let mut results = Vec::new();
        let deadline = harness.start + Duration::from_nanos(1);
        for _ in 0..65 {
            let (socket, _peer) = UnixStream::pair().unwrap();
            results.push(harness.driver.admit(
                recv(socket, 1, Some(deadline)),
                Observer::Local(None),
                harness.start,
                &mut harness.deferred,
            ));
        }
        harness.service();

        assert_eq!(harness.driver.len(), 1);
        assert!(harness.driver.state.ready_queue.is_empty());
        assert!(harness.driver.state.pending_deadlines.is_empty());
        assert!(harness.driver.next_deadline().is_none());
        assert!(!harness.driver.has_pending_submissions());

        // Below the compaction threshold, staging itself must skip the ID
        // even though its generation still matches a retained result.
        let (socket, _peer) = UnixStream::pair().unwrap();
        results.push(harness.driver.admit(
            recv(socket, 1, Some(deadline)),
            Observer::Local(None),
            harness.start,
            &mut harness.deferred,
        ));
        harness.service();

        assert_eq!(harness.driver.state.ready_queue.len(), 1);

        // Releasing capacity lets staging discard the one remaining stale ID.
        peer.write_all(b"x").unwrap();
        harness.until(1);
        harness.service();

        assert!(harness.driver.is_empty());
        assert!(!harness.driver.has_pending_submissions());

        // Neither compaction nor skipped staging may consume the results.
        for id in results {
            assert!(matches!(
                harness.driver.observe(id, Waker::noop()),
                Observation::Ready(RequestOutput::Recv(Err((_, Error::Timeout))))
            ));
        }

        harness.drain();
    }

    #[test]
    fn test_cancelled_backlog_compacts_at_staging_limit() {
        let mut harness = Harness::new(1);
        let (active, mut active_peer) = UnixStream::pair().unwrap();
        harness.admit(recv(active, 1, None), 0);
        harness.service();

        // Cancellation must bound stale storage even while a live request at
        // the front prevents normal FIFO removal.
        let mut peak_queued = 0;
        for tag in 1..=2 {
            let (queued, mut peer) = UnixStream::pair().unwrap();
            peer.write_all(b"x").unwrap();
            harness.admit(recv(queued, 1, None), tag);

            // Stale IDs sit behind live requests. The second live request also
            // reuses a slot still named by earlier cancelled queue entries.
            for _ in 0..256 {
                let (socket, _peer) = UnixStream::pair().unwrap();
                let id = harness.admit(recv(socket, 1, None), 3);
                harness.orphan(id);
                harness.service();
                harness.completed.clear();
                peak_queued = peak_queued.max(harness.driver.state.ready_queue.len());
            }
        }

        assert_eq!(harness.driver.len(), 3);
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);
        assert!(!harness.driver.has_pending_submissions());

        // Compaction must preserve both live identities and their FIFO order.
        active_peer.write_all(b"x").unwrap();
        harness.until(3);
        for (tag, completed) in harness.completed.iter().enumerate() {
            assert!(matches!(completed.observer, TestObserver::Local(id) if id == tag as u64));
            assert_eq!(received(completed), b"x");
        }

        assert!(peak_queued <= 128, "retained {peak_queued} queue entries");

        harness.drain();
    }

    #[test]
    fn test_expired_backlog_compacts_at_staging_limit() {
        let mut harness = Harness::new(1);
        let (active, _active_peer) = UnixStream::pair().unwrap();
        harness.admit(recv(active, 1, None), 0);
        harness.service();

        let (queued, _queued_peer) = UnixStream::pair().unwrap();
        harness.admit(recv(queued, 1, None), 1);

        let mut now = harness.start;
        let mut peak_queued = 0;
        for register_first in [false, true] {
            for _ in 0..256 {
                let deadline = now + Duration::from_millis(10);
                let (socket, _peer) = UnixStream::pair().unwrap();
                let id = harness.admit(recv(socket, 1, Some(deadline)), 2);

                // Exercise expiry during initial registration and through the
                // timeout wheel, while the active request prevents staging.
                if register_first {
                    harness.service_at(now, false);
                }
                now = deadline;
                harness.service_at(now, false);

                assert!(!harness.driver.state.waiters.is_pending(id));
                assert_eq!(harness.completed.len(), 1);
                assert!(matches!(
                    harness.completed[0].output,
                    RequestOutput::Recv(Err((_, Error::Timeout)))
                ));

                harness.completed.clear();
                peak_queued = peak_queued.max(harness.driver.state.ready_queue.len());
            }
        }

        assert_eq!(harness.driver.len(), 2);
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);
        assert!(!harness.driver.has_pending_submissions());
        assert!(peak_queued <= 128, "retained {peak_queued} queue entries");

        harness.drain();
    }

    #[test]
    fn test_staging_limit_parks_and_preserves_fifo_across_growth() {
        let mut harness = Harness::new(1);
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        let first = harness.admit(recv(first, 1, None), 0);
        harness.service();

        assert!(harness.driver.state.waiters.is_in_flight(first));

        // Grow the waiter slab while the kernel still holds the first buffer.
        for (tag, bytes) in [(1, b"b"), (2, b"c")] {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            peer.write_all(bytes).unwrap();
            harness.admit(recv(socket, 1, None), tag);
        }
        harness.service();

        assert_eq!(harness.driver.len(), 3);
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);
        assert!(!harness.driver.has_pending_submissions());

        // The backlog waits for a CQE. It must not prevent entering the idle wait.
        assert!(harness.park(0, Some(Instant::now())).unwrap());
        first_peer.write_all(b"a").unwrap();
        harness.until(3);

        for (tag, expected) in [b"a", b"b", b"c"].into_iter().enumerate() {
            let completed = &harness.completed[tag];
            assert!(matches!(completed.observer, TestObserver::Local(id) if id == tag as u64));
            assert_eq!(received(completed), expected);
        }

        assert_eq!(harness.driver.state.waiters.in_flight(), 0);

        harness.drain();
    }

    #[test]
    fn test_queued_expiry_and_cancellation_progress_at_staging_limit() {
        let mut harness = Harness::new(1);
        let (first, _first_peer) = UnixStream::pair().unwrap();
        let first = harness.admit(recv(first, 1, None), 0);
        harness.service();

        let (timed, _timed_peer) = UnixStream::pair().unwrap();
        let timed = harness.admit(
            recv(timed, 1, Some(harness.start + Duration::from_secs(1))),
            1,
        );

        let (cancelled, _cancelled_peer) = UnixStream::pair().unwrap();
        let cancelled = harness.admit(recv(cancelled, 1, None), 2);
        harness.orphan(cancelled);

        // Neither queued request needs an SQE to retire while the first is blocked.
        harness.service_at(harness.start + Duration::from_secs(2), false);

        assert!(!harness.driver.state.waiters.is_pending(cancelled));
        assert!(!harness.driver.state.waiters.is_pending(timed));
        assert_eq!(harness.completed.len(), 2);
        assert!(matches!(
            harness.completed[0].observer,
            TestObserver::Orphaned
        ));
        assert!(matches!(
            harness.completed[1].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));
        assert!(harness.driver.state.waiters.is_in_flight(first));
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);
        assert!(!harness.driver.has_pending_submissions());

        // Cancelling the active request must still stage its cancellation at the limit.
        harness.drain();

        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
    }

    #[test]
    fn test_unconsumed_result_releases_staging_capacity() {
        let mut harness = Harness::new(1);
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        first_peer.write_all(b"a").unwrap();

        // Omit the observer waker so the harness leaves this result in Waiters.
        let first = harness.driver.admit(
            recv(first, 1, None),
            Observer::Local(None),
            harness.start,
            &mut harness.deferred,
        );

        let (second, mut second_peer) = UnixStream::pair().unwrap();
        second_peer.write_all(b"b").unwrap();
        harness.admit(recv(second, 1, None), 1);

        // The second request needs the sole operation slot released by the first.
        harness.until(1);

        assert!(harness.driver.is_empty());
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
        assert_eq!(received(&harness.completed[0]), b"b");

        // Only now consume the first result, after the second has finished.
        assert!(matches!(
            harness.driver.observe(first, Waker::noop()),
            Observation::Ready(RequestOutput::Recv(Ok((_, 1))))
        ));

        harness.drain();
    }

    #[test]
    fn test_expired_registration_never_stages() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let deadline = harness.start + Duration::from_nanos(1);
        harness.admit(recv(left, 8, Some(deadline)), 0);

        // A deadline equal to this turn's time has already expired.
        harness.service_at(deadline, true);

        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));
        assert!(harness.driver.is_empty());
        assert!(harness.driver.next_deadline().is_none());

        // The expired receive never reached the SQ.
        assert!(harness.driver.ring.submission().is_empty());

        harness.drain();
    }

    #[test]
    fn test_staging_discards_stale_ids_with_full_sq() {
        for with_pending in [false, true] {
            let mut harness = Harness::new(1);

            // A control SQE fills the SQ without using an operation slot.
            harness.fill_with_control();

            assert!(harness.driver.ring.submission().is_full());

            let (socket, _peer) = UnixStream::pair().unwrap();
            let deadline = harness.start + Duration::from_secs(10);
            let stale = harness.admit(recv(socket, 1, Some(deadline)), 0);
            harness.orphan(stale);

            let pending = with_pending.then(|| {
                let (socket, mut peer) = UnixStream::pair().unwrap();
                peer.write_all(b"x").unwrap();
                harness.admit(recv(socket, 1, None), 1)
            });
            if let Some(pending) = pending {
                assert_eq!(stale.0.index, pending.0.index);
                assert_ne!(stale, pending);
            }

            let flush = harness
                .driver
                .state
                .stage_ready_requests(&mut harness.driver.ring.submission());

            // Only a live request justifies a flush. A stale ID must disappear
            // even if there is no SQ space and its slot has already been reused.
            assert_eq!(flush, with_pending);
            assert_eq!(
                harness.driver.state.ready_queue.len(),
                usize::from(with_pending)
            );
            assert_eq!(harness.driver.state.ready_queue.front().copied(), pending);
            assert_eq!(harness.driver.state.waiters.in_flight(), 0);
            assert!(harness.driver.ring.submission().is_full());

            if with_pending {
                harness.until(2);

                assert_eq!(received(&harness.completed[1]), b"x");
            }

            harness.drain();

            // The old deadline registration must also be skipped after reuse.
            assert!(harness.driver.next_deadline().is_none());
            assert!(harness.driver.state.pending_deadlines.is_empty());
        }
    }

    #[test]
    fn test_advance_timeouts_ignores_stale_entry_after_slot_reuse() {
        let mut harness = Harness::new(1);
        let early = harness.start + Duration::from_millis(5);
        let late = harness.start + Duration::from_millis(15);
        let (old, _old_peer) = UnixStream::pair().unwrap();
        let old = harness.admit(recv(old, 1, Some(early)), 0);
        let (survivor, _survivor_peer) = UnixStream::pair().unwrap();
        let survivor = harness.admit(recv(survivor, 1, Some(early)), 1);
        harness
            .driver
            .state
            .register_deadlines(harness.start, &mut harness.deferred);

        // Keep another live deadline in the old bucket. Otherwise the wheel
        // can skip it entirely, without passing its stale record to the driver.
        harness.orphan(old);
        harness.completed.clear();
        let (current, _current_peer) = UnixStream::pair().unwrap();
        let current = harness.admit(recv(current, 1, Some(late)), 2);
        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old, current);
        harness
            .driver
            .state
            .register_deadlines(harness.start, &mut harness.deferred);

        // The shared bucket expires, but its stale ID must not cancel the
        // replacement or remove the replacement's later deadline.
        harness
            .driver
            .state
            .advance_timeouts(early, &mut harness.deferred);
        harness.collect();

        assert!(!harness.driver.state.waiters.is_pending(survivor));
        assert!(harness.driver.state.waiters.is_pending(current));
        assert_eq!(harness.completed.len(), 1);
        assert_eq!(harness.driver.next_deadline(), Some(late));

        // The replacement must still expire at its own deadline.
        harness
            .driver
            .state
            .advance_timeouts(late, &mut harness.deferred);
        harness.collect();

        assert!(harness.driver.is_empty());
        assert!(harness.driver.next_deadline().is_none());
        assert_eq!(harness.completed.len(), 2);
        for (tag, completed) in (1..=2).zip(&harness.completed) {
            assert!(matches!(completed.observer, TestObserver::Local(id) if id == tag));
            assert!(matches!(
                completed.output,
                RequestOutput::Recv(Err((_, Error::Timeout)))
            ));
        }

        harness.drain();
    }

    #[test]
    fn test_deadline_registration_uses_refreshed_wheel() {
        let mut harness = Harness::new(1);
        let now = harness.start + Duration::from_secs(3600) + Duration::from_millis(1);
        let deadline = now + Duration::from_secs(60);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.admit(recv(left, 1, Some(deadline)), 0);

        // The wheel is an hour behind, but the deadline fits its horizon when
        // measured from this service turn. Refresh before validating it.
        harness.service_at(now, true);

        assert!(harness.completed.is_empty());
        let scheduled = harness.driver.next_deadline().unwrap();
        assert!(scheduled >= deadline);
        assert!(scheduled < deadline + Duration::from_millis(5));

        harness.orphan(id);
        harness.drain();
    }

    #[test]
    fn test_unsupported_deadline_is_rejected_without_submission() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();

        // This future deadline exceeds the harness's 60-second horizon.
        harness.admit(
            recv(left, 1, Some(harness.start + Duration::from_secs(61))),
            0,
        );
        harness.service_at(harness.start, true);

        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Io(_))))
        ));
        assert!(harness.driver.is_empty());

        // The rejected receive never reached the SQ.
        assert!(harness.driver.ring.submission().is_empty());

        harness.drain();
    }

    #[test]
    fn test_completion_wins_cancellation() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.stage(recv(left, 5, None), None, 0);
        harness.driver.state.cancel(id, &mut harness.deferred);

        // A cancellation request cannot undo a successful terminal CQE.
        harness.simulated_completion(id, 5);

        assert_eq!(received(&harness.completed[0]).len(), 5);

        harness.drain();
    }

    #[test]
    fn test_cancel_acknowledgements_leave_requests_and_results_untouched() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.stage(recv(left, 5, None), None, 0);
        harness.driver.state.cancel(id, &mut harness.deferred);

        // Acknowledgements cannot release the operation's kernel resources.
        for result in [0, -libc::EALREADY, -libc::ENOENT, -libc::EPERM] {
            harness
                .driver
                .state
                .handle_cqe(CANCEL_USER_DATA, result, &mut harness.deferred);

            assert_eq!(harness.driver.state.waiters.in_flight(), 1);
            assert!(harness.driver.state.waiters.is_pending(id));
        }

        // Complete without collecting the result, leaving it in its waiter slot.
        let CompletionOutcome::Complete(current, result) = harness
            .driver
            .state
            .waiters
            .on_completion(id.user_data(), 5)
        else {
            panic!("expected terminal completion");
        };
        assert_eq!(current, id);
        harness
            .driver
            .state
            .complete(id, result, &mut harness.deferred);

        for result in [0, -libc::ENOENT] {
            harness
                .driver
                .state
                .handle_cqe(CANCEL_USER_DATA, result, &mut harness.deferred);

            assert_eq!(harness.driver.state.waiters.in_flight(), 0);
        }

        harness.collect();
        assert_eq!(harness.completed.len(), 1);
        assert_eq!(received(&harness.completed[0]).len(), 5);
        harness.drain();
    }

    #[test]
    fn test_cancel_acknowledgement_invariants() {
        // Both control tokens use the index that Waiters refuses to allocate.
        assert_ne!(CANCEL_USER_DATA, RING_WAIT_USER_DATA);
        for token in [CANCEL_USER_DATA, RING_WAIT_USER_DATA] {
            assert_eq!(token as u32, u32::MAX);
        }

        let mut harness = Harness::new(1);

        // EINVAL rejects the cancellation SQE itself, regardless of slot reuse.
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                harness.driver.state.handle_cqe(
                    CANCEL_USER_DATA,
                    -libc::EINVAL,
                    &mut harness.deferred,
                );
            }))
            .is_err()
        );
    }

    #[test]
    fn test_request_retirement_releases_hold_before_cancel_acknowledgement() {
        for consume_cancel in [false, true] {
            for reuse in [false, true] {
                let mut harness = Harness::new(1);
                let directory = std::env::temp_dir().join(format!(
                    "commonware_driver_retirement_{}_{}_{}",
                    std::process::id(),
                    consume_cancel,
                    reuse,
                ));
                let hold = Hold::acquire(&directory).unwrap();
                let path = directory.join("read");
                fs::write(&path, b"hello").unwrap();
                let file = OpenOptions::new().read(true).open(path).unwrap();
                let probe = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(directory.join(".hold"))
                    .unwrap();
                let id = harness.admit(
                    Request::ReadAt(ReadAtRequest::new(
                        Shared::detached(file, hold),
                        0,
                        IoBufMut::zeroed(5),
                        Cache::Enabled,
                    )),
                    0,
                );

                // Complete the real read in the kernel, retaining its CQE and
                // userspace owner while a later cancellation enters the SQ.
                assert!(
                    !harness
                        .driver
                        .state
                        .stage_ready_requests(&mut harness.driver.ring.submission())
                );
                harness.driver.ring.submit_and_wait(1).unwrap();
                assert!(matches!(
                    probe.try_lock(),
                    Err(fs::TryLockError::WouldBlock)
                ));
                harness.driver.orphan(id, &mut harness.deferred);
                assert!(
                    !harness
                        .driver
                        .state
                        .stage_cancellations(&mut harness.driver.ring.submission())
                );
                assert_eq!(harness.driver.ring.submission().len(), 1);

                // Only processing the target CQE permits resource retirement.
                // The deferred owner still protects the directory until disposal.
                harness
                    .driver
                    .state
                    .reap(&mut harness.driver.ring, &mut harness.deferred);
                assert!(matches!(
                    probe.try_lock(),
                    Err(fs::TryLockError::WouldBlock)
                ));
                harness.collect();
                let RequestOutput::ReadAt(Ok(buf)) = &harness.completed[0].output else {
                    panic!("real read did not complete successfully");
                };
                assert_eq!(buf.as_ref(), b"hello");
                probe.try_lock().unwrap();
                probe.unlock().unwrap();

                if consume_cancel {
                    // Leave the real cancellation acknowledgement unobserved.
                    harness.driver.ring.submit_and_wait(1).unwrap();
                    assert!(harness.driver.ring.submission().is_empty());
                    assert!(!harness.driver.ring.completion().is_empty());
                } else {
                    assert_eq!(harness.driver.ring.submission().len(), 1);
                }

                if reuse {
                    let (left, mut right) = UnixStream::pair().unwrap();
                    right.write_all(b"x").unwrap();
                    let next = harness.admit(recv(left, 1, None), 1);
                    assert_eq!(next.0.index, id.0.index);
                    assert_ne!(next, id);
                    harness.until(2);
                    assert_eq!(received(&harness.completed[1]), b"x");
                }

                harness.drain();
                drop(harness);
                probe.try_lock().unwrap();
                drop(probe);
                fs::remove_dir_all(directory).unwrap();
            }
        }
    }

    #[test]
    fn test_timeout_between_partial_completions() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.stage(recv(left, 8, None), Some(1), 0);

        // Partial progress leaves the request queued, with no SQE in flight.
        harness.simulated_completion(id, 4);

        assert_eq!(harness.driver.state.ready_queue.len(), 1);

        // Expiring between SQEs must finish locally, without an async cancel.
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.deferred,
        );
        assert!(harness.driver.state.pending_cancels.is_empty());
        assert!(harness.driver.is_empty());
        harness.collect();

        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));

        harness.drain();
    }

    #[test]
    fn test_orphaned_follow_up_cannot_stage_reused_slot() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.stage(recv(left, 8, None), None, 0);
        harness.simulated_completion(id, 4);
        harness.orphan(id);

        // Reuse the slot while the abandoned follow-up ID is still queued.
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"fresh").unwrap();
        let new = harness.admit(recv(left, 5, None), 1);
        assert_eq!(new.0.index, id.0.index);
        harness.until(2);

        assert_eq!(received(&harness.completed[1]), b"fresh");

        harness.drain();
    }

    #[test]
    fn test_orphaned_read_retries_do_not_requeue() {
        let directory = std::env::temp_dir().join(format!(
            "commonware_driver_read_test_{}",
            std::process::id()
        ));
        let hold = Hold::acquire(&directory).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(directory.join("read"))
            .unwrap();
        let held = Shared::detached(file, hold);

        for close in [false, true] {
            for result in [-libc::EAGAIN, 2] {
                let mut harness = Harness::new(1);
                let id = harness.stage(
                    Request::ReadAt(ReadAtRequest::new(
                        held.clone(),
                        0,
                        IoBufMut::zeroed(5),
                        Cache::Enabled,
                    )),
                    None,
                    0,
                );

                if close {
                    harness.close();
                } else {
                    harness.orphan(id);
                }

                // ReadAt reports a retry or partial progress even after
                // cancellation. CancelRequested prevents a follow-up SQE
                // and retires the request at this CQE.
                harness.simulated_completion(id, result);

                assert!(harness.driver.state.ready_queue.is_empty());
                assert!(harness.driver.is_empty());
                assert_eq!(harness.completed.len(), 1);
                assert!(matches!(
                    harness.completed[0].observer,
                    TestObserver::Orphaned
                ));

                harness.drain();
            }
        }

        drop(held);
        fs::remove_dir_all(directory).unwrap();
    }

    /// Cancelling a direct read never stages a successor. When its observer is dropped or its
    /// worker closes, a read the kernel holds keeps its open and buffer until its operation CQE
    /// decides its outcome, even when the cancellation acknowledgement arrives first. A read the
    /// kernel does not hold releases them at once when its observer is dropped, whether it is
    /// queued for its first submission or requeued after aligned progress or a switch to a
    /// buffered read.
    #[test]
    fn test_cancelled_direct_reads_retain_their_owners_until_completion() {
        let (directory, file) = make_file("direct_cancel");
        let fd = file.set_direct(
            OpenOptions::new()
                .read(true)
                .open(directory.join("blob"))
                .unwrap(),
        );
        let probe = OpenOptions::new()
            .write(true)
            .open(directory.join(".hold"))
            .unwrap();

        // Each read covers three blocks less 200 bytes at offset 0, so its superset is three
        // blocks. An output returns its request's buffer, so the buffer's address ties the two.
        let len = 3 * DIRECT_ALIGN - 200;
        let request = || {
            let mut request = ReadAtRequest::direct(file.clone(), fd, 0, len).unwrap();
            let target = request.buf.as_mut_ptr();
            (Request::ReadAt(request), target)
        };
        let returned = |completed: &mut Completed| match &mut completed.output {
            RequestOutput::ReadAt(Ok(buf) | Err((buf, _))) => buf.as_mut_ptr(),
            _ => unreachable!("a read request must return a read output"),
        };

        for close in [false, true] {
            for acknowledged in [false, true] {
                for (result, outcome) in [
                    (-libc::EAGAIN, Err(Error::Timeout)),
                    (DIRECT_ALIGN as i32, Err(Error::Timeout)),
                    (10, Err(Error::Timeout)),
                    (0, Err(Error::Timeout)),
                    (-libc::EINVAL, Err(Error::Timeout)),
                    (-libc::EIO, Err(Error::Timeout)),
                    (-libc::ECANCELED, Err(Error::ReadFailed)),
                    (3 * DIRECT_ALIGN as i32, Ok(())),
                ] {
                    // Orphan a staged read or close its worker, with or without a simulated
                    // cancellation acknowledgement. The kernel may write the buffer until the
                    // operation CQE, so the request keeps its open and buffer.
                    let mut harness = Harness::new(1);
                    let (request, target) = request();
                    let id = harness.stage(request, None, 0);
                    if close {
                        harness.close();
                    } else {
                        harness.orphan(id);
                    }
                    if acknowledged {
                        harness
                            .driver
                            .state
                            .handle_cqe(CANCEL_USER_DATA, 0, &mut harness.deferred);
                        harness.collect();
                    }
                    assert_eq!(Arc::strong_count(&file), 2);
                    assert_eq!(harness.driver.state.waiters.in_flight(), 1);
                    assert!(harness.completed.is_empty());

                    // The simulated operation CQE ends the read without a successor. A covering
                    // completion succeeds, ECANCELED fails, and any other result times out,
                    // including one that would otherwise continue the read or fall back.
                    harness.simulated_completion(id, result);
                    assert!(harness.driver.is_empty());
                    assert!(harness.driver.state.ready_queue.is_empty());
                    assert_eq!(harness.driver.state.waiters.in_flight(), 0);
                    let RequestOutput::ReadAt(output) = &harness.completed[0].output else {
                        panic!("a read request must return a read output");
                    };
                    match (output, outcome) {
                        (Ok(buf), Ok(())) => assert_eq!(buf.len(), len),
                        (Err((_, Error::Timeout)), Err(Error::Timeout))
                        | (Err((_, Error::ReadFailed)), Err(Error::ReadFailed)) => {}
                        (output, outcome) => panic!("{result}: {output:?} must match {outcome:?}"),
                    }

                    // The CQE released the open, and the unobserved output owns the buffer until
                    // the worker disposes of it.
                    assert_eq!(Arc::strong_count(&file), 1);
                    assert_eq!(harness.completed.len(), 1);
                    assert_eq!(returned(&mut harness.completed[0]), target);

                    harness.completed.clear();
                    harness.drain();
                }
            }
        }

        // Cancel a read still queued for its first submission, or requeued after simulated
        // aligned progress or a rejection that switched it to a buffered read. The kernel holds
        // none of them, so cancelling completes the read at once with a timeout and releases its
        // open and buffer, and the next service has nothing to submit.
        for progress in [None, Some(DIRECT_ALIGN as i32), Some(-libc::EINVAL)] {
            let mut harness = Harness::new(1);
            let (request, target) = request();
            let id = match progress {
                None => harness.admit(request, 0),
                Some(result) => {
                    let id = harness.stage(request, None, 0);
                    harness.simulated_completion(id, result);
                    assert_eq!(harness.driver.state.ready_queue.len(), 1);
                    id
                }
            };
            assert_eq!(harness.driver.state.waiters.in_flight(), 0);
            assert_eq!(Arc::strong_count(&file), 2);

            harness.orphan(id);
            assert!(harness.driver.is_empty());
            assert_eq!(Arc::strong_count(&file), 1);
            assert_eq!(harness.completed.len(), 1);
            assert_eq!(returned(&mut harness.completed[0]), target);
            assert!(matches!(
                harness.completed[0].output,
                RequestOutput::ReadAt(Err((_, Error::Timeout)))
            ));

            harness.service();
            assert!(harness.driver.state.ready_queue.is_empty());
            assert_eq!(harness.driver.state.waiters.in_flight(), 0);

            harness.completed.clear();
            harness.drain();
        }

        // Only the open retains the directory hold, so dropping it releases the hold.
        assert!(matches!(
            probe.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
        drop(file);
        probe.try_lock().unwrap();

        drop(probe);
        fs::remove_dir_all(directory).unwrap();
    }

    /// A direct read whose observer is forwarded before its rejection falls back within the same
    /// request and delivers the buffered result through that observer.
    #[test]
    fn test_forwarded_direct_read_falls_back_through_its_observer() {
        let (directory, file) = make_file("direct_forwarded");
        let data: Vec<u8> = (0..2 * DIRECT_ALIGN).map(|i| (i % 251) as u8).collect();
        fs::write(directory.join("blob"), &data).unwrap();
        let fd = file.set_direct(
            OpenOptions::new()
                .read(true)
                .open(directory.join("blob"))
                .unwrap(),
        );
        let request =
            Request::ReadAt(ReadAtRequest::direct(file.clone(), fd, 100, DIRECT_ALIGN).unwrap());

        // Forward the observer of a staged read, then simulate a rejection of its direct read.
        // The request switches to a buffered read and requeues, so it stays in the driver and the
        // forwarded observer has no result yet.
        let mut harness = Harness::new(1);
        let id = harness.stage(request, None, 0);
        let (sender, mut receiver) = oneshot::channel();
        harness.driver.forward(id, sender, &mut harness.deferred);
        harness.collect();
        harness.simulated_completion(id, -libc::EINVAL);
        assert_eq!(harness.driver.len(), 1);
        assert_eq!(harness.driver.state.ready_queue.len(), 1);

        // The kernel serves the buffered read through the open's file, and the request retires
        // with one result for the forwarded observer.
        let limit = Instant::now() + Duration::from_secs(10);
        while !harness.driver.is_empty() {
            assert!(Instant::now() < limit, "the buffered read must finish");
            harness.service();
        }
        assert_eq!(harness.deferred.results.len(), 1);

        // Publishing the result delivers the range's bytes to the forwarded observer.
        for (sender, output) in harness.deferred.results.drain(..) {
            let _ = sender.send(output);
        }
        let Ok(Ok(RequestOutput::ReadAt(Ok(buf)))) = receiver.try_recv() else {
            panic!("the forwarded observer must receive a successful read");
        };
        assert_eq!(buf.as_ref(), &data[100..100 + DIRECT_ALIGN]);

        harness.drain();
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    /// The kernel serves direct reads through a real `O_DIRECT` descriptor, for an unaligned
    /// range and for a range ending at an unaligned end of file. The open's own file is empty, so
    /// only a read served by the direct descriptor returns the data.
    #[test]
    fn test_direct_reads_are_served_by_the_direct_descriptor() {
        let (directory, file) = make_file("direct_served");
        let data: Vec<u8> = (0..3 * DIRECT_ALIGN - 50)
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(directory.join("data"), &data).unwrap();
        let fd = file.set_direct(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECT)
                .open(directory.join("data"))
                .expect("temporary directory must support O_DIRECT"),
        );

        // The direct read of the first range fills its whole superset [0, 8192). The second range
        // ends at the end of the file, inside the last superset, so its direct read completes
        // short and unaligned.
        let mut harness = Harness::new(1);
        for (offset, len) in [(100, 5000), (2 * DIRECT_ALIGN + 10, DIRECT_ALIGN - 60)] {
            let request = ReadAtRequest::direct(file.clone(), fd, offset as u64, len).unwrap();
            harness.admit(Request::ReadAt(request), 0);
            harness.until(1);
            let RequestOutput::ReadAt(Ok(buf)) = harness.completed.remove(0).output else {
                panic!("the direct read of {offset}..{} must succeed", offset + len);
            };
            assert_eq!(buf.as_ref(), &data[offset..offset + len]);
        }

        harness.drain();
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_orphan_in_flight_cancels_once_and_releases_deadline() {
        for expire_bucket in [false, true] {
            let mut harness = Harness::new(1);
            let deadline = harness.start + Duration::from_secs(10);
            let (left, _right) = UnixStream::pair().unwrap();
            let id = harness.admit(recv(left, 8, Some(deadline)), 0);
            let (survivor, _survivor_peer) = UnixStream::pair().unwrap();
            if expire_bucket {
                harness.admit(recv(survivor, 1, Some(deadline)), 1);
            }
            harness.service();

            assert!(harness.driver.state.waiters.is_in_flight(id));

            // Repeated observer drops must not queue another cancel or remove the
            // same deadline from the wheel twice.
            harness.orphan(id);
            harness.orphan(id);

            if expire_bucket {
                // A live sibling forces the orphan's stale wheel record through
                // expiry before its cancellation or operation CQE arrives.
                harness
                    .driver
                    .state
                    .advance_timeouts(deadline, &mut harness.deferred);
                assert!(harness.driver.state.waiters.is_in_flight(id));
            }
            assert_eq!(harness.driver.state.pending_cancels.len(), 1);
            assert!(harness.driver.next_deadline().is_none());

            harness.collect();
            harness.drain();

            assert_eq!(harness.completed.len(), 1 + usize::from(expire_bucket));
            assert_eq!(
                harness
                    .completed
                    .iter()
                    .filter(|completed| matches!(completed.observer, TestObserver::Orphaned))
                    .count(),
                1
            );
            if expire_bucket {
                let survivor = harness
                    .completed
                    .iter()
                    .find(|completed| matches!(completed.observer, TestObserver::Local(1)))
                    .unwrap();
                assert!(matches!(
                    survivor.output,
                    RequestOutput::Recv(Err((_, Error::Timeout)))
                ));
            }
        }
    }

    #[test]
    fn test_expiring_bucket_preserves_unconsumed_success() {
        let mut harness = Harness::new(1);
        let deadline = harness.start + Duration::from_secs(30);
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"x").unwrap();
        let completed = harness.admit(recv(socket, 1, Some(deadline)), 0);
        let (survivor, _peer) = UnixStream::pair().unwrap();
        harness.admit(recv(survivor, 1, Some(deadline)), 1);

        // Retain the first result while another request keeps its bucket live.
        let limit = Instant::now() + Duration::from_secs(10);
        while harness.driver.state.waiters.is_pending(completed) {
            assert!(Instant::now() < limit, "receive stalled");
            harness
                .driver
                .service(Instant::now(), false, &mut harness.deferred)
                .unwrap();
            thread::yield_now();
        }
        harness
            .driver
            .state
            .advance_timeouts(deadline, &mut harness.deferred);
        assert!(harness.driver.next_deadline().is_none());

        harness.collect();
        assert!(matches!(
            harness.completed[0].observer,
            TestObserver::Local(0)
        ));
        assert_eq!(received(&harness.completed[0]), b"x");
        harness.drain();
        assert_eq!(harness.completed.len(), 2);
        assert!(matches!(
            harness.completed[1].observer,
            TestObserver::Local(1)
        ));
        assert!(matches!(
            harness.completed[1].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));
    }

    #[test]
    fn test_stale_waiter_identity_cannot_orphan_reused_slot() {
        let mut harness = Harness::new(1);
        let (old, _old_peer) = UnixStream::pair().unwrap();
        let old = harness.admit(recv(old, 1, None), 0);
        harness.orphan(old);
        harness.completed.clear();

        let (socket, mut peer) = UnixStream::pair().unwrap();
        let current = harness.admit(recv(socket, 1, None), 1);
        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old, current);

        // A delayed drop from the old observer cannot affect its replacement.
        harness.orphan(old);

        assert_eq!(harness.driver.len(), 1);
        assert!(harness.completed.is_empty());
        peer.write_all(b"x").unwrap();
        harness.until(1);

        assert!(matches!(
            harness.completed[0].observer,
            TestObserver::Local(1)
        ));

        harness.drain();
    }

    #[test]
    fn test_deferred_taskrun_is_serviced_during_busy_turn() {
        // The SQE fits, so staging does not itself force a submission syscall.
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service_at(harness.start, true);

        assert!(harness.completed.is_empty());
        assert!(!harness.driver.is_empty());
        assert_eq!(harness.driver.ring.submission().len(), 1);

        // The next busy turn submits the receive, which then waits for data.
        harness.service();
        assert_eq!(harness.driver.ring.submission().len(), 0);
        assert!(harness.completed.is_empty());

        // The data's completion waits in deferred task work. Only busy turns
        // run from here, so their enter alone must post it.
        right.write_all(b"x").unwrap();
        harness.until(1);

        assert_eq!(received(&harness.completed[0]), b"x");

        harness.drain();
    }

    #[test]
    fn test_ring_wait_alone_does_not_require_kernel_service() {
        let mut harness = Harness::new(1);

        // A live ring wait must not make a CPU-only turn enter the kernel.
        assert!(harness.park(0, Some(Instant::now())).unwrap());
        harness.service();

        assert!(harness.driver.is_empty());
        assert!(!harness.driver.has_pending_submissions());
        assert!(!harness.driver.state.ring_wait_needed);

        harness.drain();
    }

    #[test]
    fn test_skipped_park_keeps_deferred_service_obligation() {
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service_at(harness.start, true);

        // A notification prevents parking, so the deferred GETEVENTS enter
        // must still happen through service before the next busy turn.
        harness.driver.state.unparker.unpark();
        assert!(!harness.park(0, None).unwrap());
        assert!(!harness.driver.is_empty());
        harness.until(1);

        harness.drain();
    }

    #[test]
    fn test_notify_wakes_ring_blocked_loop() {
        let mut harness = Harness::new(2);
        let (left, _right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service();

        // Notify after arming so the ring wait must carry the notification.
        let deadline = Instant::now() + Duration::from_secs(10);
        let unparker = harness.driver.state.unparker.clone();
        let producer = thread::spawn(move || {
            wait_until_armed(&unparker, deadline);
            unparker.unpark();
        });
        assert!(harness.park(0, Some(deadline)).unwrap());
        producer.join().unwrap();

        assert!(harness.parker.moved(0));

        // A moved sequence alone does not prove the wake reached the ring.
        harness.reap_ring_wait();

        harness.drain();
    }

    /// A ring futex wait that the kernel fails to allocate ends like any other
    /// wait, so the next park installs another, which a notification wakes.
    #[test]
    fn test_ring_wait_allocation_failure_installs_again() {
        // A receive keeps the driver busy, and a park with an elapsed deadline
        // leaves its ring wait queued.
        let mut harness = Harness::new(2);
        let (left, _right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service();
        assert!(harness.park(0, Some(Instant::now())).unwrap());
        assert!(!harness.driver.state.ring_wait_needed);

        // Cancel that wait, so none is queued.
        harness
            .driver
            .ring
            .submitter()
            .register_sync_cancel(None, CancelBuilder::user_data(RING_WAIT_USER_DATA))
            .unwrap();

        // Reap the cancellation's completion directly, so the driver never sees
        // it.
        Driver::enter(&mut harness.driver.ring, Enter::TaskWork).unwrap();
        let cqe = harness.driver.ring.completion().next().unwrap();
        assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
        assert_eq!(cqe.result(), -libc::ECANCELED);

        // Hand the driver an allocation failure of a wait that never queued,
        // which ends the wait like any other.
        harness
            .driver
            .state
            .handle_cqe(RING_WAIT_USER_DATA, -libc::ENOMEM, &mut harness.deferred);
        assert!(harness.driver.state.ring_wait_needed);

        // The next park installs a new wait, and a notification after arming
        // ends it.
        let deadline = Instant::now() + Duration::from_secs(10);
        let unparker = harness.driver.state.unparker.clone();
        let producer = thread::spawn(move || {
            wait_until_armed(&unparker, deadline);
            unparker.unpark();
        });
        assert!(harness.park(0, Some(deadline)).unwrap());
        producer.join().unwrap();

        // The new wait's own completion carried the notification well before
        // the deadline.
        assert!(Instant::now() < deadline);
        assert!(!harness.driver.state.ring_wait_needed);
        harness.reap_ring_wait();
        assert!(harness.driver.state.ring_wait_needed);

        harness.drain();
    }

    /// Dropping a driver cancels its submitted ring wait, so no waiter remains
    /// on a futex word whose address can be reused, and then releases its
    /// handles on the word. A wait that a wake already took is not found by
    /// the cancel, which also lets the word go.
    #[test]
    fn test_driver_drop_cancels_ring_wait() {
        // Create the word shared by both cancellation cases.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let handles_without_driver = handles(&parker);
        for cancel in [false, true] {
            // A park with a short deadline leaves its ring wait queued.
            let mut driver = Driver::new(
                &RingConfig::default(),
                Duration::from_secs(60),
                unparker.clone(),
                Instant::now(),
            )
            .unwrap();
            assert!(
                driver
                    .park(&parker, 0, Some(Instant::now() + Duration::from_millis(2)))
                    .unwrap()
            );

            if cancel {
                // A duplicate descriptor keeps the ring alive across the drop,
                // so its teardown, which also removes the wait, cannot run
                // before the check.
                let ring = hold_ring(&driver);

                // Cancel the live wait by dropping its owner.
                drop(driver);

                // No wait remains while the duplicate keeps the ring alive, so
                // only the drop's synchronous cancel removed it.
                assert_eq!(wake(&unparker, 2), 0, "driver left its ring wait queued");
                drop(ring);
            } else {
                // Release the wait directly to prove the park queued it. The
                // driver has not reaped its completion, so the drop's cancel
                // finds no wait.
                let woken = wake(&unparker, 2);

                // Exactly the driver's ring wait was present.
                assert_eq!(woken, 1, "park did not queue its ring wait");
                drop(driver);
            }

            // The drop kept no handle, so the word can be freed.
            assert_eq!(handles(&parker), handles_without_driver);
        }
    }

    /// A driver dropped off its owner thread cannot cancel its ring wait,
    /// since the ring accepts the cancel only from the thread that created it.
    /// The drop then keeps the word allocated under the wait it leaves queued.
    #[test]
    fn test_driver_drop_off_its_owner_leaks_the_word() {
        // A park with a short deadline leaves its ring wait queued.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let handles_without_driver = handles(&parker);
        let mut driver = Driver::new(
            &RingConfig::default(),
            Duration::from_secs(60),
            unparker.clone(),
            Instant::now(),
        )
        .unwrap();
        assert!(
            driver
                .park(&parker, 0, Some(Instant::now() + Duration::from_millis(2)))
                .unwrap()
        );

        // Drop the driver on another thread, while a duplicate descriptor
        // keeps the ring, and so any wait its cancel missed, alive.
        let ring = hold_ring(&driver);
        std::thread::spawn(move || drop(driver)).join().unwrap();

        // The cancel failed, so the drop kept one handle and the wait is
        // still queued.
        assert_eq!(handles(&parker), handles_without_driver + 1);
        assert_eq!(wake(&unparker, 2), 1, "the ring wait was cancelled");
        drop(ring);
    }

    /// A drop whose cancel fails keeps the word allocated before it reports
    /// the failure, so a tracing subscriber that panics on the warning cannot
    /// free the word under the wait left queued.
    #[test]
    fn test_failed_cancel_keeps_the_word_if_the_warning_panics() {
        // A park with a short deadline leaves its ring wait queued.
        let parker = Parker::new();
        let unparker = parker.unparker();
        let handles_without_driver = handles(&parker);
        let mut driver = Driver::new(
            &RingConfig::default(),
            Duration::from_secs(60),
            unparker.clone(),
            Instant::now(),
        )
        .unwrap();
        assert!(
            driver
                .park(&parker, 0, Some(Instant::now() + Duration::from_millis(2)))
                .unwrap()
        );

        // Drop the driver off its owner thread, so its cancel fails, under a
        // subscriber that panics on the warning. A duplicate descriptor keeps
        // the ring, and so the wait, alive.
        let ring = hold_ring(&driver);
        let panicked = thread::spawn(move || {
            let subscriber = tracing_subscriber::registry().with(PanicOnEvent);
            tracing::subscriber::with_default(subscriber, || {
                catch_unwind(AssertUnwindSafe(|| drop(driver))).is_err()
            })
        })
        .join()
        .unwrap();
        assert!(panicked, "the warning did not reach the subscriber");

        // The wait is still queued, and the drop kept one handle on its word.
        assert_eq!(wake(&unparker, 2), 1, "the ring wait was cancelled");
        assert_eq!(handles(&parker), handles_without_driver + 1);
        drop(ring);
    }

    #[test]
    fn test_park_reserves_ring_wait_slot_with_full_sq() {
        for stalled in [false, true] {
            let mut harness = Harness::new(1);
            let (socket, mut peer) = UnixStream::pair().unwrap();
            let id = harness.admit(recv(socket, 1, None), 0);

            // The receive fills the SQ before the ring wait has a slot. Keep
            // the SQE unsubmitted so park must flush before arming.
            assert!(
                !harness
                    .driver
                    .state
                    .fill_submission_queue(&mut harness.driver.ring)
            );
            assert!(harness.driver.ring.submission().is_full());
            assert!(harness.driver.state.waiters.is_in_flight(id));
            assert!(harness.driver.state.ring_wait_needed);

            let _fault = stalled.then(|| inject(&harness.driver, Fault::StallFlush));
            if stalled {
                // An unchanged SQ has no slot for the ring wait. Park must
                // return to service with the request and the wait still needed.
                assert!(!harness.park(0, Some(Instant::now())).unwrap());
                assert!(harness.driver.state.ring_wait_needed);
                assert!(!harness.driver.is_empty());
                assert!(harness.driver.ring.submission().is_full());
                harness.service();

                // Service submits the receive but leaves the wait to park.
                assert!(harness.driver.state.ring_wait_needed);
            }

            // Keep the receive blocked. Only a notification after arming can
            // produce a CQE during this bounded wait.
            let deadline = Instant::now() + Duration::from_secs(10);
            let unparker = harness.driver.state.unparker.clone();
            let producer = thread::spawn(move || {
                wait_until_armed(&unparker, deadline);
                unparker.unpark();
            });
            assert!(harness.park(0, Some(deadline)).unwrap());
            producer.join().unwrap();

            assert!(harness.parker.moved(0));
            assert!(!harness.driver.state.ring_wait_needed);

            // Reap directly so the wait's own CQE carries the wake. The receive
            // must still be in flight.
            harness.reap_ring_wait();
            assert!(harness.driver.state.waiters.is_in_flight(id));

            // Reserving the slot must preserve the receive that occupied the SQ.
            peer.write_all(b"x").unwrap();
            harness.until(1);

            assert_eq!(received(&harness.completed[0]), b"x");

            harness.drain();
        }
    }

    #[test]
    fn test_transient_flush_without_sq_progress_returns_through_service() {
        let mut harness = Harness::new(1);
        harness.fill_with_control();

        assert_eq!(harness.driver.ring.submission().len(), 1);

        // Stall the flush needed to get past the already staged control SQE.
        let _fault = inject(&harness.driver, Fault::StallFlush);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        let id = harness.admit(recv(left, 1, None), 0);
        harness.service();

        // The failed flush must not consume or mark the queued operation as
        // in-flight. Its next attempt follows one GETEVENTS service point.
        assert!(!harness.driver.state.waiters.is_in_flight(id));
        assert_eq!(harness.driver.state.ready_queue.front(), Some(&id));
        assert!(FAULT.get().is_none());

        harness.until(1);

        assert_eq!(received(&harness.completed[0]), b"x");

        harness.drain();
    }

    #[test]
    fn test_partial_completion_releases_capacity_to_next_queued_request() {
        let mut harness = Harness::new(1);
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        first_peer.write_all(b"a").unwrap();
        harness.admit(recv(first, 2, None), 0);

        let (second, mut second_peer) = UnixStream::pair().unwrap();
        second_peer.write_all(b"x").unwrap();
        harness.admit(recv(second, 1, None), 1);

        // The first request needs another SQE. Its partial CQE releases the
        // sole slot so the older queued SQE can run before that follow-up.
        harness.until(1);

        assert!(matches!(
            harness.completed[0].observer,
            TestObserver::Local(1)
        ));
        assert_eq!(received(&harness.completed[0]), b"x");
        assert!(harness.driver.state.waiters.in_flight() <= 1);

        // The retry must append to the original buffer and finish second.
        first_peer.write_all(b"b").unwrap();
        harness.until(2);

        assert!(matches!(
            harness.completed[1].observer,
            TestObserver::Local(0)
        ));
        assert_eq!(received(&harness.completed[1]), b"ab");
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);

        harness.drain();
    }

    #[test]
    fn test_same_open_sync_waits_for_failure_accounting() {
        for state in [
            None,
            Some(WriteAtState::WritingSync),
            Some(WriteAtState::WritingBeforeSync),
        ] {
            let (directory, held) = make_file("sync_order");
            held.tracker.write();
            held.tracker.complete();

            // Both barriers are accepted while staging capacity remains available.
            let mut harness = Harness::new(2);
            let first = harness.admit(Request::Sync(SyncRequest::new(held.clone())), 0);
            let successor = state.map_or_else(
                || Request::Sync(SyncRequest::new(held.clone())),
                |state| {
                    let bufs = if state == WriteAtState::WritingBeforeSync {
                        (0..IOVEC_BATCH_SIZE + 1)
                            .map(|_| IoBuf::from(b"x"))
                            .collect()
                    } else {
                        IoBufs::from(IoBuf::from(b"new"))
                    };
                    Request::WriteAt(WriteAtRequest::new(
                        held.clone(),
                        0,
                        bufs.into(),
                        state,
                        Cache::Enabled,
                    ))
                },
            );
            let second = harness.admit(successor, 1);
            assert_eq!(harness.driver.len(), 2);
            assert_eq!(harness.driver.state.ready_queue.pop_front(), Some(first));
            assert!(
                !harness.driver.state.ready_queue.contains(&second),
                "durability request became ready before its predecessor was accounted"
            );

            // Keep the SQE out of the ring so its failure is supplied only by the
            // synthetic CQE. This models terminal ordering without a disk fault.
            harness.driver.state.waiters.stage(first);
            assert_eq!(harness.driver.state.waiters.in_flight(), 1);
            assert!(!harness.driver.has_pending_submissions());
            harness
                .driver
                .state
                .handle_cqe(first.user_data(), -libc::EIO, &mut harness.deferred);
            assert!(matches!(
                held.tracker.failure(),
                Some(Error::BlobSyncFailed(_, _, error))
                    if error.raw_os_error() == Some(libc::EIO)
            ));

            // The already accepted successor observes the retained failure without
            // staging a second kernel barrier or consuming the first result.
            harness
                .driver
                .service(Instant::now(), true, &mut harness.deferred)
                .unwrap();
            assert!(harness.driver.is_empty());
            assert_eq!(harness.driver.state.waiters.in_flight(), 0);
            harness.collect();
            assert_eq!(harness.completed.len(), 2);
            assert!(matches!(
                &harness.completed[0].output,
                RequestOutput::Sync(Err(Error::Io(error)))
                    if error.raw_os_error() == Some(libc::EIO)
            ));
            assert!(matches!(
                &harness.completed[1].output,
                RequestOutput::Sync(Err(Error::BlobSyncFailed(_, _, error)))
                    | RequestOutput::WriteAt(Err(Error::BlobSyncFailed(_, _, error)))
                    if error.raw_os_error() == Some(libc::EIO)
            ));

            harness.drain();
            drop(harness);
            drop(held);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn test_durable_write_keeps_permit_through_follow_up_sqes() {
        for state in [WriteAtState::WritingSync, WriteAtState::WritingBeforeSync] {
            let multibatch = state == WriteAtState::WritingBeforeSync;
            let (directory, file) = make_file("durable_follow_up");
            file.tracker.write();
            file.tracker.complete();
            let mut harness = Harness::new(2);
            let (bufs, completions) = if !multibatch {
                (
                    IoBufs::from(IoBuf::from(b"hello")),
                    vec![-libc::EOPNOTSUPP, -libc::EINTR, 2, 3],
                )
            } else {
                (
                    (0..IOVEC_BATCH_SIZE + 1)
                        .map(|_| IoBuf::from(b"x"))
                        .collect(),
                    vec![
                        -libc::EOPNOTSUPP,
                        -libc::EAGAIN,
                        IOVEC_BATCH_SIZE as i32,
                        1,
                        0,
                    ],
                )
            };
            let first = harness.driver.admit(
                Request::WriteAt(WriteAtRequest::new(
                    file.clone(),
                    0,
                    bufs.into(),
                    state,
                    Cache::Disabled,
                )),
                Observer::Local(None),
                harness.start,
                &mut harness.deferred,
            );
            let second = harness.admit(Request::Sync(SyncRequest::new(file.clone())), 1);

            // Orphaned work and unconsumed local outputs have the same permit lifetime.
            if multibatch {
                harness.driver.orphan(first, &mut harness.deferred);
            }
            for (index, result) in completions.iter().enumerate() {
                assert_eq!(harness.driver.state.ready_queue.pop_front(), Some(first));
                assert!(harness.driver.state.ready_queue.is_empty());
                harness.driver.state.waiters.stage(first);
                harness
                    .driver
                    .state
                    .handle_cqe(first.user_data(), *result, &mut harness.deferred);
                harness
                    .driver
                    .state
                    .poll_acquisitions(&mut harness.deferred);

                if index + 1 < completions.len() {
                    assert_eq!(harness.driver.state.acquiring.len(), 1);
                    assert!(!harness.driver.state.ready_queue.contains(&second));
                    assert!(file.durability.try_lock().is_err());
                }
            }

            assert!(harness.driver.state.acquiring.is_empty());
            assert!(!harness.driver.state.waiters.is_pending(first));

            // A trailing sync credits the write completed before it under the permit, so the
            // successor resolves without an SQE. A fused write covers only its own range.
            if multibatch {
                assert!(harness.driver.state.ready_queue.is_empty());
                assert!(!harness.driver.state.waiters.is_pending(second));
                harness.collect();
            } else {
                assert_eq!(harness.driver.state.ready_queue.pop_front(), Some(second));
                assert!(matches!(
                    harness.driver.observe(first, Waker::noop()),
                    Observation::Ready(RequestOutput::WriteAt(Ok(())))
                ));
                harness.driver.state.waiters.stage(second);
                harness.simulated_completion(second, 0);
            }
            assert_eq!(harness.completed.len(), 1 + usize::from(multibatch));
            assert!(harness.completed.iter().all(|completion| matches!(
                completion.output,
                RequestOutput::WriteAt(Ok(())) | RequestOutput::Sync(Ok(()))
            )));
            assert!(!file.tracker.is_dirty());
            harness.drain();
            drop(harness);
            drop(file);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn test_blocked_durability_does_not_count_as_ready_during_compaction() {
        let (directory, file) = make_file("blocked_compaction");
        file.tracker.write();
        file.tracker.complete();
        let permit = file.durability.clone().try_lock_owned().unwrap();
        let mut harness = Harness::new(1);
        let (active, mut active_peer) = UnixStream::pair().unwrap();
        harness.admit(recv(active, 1, None), 0);
        harness.service();
        let (independent, mut independent_peer) = UnixStream::pair().unwrap();
        independent_peer.write_all(b"x").unwrap();
        let independent = harness.admit(recv(independent, 1, None), 1);
        for tag in 2..4 {
            harness.admit(Request::Sync(SyncRequest::new(file.clone())), tag);
        }
        for _ in 0..65 {
            let (socket, _peer) = UnixStream::pair().unwrap();
            let stale = harness.admit(recv(socket, 1, None), 4);
            harness.orphan(stale);
        }
        harness.completed.clear();
        harness.service();
        assert_eq!(harness.driver.state.ready_queue, [independent]);
        assert_eq!(harness.driver.state.acquiring.len(), 2);
        assert_eq!(harness.driver.len(), 4);

        active_peer.write_all(b"x").unwrap();
        harness.until(2);
        assert_eq!(harness.driver.len(), 2);
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
        assert!(!harness.driver.has_pending_submissions());
        assert!(harness.driver.state.ready_queue.is_empty());
        drop(permit);
        harness.until(4);
        for (tag, completed) in harness.completed.iter().enumerate() {
            assert!(matches!(completed.observer, TestObserver::Local(id) if id == tag as u64));
        }
        harness.drain();
        drop(harness);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn test_durability_admitted_after_service_registers_its_wait() {
        let (directory, file) = make_file("admission_poll");
        let permit = file.durability.clone().try_lock_owned().unwrap();
        let mut harness = Harness::new(2);
        harness.service();

        // The native driver must progress even once the enclosing task has spent its
        // cooperative budget.
        while tokio::task::coop::has_budget_remaining() {
            tokio::task::consume_budget().await;
        }

        // A deferred callback can admit work after service, immediately before parking.
        harness.admit(Request::Sync(SyncRequest::new(file.clone())), 0);
        drop(permit);
        assert!(
            file.durability.try_lock().is_err(),
            "accepted wait did not reserve the released permit"
        );
        harness.until(1);
        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Sync(Ok(()))
        ));
        harness.drain();
        drop(harness);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_foreign_durability_release_wakes_closed_worker_park() {
        let (directory, file) = make_file("closed_permit_wake");
        let permit = file.durability.clone().try_lock_owned().unwrap();
        let parker = Parker::new();
        let mailbox = Arc::new(Mailbox::new(parker.unparker()));
        let mut driver = Driver::new(
            &RingConfig {
                size: 2,
                timeout_wheel_tick: Duration::from_millis(5),
            },
            Duration::from_secs(60),
            mailbox.unparker.clone(),
            Instant::now(),
        )
        .unwrap();
        let mut deferred = Deferred::default();
        let (sender, receiver) = oneshot::channel();
        driver.admit(
            Request::Sync(SyncRequest::new(file.clone())),
            Observer::DetachedSync(sender),
            Instant::now(),
            &mut deferred,
        );
        drop(receiver);
        assert!(mailbox.close().is_empty());
        driver.close(&mut deferred);
        driver.service(Instant::now(), true, &mut deferred).unwrap();

        // Observe before service, as cleanup does on every pass, so the measured
        // park compares against every earlier notification. No operation SQE can
        // produce a CQE.
        let seen = parker.observe();
        driver.service(Instant::now(), true, &mut deferred).unwrap();
        assert_eq!(driver.len(), 1);
        assert_eq!(driver.state.waiters.in_flight(), 0);
        assert!(!driver.has_pending_submissions());
        assert!(driver.ring.completion().is_empty());
        let deadline = Instant::now() + Duration::from_secs(10);
        let producer = thread::spawn(move || {
            wait_until_armed(&mailbox.unparker, deadline);
            assert!(!mailbox.is_open());
            drop(permit);
        });
        assert!(driver.park(&parker, seen, Some(deadline)).unwrap());
        producer.join().unwrap();
        let cqe = driver
            .ring
            .completion()
            .next()
            .expect("permit release did not wake the ring");
        assert_eq!(cqe.user_data(), RING_WAIT_USER_DATA);
        assert!(parker.moved(seen));
        driver
            .state
            .handle_cqe(cqe.user_data(), cqe.result(), &mut deferred);
        driver.service(Instant::now(), true, &mut deferred).unwrap();
        assert!(driver.is_empty());
        assert_eq!(deferred.completions.len(), 1);
        let (sender, result) = deferred.completions.pop().unwrap();
        assert!(result.is_ok());
        assert!(sender.send(result).is_err());
        drop(deferred);
        drop(driver);
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_shutdown_finishes_orphaned_write_and_detached_sync() {
        let mut harness = Harness::new(1);
        let directory =
            std::env::temp_dir().join(format!("commonware_driver_test_{}", std::process::id()));
        let hold = Hold::acquire(&directory).unwrap();
        let path = directory.join("durable");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let held = Shared::detached(file, hold);

        // More than one iovec batch forces a follow-up write before the sync.
        let bufs = (0..IOVEC_BATCH_SIZE + 1)
            .map(|_| IoBuf::from(b"x"))
            .collect::<IoBufs>();
        let id = harness.admit(
            Request::WriteAt(WriteAtRequest::new(
                held.clone(),
                0,
                bufs.into(),
                WriteAtState::WritingBeforeSync,
                Cache::Enabled,
            )),
            0,
        );
        harness.orphan(id);

        let (sender, receiver) = oneshot::channel();
        harness.driver.admit(
            Request::Sync(SyncRequest::new(held)),
            Observer::DetachedSync(sender),
            harness.start,
            &mut harness.deferred,
        );

        // Retained completion receivers do not participate in drain progress.
        harness.drain();

        assert_eq!(fs::read(&path).unwrap(), vec![b'x'; IOVEC_BATCH_SIZE + 1]);
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);

        // Publish only after request ownership has retired. The receiver has
        // not participated in the drain.
        let mut published = false;
        for completed in harness.completed {
            if let TestObserver::DetachedSync(sender) = completed.observer {
                let RequestOutput::Sync(result) = completed.output else {
                    panic!("wrong sync result");
                };
                assert!(sender.send(result).is_ok());
                published = true;
            }
        }

        assert!(published);
        assert!(futures::executor::block_on(receiver).unwrap().is_ok());

        fs::remove_dir_all(directory).unwrap();
    }

    /// Voluntary context switches of the calling thread so far.
    fn voluntary_switches() -> libc::c_long {
        // SAFETY: rusage holds only integers and timevals, for which all-zero
        // bytes are a valid value.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: `usage` is valid, writable storage for one rusage.
            unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut usage) },
            0
        );
        usage.ru_nvcsw
    }

    /// Busy service turns and parks whose deadline already passed must not
    /// sleep while a request is unfinished, and such a park must still run the
    /// deferred task work. A zero-timeout GETEVENTS wait arms a timer and
    /// schedules whenever no completion is ready, which shows as a voluntary
    /// context switch per enter.
    #[test]
    fn test_busy_service_and_expired_park_do_not_sleep() {
        /// Turns of one busy service enter and one expired park each.
        const TURNS: usize = 200;
        /// Voluntary context switches that unrelated sources may add over the
        /// turns. A sleeping enter would cost one for every enter.
        const MAX_VOLUNTARY_SWITCHES: libc::c_long = 20;

        // Keep a receive in flight with no data, so every turn must enter the
        // ring for its deferred task work and no completion is ready.
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service();
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);

        // Each turn makes one busy service enter and one park whose deadline
        // has already passed.
        let before = voluntary_switches();
        for _ in 0..TURNS {
            harness.service();
            assert!(harness.park(0, Some(Instant::now())).unwrap());
        }
        let switches = voluntary_switches() - before;
        assert!(
            switches < MAX_VOLUNTARY_SWITCHES,
            "{switches} voluntary context switches in {TURNS} turns"
        );

        // The data's completion now waits in deferred task work, which a park
        // whose deadline already passed must still run.
        right.write_all(b"x").unwrap();
        assert_eq!(harness.driver.ring.completion().len(), 0);
        assert!(harness.park(0, Some(Instant::now())).unwrap());
        assert_eq!(harness.driver.ring.completion().len(), 1);
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), b"x");
        harness.drain();
    }

    /// A completion the kernel dropped fails every kind of enter with `EBADR`,
    /// as it fails a wait that finds no completion ready. The kernel checks
    /// for dropped completions only in that wait. The fault simulates a
    /// nonzero overflow counter, so this checks how a drop propagates, not
    /// the counter read itself.
    #[test]
    fn test_every_enter_reports_a_dropped_completion() {
        // A flush fails, here the one park needs to reserve its ring wait's
        // SQ slot behind a receive that fills the SQ.
        let mut harness = Harness::new(1);
        let (socket, _peer) = UnixStream::pair().unwrap();
        harness.admit(recv(socket, 1, None), 0);
        assert!(
            !harness
                .driver
                .state
                .fill_submission_queue(&mut harness.driver.ring)
        );
        assert!(harness.driver.ring.submission().is_full());
        assert!(harness.driver.state.ring_wait_needed);
        let fault = inject(&harness.driver, Fault::DropCompletion);
        let error = harness.park(0, Some(Instant::now())).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADR));
        // The flush failed before installing the ring wait, not a later enter
        // in this park.
        assert!(harness.driver.state.ring_wait_needed);
        drop(fault);
        harness.drain();

        // Keep a receive in flight, so every turn enters the ring.
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service();
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);

        // A task-work enter fails, here the next busy service turn.
        let fault = inject(&harness.driver, Fault::DropCompletion);
        let error = harness
            .driver
            .service(Instant::now(), false, &mut harness.deferred)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADR));
        drop(fault);

        // So does a park whose deadline already passed.
        let fault = inject(&harness.driver, Fault::DropCompletion);
        let error = harness.park(0, Some(Instant::now())).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADR));
        drop(fault);

        // A timed wait fails too, here one that times out.
        let fault = inject(&harness.driver, Fault::DropCompletion);
        let deadline = Instant::now() + TIMED_WAIT;
        let error = harness.park(0, Some(deadline)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADR));
        drop(fault);

        // So does a wait that returns a completion, here an unbounded one
        // whose receive has data.
        right.write_all(b"x").unwrap();
        let fault = inject(&harness.driver, Fault::DropCompletion);
        let error = harness.park(0, None).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADR));
        drop(fault);

        // With no completion dropped, the receive completes and retires.
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), b"x");
        harness.drain();
    }

    #[test]
    fn test_enter_distinguishes_timeout_from_failure() {
        let mut harness = Harness::new(1);

        // The empty ring cannot produce a CQE. A wait that times out, a wait
        // whose deadline already passed and the enters that never wait still
        // succeed.
        for enter in [
            Enter::Flush,
            Enter::TaskWork,
            Enter::Wait {
                deadline: Some(Instant::now() + TIMED_WAIT),
            },
            Enter::Wait {
                deadline: Some(Instant::now()),
            },
        ] {
            Driver::enter(&mut harness.driver.ring, enter).unwrap();
        }

        // SAFETY: This isolated test closes the unused ring descriptor once,
        // then forgets the ring mapping owner before another FD can reuse it.
        assert_eq!(unsafe { libc::close(harness.driver.ring.as_raw_fd()) }, 0);
        let results = [
            Enter::Flush,
            Enter::TaskWork,
            Enter::Wait { deadline: None },
            Enter::Wait {
                deadline: Some(Instant::now() + Duration::from_secs(1)),
            },
            Enter::Wait {
                deadline: Some(Instant::now()),
            },
        ]
        .map(|enter| Driver::enter(&mut harness.driver.ring, enter));
        std::mem::forget(harness.driver);

        // Every enter path must preserve a permanent error. Forget the closed
        // ring before asserting so a failure cannot try to close its FD again.
        for result in results {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EBADF));
        }
    }
}
