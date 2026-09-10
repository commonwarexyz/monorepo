//! Worker-local io_uring submission, completion, and deadlines.
//!
//! [`Waiters`] owns each request's descriptors, buffers, progress, and observer.
//! The driver queues only IDs. New requests and partial completions join the
//! ready queue, waiting for both SQ space and an available operation slot.
//! Completion releases that slot even if the ordinary result remains unconsumed
//! in its waiter. Detached sync results leave through [`Deferred`].
//!
//! # Submission and Cancellation
//!
//! Staging keeps every SQE-referenced resource alive until the operation CQE,
//! including when submission returns a transient error. Cancellation CQEs only
//! acknowledge the cancellation attempt. They cannot release those resources.
//!
//! Dropping an ordinary observer cancels reads and network operations. Queued
//! requests can finish immediately, while in-flight requests need a cancellation
//! SQE and must await their operation CQE. Writes and syncs continue through all
//! follow-up SQEs after their observers are dropped.
//!
//! Cancellations stage first, followed by operations in FIFO order and wake-poll
//! rearming. The operation limit excludes cancellation and wake SQEs. A full SQ
//! needs a flush, but reaching the operation limit requires a CQE to free capacity.
//!
//! # Service and Parking
//!
//! Each service turn reaps completions, advances the timeout wheel, registers new
//! deadlines, and stages queued work. Reaping first lets a terminal completion
//! win a race with expiry. Partial progress after expiry cannot issue another SQE.
//! Queued requests expire even while all operation slots are occupied.
//!
//! The ring uses SINGLE_ISSUER and DEFER_TASKRUN, requiring Linux 6.1 or newer.
//! Pending operation and cancellation SQEs need a GETEVENTS enter even when tasks
//! keep the worker busy. An idle turn may defer that enter to [`Driver::park`].
//! The mailbox wake poll alone requires no syscall on a busy turn.
//!
//! Parking installs the wake poll if needed, then arms the mailbox waker and
//! rechecks publication before blocking. A wake CQE without MORE requires rearm
//! before the next blocking wait.
//!
//! # Cleanup
//!
//! All callbacks and resource destruction go through [`Deferred`], outside the
//! worker borrow. Closure detaches ordinary observers and cancels eligible
//! requests. The worker continues servicing until all requests and cancellation
//! CQEs retire, keeping the driver in place throughout the drain.

use super::{
    request::Request,
    runtime::{Deferred, RingConfig},
    timeout::TimeoutWheel,
    waiter::{CompletionOutcome, Observation, Observer, WaiterId, Waiters},
    waker::{WAKE_USER_DATA, Waker},
};
use crate::Error;
use io_uring::{
    IoUring,
    cqueue::Entry as CqueueEntry,
    opcode::AsyncCancel,
    squeue::SubmissionQueue,
    types::{SubmitArgs, Timespec},
};
use std::{
    collections::VecDeque,
    io,
    task::Waker as TaskWaker,
    time::{Duration, Instant},
};

/// Ring and request state accessed exclusively by the owning worker.
pub struct Driver {
    /// Declared first so ring destruction precedes descriptor and buffer release.
    ring: IoUring,
    /// Kept separately to allow batching SQ access while updating request state.
    state: State,
}

/// Request state borrowed independently of the ring's SQ and CQ mappings.
struct State {
    /// Queued requests, in-flight requests, and unconsumed ordinary results.
    waiters: Waiters,
    /// Maximum number of outstanding operation SQEs.
    in_flight_limit: usize,
    /// FIFO of initial and follow-up operation SQEs, with lazily removed stale IDs.
    ready_queue: VecDeque<WaiterId>,
    /// New requests whose deadlines must be registered after advancing the wheel.
    pending_deadlines: VecDeque<WaiterId>,
    /// Requests awaiting a cancellation SQE, skipped if their operation finishes first.
    pending_cancels: VecDeque<WaiterId>,
    /// Deadlines for queued and in-flight requests, independent of sleepers.
    timeout_wheel: TimeoutWheel,
    /// Shared mailbox wake source retained through ring destruction.
    waker: Waker,
    /// Whether the multishot wake poll needs to be installed again.
    wake_rearm_needed: bool,
    /// Cancellation SQEs staged but not yet acknowledged by their own CQEs.
    outstanding_cancels: usize,
    /// Whether a transient submit left work requiring another service enter.
    submit_retry: bool,
}

impl Driver {
    /// Create a ring on its permanent owner thread after configuration validation.
    ///
    /// Uses the CQ sizing and overflow policy described by [`RingConfig::size`].
    pub fn new(
        cfg: &RingConfig,
        max_timeout: Duration,
        waker: Waker,
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
                pending_deadlines: VecDeque::with_capacity(size),
                pending_cancels: VecDeque::with_capacity(size),
                timeout_wheel: TimeoutWheel::new(max_timeout, cfg.timeout_wheel_tick, now),
                waker,
                wake_rearm_needed: true,
                outstanding_cancels: 0,
                submit_retry: false,
            },
        })
    }

    /// Accept an owned request into the FIFO without staging kernel work.
    ///
    /// Deadline validation happens during service after the wheel has advanced.
    pub fn admit(&mut self, request: Request, observer: Observer) -> WaiterId {
        let timed = request.deadline().is_some();

        // Transfer ownership once. Both queues below carry only this identity.
        let id = self.state.waiters.insert(request, observer);
        if timed {
            // A task poll may have taken long enough to leave the wheel behind.
            // Service refreshes it before assigning this deadline a tick.
            self.state.pending_deadlines.push_back(id);
        }

        // First submissions join the same FIFO as follow-ups from partial CQEs.
        self.state.ready_queue.push_back(id);
        id
    }

    /// Number of active logical requests, excluding retained completed outputs.
    pub const fn len(&self) -> usize {
        self.state.waiters.len()
    }

    /// Whether all logical requests and cancellation acknowledgements retired.
    pub const fn is_empty(&self) -> bool {
        self.state.waiters.is_empty() && self.state.outstanding_cancels == 0
    }

    /// Whether kernel work needs a GETEVENTS service opportunity.
    pub const fn needs_kernel_service(&self) -> bool {
        !self.is_empty() || self.state.submit_retry
    }

    /// Whether actionable staging or deadline registration must run before parking.
    pub fn has_pending_submissions(&self) -> bool {
        (!self.state.ready_queue.is_empty()
            && self.state.waiters.in_flight() < self.state.in_flight_limit)
            || !self.state.pending_deadlines.is_empty()
            || !self.state.pending_cancels.is_empty()
            || self.state.submit_retry
    }

    /// Earliest active deadline registered on the operation wheel.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.timeout_wheel.next_deadline_at()
    }

    /// Consume a retained result or check whether its waker needs refreshing.
    pub fn observe(&mut self, id: WaiterId, waker: &TaskWaker) -> Observation {
        self.state.waiters.observe(id, waker)
    }

    /// Install a waker cloned outside the worker borrow, returning the displaced one.
    pub fn set_waker(&mut self, id: WaiterId, waker: TaskWaker) -> Option<TaskWaker> {
        self.state.waiters.set_waker(id, waker)
    }

    /// Detach ordinary observation and request eligible cancellation.
    pub fn orphan(&mut self, id: WaiterId, deferred: &mut Deferred) {
        if self.state.waiters.orphan(id, deferred) {
            self.state.cancel(id, deferred);
        }
    }

    /// Reject an expired registration before its first SQE.
    pub fn expire(&mut self, id: WaiterId, deferred: &mut Deferred) {
        self.state.cancel(id, deferred);
    }

    /// Clear ordinary observation before draining retained writes and syncs.
    pub fn close(&mut self, deferred: &mut Deferred) {
        for id in self.state.waiters.close(deferred) {
            self.state.cancel(id, deferred);
        }
    }

    /// Process completions, deadlines, and queued submissions without callbacks.
    ///
    /// Returns whether a wake CQE requested an inbox recheck. `defer_kernel_service`
    /// permits the following idle ring wait to supply GETEVENTS. It is ignored
    /// when callbacks or unfinished staging already require another busy turn.
    pub fn service(
        &mut self,
        now: Instant,
        defer_kernel_service: bool,
        deferred: &mut Deferred,
    ) -> io::Result<bool> {
        // Finish posted work before expiring requests, then register deadlines
        // against the refreshed wheel so an idle interval cannot shorten them.
        let mut woke = self.state.reap(&mut self.ring, deferred);
        self.state.advance_timeouts(now, deferred);
        self.state.register_deadlines(now, deferred);
        self.state.compact_ready_queue();

        while self.state.fill_submission_queue(&mut self.ring) {
            let before = self.ring.submission().len();
            Self::submit_and_wait(&mut self.ring, 0, None)?;
            if self.ring.submission().len() >= before {
                // A transient enter may leave the SQ full. Preserve queued
                // identities and give the kernel a completion-service point
                // before another staging attempt.
                self.state.submit_retry = true;
                break;
            }
        }

        // Busy turns must run deferred kernel work. An idle turn can leave this
        // enter to park, unless callbacks or more submissions need attention.
        if self.needs_kernel_service()
            && (!defer_kernel_service || !deferred.is_empty() || self.has_pending_submissions())
        {
            Self::submit_and_wait(&mut self.ring, 1, Some(Duration::ZERO))?;
            self.state.submit_retry = !self.ring.submission().is_empty();
        }

        // New CQEs can complete requests or terminate the multishot wake poll.
        // Park rechecks rearm before its next blocking enter.
        woke |= self.state.reap(&mut self.ring, deferred);

        #[cfg(test)]
        tests::after_service(&self.ring, deferred)?;

        Ok(woke)
    }

    /// Wait for ring activity or the deadline while retaining worker ownership.
    ///
    /// Returns `false` when rearm needs another service turn or the publication
    /// handshake rejects sleeping. A skipped wait does not satisfy a deferred
    /// GETEVENTS requirement, so the worker must service nonblocking before its
    /// next task-polling turn when kernel work remains.
    pub fn park(&mut self, processed_seq: u32, deadline: Option<Instant>) -> io::Result<bool> {
        if self.has_pending_submissions() {
            return Ok(false);
        }

        // Rearm before publishing the intention to sleep. A transient flush can
        // leave the SQ full, in which case service must run before trying again.
        if self.state.wake_rearm_needed {
            if !self.state.waker.reinstall(&mut self.ring.submission()) {
                Self::submit_and_wait(&mut self.ring, 0, None)?;
                if !self.state.waker.reinstall(&mut self.ring.submission()) {
                    self.state.submit_retry = true;
                    return Ok(false);
                }
            }
            self.state.wake_rearm_needed = false;
        }

        // Keep the arm guard alive through the wait. A publication racing this
        // check either prevents sleeping or signals the installed wake poll.
        let arm = self.state.waker.arm(processed_seq);
        if !arm.still_idle() {
            return Ok(false);
        }
        let timeout = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        Self::submit_and_wait(&mut self.ring, 1, timeout)?;
        self.state.submit_retry = !self.ring.submission().is_empty();
        Ok(true)
    }

    /// Submit queued SQEs and wait for `want` completions, optionally with a timeout.
    ///
    /// Timeouts and transient enter errors return successfully so the caller can
    /// reap CQEs and retry through the service loop. Success does not guarantee
    /// that the kernel consumed the SQ or produced a completion.
    fn submit_and_wait(
        ring: &mut IoUring,
        want: usize,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        #[cfg(test)]
        if tests::stall_flush(ring, want) {
            return Ok(());
        }

        // Callers request zero completions for a flush and one for kernel
        // service. A zero-duration timeout keeps a busy service turn nonblocking.
        let result = timeout.map_or_else(
            || ring.submit_and_wait(want),
            |timeout| {
                // EXT_ARG bounds the wait without reserving an SQE for a timeout.
                let ts = Timespec::new()
                    .sec(timeout.as_secs())
                    .nsec(timeout.subsec_nanos());
                let args = SubmitArgs::new().timespec(&ts);
                ring.submitter().submit_with_args(want, &args)
            },
        );

        match result {
            Ok(_) => Ok(()),
            Err(err) => match err.raw_os_error() {
                // This timeout bounds the enter. Request expiry belongs to the wheel.
                Some(libc::ETIME) if timeout.is_some() => Ok(()),
                // Reap before retrying. An immediate retry here could spin while
                // the kernel needs CQ space to make further progress.
                Some(libc::EINTR | libc::EAGAIN | libc::EBUSY) => Ok(()),
                _ => Err(err),
            },
        }
    }
}

impl State {
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
        for entry in expired {
            // A stale wheel entry must match both the waiter generation and
            // its scheduled tick before changing deadline state.
            if self.waiters.target_tick(entry.waiter_id) == Some(entry.target_tick) {
                self.cancel(entry.waiter_id, deferred);
            }
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
                    // An unsupported deadline fails through the ordinary result
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
        // Every pending request without an in-flight SQE has exactly one ID
        // in the ready queue. Any additional IDs belong to retired requests.
        let queued = self.waiters.len() - self.waiters.in_flight();
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
        // cancellation and mailbox wake SQEs must still be allowed to stage.
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
                .user_data(id.cancel_user_data());

            // SAFETY: AsyncCancel carries only the stable user_data identity.
            // Its target's waiter retains every kernel-visible owner, and the
            // loop checked SQ capacity before taking this queued identity.
            unsafe {
                submission_queue
                    .push(&cancel)
                    .expect("checked cancellation SQ capacity");
            }
            self.outstanding_cancels += 1;
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
        if self.stage_ready_requests(&mut submission_queue) {
            return true;
        }

        // Reaching the operation limit still leaves wake polling eligible.
        // If the SQ itself is full, retain the rearm flag across the flush.
        if self.wake_rearm_needed {
            if !self.waker.reinstall(&mut submission_queue) {
                return true;
            }
            self.wake_rearm_needed = false;
        }
        false
    }

    /// Reap every posted CQE without invoking observer callbacks.
    fn reap(&mut self, ring: &mut IoUring, deferred: &mut Deferred) -> bool {
        let mut woke = false;

        // Dropping this CQ view returns the consumed slots to the kernel.
        // Observer callbacks remain deferred until the worker borrow ends.
        for cqe in ring.completion() {
            // Keep processing the batch after a wake has requested an inbox check.
            woke |= self.handle_cqe(cqe, deferred);
        }

        woke
    }

    /// Apply a CQE, returning whether the worker should recheck its mailbox.
    fn handle_cqe(&mut self, cqe: CqueueEntry, deferred: &mut Deferred) -> bool {
        let user_data = cqe.user_data();

        // The reserved mailbox token is outside the waiter's ID space.
        if user_data == WAKE_USER_DATA {
            assert!(
                cqe.result() >= 0,
                "wake poll CQE failed: requires Linux 6.1+ multishot polling"
            );
            // Clear eventfd readiness. The worker drains the actual messages
            // after this CQ batch and the local borrow have ended.
            self.waker.acknowledge();
            if !io_uring::cqueue::more(cqe.flags()) {
                // The kernel removed the multishot poll. Reinstall it before
                // the next blocking wait, even if this was service's final reap.
                self.wake_rearm_needed = true;
            }
            return true;
        }

        // Waiters releases an operation's in-flight count before returning its
        // outcome. Cancellation acknowledgements leave that count untouched.
        match self.waiters.on_completion(user_data, cqe.result()) {
            CompletionOutcome::Cancel => {
                // This CQE can outlive the request and its slot. Track the debt
                // separately so shutdown still waits for its acknowledgement.
                self.outstanding_cancels = self
                    .outstanding_cancels
                    .checked_sub(1)
                    .expect("untracked cancellation CQE");
            }
            // Partial progress rejoins the tail behind already queued work.
            CompletionOutcome::Requeue(id) => self.ready_queue.push_back(id),
            CompletionOutcome::Complete(id, result) => self.complete(id, result, deferred),
        }
        false
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        IoBuf, IoBufMut, IoBufs,
        iouring::{
            request::{
                Cache, Held, IOVEC_BATCH_SIZE, ReadAtRequest, RecvRequest, RequestOutput,
                SyncRequest, WriteAtRequest, WriteAtState,
            },
            waker::tests::wait_until_eventfd_armed,
        },
        storage::hold::Hold,
    };
    use commonware_utils::channel::oneshot;
    use std::{
        cell::Cell,
        fs::{self, OpenOptions},
        io::Write,
        os::{
            fd::{AsRawFd, RawFd},
            unix::net::UnixStream,
        },
        sync::Arc,
        task::Wake,
        thread,
    };

    /// Kernel outcomes that cannot be scheduled reliably with a real ring.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        /// A transient flush leaves every SQ entry untouched.
        StallFlush,
        /// Service fails with retired resources awaiting deferred cleanup.
        AfterCompletion,
    }

    thread_local! {
        /// One failure scoped to the calling thread and the selected ring.
        static FAULT: Cell<Option<(RawFd, Fault)>> = const { Cell::new(None) };
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
    pub fn stall_flush(ring: &IoUring, want: usize) -> bool {
        want == 0 && take_fault(ring, Fault::StallFlush)
    }

    /// Fail service when retired resources are awaiting deferred cleanup.
    pub fn after_service(ring: &IoUring, deferred: &Deferred) -> io::Result<()> {
        if !deferred.resources.is_empty() && take_fault(ring, Fault::AfterCompletion) {
            return Err(io::Error::other(
                "injected service failure after completion",
            ));
        }

        Ok(())
    }

    /// Destination of a result collected by the harness.
    enum TestObserver {
        /// Ordinary result identified by a test-assigned tag.
        Ordinary(u64),
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

    /// Distinct waker allocation used to identify an ordinary completion.
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
        /// Callbacks and resources detached by driver transitions.
        deferred: Deferred,
        /// Ordinary observers matched by waker identity, with test-assigned tags.
        tracked: Vec<(WaiterId, u64, TaskWaker)>,
        /// Collected results retained for assertions.
        completed: Vec<Completed>,
        /// Initial wheel time, also used as the origin for simulated deadlines.
        start: Instant,
    }

    impl Harness {
        /// Create a real ring whose SQ size also bounds in-flight operations.
        fn new(size: u32) -> Self {
            let start = Instant::now();
            Self {
                driver: Driver::new(
                    &RingConfig {
                        size,
                        timeout_wheel_tick: Duration::from_millis(5),
                    },
                    Duration::from_secs(60),
                    Waker::new().unwrap(),
                    start,
                )
                .unwrap(),
                deferred: Deferred::default(),
                tracked: Vec::new(),
                completed: Vec::new(),
                start,
            }
        }

        /// Queue an ordinary request whose result `collect` will consume automatically.
        fn admit(&mut self, request: Request, tag: u64) -> WaiterId {
            let waker = TaskWaker::from(Arc::new(Notify));
            let id = self
                .driver
                .admit(request, Observer::Ordinary(Some(waker.clone())));
            self.tracked.push((id, tag, waker));
            id
        }

        /// Stage a request without submitting its SQE, for simulated completions.
        fn stage(&mut self, request: Request, tick: Option<u64>, tag: u64) -> WaiterId {
            let waker = TaskWaker::from(Arc::new(Notify));
            let id = self
                .driver
                .state
                .waiters
                .insert(request, Observer::Ordinary(Some(waker.clone())));
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

        /// Collect deferred outputs and consume ordinary results in wake order.
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
                    observer: TestObserver::Ordinary(tag),
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
            for (sender, output) in self.deferred.sync_results.drain(..) {
                self.completed.push(Completed {
                    observer: TestObserver::DetachedSync(sender),
                    output: RequestOutput::Sync(output),
                });
            }
        }

        /// Drop an ordinary observer and collect any immediately discarded output.
        fn orphan(&mut self, id: WaiterId) {
            self.driver.orphan(id, &mut self.deferred);
            self.collect();
        }

        /// Service at a chosen time, collect results, and report mailbox wake CQEs.
        fn service_at(&mut self, now: Instant, defer: bool) -> bool {
            let woke = self.driver.service(now, defer, &mut self.deferred).unwrap();
            self.collect();
            woke
        }

        /// Service using wall-clock time and run deferred kernel work immediately.
        fn service(&mut self) -> bool {
            self.service_at(Instant::now(), false)
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

        /// Close ordinary observation and wait for request and cancellation retirement.
        fn drain(&mut self) {
            self.driver.close(&mut self.deferred);
            self.collect();

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
                CompletionOutcome::Cancel => unreachable!(),
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
        for _ in 0..65 {
            let (socket, _peer) = UnixStream::pair().unwrap();
            results.push(harness.driver.admit(
                recv(socket, 1, Some(harness.start)),
                Observer::Ordinary(None),
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
            recv(socket, 1, Some(harness.start)),
            Observer::Ordinary(None),
        ));
        harness.service();

        assert_eq!(harness.driver.state.ready_queue.len(), 1);

        // Releasing capacity lets staging discard the one remaining stale ID.
        peer.write_all(b"x").unwrap();
        harness.until(1);
        harness.service();

        assert!(harness.driver.is_empty());
        assert!(!harness.driver.needs_kernel_service());
        assert!(!harness.driver.has_pending_submissions());

        // Neither compaction nor skipped staging may consume the results.
        for id in results {
            assert!(matches!(
                harness.driver.observe(id, TaskWaker::noop()),
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
            assert!(matches!(completed.observer, TestObserver::Ordinary(id) if id == tag as u64));
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
        assert!(harness.driver.park(0, Some(Instant::now())).unwrap());
        first_peer.write_all(b"a").unwrap();
        harness.until(3);

        for (tag, expected) in [b"a", b"b", b"c"].into_iter().enumerate() {
            let completed = &harness.completed[tag];
            assert!(matches!(completed.observer, TestObserver::Ordinary(id) if id == tag as u64));
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
        assert_eq!(harness.driver.state.outstanding_cancels, 0);
    }

    #[test]
    fn test_unconsumed_result_releases_staging_capacity() {
        let mut harness = Harness::new(1);
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        first_peer.write_all(b"a").unwrap();

        // Omit the observer waker so the harness leaves this result in Waiters.
        let first = harness
            .driver
            .admit(recv(first, 1, None), Observer::Ordinary(None));

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
            harness.driver.observe(first, TaskWaker::noop()),
            Observation::Ready(RequestOutput::Recv(Ok((_, 1))))
        ));

        harness.drain();
    }

    #[test]
    fn test_expired_registration_never_stages() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 8, Some(harness.start)), 0);

        // A deadline equal to this turn's time has already expired.
        harness.service_at(harness.start, true);

        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));
        assert!(harness.driver.is_empty());
        assert!(harness.driver.next_deadline().is_none());

        // Only the mailbox poll reached the SQ. The expired receive did not.
        assert_eq!(harness.driver.ring.submission().len(), 1);

        harness.drain();
    }

    #[test]
    fn test_staging_discards_stale_ids_with_full_sq() {
        for with_pending in [false, true] {
            let mut harness = Harness::new(1);

            // The mailbox poll fills the SQ without using an operation slot.
            harness.service();

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
            assert!(matches!(completed.observer, TestObserver::Ordinary(id) if id == tag));
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
        assert_eq!(harness.driver.ring.submission().len(), 1);

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
    fn test_drain_waits_for_cancel_cqe_after_request_finishes() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.stage(recv(left, 8, None), Some(1), 0);

        // Submit only the cancellation to the real kernel. Simulate the
        // operation CQE so logical retirement is guaranteed to happen first.
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.deferred,
        );
        assert!(
            !harness
                .driver
                .state
                .stage_cancellations(&mut harness.driver.ring.submission())
        );
        assert_eq!(harness.driver.state.outstanding_cancels, 1);

        harness.simulated_completion(id, 4);

        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));

        // The kernel will acknowledge the staged cancel after logical
        // retirement. Drain must wait for that CQE despite the empty slab.
        assert_eq!(harness.driver.len(), 0);
        assert!(!harness.driver.is_empty());
        assert!(harness.driver.next_deadline().is_none());

        harness.drain();

        assert_eq!(harness.driver.state.outstanding_cancels, 0);
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
        let held = Held::new(file, hold);

        for close in [false, true] {
            for result in [-libc::EAGAIN, 2] {
                let mut harness = Harness::new(1);
                let id = harness.stage(
                    Request::ReadAt(ReadAtRequest {
                        file: held.clone(),
                        offset: 0,
                        len: 5,
                        read: 0,
                        buf: IoBufMut::with_capacity(5),
                        cache: Cache::Enabled,
                    }),
                    None,
                    0,
                );

                if close {
                    harness.driver.close(&mut harness.deferred);
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

    #[test]
    fn test_orphan_in_flight_cancels_once_and_releases_deadline() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.admit(
            recv(left, 8, Some(harness.start + Duration::from_secs(10))),
            0,
        );
        harness.service();

        assert!(harness.driver.state.waiters.is_in_flight(id));

        // Repeated observer drops must not queue another cancel or remove the
        // same deadline from the wheel twice.
        harness.orphan(id);
        harness.orphan(id);

        assert_eq!(harness.driver.state.pending_cancels.len(), 1);
        assert!(harness.driver.next_deadline().is_none());

        harness.drain();

        assert_eq!(harness.completed.len(), 1);
        assert!(matches!(
            harness.completed[0].observer,
            TestObserver::Orphaned
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
            TestObserver::Ordinary(1)
        ));

        harness.drain();
    }

    #[test]
    fn test_deferred_taskrun_is_serviced_during_busy_turn() {
        // Both SQEs fit, so staging does not itself force a submission syscall.
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service_at(harness.start, true);

        assert!(harness.completed.is_empty());
        assert!(harness.driver.needs_kernel_service());

        // No further admission is needed to drive the deferred task work.
        harness.until(1);

        assert_eq!(received(&harness.completed[0]), b"x");

        harness.drain();
    }

    #[test]
    fn test_wake_poll_alone_does_not_require_kernel_service() {
        let mut harness = Harness::new(1);

        // Staging the mailbox poll must not make a CPU-only turn enter the kernel.
        harness.service();

        assert!(!harness.driver.needs_kernel_service());
        assert!(!harness.driver.has_pending_submissions());
        assert_eq!(harness.driver.ring.submission().len(), 1);

        harness.drain();
    }

    #[test]
    fn test_skipped_park_keeps_deferred_service_obligation() {
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service_at(harness.start, true);

        // Publication prevents parking, so the deferred GETEVENTS enter must
        // still happen through service before the next busy turn.
        harness.driver.state.waker.wake();
        assert!(!harness.driver.park(0, None).unwrap());
        assert!(harness.driver.needs_kernel_service());
        harness.until(1);

        harness.drain();
    }

    #[test]
    fn test_publish_wakes_eventfd_blocked_loop() {
        let mut harness = Harness::new(2);
        let (left, _right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 1, None), 0);
        harness.service();

        // Publish after arming so the eventfd path must carry the notification.
        let deadline = Instant::now() + Duration::from_secs(10);
        let waker = harness.driver.state.waker.clone();
        let producer = thread::spawn(move || {
            wait_until_eventfd_armed(&waker, deadline);
            if waker.publish_deferred() {
                waker.wake();
            }
        });
        assert!(harness.driver.park(0, Some(deadline)).unwrap());
        producer.join().unwrap();

        assert!(harness.driver.state.waker.pending(0));

        // A published sequence alone does not prove eventfd reached the ring.
        // Service must observe the wake CQE produced during the wait.
        assert!(harness.service());

        harness.drain();
    }

    #[test]
    fn test_park_rearms_wake_poll_with_full_sq() {
        for stalled in [false, true] {
            let mut harness = Harness::new(1);
            let (socket, mut peer) = UnixStream::pair().unwrap();
            let id = harness.admit(recv(socket, 1, None), 0);

            // The receive fills the SQ before wake polling can be installed.
            // Keep the SQE unsubmitted so park must flush before rearming.
            assert!(
                harness
                    .driver
                    .state
                    .fill_submission_queue(&mut harness.driver.ring)
            );
            assert!(harness.driver.ring.submission().is_full());
            assert!(harness.driver.state.waiters.is_in_flight(id));
            assert!(harness.driver.state.wake_rearm_needed);

            let _fault = stalled.then(|| inject(&harness.driver, Fault::StallFlush));
            if stalled {
                // An unchanged SQ cannot accept the wake poll. Park must return
                // to service with both rearm and submission retry still pending.
                assert!(!harness.driver.park(0, Some(Instant::now())).unwrap());
                assert!(harness.driver.state.wake_rearm_needed);
                assert!(harness.driver.has_pending_submissions());
                assert!(harness.driver.ring.submission().is_full());
                harness.service();

                assert!(!harness.driver.state.wake_rearm_needed);
            }

            // Keep the receive blocked. Only a wake published after arming can
            // produce a CQE during this bounded wait.
            let deadline = Instant::now() + Duration::from_secs(10);
            let waker = harness.driver.state.waker.clone();
            let producer = thread::spawn(move || {
                wait_until_eventfd_armed(&waker, deadline);
                if waker.publish_deferred() {
                    waker.wake();
                }
            });
            assert!(harness.driver.park(0, Some(deadline)).unwrap());
            producer.join().unwrap();

            assert!(harness.driver.state.waker.pending(0));
            assert!(!harness.driver.state.wake_rearm_needed);

            // Reap directly so service cannot hide a missing poll by installing
            // one after park returns. The receive must still be in flight.
            assert!(
                harness
                    .driver
                    .state
                    .reap(&mut harness.driver.ring, &mut harness.deferred)
            );
            assert!(harness.driver.state.waiters.is_in_flight(id));

            // Rearming must preserve the receive that occupied the SQ.
            peer.write_all(b"x").unwrap();
            harness.until(1);

            assert_eq!(received(&harness.completed[0]), b"x");

            harness.drain();
        }
    }

    #[test]
    fn test_transient_flush_without_sq_progress_returns_through_service() {
        let mut harness = Harness::new(1);
        harness.service();

        assert_eq!(harness.driver.ring.submission().len(), 1);

        // Stall the flush needed to get past the already staged mailbox poll.
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
            TestObserver::Ordinary(1)
        ));
        assert_eq!(received(&harness.completed[0]), b"x");
        assert!(harness.driver.state.waiters.in_flight() <= 1);

        // The retry must append to the original buffer and finish second.
        first_peer.write_all(b"b").unwrap();
        harness.until(2);

        assert!(matches!(
            harness.completed[1].observer,
            TestObserver::Ordinary(0)
        ));
        assert_eq!(received(&harness.completed[1]), b"ab");
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);

        harness.drain();
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
        let held = Held::new(file, hold);

        // More than one iovec batch forces a follow-up write before the sync.
        let bufs = IoBufs::from(
            (0..IOVEC_BATCH_SIZE + 1)
                .map(|_| IoBuf::from(b"x"))
                .collect::<Vec<_>>(),
        );
        let id = harness.admit(
            Request::WriteAt(WriteAtRequest {
                file: held.clone(),
                offset: 0,
                written: 0,
                write: bufs.into(),
                state: WriteAtState::WritingBeforeSync,
                cache: Cache::Enabled,
            }),
            0,
        );
        harness.orphan(id);

        let (sender, receiver) = oneshot::channel();
        harness.driver.admit(
            Request::Sync(SyncRequest { file: held }),
            Observer::DetachedSync(sender),
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

    #[test]
    fn test_submit_and_wait_distinguishes_timeout_from_failure() {
        let mut harness = Harness::new(1);

        // The empty ring cannot produce a CQE. A timed wait is still successful.
        Driver::submit_and_wait(&mut harness.driver.ring, 1, Some(Duration::ZERO)).unwrap();

        // SAFETY: This isolated test closes the unused ring descriptor once,
        // then forgets the ring mapping owner before another FD can reuse it.
        assert_eq!(unsafe { libc::close(harness.driver.ring.as_raw_fd()) }, 0);
        let results = [None, Some(Duration::ZERO)]
            .map(|timeout| Driver::submit_and_wait(&mut harness.driver.ring, 1, timeout));
        std::mem::forget(harness.driver.ring);

        // Both enter paths must preserve a permanent error. Forget the closed
        // ring before asserting so a failure cannot try to close its FD again.
        for result in results {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EBADF));
        }
    }
}
