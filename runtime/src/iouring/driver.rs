//! Owner-local io_uring submission, completion, and kernel resource retirement.
//!
//! A [`Driver`] owns its ring and growable [`Waiters`] slab. Requests enter on
//! their first poll and wait in the driver's FIFO until staging capacity opens.
//! The driver owns their descriptors, buffers, and progress state until each
//! logical request reaches a terminal completion. It retains ordinary results
//! in their waiter slots and defers callbacks and resource destruction until
//! after the local-state borrow.
//!
//! # Request Flow
//!
//! ```text
//! first poll -> waiter: Pending -> SQE -> kernel
//!                    ^                    |
//!                    +-- partial CQE -----+
//!                                         |
//! waiter: Ready <- terminal completion <--+
//!       |
//! result consumed -> slot recycled
//!
//! detached sync -> result sender (outside Local borrow) -> receiver
//! ```
//!
//! An operation SQE is kernel-visible as soon as it is staged, including before
//! a successful submission syscall. Its waiter retains every referenced owner
//! until the operation CQE arrives. Cancellation acknowledgements never release
//! those resources. Ordinary observer drop cancels reads and network operations,
//! while admitted writes and syncs retain their complete logical sequence.
//!
//! # Deadline and Submission Ordering
//!
//! Each service turn reaps completions, advances the operation wheel with the
//! worker's time sample, then registers newly admitted deadlines. Expired backlog
//! requests retire without issuing an SQE. A completion that finishes the whole
//! request remains successful even if it races deadline expiry. Partial progress
//! after expiry cannot issue another operation SQE.
//!
//! Staging prioritizes cancellations, then initial and follow-up operation SQEs
//! in FIFO order. Operation SQEs are bounded from staging through their CQEs.
//! Cancellation and wake SQEs can still stage at that limit. A full SQ is
//! flushed when more staging work remains. A backlog blocked by the operation
//! limit can park until a CQE or deadline allows progress. A transient flush
//! that does not release SQ capacity returns through completion service.
//!
//! Linux 6.1 or newer is required. Each ring uses SINGLE_ISSUER and DEFER_TASKRUN,
//! so pending operations require a GETEVENTS enter even during a busy executor
//! turn. An otherwise idle turn may defer that enter to [`Driver::park`]. An
//! armed mailbox wake poll alone does not require a syscall on a CPU-only turn.
//!
//! # Waking and Shutdown
//!
//! The mailbox's hybrid waker retains the eventfd used by the multishot PollAdd.
//! Wake CQEs acknowledge readiness and schedule rearm when MORE is absent.
//! Every blocking ring wait checks rearm and uses the same arm-and-recheck
//! publication handshake as futex parking. Synchronous parking keeps the driver
//! in Local and invokes no user callbacks. The local borrow ends before result
//! publication or error handling.
//!
//! Worker closure detaches ordinary observation and requests eligible
//! cancellation. The worker keeps servicing the driver until all logical
//! requests and cancellation CQEs retire. Completed outputs do not consume
//! in-flight capacity. There is no time limit or abandonment of kernel-owned
//! resources. The caller protects this mandatory drain with an abort-on-unwind
//! guard and executes detached callbacks under independent panic isolation.

use super::{
    request::Request,
    runtime::{Deferred, RingConfig},
    timeout::TimeoutWheel,
    waiter::{CompletionOutcome, Observation, Observer, StageOutcome, WaiterId, Waiters},
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
    time::{Duration, Instant},
};

/// Ring and its exclusively owner-thread request state.
pub(super) struct Driver {
    /// Declared first so ring destruction precedes descriptor and buffer release.
    ring: IoUring,
    /// Kept separately to allow batching SQ access while updating request state.
    state: State,
    /// Inject one service error after transferring a terminal completion.
    #[cfg(test)]
    pub(super) fail_service_after_completion: bool,
}

/// Request state borrowed independently of the ring's SQ and CQ mappings.
struct State {
    /// Growable owners of queued requests, in-flight requests, and results.
    waiters: Waiters,
    /// Maximum number of outstanding operation SQEs.
    in_flight_limit: usize,
    /// Requests needing an initial or follow-up operation SQE.
    ready_queue: VecDeque<WaiterId>,
    /// Admitted requests whose deadlines await the next service-time advance.
    pending_deadlines: VecDeque<WaiterId>,
    /// Cancel-requested operations awaiting one cancellation SQE.
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
    /// Inject one transient flush that leaves the SQ untouched.
    #[cfg(test)]
    stall_flush_once: bool,
}

impl Driver {
    /// Create a ring on its permanent owner thread after configuration validation.
    pub fn new(
        cfg: &RingConfig,
        max_timeout: Duration,
        waker: Waker,
        now: Instant,
    ) -> Result<Self, std::io::Error> {
        assert!(cfg.size > 0 && cfg.size.is_power_of_two() && cfg.size <= 32_768);
        TimeoutWheel::validate_layout(max_timeout, cfg.timeout_wheel_tick)
            .expect("validated timeout wheel configuration");
        let ring = new_ring(cfg)?;
        let size = cfg.size as usize;
        Ok(Self {
            ring,
            #[cfg(test)]
            fail_service_after_completion: false,
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
                #[cfg(test)]
                stall_flush_once: false,
            },
        })
    }

    /// Accept an owned request into the FIFO without staging kernel work.
    ///
    /// Deadline validation happens during service after the wheel has advanced.
    pub fn admit(&mut self, request: Request, observer: Observer) -> WaiterId {
        let timed = request.deadline().is_some();
        let id = self.state.waiters.insert(request, None, observer);
        if timed {
            self.state.pending_deadlines.push_back(id);
        }
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

    /// Earliest absolute operation deadline after released deadlines are removed.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.timeout_wheel.next_deadline_at()
    }

    /// Inspect a retained result or determine whether its waker needs refreshing.
    pub fn observe(&mut self, id: WaiterId, waker: &std::task::Waker) -> Observation {
        self.state.waiters.observe(id, waker)
    }

    pub fn set_waker(&mut self, id: WaiterId, waker: std::task::Waker) -> Option<std::task::Waker> {
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

    /// Service posted completions, logical deadlines, and pending SQ work.
    ///
    /// Returns whether a wake CQE requested an inbox recheck. `defer_kernel_service`
    /// permits the following idle ring wait to supply GETEVENTS. It is ignored
    /// when callbacks or unfinished staging already require another busy turn.
    pub fn service(
        &mut self,
        now: Instant,
        defer_kernel_service: bool,
        deferred: &mut Deferred,
    ) -> Result<bool, std::io::Error> {
        #[cfg(test)]
        let retired_before = deferred.resources.len();
        let mut woke = self.state.reap(&mut self.ring, deferred);
        self.state.advance_timeouts(now, deferred);
        self.state.register_deadlines(now, deferred);
        self.state.compact_ready_queue();
        while self.state.fill_submission_queue(&mut self.ring, deferred) {
            let before = self.ring.submission().len();
            self.state.submit(&mut self.ring)?;
            if self.ring.submission().len() >= before {
                // A transient enter may leave the SQ full. Preserve queued
                // identities and give the kernel a completion-service point
                // before another staging attempt.
                self.state.submit_retry = true;
                break;
            }
        }

        if self.needs_kernel_service()
            && (!defer_kernel_service || !deferred.is_empty() || self.has_pending_submissions())
        {
            self.state
                .submit_and_wait(&mut self.ring, 1, Some(Duration::ZERO))?;
            self.state.submit_retry = !self.ring.submission().is_empty();
        }
        woke |= self.state.reap(&mut self.ring, deferred);
        // Preserve real retirement before simulating a later service failure.
        #[cfg(test)]
        if deferred.resources.len() != retired_before
            && std::mem::take(&mut self.fail_service_after_completion)
        {
            return Err(std::io::Error::other(
                "injected service failure after completion",
            ));
        }
        // A final CQE can terminate multishot polling. `park` checks this flag
        // again before every blocking enter, including this final-reap case.
        Ok(woke)
    }

    /// Perform the synchronous idle ring wait while retaining Local ownership.
    ///
    /// Returns `false` when rearm needs another service turn or the publication
    /// handshake rejects sleeping. A skipped wait does not satisfy a deferred
    /// GETEVENTS requirement, so the worker must service nonblocking before its
    /// next task-polling turn when kernel work remains.
    pub fn park(
        &mut self,
        processed_seq: u32,
        deadline: Option<Instant>,
    ) -> Result<bool, std::io::Error> {
        if self.has_pending_submissions() {
            return Ok(false);
        }
        if self.state.wake_rearm_needed {
            if !self.state.waker.reinstall(&mut self.ring.submission()) {
                self.state.submit(&mut self.ring)?;
                if !self.state.waker.reinstall(&mut self.ring.submission()) {
                    self.state.submit_retry = true;
                    return Ok(false);
                }
            }
            self.state.wake_rearm_needed = false;
        }
        let arm = self.state.waker.arm(processed_seq);
        if !arm.still_idle() {
            return Ok(false);
        }
        let timeout = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        self.state.submit_and_wait(&mut self.ring, 1, timeout)?;
        self.state.submit_retry = !self.ring.submission().is_empty();
        Ok(true)
    }
}

impl State {
    /// Store the terminal result and defer resource destruction and callbacks.
    fn complete(&mut self, id: WaiterId, error: Option<Error>, deferred: &mut Deferred) {
        if let Some(tick) = self.waiters.finish(id, error, deferred) {
            self.timeout_wheel.remove(tick);
        }
    }

    /// Request one cancellation attempt or retire an unsubmitted operation.
    fn cancel(&mut self, id: WaiterId, deferred: &mut Deferred) {
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
            self.complete(id, Some(Error::Timeout), deferred);
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

    /// Register newly admitted deadlines against this turn's refreshed wheel.
    fn register_deadlines(&mut self, now: Instant, deferred: &mut Deferred) {
        while let Some(id) = self.pending_deadlines.pop_front() {
            if !self.waiters.is_pending(id) {
                continue;
            }
            let Some(deadline) = self.waiters.deadline(id) else {
                continue;
            };
            match self.timeout_wheel.checked_target_tick(deadline, now) {
                Ok(Some(tick)) => {
                    self.timeout_wheel.schedule(id, tick);
                    self.waiters.set_deadline(id, tick);
                }
                Ok(None) => self.complete(id, Some(Error::Timeout), deferred),
                Err(message) => {
                    let error = Error::Io(
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into(),
                    );
                    self.complete(id, Some(error), deferred);
                }
            }
        }
    }

    /// Remove stale queue IDs once they exceed both 64 and the live queued count.
    fn compact_ready_queue(&mut self) {
        let queued = self.waiters.len() - self.waiters.in_flight();
        let stale = self.ready_queue.len() - queued;
        if stale <= 64 || stale <= queued {
            return;
        }

        // Queued cancellations and expirations leave IDs behind even when no
        // staging capacity opens. Compact in place without disturbing FIFO order.
        self.ready_queue.retain(|id| self.waiters.is_pending(*id));
    }

    /// Build and push the SQE for a validated live waiter.
    ///
    /// SQE construction for requests retained after orphaning is callback-free
    /// and cannot unwind for valid, validated request state.
    fn stage_request(
        &mut self,
        id: WaiterId,
        submission_queue: &mut SubmissionQueue<'_>,
        deferred: &mut Deferred,
    ) {
        if !self.waiters.is_pending(id) {
            return;
        }
        match self.waiters.stage(id) {
            StageOutcome::Timeout(id) => self.complete(id, Some(Error::Timeout), deferred),
            StageOutcome::Orphaned(id) => self.complete(id, None, deferred),
            StageOutcome::Submit(sqe) => {
                // SAFETY: The waiter owns all SQE-referenced descriptors and
                // buffers until its operation CQE. Capacity was checked by the
                // staging loop, and no callback can retire the waiter here.
                unsafe {
                    submission_queue
                        .push(&sqe)
                        .expect("checked operation SQ capacity");
                }
            }
        }
    }

    /// Stage operation SQEs in FIFO order, returning whether an SQ flush is needed.
    fn stage_ready_requests(
        &mut self,
        submission_queue: &mut SubmissionQueue<'_>,
        deferred: &mut Deferred,
    ) -> bool {
        while self.waiters.in_flight() < self.in_flight_limit {
            let Some(id) = self.ready_queue.front().copied() else {
                return false;
            };
            if submission_queue.is_full() {
                return true;
            }
            self.ready_queue.pop_front();
            self.stage_request(id, submission_queue, deferred);
        }
        // Only a completion can release this limit. A flush cannot, and
        // cancellation and mailbox wake SQEs must still be allowed to stage.
        false
    }

    /// Stage cancellation SQEs, retaining requests until their operation CQEs.
    fn stage_cancellations(&mut self, submission_queue: &mut SubmissionQueue<'_>) -> bool {
        while !submission_queue.is_full() {
            let Some(id) = self.pending_cancels.pop_front() else {
                return false;
            };
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
    fn fill_submission_queue(&mut self, ring: &mut IoUring, deferred: &mut Deferred) -> bool {
        let mut submission_queue = ring.submission();
        if self.stage_cancellations(&mut submission_queue) {
            return true;
        }
        if self.stage_ready_requests(&mut submission_queue, deferred) {
            return true;
        }
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
        for cqe in ring.completion() {
            woke |= self.handle_cqe(cqe, deferred);
        }
        woke
    }

    /// Apply one kernel completion while preserving cancellation identity rules.
    fn handle_cqe(&mut self, cqe: CqueueEntry, deferred: &mut Deferred) -> bool {
        let user_data = cqe.user_data();
        if user_data == WAKE_USER_DATA {
            assert!(
                cqe.result() >= 0,
                "wake poll CQE failed: requires Linux 6.1+ multishot polling"
            );
            self.waker.acknowledge();
            if !io_uring::cqueue::more(cqe.flags()) {
                self.wake_rearm_needed = true;
            }
            return true;
        }
        match self.waiters.on_completion(user_data, cqe.result()) {
            CompletionOutcome::Cancel => {
                self.outstanding_cancels = self
                    .outstanding_cancels
                    .checked_sub(1)
                    .expect("untracked cancellation CQE");
            }
            CompletionOutcome::Requeue(id) => self.ready_queue.push_back(id),
            CompletionOutcome::Complete(id) => self.complete(id, None, deferred),
        }
        false
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
    fn submit(&mut self, ring: &mut IoUring) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if std::mem::take(&mut self.stall_flush_once) {
            // Model EINTR/EAGAIN/EBUSY normalized by `submit_and_wait`, with
            // no kernel SQ consumption before the successful return.
            return Ok(());
        }
        self.submit_and_wait(ring, 0, None).map(|_| ())
    }
}

/// Build a single-issuer ring requiring explicit completion-service enters.
fn new_ring(cfg: &RingConfig) -> Result<IoUring, std::io::Error> {
    // DEFER_TASKRUN processes task work only during GETEVENTS. Every turn with
    // pending operation or cancellation SQEs therefore provides either a
    // nonblocking completion-service enter or the idle blocking ring wait.
    IoUring::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .build(cfg.size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IoBuf, IoBufMut, IoBufs,
        iouring::{
            request::{
                Cache, Held, IOVEC_BATCH_SIZE, RecvRequest, RequestOutput, SyncRequest,
                WriteAtRequest, WriteAtState,
            },
            waker::tests::wait_until_eventfd_armed,
        },
        storage::hold::Hold,
    };
    use commonware_utils::channel::oneshot;
    use std::{
        fs::OpenOptions,
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixStream},
        sync::Arc,
        task::{Wake, Waker as TaskWaker},
    };

    enum TestObserver {
        Ordinary(u64),
        DetachedSync(oneshot::Sender<Result<(), Error>>),
        Orphaned,
    }

    struct Completed {
        observer: TestObserver,
        output: RequestOutput,
    }

    struct Notify;

    // Each observer needs a distinct identity for matching its deferred wake.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for Notify {
        fn wake(self: Arc<Self>) {}
    }

    /// Consume ordinary outputs in the order their deferred wakes are published.
    struct Harness {
        driver: Driver,
        deferred: Deferred,
        tracked: Vec<(WaiterId, u64, TaskWaker)>,
        completed: Vec<Completed>,
        start: Instant,
    }

    impl Harness {
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

        fn admit(&mut self, request: Request, generation: u64) -> WaiterId {
            let waker = TaskWaker::from(Arc::new(Notify));
            let id = self
                .driver
                .admit(request, Observer::Ordinary(Some(waker.clone())));
            self.tracked.push((id, generation, waker));
            id
        }

        /// Insert an unstaged fixture for a deliberately simulated operation CQE.
        fn insert(&mut self, request: Request, tick: Option<u64>, generation: u64) -> WaiterId {
            let waker = TaskWaker::from(Arc::new(Notify));
            let id = self.driver.state.waiters.insert(
                request,
                tick,
                Observer::Ordinary(Some(waker.clone())),
            );
            self.tracked.push((id, generation, waker));
            id
        }

        fn flush(&mut self) {
            for output in self.deferred.outputs.drain(..) {
                self.completed.push(Completed {
                    observer: TestObserver::Orphaned,
                    output,
                });
            }
            for waker in self.deferred.wakes.drain(..) {
                let index = self
                    .tracked
                    .iter()
                    .position(|(_, _, current)| current.will_wake(&waker))
                    .unwrap();
                let (id, generation, _) = self.tracked.swap_remove(index);
                let Observation::Ready(output) = self.driver.observe(id, &waker) else {
                    panic!("completion wake without retained output");
                };
                self.completed.push(Completed {
                    observer: TestObserver::Ordinary(generation),
                    output,
                });
                waker.wake();
            }
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
            for (sender, output) in self.deferred.sync_results.drain(..) {
                self.completed.push(Completed {
                    observer: TestObserver::DetachedSync(sender),
                    output: RequestOutput::Sync(output),
                });
            }
        }

        fn orphan(&mut self, id: WaiterId) {
            self.driver.orphan(id, &mut self.deferred);
            self.flush();
        }

        fn service_at(&mut self, now: Instant, defer: bool) {
            self.driver.service(now, defer, &mut self.deferred).unwrap();
            self.flush();
        }

        fn service(&mut self) {
            self.service_at(Instant::now(), false);
        }

        fn until(&mut self, count: usize) {
            let limit = Instant::now() + Duration::from_secs(10);
            while self.completed.len() < count {
                assert!(Instant::now() < limit, "driver completion stalled");
                self.service();
                std::thread::yield_now();
            }
        }

        fn drain(&mut self) {
            self.driver.close(&mut self.deferred);
            self.flush();
            let limit = Instant::now() + Duration::from_secs(10);
            while !self.driver.is_empty() || self.driver.has_pending_submissions() {
                assert!(Instant::now() < limit, "driver retirement stalled");
                self.service();
                std::thread::yield_now();
            }
        }

        /// Inject progress only for SQEs deliberately kept out of the real ring.
        fn simulated_completion(&mut self, id: WaiterId, result: i32) {
            match self
                .driver
                .state
                .waiters
                .on_completion(id.user_data(), result)
            {
                CompletionOutcome::Complete(id) => {
                    self.driver.state.complete(id, None, &mut self.deferred)
                }
                CompletionOutcome::Requeue(id) => self.driver.state.ready_queue.push_back(id),
                CompletionOutcome::Cancel => unreachable!(),
            }
            self.flush();
        }
    }

    fn recv(fd: UnixStream, len: usize, exact: bool, deadline: Option<Instant>) -> Request {
        Request::Recv(RecvRequest {
            fd: Arc::new(fd.into()),
            buf: IoBufMut::with_capacity(len),
            offset: 0,
            len,
            exact,
            deadline,
            result: None,
        })
    }

    fn received(output: &Completed) -> usize {
        match &output.output {
            RequestOutput::Recv(Ok((_, len))) => *len,
            _ => panic!("expected successful recv"),
        }
    }

    #[test]
    fn test_unconsumed_results_leave_staging_and_deadline_tracking() {
        let mut harness = Harness::new(1);
        let (active, mut peer) = UnixStream::pair().unwrap();
        harness.admit(recv(active, 1, true, None), 0);
        harness.service();
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);

        // Keep completed results in their slots while the sole operation slot
        // stays occupied. Their queue IDs must still count as stale.
        let mut results = Vec::new();
        for _ in 0..65 {
            let (socket, _peer) = UnixStream::pair().unwrap();
            results.push(harness.driver.admit(
                recv(socket, 1, true, Some(harness.start)),
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
            recv(socket, 1, true, Some(harness.start)),
            Observer::Ordinary(None),
        ));
        harness.service();
        assert_eq!(harness.driver.state.ready_queue.len(), 1);

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
        harness.admit(recv(active, 1, true, None), 0);
        harness.service();

        let mut peak_queued = 0;
        for generation in 1..=2 {
            let (queued, mut peer) = UnixStream::pair().unwrap();
            peer.write_all(b"x").unwrap();
            harness.admit(recv(queued, 1, true, None), generation);

            // Stale IDs sit behind live requests. The second live request also
            // reuses a slot still named by earlier cancelled queue entries.
            for _ in 0..256 {
                let (socket, _peer) = UnixStream::pair().unwrap();
                let id = harness.admit(recv(socket, 1, true, None), 3);
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
        harness.drain();
        for (generation, completed) in harness.completed.iter().enumerate() {
            assert!(
                matches!(completed.observer, TestObserver::Ordinary(id) if id == generation as u64)
            );
            assert_eq!(received(completed), 1);
        }
        assert!(peak_queued <= 128, "retained {peak_queued} queue entries");
    }

    #[test]
    fn test_expired_backlog_compacts_at_staging_limit() {
        let mut harness = Harness::new(1);
        let (active, _active_peer) = UnixStream::pair().unwrap();
        harness.admit(recv(active, 1, true, None), 0);
        harness.service();
        let (queued, _queued_peer) = UnixStream::pair().unwrap();
        harness.admit(recv(queued, 1, true, None), 1);

        let mut now = harness.start;
        let mut peak_queued = 0;
        for register_first in [false, true] {
            for _ in 0..256 {
                let deadline = now + Duration::from_millis(10);
                let (socket, _peer) = UnixStream::pair().unwrap();
                let id = harness.admit(recv(socket, 1, true, Some(deadline)), 2);

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
        harness.drain();

        assert!(peak_queued <= 128, "retained {peak_queued} queue entries");
    }

    #[test]
    fn test_staging_limit_parks_and_preserves_fifo_across_growth() {
        let mut harness = Harness::new(1);
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        let first = harness.admit(recv(first, 1, true, None), 0);
        harness.service();
        assert!(harness.driver.state.waiters.is_in_flight(first));

        // Grow the waiter slab while the kernel still holds the first buffer.
        for generation in 1..=2 {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            peer.write_all(b"x").unwrap();
            harness.admit(recv(socket, 1, true, None), generation);
        }
        harness.service();
        assert_eq!(harness.driver.len(), 3);
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);
        assert!(!harness.driver.has_pending_submissions());

        // The backlog waits for a CQE. It must not prevent entering the idle wait.
        assert!(harness.driver.park(0, Some(Instant::now())).unwrap());
        first_peer.write_all(b"x").unwrap();
        harness.until(3);
        for (generation, completed) in harness.completed.iter().enumerate() {
            assert!(
                matches!(completed.observer, TestObserver::Ordinary(id) if id == generation as u64)
            );
            assert_eq!(received(completed), 1);
        }
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
        harness.drain();
    }

    #[test]
    fn test_queued_expiry_and_cancellation_progress_at_staging_limit() {
        let mut harness = Harness::new(1);
        let (first, _first_peer) = UnixStream::pair().unwrap();
        let first = harness.admit(recv(first, 1, true, None), 0);
        harness.service();
        let (timed, _timed_peer) = UnixStream::pair().unwrap();
        let timed = harness.admit(
            recv(timed, 1, true, Some(harness.start + Duration::from_secs(1))),
            1,
        );
        let (cancelled, _cancelled_peer) = UnixStream::pair().unwrap();
        let cancelled = harness.admit(recv(cancelled, 1, true, None), 2);
        harness.orphan(cancelled);

        // Neither queued request needs an SQE to retire while the first is blocked.
        harness.service_at(harness.start + Duration::from_secs(2), false);
        assert!(!harness.driver.state.waiters.is_pending(cancelled));
        assert!(!harness.driver.state.waiters.is_pending(timed));
        assert_eq!(harness.completed.len(), 2);
        assert!(harness.driver.state.waiters.is_in_flight(first));
        assert_eq!(harness.driver.state.waiters.in_flight(), 1);
        assert!(!harness.driver.has_pending_submissions());

        // Cancelling the active request must still stage its cancellation at the limit.
        harness.drain();
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
        assert_eq!(harness.driver.state.outstanding_cancels, 0);
    }

    #[test]
    fn test_size_one_capacity_released_before_result_consumption() {
        let mut harness = Harness::new(1);
        for generation in 0..2 {
            let (left, mut right) = UnixStream::pair().unwrap();
            right.write_all(b"x").unwrap();
            harness.admit(recv(left, 1, false, None), generation);
            harness.until(generation as usize + 1);
            assert_eq!(harness.driver.state.waiters.in_flight(), 0);
            assert_eq!(received(&harness.completed[generation as usize]), 1);
        }
        // Both outputs remain retained while the sole waiter is already free.
        assert_eq!(harness.completed.len(), 2);
        harness.drain();
    }

    #[test]
    fn test_fill_submission_queue_expired_deadline_completes_immediately() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        harness.admit(recv(left, 8, true, Some(harness.start)), 0);
        harness.service_at(harness.start, true);
        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));
        assert!(harness.driver.is_empty());
        assert!(harness.driver.next_deadline().is_none());
        assert_eq!(harness.driver.ring.submission().len(), 1);
        harness.drain();
    }

    #[test]
    fn test_stage_request_skips_stale_ready_queue_entry() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let old = harness.admit(
            recv(
                left,
                8,
                true,
                Some(harness.start + Duration::from_millis(5)),
            ),
            0,
        );
        harness.orphan(old);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"ok").unwrap();
        let new = harness.admit(recv(left, 2, true, None), 1);
        assert_eq!(new.0.index, old.0.index);
        assert_ne!(new, old);
        harness.until(2);
        assert_eq!(received(&harness.completed[1]), 2);
        assert!(harness.driver.next_deadline().is_none());
        harness.drain();
    }

    #[test]
    fn test_advance_timeouts_ignores_stale_entry_after_slot_reuse() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let old = harness.admit(
            recv(
                left,
                1,
                true,
                Some(harness.start + Duration::from_millis(5)),
            ),
            0,
        );
        harness
            .driver
            .state
            .register_deadlines(harness.start, &mut harness.deferred);
        harness.orphan(old);
        let (left, _right) = UnixStream::pair().unwrap();
        let new = harness.admit(
            recv(
                left,
                1,
                true,
                Some(harness.start + Duration::from_millis(15)),
            ),
            1,
        );
        harness
            .driver
            .state
            .register_deadlines(harness.start, &mut harness.deferred);
        assert_eq!(old.0.index, new.0.index);
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.deferred,
        );
        assert!(harness.driver.state.waiters.is_pending(new));
        assert_eq!(
            harness.driver.next_deadline(),
            Some(harness.start + Duration::from_millis(15))
        );
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(15),
            &mut harness.deferred,
        );
        assert!(harness.driver.is_empty());
        harness.flush();
        assert_eq!(harness.completed.len(), 2);
        harness.drain();
    }

    #[test]
    fn test_valid_deadline_after_idle_and_long_poll() {
        let mut harness = Harness::new(1);
        let now = harness.start + Duration::from_secs(3600) + Duration::from_millis(1);
        let deadline = now + Duration::from_secs(60);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.admit(recv(left, 1, true, Some(deadline)), 0);
        harness.service_at(now, true);
        assert!(harness.completed.is_empty());
        assert!(harness.driver.next_deadline().unwrap() >= deadline);
        assert!(harness.driver.next_deadline().unwrap() < deadline + Duration::from_millis(5));
        harness.orphan(id);
        harness.drain();
    }

    #[test]
    fn test_unsupported_deadline_is_rejected_without_submission() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        harness.admit(
            recv(left, 1, true, Some(harness.start + Duration::from_secs(61))),
            0,
        );
        harness.service_at(harness.start, true);
        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Io(_))))
        ));
        assert!(harness.driver.is_empty());
        harness.drain();
    }

    #[test]
    fn test_cancel_completion_returns_saved_op_result() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.insert(recv(left, 5, true, None), None, 0);
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.driver.state.cancel(id, &mut harness.deferred);
        harness.simulated_completion(id, 5);
        assert_eq!(received(&harness.completed[0]), 5);
        assert!(matches!(
            harness
                .driver
                .state
                .waiters
                .on_completion(id.cancel_user_data(), -libc::ENOENT),
            CompletionOutcome::Cancel
        ));
        harness.drain();
    }

    #[test]
    fn test_staged_cancel_cqe_is_ignored_after_timeout_completion() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.insert(recv(left, 8, true, None), Some(1), 0);
        harness.driver.state.timeout_wheel.schedule(id, 1);
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
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
    fn test_timeout_fires_while_request_in_ready_queue() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.insert(recv(left, 8, true, None), Some(1), 0);
        harness.driver.state.timeout_wheel.schedule(id, 1);
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.simulated_completion(id, 4);
        assert_eq!(harness.driver.state.ready_queue.len(), 1);
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.deferred,
        );
        assert!(harness.driver.state.pending_cancels.is_empty());
        assert!(harness.driver.is_empty());
        harness.flush();
        assert!(matches!(
            harness.completed[0].output,
            RequestOutput::Recv(Err((_, Error::Timeout)))
        ));
        harness.drain();
    }

    #[test]
    fn test_orphan_partial_progress_then_reuse_skips_restage() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.insert(recv(left, 8, true, None), None, 0);
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.simulated_completion(id, 4);
        harness.orphan(id);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"fresh").unwrap();
        let new = harness.admit(recv(left, 5, true, None), 1);
        assert_eq!(new.0.index, id.0.index);
        harness.until(2);
        assert_eq!(received(&harness.completed[1]), 5);
        harness.drain();
    }

    #[test]
    fn test_orphan_in_flight_cancels_once_and_releases_deadline() {
        let mut harness = Harness::new(1);
        let (left, _right) = UnixStream::pair().unwrap();
        let id = harness.admit(
            recv(left, 8, true, Some(harness.start + Duration::from_secs(10))),
            0,
        );
        harness.service();
        assert!(harness.driver.state.waiters.is_in_flight(id));
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
        let old = harness.admit(recv(old, 1, true, None), 0);
        harness.orphan(old);
        harness.completed.clear();

        let (socket, mut peer) = UnixStream::pair().unwrap();
        let current = harness.admit(recv(socket, 1, true, None), 1);
        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old, current);
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
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        harness.admit(recv(left, 1, true, None), 0);
        harness.service_at(harness.start, true);
        assert!(harness.completed.is_empty());
        assert!(harness.driver.needs_kernel_service());
        // No further admission is needed to drive the deferred task work.
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), 1);
        harness.drain();
    }

    #[test]
    fn test_wake_poll_alone_does_not_require_kernel_service() {
        let mut harness = Harness::new(1);
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
        harness.admit(recv(left, 1, true, None), 0);
        harness.service_at(harness.start, true);
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
        harness.admit(recv(left, 1, true, None), 0);
        harness.service();
        let waker = harness.driver.state.waker.clone();
        let producer = std::thread::spawn(move || {
            wait_until_eventfd_armed(&waker);
            if waker.publish_deferred() {
                waker.wake();
            }
        });
        assert!(
            harness
                .driver
                .park(0, Some(Instant::now() + Duration::from_secs(10)))
                .unwrap()
        );
        producer.join().unwrap();
        assert!(harness.driver.state.waker.pending(0));
        harness.drain();
    }

    #[test]
    fn test_wake_reinstall_survives_submission_queue_full() {
        let mut harness = Harness::new(1);
        assert!(
            harness
                .driver
                .state
                .waker
                .reinstall(&mut harness.driver.ring.submission())
        );
        // An old wake SQE fills the sole slot while a new arm is still required.
        // Flushing it must permit admitted operation progress before parking.
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        harness.admit(recv(left, 1, true, None), 0);
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), 1);
        harness.drain();
    }

    #[test]
    fn test_transient_flush_without_sq_progress_returns_through_service() {
        let mut harness = Harness::new(1);
        harness.service();
        assert_eq!(harness.driver.ring.submission().len(), 1);
        harness.driver.state.stall_flush_once = true;
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        let id = harness.admit(recv(left, 1, true, None), 0);
        harness.service();
        // The failed flush must not consume or mark the queued operation as
        // in-flight. Its next attempt follows one GETEVENTS service point.
        assert!(!harness.driver.state.waiters.is_in_flight(id));
        assert_eq!(harness.driver.state.ready_queue.front(), Some(&id));
        assert!(!harness.driver.state.stall_flush_once);
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), 1);
        harness.drain();
    }

    #[test]
    fn test_partial_completion_releases_capacity_to_next_queued_request() {
        let mut harness = Harness::new(1);
        let (first, mut first_peer) = UnixStream::pair().unwrap();
        first_peer.write_all(b"a").unwrap();
        harness.admit(recv(first, 2, true, None), 0);
        let (second, mut second_peer) = UnixStream::pair().unwrap();
        second_peer.write_all(b"x").unwrap();
        harness.admit(recv(second, 1, true, None), 1);

        // The first request needs another SQE. Its partial CQE releases the
        // sole slot so the older queued SQE can run before that follow-up.
        harness.until(1);
        assert!(matches!(harness.completed[0].observer, TestObserver::Ordinary(id) if id == 1));
        assert_eq!(received(&harness.completed[0]), 1);
        assert!(harness.driver.state.waiters.in_flight() <= 1);

        first_peer.write_all(b"b").unwrap();
        harness.until(2);
        assert!(matches!(harness.completed[1].observer, TestObserver::Ordinary(id) if id == 0));
        assert_eq!(received(&harness.completed[1]), 2);
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
        harness.drain();
    }

    #[test]
    fn test_exact_recv_partial_progress() {
        let mut harness = Harness::new(1);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"he").unwrap();
        let id = harness.admit(recv(left, 5, true, None), 0);
        harness.service();
        right.write_all(b"llo").unwrap();
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), 5);
        assert!(!harness.driver.state.waiters.is_pending(id));
        harness.drain();
    }

    #[test]
    fn test_shutdown_no_timeout_finishes_durable_write_and_detached_sync() {
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
                result: None,
            }),
            0,
        );
        harness.orphan(id);
        let (sender, receiver) = oneshot::channel();
        harness.driver.admit(
            Request::Sync(SyncRequest {
                file: held,
                result: None,
            }),
            Observer::DetachedSync(sender),
        );
        // Retained completion receivers do not participate in drain progress.
        harness.drain();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            vec![b'x'; IOVEC_BATCH_SIZE + 1]
        );
        assert_eq!(harness.driver.state.waiters.in_flight(), 0);
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
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_submit_and_wait_non_etime_error_is_not_misclassified() {
        let mut harness = Harness::new(1);
        // SAFETY: This isolated test closes the unused ring descriptor once,
        // then forgets the ring mapping owner before another FD can reuse it.
        assert_eq!(unsafe { libc::close(harness.driver.ring.as_raw_fd()) }, 0);
        let error = harness
            .driver
            .state
            .submit_and_wait(&mut harness.driver.ring, 1, Some(Duration::ZERO))
            .unwrap_err();
        std::mem::forget(harness.driver.ring);
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }
}
