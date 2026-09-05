//! Owner-local io_uring submission, completion, and kernel resource retirement.
//!
//! A [`Driver`] owns its ring and the bounded [`Waiters`] slab. Ordinary
//! operations enter directly after the local admission queue reserves capacity.
//! The driver owns their descriptors, buffers, and progress state until each
//! logical request reaches a terminal completion. It detaches [`Completed`]
//! values for the worker to publish outside its local-state borrow.
//!
//! # Request Flow
//!
//! ```text
//! local admission -> waiter -> initial backlog -> SQE -> kernel
//!                         ^                       |       |
//!                         +--- partial progress <-+-- CQE-+
//!                                                        |
//! operation slab <- Completed <- terminal retirement <---+
//! detached sync  <- result sender (outside Local borrow)
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
//! Staging prioritizes cancellations and already admitted requests. A full SQ
//! is flushed when additional staging work remains. Waiter saturation never
//! suppresses staging of an existing request. A transient flush that does not
//! release SQ capacity returns through completion service before retrying.
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
//! Closing admission detaches ordinary observation and requests eligible
//! cancellation. The worker keeps servicing the driver until all logical
//! requests and cancellation CQEs retire. Completed outputs do not consume
//! waiter capacity. There is no time limit or abandonment of kernel-owned
//! resources. The caller protects this mandatory drain with an abort-on-unwind
//! guard and executes detached callbacks under independent panic isolation.

use super::{
    operation::OperationId,
    request::{Request, RequestOutput, RetiredResources},
    runtime::RingConfig,
    timeout::TimeoutWheel,
    waiter::{CompletionOutcome, Observer, Retired, StageOutcome, WaiterId, Waiters},
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

/// Terminal output detached before releasing waiter capacity to new admissions.
pub(super) struct Completed {
    /// Ordinary result entry, detached sync channel, or absent observer.
    pub observer: Observer,
    /// Typed result ready for owner-local retention or detached publication.
    pub output: RequestOutput,
    /// Owners whose destruction must happen outside the Local borrow.
    pub retired: RetiredResources,
}

/// Ring and its exclusively owner-thread request state.
pub(super) struct Driver {
    /// Declared first so ring destruction precedes descriptor and buffer release.
    ring: IoUring,
    /// Kept separately to allow batching SQ access while updating request state.
    state: State,
}

/// Request state borrowed independently of the ring's SQ and CQ mappings.
struct State {
    /// Bounded owners of active logical requests and their observers.
    waiters: Waiters,
    /// Requests needing an initial or follow-up operation SQE.
    ready_queue: VecDeque<WaiterId>,
    /// Admitted requests whose deadlines await the next service-time advance.
    pending_deadlines: VecDeque<WaiterId>,
    /// Cancel-requested operations awaiting one cancellation SQE.
    pending_cancels: VecDeque<WaiterId>,
    /// Active logical deadlines, independent of task and admission timers.
    timeout_wheel: TimeoutWheel,
    /// Shared mailbox wake source retained through ring destruction.
    waker: Waker,
    /// Whether the multishot wake poll needs to be installed again.
    wake_rearm_needed: bool,
    /// Cancellation SQEs staged but not yet acknowledged by their own CQEs.
    outstanding_cancels: usize,
    /// Whether a transient submit left work requiring another service enter.
    submit_retry: bool,
    /// Whether new local admission is permanently closed.
    closed: bool,
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
            state: State {
                waiters: Waiters::new(size),
                ready_queue: VecDeque::with_capacity(size),
                pending_deadlines: VecDeque::with_capacity(size),
                pending_cancels: VecDeque::with_capacity(size),
                timeout_wheel: TimeoutWheel::new(max_timeout, cfg.timeout_wheel_tick, now),
                waker,
                wake_rearm_needed: true,
                outstanding_cancels: 0,
                submit_retry: false,
                closed: false,
                #[cfg(test)]
                stall_flush_once: false,
            },
        })
    }

    /// Reserve a waiter for an admitted request without staging kernel work.
    ///
    /// The caller reserves its ordinary-operation entry first. Deadline
    /// validation happens during service after the wheel has been advanced.
    pub fn admit(&mut self, request: Request, observer: Observer) -> WaiterId {
        assert!(!self.state.closed, "io_uring driver admission is closed");
        assert!(
            !self.state.waiters.is_full(),
            "io_uring waiter capacity exhausted"
        );
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

    /// Number of unoccupied waiter slots before admission reservations.
    pub const fn free_slots(&self) -> usize {
        self.state.waiters.free_slots()
    }

    /// Whether all logical requests and cancellation acknowledgements retired.
    pub const fn is_empty(&self) -> bool {
        self.state.waiters.is_empty() && self.state.outstanding_cancels == 0
    }

    /// Whether kernel work needs a GETEVENTS service opportunity.
    pub const fn needs_kernel_service(&self) -> bool {
        !self.is_empty() || self.state.submit_retry
    }

    /// Whether owner-local staging must run again before ordinary parking.
    pub fn has_pending_submissions(&self) -> bool {
        !self.state.ready_queue.is_empty()
            || !self.state.pending_deadlines.is_empty()
            || !self.state.pending_cancels.is_empty()
            || self.state.submit_retry
    }

    /// Earliest absolute operation deadline after released deadlines are removed.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.timeout_wheel.next_deadline_at()
    }

    /// Remove observation, validating the full ordinary-operation identity.
    ///
    /// The operation slab has already detached the corresponding result entry.
    /// A late cancellation cannot alias another observer after waiter reuse.
    pub fn orphan(&mut self, id: WaiterId, operation: OperationId, completed: &mut Vec<Completed>) {
        if !self.state.waiters.orphan(id, operation) {
            return;
        }
        if !self.state.waiters.retains_on_orphan(id) {
            self.state.cancel(id, completed);
        }
    }

    /// Close admission after the caller detaches its ordinary observations.
    ///
    /// The caller first clears its operation slab and admission registrations.
    /// Detached sync observers remain available for terminal publication.
    pub const fn close(&mut self) {
        self.state.closed = true;
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
        completed: &mut Vec<Completed>,
    ) -> Result<bool, std::io::Error> {
        let mut woke = self.state.reap(&mut self.ring, completed);
        self.state.advance_timeouts(now, completed);
        self.state.register_deadlines(now, completed);
        while self.state.fill_submission_queue(&mut self.ring, completed) {
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
            && (!defer_kernel_service || !completed.is_empty() || self.has_pending_submissions())
        {
            self.state
                .submit_and_wait(&mut self.ring, 1, Some(Duration::ZERO))?;
            self.state.submit_retry = !self.ring.submission().is_empty();
        }
        woke |= self.state.reap(&mut self.ring, completed);
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
    /// Turn a retired request into callback-free terminal output ownership.
    fn complete(&mut self, retired: Retired, timeout: bool, completed: &mut Vec<Completed>) {
        if let Some(tick) = retired.target_tick {
            self.timeout_wheel.remove(tick);
        }
        let (output, resources) = if timeout {
            retired.request.timeout()
        } else {
            retired.request.complete()
        };
        completed.push(Completed {
            observer: retired.observer,
            output,
            retired: resources,
        });
    }

    /// Request one cancellation attempt or retire an unsubmitted operation.
    fn cancel(&mut self, id: WaiterId, completed: &mut Vec<Completed>) {
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
            let retired = self.waiters.retire(id);
            self.complete(retired, true, completed);
        }
    }

    /// Advance the wheel even when no active operation deadline remains.
    fn advance_timeouts(&mut self, now: Instant, completed: &mut Vec<Completed>) {
        let Some(expired) = self.timeout_wheel.advance(now) else {
            return;
        };
        for entry in expired {
            // A stale wheel entry must match both the waiter generation and
            // its scheduled tick before changing deadline state.
            if self.waiters.target_tick(entry.waiter_id) == Some(entry.target_tick) {
                self.cancel(entry.waiter_id, completed);
            }
        }
    }

    /// Register newly admitted deadlines against this turn's refreshed wheel.
    fn register_deadlines(&mut self, now: Instant, completed: &mut Vec<Completed>) {
        while let Some(id) = self.pending_deadlines.pop_front() {
            if !self.waiters.contains(id) {
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
                Ok(None) => {
                    let retired = self.waiters.retire(id);
                    self.complete(retired, true, completed);
                }
                Err(message) => {
                    let retired = self.waiters.retire(id);
                    let error = Error::Io(
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into(),
                    );
                    let (output, resources) = retired.request.fail(error);
                    completed.push(Completed {
                        observer: retired.observer,
                        output,
                        retired: resources,
                    });
                }
            }
        }
    }

    /// Build and push the SQE for a validated live waiter.
    ///
    /// SQE construction for requests retained after orphaning is callback-free
    /// and cannot unwind for valid, validated request state.
    fn stage_request(
        &mut self,
        id: WaiterId,
        submission_queue: &mut SubmissionQueue<'_>,
        completed: &mut Vec<Completed>,
    ) {
        if !self.waiters.contains(id) {
            return;
        }
        match self.waiters.stage(id) {
            StageOutcome::Timeout(retired) => self.complete(retired, true, completed),
            StageOutcome::Orphaned(retired) => self.complete(retired, false, completed),
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

    /// Stage initial and follow-up operation SQEs in FIFO order.
    fn stage_ready_requests(
        &mut self,
        submission_queue: &mut SubmissionQueue<'_>,
        completed: &mut Vec<Completed>,
    ) -> bool {
        while !submission_queue.is_full() {
            let Some(id) = self.ready_queue.pop_front() else {
                return false;
            };
            self.stage_request(id, submission_queue, completed);
        }
        !self.ready_queue.is_empty()
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
    fn fill_submission_queue(
        &mut self,
        ring: &mut IoUring,
        completed: &mut Vec<Completed>,
    ) -> bool {
        let mut submission_queue = ring.submission();
        if self.stage_cancellations(&mut submission_queue) {
            return true;
        }
        if self.stage_ready_requests(&mut submission_queue, completed) {
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
    fn reap(&mut self, ring: &mut IoUring, completed: &mut Vec<Completed>) -> bool {
        let mut woke = false;
        for cqe in ring.completion() {
            woke |= self.handle_cqe(cqe, completed);
        }
        woke
    }

    /// Apply one kernel completion while preserving cancellation identity rules.
    fn handle_cqe(&mut self, cqe: CqueueEntry, completed: &mut Vec<Completed>) -> bool {
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
            CompletionOutcome::Complete {
                request,
                observer,
                target_tick,
            } => {
                self.complete(
                    Retired {
                        request,
                        observer,
                        target_tick,
                    },
                    false,
                    completed,
                );
            }
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
                Cache, Held, IOVEC_BATCH_SIZE, RecvRequest, SyncRequest, WriteAtRequest,
                WriteAtState,
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
    };

    /// Owner-thread driver harness with retained terminal outputs and controlled time.
    struct Harness {
        driver: Driver,
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
                completed: Vec::new(),
                start,
            }
        }

        fn admit(&mut self, request: Request, generation: u64) -> WaiterId {
            self.driver
                .admit(request, Observer::Ordinary(operation(generation)))
        }

        fn service(&mut self) {
            self.driver
                .service(Instant::now(), false, &mut self.completed)
                .unwrap();
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
            // The harness admits directly without Local's operation slab, so
            // detach its observers before closing admission and retiring I/O.
            let observers = self
                .driver
                .state
                .waiters
                .ordinary_observers()
                .collect::<Vec<_>>();
            for (id, operation) in observers {
                self.driver.orphan(id, operation, &mut self.completed);
            }
            self.driver.close();
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
                CompletionOutcome::Complete {
                    request,
                    observer,
                    target_tick,
                } => {
                    self.driver.state.complete(
                        Retired {
                            request,
                            observer,
                            target_tick,
                        },
                        false,
                        &mut self.completed,
                    );
                }
                CompletionOutcome::Requeue(id) => self.driver.state.ready_queue.push_back(id),
                CompletionOutcome::Cancel => unreachable!(),
            }
        }
    }

    fn operation(generation: u64) -> OperationId {
        OperationId(crate::iouring::slab::Id {
            index: 0,
            generation,
        })
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
    fn test_size_one_capacity_released_before_result_consumption() {
        let mut harness = Harness::new(1);
        for generation in 0..2 {
            let (left, mut right) = UnixStream::pair().unwrap();
            right.write_all(b"x").unwrap();
            harness.admit(recv(left, 1, false, None), generation);
            harness.until(generation as usize + 1);
            assert_eq!(harness.driver.free_slots(), 1);
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
        harness
            .driver
            .service(harness.start, true, &mut harness.completed)
            .unwrap();
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
        harness
            .driver
            .orphan(old, operation(0), &mut harness.completed);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"ok").unwrap();
        let new = harness.admit(recv(left, 2, true, None), 1);
        assert_eq!(new.index(), old.index());
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
            .register_deadlines(harness.start, &mut harness.completed);
        harness
            .driver
            .orphan(old, operation(0), &mut harness.completed);
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
            .register_deadlines(harness.start, &mut harness.completed);
        assert_eq!(old.index(), new.index());
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.completed,
        );
        assert!(harness.driver.state.waiters.contains(new));
        assert_eq!(
            harness.driver.next_deadline(),
            Some(harness.start + Duration::from_millis(15))
        );
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(15),
            &mut harness.completed,
        );
        assert!(harness.driver.is_empty());
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
        harness
            .driver
            .service(now, true, &mut harness.completed)
            .unwrap();
        assert!(harness.completed.is_empty());
        assert!(harness.driver.next_deadline().unwrap() >= deadline);
        assert!(harness.driver.next_deadline().unwrap() < deadline + Duration::from_millis(5));
        harness
            .driver
            .orphan(id, operation(0), &mut harness.completed);
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
        harness
            .driver
            .service(harness.start, true, &mut harness.completed)
            .unwrap();
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
        let id = harness.driver.state.waiters.insert(
            recv(left, 5, true, None),
            None,
            Observer::Ordinary(operation(0)),
        );
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.driver.state.cancel(id, &mut harness.completed);
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
        let id = harness.driver.state.waiters.insert(
            recv(left, 8, true, None),
            Some(1),
            Observer::Ordinary(operation(0)),
        );
        harness.driver.state.timeout_wheel.schedule(id, 1);
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.completed,
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
        let id = harness.driver.state.waiters.insert(
            recv(left, 8, true, None),
            Some(1),
            Observer::Ordinary(operation(0)),
        );
        harness.driver.state.timeout_wheel.schedule(id, 1);
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.simulated_completion(id, 4);
        assert_eq!(harness.driver.state.ready_queue.len(), 1);
        harness.driver.state.advance_timeouts(
            harness.start + Duration::from_millis(5),
            &mut harness.completed,
        );
        assert!(harness.driver.state.pending_cancels.is_empty());
        assert!(harness.driver.is_empty());
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
        let id = harness.driver.state.waiters.insert(
            recv(left, 8, true, None),
            None,
            Observer::Ordinary(operation(0)),
        );
        assert!(matches!(
            harness.driver.state.waiters.stage(id),
            StageOutcome::Submit(_)
        ));
        harness.simulated_completion(id, 4);
        harness
            .driver
            .orphan(id, operation(0), &mut harness.completed);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"fresh").unwrap();
        let new = harness.admit(recv(left, 5, true, None), 1);
        assert_eq!(new.index(), id.index());
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
        harness
            .driver
            .orphan(id, operation(0), &mut harness.completed);
        harness
            .driver
            .orphan(id, operation(0), &mut harness.completed);
        assert_eq!(harness.driver.state.pending_cancels.len(), 1);
        assert!(harness.driver.next_deadline().is_none());
        harness.drain();
        assert_eq!(harness.completed.len(), 1);
        assert!(matches!(harness.completed[0].observer, Observer::Orphaned));
    }

    #[test]
    fn test_stale_operation_identity_cannot_orphan_waiter() {
        let mut harness = Harness::new(1);
        let (left, mut right) = UnixStream::pair().unwrap();
        let id = harness.admit(recv(left, 1, true, None), 1);
        harness
            .driver
            .orphan(id, operation(0), &mut harness.completed);
        assert_eq!(harness.driver.len(), 1);
        assert!(harness.completed.is_empty());
        right.write_all(b"x").unwrap();
        harness.until(1);
        assert!(
            matches!(harness.completed[0].observer, Observer::Ordinary(id) if id == operation(1))
        );
        harness.drain();
    }

    #[test]
    fn test_deferred_taskrun_is_serviced_during_busy_turn() {
        let mut harness = Harness::new(2);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"x").unwrap();
        harness.admit(recv(left, 1, true, None), 0);
        harness
            .driver
            .service(harness.start, true, &mut harness.completed)
            .unwrap();
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
        harness
            .driver
            .service(harness.start, true, &mut harness.completed)
            .unwrap();
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
    fn test_exact_recv_partial_progress() {
        let mut harness = Harness::new(1);
        let (left, mut right) = UnixStream::pair().unwrap();
        right.write_all(b"he").unwrap();
        let id = harness.admit(recv(left, 5, true, None), 0);
        harness.service();
        right.write_all(b"llo").unwrap();
        harness.until(1);
        assert_eq!(received(&harness.completed[0]), 5);
        assert!(!harness.driver.state.waiters.contains(id));
        harness.drain();
    }

    #[test]
    fn test_shutdown_no_timeout_finishes_durable_write_and_detached_sync() {
        let mut harness = Harness::new(2);
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
        harness
            .driver
            .orphan(id, operation(0), &mut harness.completed);
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
        assert_eq!(harness.driver.free_slots(), 2);
        let mut published = false;
        for completed in harness.completed {
            if let Observer::DetachedSync(sender) = completed.observer {
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
