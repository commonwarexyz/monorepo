//! Thread-affine op submission for the io_uring runtime.
//!
//! The [DriverHandle] is the shared half of the driver: the waiter slab, the
//! backlog and cancel queues, and the capacity wait list reached by op futures
//! and by the event loop that services them (see [super::Driver]). The
//! runtime traits force [crate::Blob], [crate::Sink], and [crate::Stream] to
//! be `Send + Sync` and op futures to be `Send`, so they reach this state
//! through an [Affine] cell that pins every access to the loop thread instead
//! of through locks: submissions and completions are single-threaded by
//! construction, and the compiler-visible `Sync` is backed by a runtime
//! thread assert.
//!
//! Op futures ([Op]) stage requests by inserting into the slab and pushing
//! onto the backlog during `poll`. The loop builds and submits SQEs in
//! its own turn, parks ordinary op results in the slot, and wakes the stored
//! task waker. Detached ticket results move to an independent completion arena
//! before their waiter is recycled. Dropping an op future
//! orphans its slot: cancelable kinds are
//! async-cancelled eagerly, while storage writes and syncs detach and keep
//! running for durability parity with the tokio backend. Dropping an admitted
//! op future or a [Ticket] (including one held inside a front-end object such
//! as a listener) on a foreign thread cannot touch the table directly (drop
//! must not panic, so the affinity check cannot reject it), so it is routed
//! through the [OrphanMailbox] and wound down by the loop on its next turn.
//! Ring-bound resources may therefore be dropped from any thread, even
//! though they must only be used on their owning worker.
//!
//! Capacity and terminal ownership move through these states:
//!
//! ```text
//! full waiter slab
//!       |
//!       v
//! Queued CapacityId --slot freed--> Granted CapacityId --owner repolls--> waiter owns request
//!       |                                  |                                      |
//!       | deadline, drop, or close         | deadline, drop, or close             |
//!       v                                  v                                      |
//!      Free <------------------------------+                  +-------------------+-------------------+
//!                                                             |                                       |
//!                                                          Op Ready                           Ticket Pending
//!                                                             |                                       |
//!                                                             v                                       v
//!                                                      recycle waiter                 publish Ticket Ready
//!                                                                                                     |
//!                                                                                                     v
//!                                                                                              recycle waiter
//! ```
//!
//! Every state transition completes while [Ops] is borrowed. Stored waker
//! drops and callbacks are detached into [WakerAction] values, then processed
//! after releasing that borrow. This permits callback reentrancy without a
//! nested [RefCell] borrow and lets callback panics propagate only after the
//! state they observe has been committed.

use super::{
    Tick,
    callbacks::{WakerActionSink, DeferredWakerActions, WakerAction, run_waker_actions},
    capacity::{CapacityAdmission, CapacityId, CapacityWaiters},
    request::{Cache, Output, Request},
    waiter::{
        CompletionDropOutcome, CompletionId, DeferredPoll, DropOutcome, PollState,
        TicketCompletions, WaiterId, Waiters,
    },
    waker::RingWaker,
};
use crate::{Error, IoBufMut, IoBufs, WriteOptions};
use commonware_utils::sync::Mutex;
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs::File,
    future::Future,
    net::SocketAddr,
    os::fd::OwnedFd,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    thread::{self, ThreadId},
    time::Instant,
};

thread_local! {
    /// Cached identity for thread-affinity checks.
    static CURRENT_THREAD_ID: ThreadId = thread::current().id();
}

/// Return the current thread identity without cloning its [`std::thread::Thread`].
#[inline]
pub(crate) fn current_thread_id() -> ThreadId {
    CURRENT_THREAD_ID.with(|id| *id)
}

/// Cell whose contents are only accessible from the thread that created it.
///
/// The affinity assert makes the cell shareable (`Sync`) without any lock:
/// cross-thread access fails loudly instead of racing.
pub(crate) struct Affine<T> {
    owner: ThreadId,
    cell: T,
}

// SAFETY: `cell` is only ever accessed through `with`/`try_with`, which
// require the calling thread to be `owner`, so no concurrent access to the
// contents can occur. `T: Send` keeps the final drop (which may happen on
// whichever thread releases the last reference) sound.
unsafe impl<T: Send> Sync for Affine<T> {}

impl<T> Affine<T> {
    /// Wrap `cell`, pinning access to the calling thread.
    pub(crate) fn new(cell: T) -> Self {
        Self::pinned(current_thread_id(), cell)
    }

    /// Wrap `cell`, pinning access to `owner`.
    ///
    /// Used when the cell is built away from its owning thread (e.g. a task
    /// registered from another thread but polled only on its worker). Handing
    /// the contents to `owner` is an ordinary `Send` transfer, which the auto
    /// `Send` bound on `Affine<T>` already requires.
    pub(crate) const fn pinned(owner: ThreadId, cell: T) -> Self {
        Self { owner, cell }
    }

    /// Access the contents from the owning thread.
    ///
    /// Panics when called from any other thread.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        assert!(
            current_thread_id() == self.owner,
            "io_uring runtime operations must run on the runtime thread"
        );
        f(&self.cell)
    }

    /// Access the contents if the calling thread is the owner.
    ///
    /// Returns `None` off-thread. Used on drop paths, which must not panic.
    fn try_with<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        (current_thread_id() == self.owner).then(|| f(&self.cell))
    }
}

/// Shared operation state for futures, detached tickets, and the event loop.
pub(super) struct Ops {
    /// Slot table tracking every admitted logical request. Slots own all
    /// operation resources (buffers, FDs) for the request lifetime.
    pub(super) waiters: Waiters,
    /// Detached ticket state. Pending entries point to an active waiter,
    /// while Ready entries own userspace-only output after that waiter has
    /// already been recycled.
    pub(super) completions: TicketCompletions,
    /// Waiter ids whose next SQE the loop must build, in FIFO order. Fresh
    /// admissions and requeued partial operations share this queue.
    pub(super) backlog: VecDeque<WaiterId>,
    /// Waiter ids needing an async-cancel SQE.
    pub(super) pending_cancels: VecDeque<WaiterId>,
    /// Wheel ticks released by dropped observers, including ordinary op
    /// futures and detached tickets, awaiting removal by the loop. The timeout
    /// wheel is loop-owned, so drop paths cannot touch it.
    pub(super) released_deadlines: Vec<Tick>,
    /// FIFO of tasks waiting for a free waiter slot, including grants reserved
    /// for tasks that have been woken but have not repolled yet.
    pub(super) capacity: CapacityWaiters,
    /// Set at teardown: admission fails with the kind-specific error.
    pub(super) closed: bool,
}

impl Ops {
    /// Aggregate logical operations for metric compatibility.
    ///
    /// Pending completion entries are represented by their active waiter and
    /// are not counted again. Ready entries have no waiter and are added.
    pub(super) const fn operation_count(&self) -> usize {
        self.waiters.len() + self.completions.ready()
    }
}

/// RAII registration of one admission attempt on the capacity wait list.
///
/// The slot is cleared on admission or closed-driver resolution (inside the
/// admission poll) and cancelled when the attempt is dropped while parked. A
/// foreign-thread drop cannot touch the thread-affine arena, so it transfers
/// the generation-tagged ID through [OrphanMailbox]. The loop cancels that ID
/// and transfers any released permit on its next turn. Expiry and close
/// recycle the slot immediately, so a later stale cancellation is a no-op.
struct CapacityRegistration<'a> {
    /// Affine driver state and cross-thread orphan mailbox.
    handle: &'a DriverHandle,
    /// Live capacity registration, if the admission is queued or granted.
    slot: Option<CapacityId>,
}

impl<'a> CapacityRegistration<'a> {
    /// Construct an unregistered guard for one admission future.
    const fn new(handle: &'a DriverHandle) -> Self {
        Self { handle, slot: None }
    }
}

impl Drop for CapacityRegistration<'_> {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        // A foreign-thread drop cannot touch the thread-affine table (drop
        // must not panic): hand the slot to the loop so a saturated ring
        // cannot accumulate cancelled registrations without bound.
        let mut slot = Some(slot);
        let cancelled = self.handle.try_with(|ops| {
            let slot = slot.take().expect("capacity slot consumed twice");
            let mut actions = DeferredWakerActions::new();
            ops.capacity
                .cancel(slot, ops.waiters.free_len(), &mut actions);
            actions
        });
        let Some(actions) = cancelled else {
            let slot = slot.take().expect("capacity slot lost on foreign drop");
            self.handle.push_orphan(Orphan::Capacity(slot));
            return;
        };
        run_waker_actions(actions);
    }
}

/// Shared driver handle used by the network and storage front-ends and the
/// event loop.
///
/// Operation state remains protected by an affinity-checked [Affine] cell,
/// while foreign-thread drops reach the colocated mailbox without touching
/// that cell.
#[derive(Clone)]
pub(crate) struct DriverHandle {
    inner: Arc<HandleInner>,
}

/// State with the same lifetime as every [DriverHandle] clone.
struct HandleInner {
    /// Operation state accessible only from the owning runtime thread.
    ops: Affine<RefCell<Ops>>,
    /// Cross-thread wind-down mailbox for foreign-thread drops.
    orphans: OrphanMailbox,
}

/// Wind-down work dropped on a foreign thread, where the thread-affine op
/// table is unreachable.
///
/// Drop is the one op interaction that can legally arrive off-thread (drop
/// must not panic, so the affinity check cannot reject it). Entries pushed
/// here are wound down by the loop on its next turn exactly as an on-thread
/// drop would have been, so foreign drops release their state instead of
/// leaking it until shutdown.
pub(super) enum Orphan {
    /// An admitted waiter whose future or ticket was dropped.
    Waiter(WaiterId),
    /// A detached ticket dropped after admission. The completion entry owns
    /// the waiter link while Pending and identifies foreign drops.
    Completion(CompletionId),
    /// A capacity registration whose admission attempt was dropped while
    /// parked on a full slab (before any waiter existed).
    Capacity(CapacityId),
}

/// Cross-thread mailbox of [Orphan] wind-down work.
struct OrphanMailbox {
    /// Fast-path gate so the loop's per-turn drain skips the lock when the
    /// mailbox is empty (the common case).
    pending: AtomicBool,
    orphans: Mutex<Vec<Orphan>>,
    /// Wakes the loop so a parked runtime winds the orphan down promptly.
    waker: RingWaker,
}

impl OrphanMailbox {
    fn push(&self, orphan: Orphan) {
        self.orphans.lock().push(orphan);
        self.pending.store(true, Ordering::Release);
        self.waker.wake();
    }

    /// Take all pending foreign-drop work.
    ///
    /// A push racing the gate check lands on the next turn: its `wake` latch
    /// guarantees the loop runs again before parking indefinitely.
    fn drain_into(&self, destination: &mut Vec<Orphan>) {
        assert!(destination.is_empty(), "orphan destination is not drained");
        if !self.pending.swap(false, Ordering::Acquire) {
            return;
        }
        destination.append(&mut self.orphans.lock());
    }
}

impl DriverHandle {
    /// Create the op state for a driver whose slab tracks at most `capacity`
    /// requests, waking the loop through `waker` for foreign-thread drops.
    ///
    /// The calling thread becomes the owning (runtime) thread.
    pub(crate) fn new(capacity: usize, waker: RingWaker) -> Self {
        Self {
            inner: Arc::new(HandleInner {
                ops: Affine::new(RefCell::new(Ops {
                    waiters: Waiters::new(capacity),
                    completions: TicketCompletions::new(),
                    backlog: VecDeque::with_capacity(capacity),
                    pending_cancels: VecDeque::with_capacity(capacity),
                    released_deadlines: Vec::new(),
                    capacity: CapacityWaiters::new(),
                    closed: false,
                })),
                orphans: OrphanMailbox {
                    pending: AtomicBool::new(false),
                    orphans: Mutex::new(Vec::new()),
                    waker,
                },
            }),
        }
    }

    /// Access the shared op state from the runtime thread.
    ///
    /// The borrow is a leaf section: callers must not invoke wakers or user
    /// code inside `f`.
    pub(super) fn with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> R {
        self.inner.ops.with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Assert that the caller is running on the driver's owning thread.
    ///
    /// Front-ends call this before validation, no-op, or synchronous paths
    /// that would otherwise bypass the affinity check in op admission.
    pub(crate) fn assert_owner(&self) {
        self.inner.ops.with(|_| ());
    }

    /// Access the shared op state if called on the runtime thread.
    fn try_with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> Option<R> {
        self.inner.ops.try_with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Queue one foreign-thread drop for the owning event loop.
    fn push_orphan(&self, orphan: Orphan) {
        self.inner.orphans.push(orphan);
    }

    /// Drain foreign-thread drops into the event loop's reusable scratch.
    pub(super) fn drain_orphans(&self, destination: &mut Vec<Orphan>) {
        self.inner.orphans.drain_into(destination);
    }

    /// Close the op state: subsequent admissions fail with their
    /// kind-specific error. Returns the capacity waiters so the caller can wake them
    /// outside the borrow.
    pub(crate) fn close_admission(&self) -> Vec<Waker> {
        self.with(|ops| {
            ops.closed = true;
            ops.capacity.close()
        })
    }

    /// Submit a logical send request and wait for its completion.
    pub(crate) async fn send(
        &self,
        fd: Arc<OwnedFd>,
        bufs: IoBufs,
        deadline: Instant,
    ) -> Result<(), Error> {
        let request = Request::send(fd, bufs, Some(deadline));
        match Op::new(self, request).await {
            Output::Send(result) => result.map_err(|e| *e),
            _ => unreachable!("send op produced foreign output"),
        }
    }

    /// Submit a logical recv request and wait for its completion.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn recv(
        &self,
        fd: Arc<OwnedFd>,
        buf: IoBufMut,
        offset: usize,
        len: usize,
        exact: bool,
        deadline: Instant,
    ) -> Result<(IoBufMut, usize), (IoBufMut, Error)> {
        let request = Request::recv(fd, buf, offset, len, exact, Some(deadline));
        match Op::new(self, request).await {
            Output::Recv(result) => result.map_err(|e| *e),
            _ => unreachable!("recv op produced foreign output"),
        }
    }

    /// Begin a logical accept request, returning the completion ticket
    /// without waiting.
    ///
    /// Admission applies the same backpressure as every other request. The
    /// returned ticket resolves once a connection is accepted, the deadline
    /// expires, or the accept fails. Callers should treat [Error::Timeout] as
    /// a cue to issue a fresh accept: the deadline exists so an abandoned
    /// accept cannot occupy a waiter slot forever.
    pub(crate) async fn start_accept(&self, fd: Arc<OwnedFd>, deadline: Instant) -> AcceptTicket {
        let request = Request::accept(fd, Some(deadline));
        AcceptTicket(Ticket::admit(self, request).await)
    }

    /// Submit a logical connect request and wait for its completion.
    pub(crate) async fn connect(
        &self,
        fd: Arc<OwnedFd>,
        addr: SocketAddr,
        deadline: Instant,
    ) -> Result<(), Error> {
        let request = Request::connect(fd, &addr, Some(deadline));
        match Op::new(self, request).await {
            Output::Connect(result) => result.map_err(|e| *e),
            _ => unreachable!("connect op produced foreign output"),
        }
    }

    /// Submit a logical positioned read request and wait for its completion.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn read_at(
        &self,
        file: Arc<File>,
        offset: u64,
        len: usize,
        buf: IoBufMut,
        cache: Cache,
    ) -> Result<IoBufMut, (IoBufMut, Error)> {
        let request = Request::read_at(file, offset, len, buf, cache);
        match Op::new(self, request).await {
            Output::ReadAt(result) => result.map_err(|e| *e),
            _ => unreachable!("read_at op produced foreign output"),
        }
    }

    /// Submit a positioned write with the provided options and wait for its
    /// completion.
    ///
    /// A durable write submits all of its bytes before issuing one data sync.
    /// The file-wide sync may also persist earlier dirty data, but callers
    /// cannot rely on that stronger durability boundary.
    pub(crate) async fn write_at(
        &self,
        file: Arc<File>,
        offset: u64,
        bufs: IoBufs,
        options: WriteOptions,
        cache: Cache,
    ) -> Result<(), Error> {
        let request = Request::write_at(file, offset, bufs, options, cache);
        match Op::new(self, request).await {
            Output::WriteAt(result) => result.map_err(|e| *e),
            _ => unreachable!("write_at op produced foreign output"),
        }
    }

    /// Submit a logical fsync request and wait for its completion.
    pub(crate) async fn sync(&self, file: Arc<File>) -> Result<(), Error> {
        self.start_sync(file).await.await
    }

    /// Begin a logical fsync request, returning the completion ticket without
    /// waiting.
    ///
    /// Admission applies the same backpressure as every other request. The
    /// returned ticket resolves once the fsync completes.
    pub(crate) async fn start_sync(&self, file: Arc<File>) -> SyncTicket {
        let request = Request::sync(file);
        SyncTicket(Ticket::admit(self, request).await)
    }
}

/// Poll one admission attempt for `request`, using `admit` to bind its observer.
///
/// On a closed driver the request resolves immediately to its kind-specific
/// failure (returned as `Err`). On a full slab the task parks on the capacity
/// wait list through `registration` (one slot per attempt, refreshed on
/// re-polls and released here once the attempt resolves). Otherwise the
/// observer-specific state and waiter are published under one op-state borrow,
/// then the waiter id is pushed onto the backlog. The generic closure is
/// monomorphized for ordinary ops and detached tickets.
fn poll_admission<T>(
    handle: &DriverHandle,
    request: &mut Option<Request>,
    registration: &mut CapacityRegistration<'_>,
    cx: &mut Context<'_>,
    admit: impl FnOnce(&mut Ops, Request, &mut Option<Waker>) -> (T, WaiterId),
) -> (Poll<Result<T, Output>>, DeferredWakerActions) {
    let mut actions = DeferredWakerActions::new();
    // RawWaker clone callbacks are external code. Run them before borrowing
    // Ops, then move or defer-drop the clone during the state transition.
    let mut incoming_waker = Some(cx.waker().clone());
    let deadline = request
        .as_ref()
        .expect("request missing before admission")
        .deadline();
    let outcome = handle.with(|ops| {
        if ops.closed {
            actions.reserve(1 + usize::from(registration.slot.is_some()));
            if let Some(slot) = registration.slot.take() {
                ops.capacity
                    .cancel(slot, ops.waiters.free_len(), &mut actions);
            }
            actions.push(WakerAction::Drop(
                incoming_waker
                    .take()
                    .expect("admission waker consumed twice"),
            ));
            return Admission::Closed;
        }
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            actions.reserve(1 + usize::from(registration.slot.is_some()));
            if let Some(slot) = registration.slot.take() {
                ops.capacity
                    .cancel(slot, ops.waiters.free_len(), &mut actions);
            }
            actions.push(WakerAction::Drop(
                incoming_waker
                    .take()
                    .expect("admission waker consumed twice"),
            ));
            return Admission::Expired;
        }
        match ops.capacity.poll(
            &mut registration.slot,
            ops.waiters.free_len(),
            deadline,
            &mut incoming_waker,
            &mut actions,
        ) {
            CapacityAdmission::Queued => return Admission::Full,
            CapacityAdmission::Direct | CapacityAdmission::Granted => {}
        }
        let request = request.take().expect("request consumed before admission");
        let (id, waiter_id) = admit(ops, request, &mut incoming_waker);
        assert!(ops.capacity.reserved() <= ops.waiters.free_len());
        ops.backlog.push_back(waiter_id);
        Admission::Admitted(id)
    });
    debug_assert!(incoming_waker.is_none());
    let poll = match outcome {
        Admission::Admitted(id) => Poll::Ready(Ok(id)),
        Admission::Full => Poll::Pending,
        Admission::Closed => {
            let request = request.take().expect("request lost on closed driver");
            Poll::Ready(Err(request.fail()))
        }
        Admission::Expired => {
            let mut request = request.take().expect("request lost on capacity timeout");
            Poll::Ready(Err(request.timeout()))
        }
    };
    (poll, actions)
}

/// Poll for the parked result of an admitted request.
///
/// A pending poll refreshes the stored task waker. Taking a result frees its
/// slot, but the caller reconciles capacity only after publishing local Done.
fn poll_op_completion(handle: &DriverHandle, id: WaiterId, cx: &mut Context<'_>) -> Poll<Output> {
    match handle.with(|ops| ops.waiters.poll_state(id, cx.waker())) {
        PollState::Ready(output) => return Poll::Ready(output),
        PollState::PendingCurrent => return Poll::Pending,
        PollState::PendingNeedsWaker => {}
    }

    let mut incoming = Some(cx.waker().clone());
    let mut actions = DeferredWakerActions::new();
    actions.reserve(1);
    let poll = match handle.with(|ops| ops.waiters.poll_take_deferred(id, &mut incoming)) {
        DeferredPoll::Ready(output) => {
            actions.push(WakerAction::Drop(
                incoming.take().expect("ready poll missing incoming waker"),
            ));
            Poll::Ready(output)
        }
        DeferredPoll::Pending(waker) => {
            debug_assert!(incoming.is_none());
            actions.push(WakerAction::Drop(waker));
            Poll::Pending
        }
    };
    run_waker_actions(actions);
    poll
}

/// Poll a detached ticket's completion entry.
fn poll_ticket_completion(handle: &DriverHandle, id: CompletionId, cx: &mut Context<'_>) -> Poll<Output> {
    match handle.with(|ops| ops.completions.poll_state(id, cx.waker())) {
        PollState::Ready(output) => return Poll::Ready(output),
        PollState::PendingCurrent => return Poll::Pending,
        PollState::PendingNeedsWaker => {}
    }

    let mut incoming = Some(cx.waker().clone());
    let mut actions = DeferredWakerActions::new();
    actions.reserve(1);
    let poll = match handle.with(|ops| ops.completions.poll_take_deferred(id, &mut incoming)) {
        DeferredPoll::Ready(output) => {
            actions.push(WakerAction::Drop(
                incoming.take().expect("ready poll missing incoming waker"),
            ));
            Poll::Ready(output)
        }
        DeferredPoll::Pending(waker) => {
            debug_assert!(incoming.is_none());
            actions.push(WakerAction::Drop(waker));
            Poll::Pending
        }
    };
    run_waker_actions(actions);
    poll
}

/// Reserve every destination an orphan transition can append to after it
/// extracts an externally controlled waker.
fn reserve_orphan_wind_down(
    ops: &mut Ops,
    outcome: &DropOutcome,
    actions: &mut impl WakerActionSink,
) {
    let capacity_actions = usize::from(matches!(outcome, DropOutcome::Freed));
    actions.reserve(
        capacity_actions
            .checked_add(1)
            .expect("orphan action reservation overflowed"),
    );
    if let DropOutcome::Cancel {
        needs_sqe,
        target_tick,
    } = outcome
    {
        if *needs_sqe {
            ops.pending_cancels.reserve(1);
        }
        if target_tick.is_some() {
            ops.released_deadlines.reserve(1);
        }
    }
}

/// Apply a pre-reserved orphan wind-down for `id` on the op table.
fn wind_down_orphan_prepared(
    ops: &mut Ops,
    id: WaiterId,
    outcome: DropOutcome,
    completion_waker: Option<Waker>,
    actions: &mut impl WakerActionSink,
) {
    let op_waker = ops.waiters.mark_orphaned(id, &outcome);
    if let Some(waker) = completion_waker {
        actions.push(WakerAction::Drop(waker));
    }
    if let Some(waker) = op_waker {
        actions.push(WakerAction::Drop(waker));
    }

    match outcome {
        // A parked result was dropped, freeing a slot.
        DropOutcome::Freed => ops.capacity.reconcile(ops.waiters.free_len(), actions),
        DropOutcome::Cancel {
            needs_sqe,
            target_tick,
        } => {
            if needs_sqe {
                ops.pending_cancels.push_back(id);
            }
            // Release deadline accounting for the transition out of active
            // timeout tracking.
            ops.released_deadlines.extend(target_tick);
        }
        DropOutcome::Detached => {}
    }
}

/// Apply the orphan wind-down for `id` on the op table.
pub(super) fn wind_down_orphan(ops: &mut Ops, id: WaiterId, actions: &mut impl WakerActionSink) {
    let outcome = ops.waiters.classify_orphan(id);
    reserve_orphan_wind_down(ops, &outcome, actions);
    wind_down_orphan_prepared(ops, id, outcome, None, actions);
}

/// Apply detached-ticket wind-down through its completion ID. Pending entries
/// yield their active waiter for request-kind-specific cancellation or detach.
/// Ready entries drop only their output because the waiter was already
/// recycled at terminal completion.
pub(super) fn wind_down_ticket(
    ops: &mut Ops,
    id: CompletionId,
    actions: &mut impl WakerActionSink,
) {
    let Some(waiter_id) = ops.completions.pending_waiter(id) else {
        assert!(matches!(
            ops.completions.mark_orphaned(id),
            CompletionDropOutcome::Ready
        ));
        return;
    };
    let outcome = ops.waiters.classify_orphan(waiter_id);
    reserve_orphan_wind_down(ops, &outcome, actions);
    match ops.completions.mark_orphaned(id) {
        CompletionDropOutcome::Pending {
            waiter_id: removed_waiter,
            waker,
        } => {
            assert_eq!(removed_waiter, waiter_id, "completion waiter changed");
            wind_down_orphan_prepared(ops, removed_waiter, outcome, waker, actions);
        }
        CompletionDropOutcome::Ready => unreachable!("pending completion became ready"),
    }
}

/// Wind down an admitted request whose future or ticket is being dropped.
///
/// Drop must not panic, so a foreign-thread drop cannot touch the
/// thread-affine table directly: it hands the id to the loop through the
/// orphan mailbox instead, and the loop applies the same wind-down on its
/// next turn.
fn orphan_waiter(handle: &DriverHandle, id: WaiterId) {
    let Some(actions) = handle.try_with(|ops| {
        let mut actions = DeferredWakerActions::new();
        wind_down_orphan(ops, id, &mut actions);
        actions
    }) else {
        handle.push_orphan(Orphan::Waiter(id));
        return;
    };
    run_waker_actions(actions);
}

/// Wind down a detached ticket using only its completion ID.
fn orphan_ticket(handle: &DriverHandle, id: CompletionId) {
    let Some(actions) = handle.try_with(|ops| {
        let mut actions = DeferredWakerActions::new();
        wind_down_ticket(ops, id, &mut actions);
        actions
    }) else {
        handle.push_orphan(Orphan::Completion(id));
        return;
    };
    run_waker_actions(actions);
}

/// Outcome of one admission attempt.
enum Admission<T> {
    Admitted(T),
    Full,
    Closed,
    Expired,
}

/// Progress state of an op future.
///
/// The queued request rides inside the future until admission (boxing it
/// would put an allocation on the op hot path), so the variant sizes
/// legitimately diverge. The option is always `Some` while queued: it exists
/// so admission can move the request out in place instead of round-tripping
/// the whole state through a stack temporary on every poll.
#[allow(clippy::large_enum_variant)]
enum OpState {
    /// Not yet admitted: the future still owns the request and its buffers.
    Queued(Option<Request>),
    /// Admitted: the waiter slot owns the request. Any capacity registration
    /// or reserved grant was consumed and cleared before entering this state.
    Waiting(WaiterId),
    /// The output was delivered.
    Done,
}

/// Future driving one logical request through admission and completion.
///
/// Borrows the driver from its front-end, so the hot path carries no
/// refcount traffic. Dropping the future before completion orphans the slot
/// (see the module docs for the wind-down rules).
#[must_use]
struct Op<'a> {
    handle: &'a DriverHandle,
    state: OpState,
    /// Capacity wait-list registration while queued on a full slab, released
    /// on admission or by drop (via its RAII guard).
    registration: CapacityRegistration<'a>,
}

impl<'a> Op<'a> {
    /// Construct a queued op whose future owns `request` until admission.
    const fn new(handle: &'a DriverHandle, request: Request) -> Self {
        Self {
            handle,
            state: OpState::Queued(Some(request)),
            registration: CapacityRegistration::new(handle),
        }
    }
}

impl Future for Op<'_> {
    type Output = Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Output> {
        let this = self.get_mut();
        match &mut this.state {
            OpState::Queued(request) => {
                let (admission, actions) = poll_admission(
                    this.handle,
                    request,
                    &mut this.registration,
                    cx,
                    |ops, request, incoming_waker| {
                        let waiter_id = ops.waiters.insert_deferred(request, incoming_waker);
                        (waiter_id, waiter_id)
                    },
                );
                match admission {
                    // Completion cannot be ready before the loop's next turn,
                    // so an admitted op always returns pending here.
                    Poll::Ready(Ok(id)) => {
                        this.state = OpState::Waiting(id);
                        run_waker_actions(actions);
                        Poll::Pending
                    }
                    Poll::Ready(Err(output)) => {
                        this.state = OpState::Done;
                        run_waker_actions(actions);
                        Poll::Ready(output)
                    }
                    // A full slab leaves the request in place: no bytes move.
                    Poll::Pending => {
                        run_waker_actions(actions);
                        Poll::Pending
                    }
                }
            }
            OpState::Waiting(id) => {
                let output = std::task::ready!(poll_op_completion(this.handle, *id, cx));
                this.state = OpState::Done;
                let actions = this.handle.with(|ops| {
                    let mut actions = DeferredWakerActions::new();
                    ops.capacity.reconcile(ops.waiters.free_len(), &mut actions);
                    actions
                });
                run_waker_actions(actions);
                Poll::Ready(output)
            }
            OpState::Done => panic!("io_uring op polled after completion"),
        }
    }
}

impl Drop for Op<'_> {
    fn drop(&mut self) {
        // Queued: the request (and its buffers) drops with the future, nothing
        // reached the loop or the kernel. Done: nothing to release.
        if let OpState::Waiting(id) = self.state {
            orphan_waiter(self.handle, id);
        }
    }
}

/// State of a detached ticket.
///
/// Unlike [OpState] this never holds a [Request]: tickets are only built
/// after admission, which keeps them `Sync` (requests own iovec scratch
/// pointers) so the front-ends that retain them stay `Sync`.
enum TicketState {
    /// Admitted: the completion entry links to the waiter while Pending and
    /// owns the output after it becomes Ready.
    Waiting(CompletionId),
    /// Admission failed on a closed driver: the failure output is parked
    /// locally for the next poll.
    Failed(Output),
    /// The output was delivered.
    Done,
}

/// Detached completion handle for an admitted request.
///
/// Owns a driver clone so it can outlive its front-end call. Poll and drop use
/// only the completion ID. A Pending drop winds down the linked waiter, while
/// a Ready drop never addresses the already recycled waiter.
struct Ticket {
    handle: DriverHandle,
    state: TicketState,
}

impl Ticket {
    /// Admit `request`, parking on waiter capacity, and return its detached
    /// completion ticket.
    ///
    /// After admission the ticket retains only its completion ID, not a
    /// capacity registration or reserved grant.
    async fn admit(handle: &DriverHandle, request: Request) -> Self {
        let mut request = Some(request);
        // The guard lives outside the poll closure so cancelling this future
        // while parked releases its capacity slot.
        let mut registration = CapacityRegistration::new(handle);
        let (state, actions) = std::future::poll_fn(|cx| {
            let (admission, actions) = poll_admission(
                handle,
                &mut request,
                &mut registration,
                cx,
                |ops, request, incoming_waker| {
                    let (completions, waiters) = (&mut ops.completions, &mut ops.waiters);
                    let (completion_id, waiter_id) = completions
                        .insert_pending_deferred(incoming_waker, |completion_id| {
                            waiters.insert_ticket(request, completion_id)
                        });
                    (completion_id, waiter_id)
                },
            );
            match admission {
                Poll::Ready(Ok(id)) => Poll::Ready((TicketState::Waiting(id), actions)),
                Poll::Ready(Err(output)) => Poll::Ready((TicketState::Failed(output), actions)),
                Poll::Pending => {
                    run_waker_actions(actions);
                    Poll::Pending
                }
            }
        })
        .await;
        let ticket = Self {
            handle: handle.clone(),
            state,
        };
        run_waker_actions(actions);
        ticket
    }
}

impl Future for Ticket {
    type Output = Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Output> {
        let this = self.get_mut();
        match &mut this.state {
            TicketState::Waiting(id) => {
                let output = std::task::ready!(poll_ticket_completion(&this.handle, *id, cx));
                this.state = TicketState::Done;
                Poll::Ready(output)
            }
            TicketState::Failed(_) => {
                let TicketState::Failed(output) =
                    std::mem::replace(&mut this.state, TicketState::Done)
                else {
                    unreachable!("ticket state verified failed above");
                };
                Poll::Ready(output)
            }
            TicketState::Done => panic!("io_uring ticket polled after completion"),
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let TicketState::Waiting(id) = self.state {
            orphan_ticket(&self.handle, id);
        }
    }
}

/// Detached completion handle for an admitted accept.
///
/// Retained by the listener so a cancelled accept future resumes the same
/// admitted accept instead of losing a connection. Dropping the ticket
/// orphans the slot (closing an accepted connection nobody will take).
#[must_use]
pub(crate) struct AcceptTicket(Ticket);

impl Future for AcceptTicket {
    type Output = Result<(OwnedFd, SocketAddr), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match std::task::ready!(Pin::new(&mut self.0).poll(cx)) {
            Output::Accept(result) => Poll::Ready(result.map_err(|e| *e)),
            _ => unreachable!("accept op produced foreign output"),
        }
    }
}

/// Detached completion handle for an admitted fsync.
#[must_use]
pub(crate) struct SyncTicket(Ticket);

impl Future for SyncTicket {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match std::task::ready!(Pin::new(&mut self.0).poll(cx)) {
            Output::Sync(result) => Poll::Ready(result.map_err(|e| *e)),
            _ => unreachable!("sync op produced foreign output"),
        }
    }
}

#[cfg(test)]
#[path = "handle_tests.rs"]
mod tests;
