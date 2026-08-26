//! Thread-affine op submission for the io_uring runtime.
//!
//! The [Handle] is the shared half of the driver: the waiter slab, the
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
//! task waker. Detached ticket results move to an independently generational
//! completion arena before their waiter is recycled. Dropping an op future
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
//! Queued CapacityId --slot freed--> Granted CapacityId
//!       |       |                          |       |
//!       |       +--deadline--------------->|-------+--> Expired
//!       |                                  |
//!       | drop or close                    | owner repolls
//!       v                                  v
//! Free or Closed <-------------------- waiter owns request
//!                                          |
//!                    +---------------------+---------------------+
//!                    |                                           |
//!                 Op Ready                               Ticket Pending
//!                    |                                           |
//!                    v                                           v
//!             recycle waiter                    publish Ticket Ready
//!                                                        |
//!                                                        v
//!                                                 recycle waiter
//! ```
//!
//! Every state transition completes while [Ops] is borrowed. Stored waker
//! drops and callbacks are detached into [WakerAction] values, then processed
//! after releasing that borrow. This lets callback panics propagate without
//! exposing partially published capacity or completion state.

use super::{
    Tick,
    request::{
        AcceptRequest, Cache, ConnectRequest, IOVEC_BATCH_SIZE, Output, RawSocketAddr,
        ReadAtRequest, RecvRequest, Request, SendRequest, SyncRequest, WriteAtRequest,
        WriteAtState,
    },
    waiter::{
        CompletionDropOutcome, CompletionId, DropOutcome, PollState, TicketCompletions, WaiterId,
        Waiters,
    },
    waker::Waker as RingWaker,
};
use crate::{Error, IoBufMut, IoBufs, WriteOptions};
use commonware_utils::sync::Mutex;
use std::{
    cell::RefCell,
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
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
    time::{Duration, Instant},
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
pub(crate) struct Ops {
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

/// Deferred action for a task waker detached from owner state.
pub(super) enum WakerAction {
    /// Drop a stored waker after its owner state is disarmed.
    Drop(Waker),
    /// Invoke a waker after the state change it observes is committed.
    Wake(Waker),
}

/// Append-only destination for detached capacity waker actions.
///
/// The driver uses its reusable action vector. Future poll and drop paths keep
/// the ordinary one or two actions inline and allocate only when adversarial
/// callbacks force a larger recovery batch.
pub(super) trait CapacityActionSink {
    /// Ensure room for actions that must be recorded after a state transition.
    fn reserve(&mut self, additional: usize);

    /// Append one action whose callback must run after owner state is released.
    fn push(&mut self, action: WakerAction);
}

impl CapacityActionSink for Vec<WakerAction> {
    fn reserve(&mut self, additional: usize) {
        Self::reserve(self, additional);
    }

    fn push(&mut self, action: WakerAction) {
        Self::push(self, action);
    }
}

/// Deferred actions produced by one capacity transition.
///
/// Ordinary admission, cancellation, and grant paths produce at most two
/// actions, so they remain allocation-free. The overflow vector keeps the
/// sink general for batched teardown paths.
pub(super) struct CapacityActions {
    /// Allocation-free storage for the ordinary action count.
    inline: [Option<WakerAction>; 2],
    /// Number of initialized entries at the start of `inline`.
    inline_len: usize,
    /// Actions beyond the ordinary two-action bound.
    overflow: Vec<WakerAction>,
}

impl CapacityActions {
    /// Construct an empty batch without allocating.
    pub(super) const fn new() -> Self {
        Self {
            inline: [None, None],
            inline_len: 0,
            overflow: Vec::new(),
        }
    }
}

impl CapacityActionSink for CapacityActions {
    fn reserve(&mut self, additional: usize) {
        let inline_available = self.inline.len() - self.inline_len;
        self.overflow
            .reserve(additional.saturating_sub(inline_available));
    }

    fn push(&mut self, action: WakerAction) {
        self.reserve(1);
        if self.inline_len < self.inline.len() {
            self.inline[self.inline_len] = Some(action);
            self.inline_len += 1;
        } else {
            self.overflow.push(action);
        }
    }
}

impl IntoIterator for CapacityActions {
    type Item = WakerAction;
    type IntoIter = std::iter::Chain<
        std::iter::Flatten<std::array::IntoIter<Option<WakerAction>, 2>>,
        std::vec::IntoIter<WakerAction>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.inline.into_iter().flatten().chain(self.overflow)
    }
}

/// Run every detached waker action, then resume the earliest callback panic.
///
/// Capacity state changes are committed before their wakers leave [Ops]. A
/// panic from an earlier callback must therefore not strand later callbacks
/// whose queued or granted state already changed. Stored wakers can also run
/// user RawWaker code on drop, so their destruction follows the same ordering
/// and unwind isolation.
pub(super) fn wake_batch(actions: impl IntoIterator<Item = WakerAction>) {
    let mut first_callback_panic = None;
    for action in actions {
        match action {
            WakerAction::Drop(waker) => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    drop(waker);
                }));
                if let Err(payload) = result {
                    if first_callback_panic.is_none() {
                        first_callback_panic = Some(payload);
                    } else {
                        std::mem::forget(payload);
                    }
                }
            }
            WakerAction::Wake(waker) => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    waker.wake();
                }));
                if let Err(payload) = result {
                    if first_callback_panic.is_none() {
                        first_callback_panic = Some(payload);
                    } else {
                        std::mem::forget(payload);
                    }
                }
            }
        }
    }
    if let Some(payload) = first_callback_panic {
        std::panic::resume_unwind(payload);
    }
}

/// Intrusive FIFO of admission attempts waiting for waiter capacity.
///
/// The independently generational arena keeps queued and granted nodes live
/// until their owning admission consumes or cancels them. A grant reserves
/// one authoritative waiter-table free slot, so a fresh admission cannot
/// barge ahead while an older task is waiting to repoll. Recycled nodes retain
/// their allocation, keeping polling allocation-free after the arena and
/// action-vector high-water marks.
pub(super) struct CapacityWaiters {
    /// Generational arena holding live registrations and recyclable slots.
    nodes: Vec<CapacityNode>,
    /// Oldest queued registration, or `None` when the FIFO is empty.
    head: Option<usize>,
    /// Newest queued registration, or `None` when the FIFO is empty.
    tail: Option<usize>,
    /// Head of the singly linked recyclable-slot list.
    free: Option<usize>,
    /// Number of live [CapacityState::Granted] nodes.
    reserved: usize,
    /// Earliest-first deadlines for queued and granted registrations.
    ///
    /// Admission and cancellation leave generation-stamped tombstones behind.
    /// They are pruned when the heap head is inspected, so those hot paths do
    /// not need arbitrary heap removal.
    deadlines: BinaryHeap<Reverse<CapacityDeadline>>,
    /// Number of stale entries currently retained in `deadlines`.
    deadline_tombstones: usize,
}

/// Generation-validated registration in [CapacityWaiters].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct CapacityId {
    /// Arena slot containing this registration.
    index: usize,
    /// Slot generation captured when the registration was created.
    generation: u64,
}

/// One deadline-heap entry for a capacity registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CapacityDeadline {
    /// Absolute request deadline computed by the front-end.
    deadline: Instant,
    /// Generation-tagged arena owner of this entry.
    id: CapacityId,
}

/// One slot in the capacity registration arena.
struct CapacityNode {
    /// Generation incremented whenever a live registration is removed.
    generation: u64,
    /// Current ownership and linkage of the slot.
    state: CapacityState,
}

/// Lifecycle of one capacity arena slot.
enum CapacityState {
    /// Recyclable slot not owned by an admission attempt.
    Free {
        /// Next recyclable arena slot.
        next: Option<usize>,
    },
    /// Live registration waiting in the intrusive FIFO.
    Queued {
        /// Older queued registration.
        prev: Option<usize>,
        /// Newer queued registration.
        next: Option<usize>,
        /// Owner waker retained until grant, cancellation, or close.
        waker: Waker,
        /// Absolute operation deadline, if the request is timed.
        deadline: Option<Instant>,
    },
    /// Live registration holding one reserved waiter-table slot.
    ///
    /// The queued waker moved into the deferred wake action when this state
    /// was published. The owner's next poll supplies the observer waker used
    /// by the admitted waiter.
    Granted {
        /// Absolute operation deadline, retained until waiter insertion.
        deadline: Option<Instant>,
    },
    /// Deadline elapsed before admission.
    ///
    /// The queued waker moved into the deferred wake action. The node remains
    /// generation-live until the owner repolls or drops, preventing a stale
    /// registration from silently rejoining the FIFO.
    Expired,
    /// Driver closure won the race with the operation deadline.
    ///
    /// Queued owners have already been moved into the close wake batch.
    Closed,
}

/// Result of one atomic capacity-admission transition.
///
/// Successful variants carry the observer waker cloned before the transition
/// consumed either a direct free slot or a reserved grant. The caller can then
/// publish the waiter and retain the observer without a second external clone.
enum CapacityAdmission {
    /// Admit directly from an unreserved authoritative free slot.
    Direct,
    /// Consume the caller's previously reserved FIFO grant.
    Granted,
    /// Keep or create a FIFO registration and wait for a grant.
    Queued,
    /// The request deadline elapsed while it waited for capacity.
    Expired,
    /// The driver closed while the request waited for capacity.
    Closed,
}

/// Payload-free admission result used by capacity state-machine tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapacityAdmissionKind {
    /// The poll admitted directly from a free slot.
    Direct,
    /// The poll consumed a reserved grant.
    Granted,
    /// The poll remains registered in the FIFO.
    Queued,
    /// The poll observes a pre-admission deadline expiry.
    Expired,
    /// The poll observes driver closure before admission.
    Closed,
}

#[cfg(test)]
impl CapacityAdmission {
    /// Return the payload-free result for state-machine assertions.
    const fn kind(&self) -> CapacityAdmissionKind {
        match self {
            Self::Direct => CapacityAdmissionKind::Direct,
            Self::Granted => CapacityAdmissionKind::Granted,
            Self::Queued => CapacityAdmissionKind::Queued,
            Self::Expired => CapacityAdmissionKind::Expired,
            Self::Closed => CapacityAdmissionKind::Closed,
        }
    }
}

impl CapacityWaiters {
    /// Construct an empty FIFO and arena without allocating.
    const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            head: None,
            tail: None,
            free: None,
            reserved: 0,
            deadlines: BinaryHeap::new(),
            deadline_tombstones: 0,
        }
    }

    /// Poll one admission against the authoritative free-slot count.
    fn poll(
        &mut self,
        registration: &mut Option<CapacityId>,
        free_len: usize,
        deadline: Option<Instant>,
        incoming_waker: &mut Option<Waker>,
        actions: &mut impl CapacityActionSink,
    ) -> CapacityAdmission {
        assert!(
            self.reserved <= free_len,
            "capacity reservations exceed waiter free slots"
        );

        if let Some(id) = *registration {
            let Some(state) = self.live_state(id) else {
                *registration = None;
                return self.poll(
                    registration,
                    free_len,
                    deadline,
                    incoming_waker,
                    actions,
                );
            };
            match state {
                CapacityState::Queued { waker: stored, .. } => {
                    let incoming = incoming_waker
                        .as_ref()
                        .expect("capacity poll missing incoming waker");
                    actions.reserve(1);
                    if stored.will_wake(incoming) {
                        actions.push(WakerAction::Drop(
                            incoming_waker
                                .take()
                                .expect("capacity waker consumed twice"),
                        ));
                    } else {
                        let replacement = incoming_waker
                            .take()
                            .expect("capacity waker consumed twice");
                        let CapacityState::Queued { waker: stored, .. } =
                            &mut self.nodes[id.index].state
                        else {
                            unreachable!("capacity state changed during waker replacement")
                        };
                        let old = std::mem::replace(stored, replacement);
                        actions.push(WakerAction::Drop(old));
                    }
                    return CapacityAdmission::Queued;
                }
                CapacityState::Granted { .. } => {
                    let CapacityState::Granted { deadline } = self
                        .take_live(id)
                        .expect("validated capacity grant disappeared")
                    else {
                        unreachable!("validated capacity grant changed state")
                    };
                    self.reserved = self
                        .reserved
                        .checked_sub(1)
                        .expect("capacity reservation underflow");
                    if deadline.is_some() {
                        self.deadline_tombstones += 1;
                        self.compact_deadlines();
                    }
                    *registration = None;
                    return CapacityAdmission::Granted;
                }
                CapacityState::Expired => {
                    actions.reserve(1);
                    let CapacityState::Expired = self
                        .take_live(id)
                        .expect("validated capacity expiry disappeared")
                    else {
                        unreachable!("validated capacity expiry changed state")
                    };
                    *registration = None;
                    actions.push(WakerAction::Drop(
                        incoming_waker
                            .take()
                            .expect("capacity waker consumed twice"),
                    ));
                    return CapacityAdmission::Expired;
                }
                CapacityState::Closed => {
                    actions.reserve(1);
                    let CapacityState::Closed = self
                        .take_live(id)
                        .expect("validated capacity closure disappeared")
                    else {
                        unreachable!("validated capacity closure changed state")
                    };
                    *registration = None;
                    actions.push(WakerAction::Drop(
                        incoming_waker
                            .take()
                            .expect("capacity waker consumed twice"),
                    ));
                    return CapacityAdmission::Closed;
                }
                CapacityState::Free { .. } => unreachable!("free capacity node reported live"),
            }
        }

        if self.head.is_none() && self.reserved < free_len {
            return CapacityAdmission::Direct;
        }

        let id = self.push_back(incoming_waker, deadline);
        *registration = Some(id);
        CapacityAdmission::Queued
    }

    /// Return the delay until the earliest live capacity deadline.
    ///
    /// Generation-stale heap entries are removed before reporting the head.
    pub(super) fn next_deadline(&mut self, now: Instant) -> Option<Duration> {
        self.prune_deadlines();
        self.deadlines
            .peek()
            .map(|entry| entry.0.deadline.saturating_duration_since(now))
    }

    /// Expire every queued registration whose deadline is at or before `now`.
    ///
    /// Each expired node remains generation-live for its owner, but leaves the
    /// FIFO and no longer participates in grants. Its waker runs only after
    /// the surrounding [Ops] borrow is released.
    pub(super) fn expire(
        &mut self,
        now: Instant,
        free_len: usize,
        actions: &mut impl CapacityActionSink,
    ) {
        let mut changed = false;
        loop {
            self.prune_deadlines();
            let Some(entry) = self.deadlines.peek().copied() else {
                break;
            };
            if entry.0.deadline > now {
                break;
            }

            let id = entry.0.id;
            if matches!(self.live_state(id), Some(CapacityState::Queued { .. })) {
                actions.reserve(1);
            }
            self.deadlines.pop();
            let state = std::mem::replace(&mut self.nodes[id.index].state, CapacityState::Expired);
            match state {
                CapacityState::Queued {
                    prev, next, waker, ..
                } => {
                    self.unlink(prev, next);
                    actions.push(WakerAction::Wake(waker));
                }
                CapacityState::Granted { .. } => {
                    self.reserved = self
                        .reserved
                        .checked_sub(1)
                        .expect("capacity reservation underflow");
                }
                _ => unreachable!("live capacity deadline had a terminal state"),
            }
            changed = true;
        }
        if changed {
            self.reconcile(free_len, actions);
        }
    }

    /// Remove stale heap heads left by admission, cancellation, or slot reuse.
    fn prune_deadlines(&mut self) {
        while self
            .deadlines
            .peek()
            .is_some_and(|entry| !self.deadline_is_live(entry.0))
        {
            self.deadlines.pop();
            self.deadline_tombstones = self
                .deadline_tombstones
                .checked_sub(1)
                .expect("capacity deadline tombstone underflow");
        }
    }

    /// Rebuild the deadline heap when cancelled entries dominate it.
    ///
    /// One long-lived capacity waiter must not let later admission churn retain
    /// an unbounded tail of stale deadlines. Rebuilding at a fixed minimum and
    /// a 50 percent stale ratio keeps removal amortized while preserving the
    /// allocation high-water mark.
    fn compact_deadlines(&mut self) {
        const MIN_COMPACTION_LEN: usize = 64;
        if self.deadlines.len() < MIN_COMPACTION_LEN
            || self.deadline_tombstones.saturating_mul(2) < self.deadlines.len()
        {
            return;
        }
        let nodes = &self.nodes;
        self.deadlines
            .retain(|entry| Self::deadline_is_live_in(nodes, entry.0));
        self.deadline_tombstones = 0;
    }

    /// Return whether a deadline entry still names the queued node that owns it.
    fn deadline_is_live(&self, entry: CapacityDeadline) -> bool {
        Self::deadline_is_live_in(&self.nodes, entry)
    }

    /// Check one heap entry against an arena slice.
    fn deadline_is_live_in(nodes: &[CapacityNode], entry: CapacityDeadline) -> bool {
        matches!(
            nodes.get(entry.id.index),
            Some(CapacityNode {
                generation,
                state:
                    CapacityState::Queued {
                        deadline: Some(deadline),
                        ..
                    }
                    | CapacityState::Granted {
                        deadline: Some(deadline),
                    },
            }) if *generation == entry.id.generation && *deadline == entry.deadline
        )
    }

    /// Cancel a queued or granted admission and transfer any reserved permit.
    ///
    /// A stale generation is already cancelled and is therefore a no-op.
    pub(super) fn cancel(
        &mut self,
        id: CapacityId,
        free_len: usize,
        actions: &mut impl CapacityActionSink,
    ) {
        let Some(state) = self.live_state(id) else {
            return;
        };
        actions.reserve(usize::from(matches!(state, CapacityState::Queued { .. })));
        match self
            .take_live(id)
            .expect("validated capacity registration disappeared")
        {
            CapacityState::Queued {
                prev,
                next,
                waker,
                deadline,
            } => {
                self.unlink(prev, next);
                if deadline.is_some() {
                    self.deadline_tombstones += 1;
                    self.compact_deadlines();
                }
                actions.push(WakerAction::Drop(waker));
            }
            CapacityState::Granted { deadline } => {
                self.reserved = self
                    .reserved
                    .checked_sub(1)
                    .expect("capacity reservation underflow");
                if deadline.is_some() {
                    self.deadline_tombstones += 1;
                }
                self.reconcile(free_len, actions);
            }
            CapacityState::Expired | CapacityState::Closed => {}
            CapacityState::Free { .. } => unreachable!("free capacity node reported live"),
        }
    }

    /// Reserve authoritative free slots for FIFO heads and defer their effects.
    ///
    /// Each transition moves the queued waker into a deferred wake action and
    /// leaves a payload-free grant behind. No RawWaker vtable function runs
    /// while the capacity arena is borrowed.
    pub(super) fn reconcile(&mut self, free_len: usize, actions: &mut impl CapacityActionSink) {
        assert!(
            self.reserved <= free_len,
            "capacity reservations exceed waiter free slots"
        );
        while self.reserved < free_len {
            let Some(index) = self.head else {
                break;
            };
            // Reserve before mutation so action-buffer growth cannot leave a
            // half-published grant.
            actions.reserve(1);
            let CapacityState::Queued {
                prev,
                next,
                waker,
                deadline,
            } = std::mem::replace(
                &mut self.nodes[index].state,
                CapacityState::Granted { deadline: None },
            )
            else {
                panic!("capacity FIFO contains a non-queued node")
            };
            assert!(prev.is_none(), "capacity FIFO head has a predecessor");
            self.unlink(prev, next);
            self.nodes[index].state = CapacityState::Granted { deadline };
            self.reserved += 1;
            actions.push(WakerAction::Wake(waker));
        }
        self.compact_deadlines();
    }

    /// Mark every live registration closed and return queued owner wakers.
    ///
    /// Expired nodes preserve timeout-before-close precedence. Other live
    /// nodes become closure tombstones until their generation owner repolls or
    /// drops. Free slots and arena allocation remain reusable at high water.
    fn close(&mut self) -> Vec<Waker> {
        let queued = self
            .nodes
            .iter()
            .filter(|node| matches!(node.state, CapacityState::Queued { .. }))
            .count();
        let mut wakers = Vec::with_capacity(queued);
        self.head = None;
        self.tail = None;
        self.reserved = 0;
        self.deadlines.clear();
        self.deadline_tombstones = 0;
        for node in self.nodes.iter_mut().rev() {
            let state = std::mem::replace(&mut node.state, CapacityState::Closed);
            match state {
                CapacityState::Queued { waker, .. } => wakers.push(waker),
                CapacityState::Expired => node.state = CapacityState::Expired,
                CapacityState::Free { next } => node.state = CapacityState::Free { next },
                CapacityState::Granted { .. } | CapacityState::Closed => {}
            }
        }
        wakers
    }

    /// Return the live state identified by an exact slot generation.
    fn live_state(&self, id: CapacityId) -> Option<&CapacityState> {
        let node = self.nodes.get(id.index)?;
        if node.generation != id.generation || matches!(node.state, CapacityState::Free { .. }) {
            return None;
        }
        Some(&node.state)
    }

    /// Generation-remove a live registration and recycle its arena slot.
    fn take_live(&mut self, id: CapacityId) -> Option<CapacityState> {
        let node = self.nodes.get_mut(id.index)?;
        if node.generation != id.generation || matches!(node.state, CapacityState::Free { .. }) {
            return None;
        }
        let generation = node
            .generation
            .checked_add(1)
            .expect("capacity generation overflowed");
        let state = std::mem::replace(&mut node.state, CapacityState::Free { next: self.free });
        node.generation = generation;
        self.free = Some(id.index);
        Some(state)
    }

    /// Append a new registration to the FIFO, reusing an arena slot if possible.
    fn push_back(
        &mut self,
        incoming_waker: &mut Option<Waker>,
        deadline: Option<Instant>,
    ) -> CapacityId {
        if self.free.is_none() {
            self.nodes.reserve(1);
        }
        if deadline.is_some() {
            self.deadlines.reserve(1);
        }
        let index = match self.free {
            Some(index) => {
                let CapacityState::Free { next } = self.nodes[index].state else {
                    panic!("capacity free-list node is live")
                };
                self.free = next;
                index
            }
            None => {
                self.nodes.push(CapacityNode {
                    generation: 0,
                    state: CapacityState::Free { next: None },
                });
                self.nodes.len() - 1
            }
        };
        let id = CapacityId {
            index,
            generation: self.nodes[index].generation,
        };
        let prev = self.tail;
        self.nodes[index].state = CapacityState::Queued {
            prev,
            next: None,
            waker: incoming_waker
                .take()
                .expect("capacity waker consumed twice"),
            deadline,
        };
        match prev {
            Some(prev) => {
                let CapacityState::Queued { next, .. } = &mut self.nodes[prev].state else {
                    panic!("capacity FIFO tail is not queued")
                };
                *next = Some(index);
            }
            None => self.head = Some(index),
        }
        self.tail = Some(index);
        if let Some(deadline) = deadline {
            self.deadlines
                .push(Reverse(CapacityDeadline { deadline, id }));
        }
        id
    }

    /// Remove a queued node between `prev` and `next` from the intrusive FIFO.
    fn unlink(&mut self, prev: Option<usize>, next: Option<usize>) {
        match prev {
            Some(prev) => {
                let CapacityState::Queued {
                    next: previous_next,
                    ..
                } = &mut self.nodes[prev].state
                else {
                    panic!("capacity FIFO predecessor is not queued")
                };
                *previous_next = next;
            }
            None => self.head = next,
        }
        match next {
            Some(next) => {
                let CapacityState::Queued {
                    prev: next_prev, ..
                } = &mut self.nodes[next].state
                else {
                    panic!("capacity FIFO successor is not queued")
                };
                *next_prev = prev;
            }
            None => self.tail = prev,
        }
    }

    /// Number of live registrations.
    #[cfg(test)]
    pub(super) fn registered(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| !matches!(node.state, CapacityState::Free { .. }))
            .count()
    }

    /// Number of registrations still waiting in the FIFO.
    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| matches!(node.state, CapacityState::Queued { .. }))
            .count()
    }

    /// Number of waiter-table slots reserved for granted registrations.
    #[cfg(test)]
    pub(super) const fn reserved(&self) -> usize {
        self.reserved
    }

    /// Size of the slot arena, including recyclable entries.
    #[cfg(test)]
    pub(super) const fn arena_len(&self) -> usize {
        self.nodes.len()
    }
}

/// RAII registration of one admission attempt on the capacity wait list.
///
/// The slot is cleared on admission or closed-driver resolution (inside the
/// admission poll) and cancelled when the attempt is dropped while parked. A
/// foreign-thread drop cannot touch the thread-affine arena, so it transfers
/// the generation-tagged ID through [OrphanMailbox]. The loop cancels that ID
/// and transfers any released permit on its next turn. Expired registrations
/// stay generation-live until this guard observes or cancels them.
struct Registration<'a> {
    /// Affine driver state and cross-thread orphan mailbox.
    handle: &'a Handle,
    /// Live capacity registration, if the admission is queued or granted.
    slot: Option<CapacityId>,
}

impl<'a> Registration<'a> {
    /// Construct an unregistered guard for one admission future.
    const fn new(handle: &'a Handle) -> Self {
        Self { handle, slot: None }
    }
}

impl Drop for Registration<'_> {
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
            let mut actions = CapacityActions::new();
            ops.capacity
                .cancel(slot, ops.waiters.free_len(), &mut actions);
            actions
        });
        let Some(actions) = cancelled else {
            let slot = slot.take().expect("capacity slot lost on foreign drop");
            self.handle.push_orphan(Orphan::Capacity(slot));
            return;
        };
        wake_batch(actions);
    }
}

/// Handle to driver state shared by the network and storage front-ends and the
/// event loop itself.
///
/// Operation state remains protected by an affinity-checked [Affine] cell,
/// while foreign-thread drops reach the colocated mailbox without touching
/// that cell.
#[derive(Clone)]
pub(crate) struct Handle {
    inner: Arc<HandleInner>,
}

/// State with the same lifetime as every [Handle] clone.
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
    /// the waiter link while Pending and generation-validates foreign drops.
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

impl Handle {
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
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> R {
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
        self.inner
            .ops
            .try_with(|cell| f(&mut cell.borrow_mut()))
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
    pub(crate) fn close(&self) -> Vec<Waker> {
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
        let request = Request::Send(SendRequest {
            fd,
            write: bufs.into(),
            deadline: Some(deadline),
        });
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
        assert!(
            offset <= len && len <= buf.capacity(),
            "recv invariant violated: need offset <= len <= capacity"
        );
        let request = Request::Recv(RecvRequest {
            fd,
            buf,
            offset,
            len,
            exact,
            deadline: Some(deadline),
        });
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
        let request = Request::Accept(AcceptRequest {
            fd,
            addr: RawSocketAddr::zeroed(),
            deadline: Some(deadline),
        });
        AcceptTicket(Ticket::admit(self, request).await)
    }

    /// Submit a logical connect request and wait for its completion.
    pub(crate) async fn connect(
        &self,
        fd: Arc<OwnedFd>,
        addr: SocketAddr,
        deadline: Instant,
    ) -> Result<(), Error> {
        let request = Request::Connect(ConnectRequest {
            fd,
            addr: RawSocketAddr::boxed_from_socket_addr(&addr),
            deadline: Some(deadline),
        });
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
        assert!(len <= buf.capacity(), "read_at len exceeds buffer capacity");
        let request = Request::ReadAt(ReadAtRequest {
            file,
            offset,
            len,
            read: 0,
            buf,
            cache,
        });
        match Op::new(self, request).await {
            Output::ReadAt(result) => result.map_err(|e| *e),
            _ => unreachable!("read_at op produced foreign output"),
        }
    }

    /// Submit a positioned write with the provided options and wait for its
    /// completion.
    ///
    /// A durable write that fits one submission carries `RWF_DSYNC`. A larger
    /// write is submitted plain and finished with one data sync, avoiding one
    /// device flush per submission.
    pub(crate) async fn write_at(
        &self,
        file: Arc<File>,
        offset: u64,
        bufs: IoBufs,
        options: WriteOptions,
        cache: Cache,
    ) -> Result<(), Error> {
        let state = if !options.contains(WriteOptions::SYNC) {
            WriteAtState::Writing
        } else if bufs.chunk_count() <= IOVEC_BATCH_SIZE {
            WriteAtState::WritingSync
        } else {
            WriteAtState::WritingBeforeSync
        };
        let request = Request::WriteAt(WriteAtRequest {
            file,
            offset,
            written: 0,
            write: bufs.into(),
            state,
            cache,
        });
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
        let request = Request::Sync(SyncRequest { file });
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
    handle: &Handle,
    request: &mut Option<Request>,
    registration: &mut Registration<'_>,
    cx: &mut Context<'_>,
    admit: impl FnOnce(&mut Ops, Request, &mut Option<Waker>) -> (T, WaiterId),
) -> (Poll<Result<T, Output>>, CapacityActions) {
    let mut actions = CapacityActions::new();
    // RawWaker clone callbacks are external code. Run them before borrowing
    // Ops, then move or defer-drop the clone during the state transition.
    let mut incoming_waker = Some(cx.waker().clone());
    let deadline = request
        .as_ref()
        .expect("request missing before admission")
        .deadline();
    let outcome = handle.with(|ops| {
        if registration.slot.is_some_and(|id| {
            matches!(
                ops.capacity.live_state(id),
                Some(CapacityState::Expired | CapacityState::Closed)
            )
        }) {
            return match ops.capacity.poll(
                &mut registration.slot,
                ops.waiters.free_len(),
                deadline,
                &mut incoming_waker,
                &mut actions,
            ) {
                CapacityAdmission::Expired => Admission::Expired,
                CapacityAdmission::Closed => Admission::Closed,
                _ => unreachable!("terminal capacity registration changed state"),
            };
        }
        if ops.closed {
            if let Some(slot) = registration.slot.take() {
                ops.capacity
                    .cancel(slot, ops.waiters.free_len(), &mut actions);
            }
            actions.reserve(1);
            actions.push(WakerAction::Drop(
                incoming_waker
                    .take()
                    .expect("admission waker consumed twice"),
            ));
            return Admission::Closed;
        }
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            if let Some(slot) = registration.slot.take() {
                ops.capacity
                    .cancel(slot, ops.waiters.free_len(), &mut actions);
            }
            actions.reserve(1);
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
            CapacityAdmission::Expired => return Admission::Expired,
            CapacityAdmission::Closed => return Admission::Closed,
            CapacityAdmission::Direct | CapacityAdmission::Granted => {}
        }
        let request = request.take().expect("request consumed before admission");
        let (id, waiter_id) = admit(ops, request, &mut incoming_waker);
        assert!(ops.capacity.reserved <= ops.waiters.free_len());
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
fn poll_op_completion(handle: &Handle, id: WaiterId, cx: &mut Context<'_>) -> Poll<Output> {
    match handle.with(|ops| ops.waiters.poll_state(id, cx.waker())) {
        PollState::Ready(output) => return Poll::Ready(output),
        PollState::PendingCurrent => return Poll::Pending,
        PollState::PendingNeedsWaker => {}
    }

    let mut incoming = Some(cx.waker().clone());
    let (output, detached) =
        handle.with(|ops| ops.waiters.poll_take_deferred(id, &mut incoming));
    let mut actions = CapacityActions::new();
    actions.reserve(2);
    for waker in detached.into_iter().chain(incoming) {
        actions.push(WakerAction::Drop(waker));
    }
    wake_batch(actions);
    output.map_or(Poll::Pending, Poll::Ready)
}

/// Poll a detached ticket's completion entry.
fn poll_ticket_completion(handle: &Handle, id: CompletionId, cx: &mut Context<'_>) -> Poll<Output> {
    match handle.with(|ops| ops.completions.poll_state(id, cx.waker())) {
        PollState::Ready(output) => return Poll::Ready(output),
        PollState::PendingCurrent => return Poll::Pending,
        PollState::PendingNeedsWaker => {}
    }

    let mut incoming = Some(cx.waker().clone());
    let (output, detached) =
        handle.with(|ops| ops.completions.poll_take_deferred(id, &mut incoming));
    let mut actions = CapacityActions::new();
    actions.reserve(2);
    for waker in detached.into_iter().chain(incoming) {
        actions.push(WakerAction::Drop(waker));
    }
    wake_batch(actions);
    output.map_or(Poll::Pending, Poll::Ready)
}

/// Reserve every destination an orphan transition can append to after it
/// extracts an externally controlled waker.
fn reserve_orphan_wind_down(
    ops: &mut Ops,
    outcome: &DropOutcome,
    actions: &mut impl CapacityActionSink,
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
    completion_waker: Option<Waker>,
    actions: &mut impl CapacityActionSink,
) {
    let (outcome, op_waker) = ops.waiters.mark_orphaned(id);
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
pub(super) fn wind_down_orphan(ops: &mut Ops, id: WaiterId, actions: &mut impl CapacityActionSink) {
    let outcome = ops.waiters.classify_orphan(id);
    reserve_orphan_wind_down(ops, &outcome, actions);
    wind_down_orphan_prepared(ops, id, None, actions);
}

/// Apply detached-ticket wind-down after generation-validating its completion
/// ID. Pending entries yield their active waiter for request-kind-specific
/// cancellation or detach. Ready entries drop only their output because the
/// waiter was already recycled at terminal completion.
pub(super) fn wind_down_ticket(
    ops: &mut Ops,
    id: CompletionId,
    actions: &mut impl CapacityActionSink,
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
            wind_down_orphan_prepared(ops, removed_waiter, waker, actions);
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
fn orphan_waiter(handle: &Handle, id: WaiterId) {
    let Some(actions) = handle.try_with(|ops| {
        let mut actions = CapacityActions::new();
        wind_down_orphan(ops, id, &mut actions);
        actions
    }) else {
        handle.push_orphan(Orphan::Waiter(id));
        return;
    };
    wake_batch(actions);
}

/// Wind down a detached ticket using only its completion ID.
fn orphan_ticket(handle: &Handle, id: CompletionId) {
    let Some(actions) = handle.try_with(|ops| {
        let mut actions = CapacityActions::new();
        wind_down_ticket(ops, id, &mut actions);
        actions
    }) else {
        handle.push_orphan(Orphan::Completion(id));
        return;
    };
    wake_batch(actions);
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
    handle: &'a Handle,
    state: OpState,
    /// Capacity wait-list registration while queued on a full slab, released
    /// on admission or by drop (via its RAII guard).
    registration: Registration<'a>,
}

impl<'a> Op<'a> {
    /// Construct a queued op whose future owns `request` until admission.
    const fn new(handle: &'a Handle, request: Request) -> Self {
        Self {
            handle,
            state: OpState::Queued(Some(request)),
            registration: Registration::new(handle),
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
                        wake_batch(actions);
                        Poll::Pending
                    }
                    Poll::Ready(Err(output)) => {
                        this.state = OpState::Done;
                        wake_batch(actions);
                        Poll::Ready(output)
                    }
                    // A full slab leaves the request in place: no bytes move.
                    Poll::Pending => {
                        wake_batch(actions);
                        Poll::Pending
                    }
                }
            }
            OpState::Waiting(id) => {
                let output = std::task::ready!(poll_op_completion(this.handle, *id, cx));
                this.state = OpState::Done;
                let actions = this.handle.with(|ops| {
                    let mut actions = CapacityActions::new();
                    ops.capacity.reconcile(ops.waiters.free_len(), &mut actions);
                    actions
                });
                wake_batch(actions);
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
    Failed(Option<Output>),
    /// The output was delivered.
    Done,
}

/// Detached completion handle for an admitted request.
///
/// Owns a driver clone so it can outlive its front-end call. Poll and drop use
/// only the completion ID. A Pending drop winds down the linked waiter, while
/// a Ready drop never addresses the already recycled waiter.
struct Ticket {
    handle: Handle,
    state: TicketState,
}

impl Ticket {
    /// Admit `request`, parking on waiter capacity, and return its detached
    /// completion ticket.
    ///
    /// After admission the ticket retains only its completion ID, not a
    /// capacity registration or reserved grant.
    async fn admit(handle: &Handle, request: Request) -> Self {
        let mut request = Some(request);
        // The guard lives outside the poll closure so cancelling this future
        // while parked releases its capacity slot.
        let mut registration = Registration::new(handle);
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
                Poll::Ready(Err(output)) => {
                    Poll::Ready((TicketState::Failed(Some(output)), actions))
                }
                Poll::Pending => {
                    wake_batch(actions);
                    Poll::Pending
                }
            }
        })
        .await;
        let ticket = Self {
            handle: handle.clone(),
            state,
        };
        wake_batch(actions);
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
            TicketState::Failed(output) => {
                let output = output.take().expect("failed ticket already delivered");
                this.state = TicketState::Done;
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
mod tests {
    use super::*;
    use crate::iouring::driver::{request::RecvRequest, waiter::StageOutcome};
    use futures::task::{ArcWake, waker as arc_waker};
    use std::{
        cell::Cell,
        os::unix::net::UnixStream,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{RawWaker, RawWakerVTable},
    };

    struct LogWaker {
        id: usize,
        log: Arc<Mutex<Vec<usize>>>,
    }

    impl ArcWake for LogWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.log.lock().push(arc_self.id);
        }
    }

    struct CountWaker(AtomicUsize);

    impl ArcWake for CountWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct FlagWaker(AtomicBool);

    impl ArcWake for FlagWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.store(true, Ordering::Release);
        }
    }

    fn log_waker(id: usize, log: &Arc<Mutex<Vec<usize>>>) -> Waker {
        arc_waker(Arc::new(LogWaker {
            id,
            log: Arc::clone(log),
        }))
    }

    fn poll_capacity(
        capacity: &mut CapacityWaiters,
        registration: &mut Option<CapacityId>,
        free_len: usize,
        waker: &Waker,
    ) -> CapacityAdmissionKind {
        poll_capacity_with_deadline(capacity, registration, free_len, None, waker)
    }

    fn poll_capacity_with_deadline(
        capacity: &mut CapacityWaiters,
        registration: &mut Option<CapacityId>,
        free_len: usize,
        deadline: Option<Instant>,
        waker: &Waker,
    ) -> CapacityAdmissionKind {
        let mut actions = Vec::new();
        let mut incoming = Some(waker.clone());
        let admission = capacity.poll(
            registration,
            free_len,
            deadline,
            &mut incoming,
            &mut actions,
        );
        actions.extend(incoming.map(WakerAction::Drop));
        wake_batch(actions);
        admission.kind()
    }

    fn reconcile_capacity(capacity: &mut CapacityWaiters, free_len: usize) {
        let mut actions = Vec::new();
        capacity.reconcile(free_len, &mut actions);
        wake_batch(actions);
    }

    fn cancel_capacity(capacity: &mut CapacityWaiters, id: CapacityId, free_len: usize) {
        let mut actions = Vec::new();
        capacity.cancel(id, free_len, &mut actions);
        wake_batch(actions);
    }

    fn recv_request() -> Request {
        let (left, _right) = UnixStream::pair().unwrap();
        Request::Recv(RecvRequest {
            fd: Arc::new(left.into()),
            buf: IoBufMut::with_capacity(1),
            offset: 0,
            len: 1,
            exact: false,
            deadline: None,
        })
    }

    #[test]
    fn test_capacity_fifo_prevents_fresh_admission_barging() {
        let mut capacity = CapacityWaiters::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let wakers = [log_waker(0, &log), log_waker(1, &log), log_waker(2, &log)];
        let mut registrations = [None, None, None];

        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[0], 0, &wakers[0]),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[1], 0, &wakers[1]),
            CapacityAdmissionKind::Queued
        );
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(capacity.reserved(), 1);

        // One free slot is already reserved for the oldest waiter. A new poll
        // joins behind the remaining queued waiter instead of taking it.
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(capacity.queued(), 2);
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[0], 1, &wakers[0]),
            CapacityAdmissionKind::Granted
        );

        // Simulate insertion consuming the free waiter, then two terminal
        // removals. The older queued registration is always granted first.
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[1], 1, &wakers[1]),
            CapacityAdmissionKind::Granted
        );
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
            CapacityAdmissionKind::Granted
        );
        assert_eq!(*log.lock(), vec![0, 1, 2]);
        assert_eq!(capacity.registered(), 0);
        assert_eq!(capacity.reserved(), 0);
    }

    #[test]
    fn test_capacity_reconcile_wakes_exactly_k_fifo_heads() {
        let mut capacity = CapacityWaiters::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut registrations = [None, None, None, None, None];
        let wakers: Vec<_> = (0..registrations.len())
            .map(|id| log_waker(id, &log))
            .collect();
        for (registration, waker) in registrations.iter_mut().zip(&wakers) {
            assert_eq!(
                poll_capacity(&mut capacity, registration, 0, waker),
                CapacityAdmissionKind::Queued
            );
        }

        reconcile_capacity(&mut capacity, 3);
        assert_eq!(*log.lock(), vec![0, 1, 2]);
        assert_eq!(capacity.reserved(), 3);
        assert_eq!(capacity.queued(), 2);
        assert_eq!(capacity.registered(), 5);
    }

    #[test]
    fn test_capacity_granted_deadline_transfers_permit_to_fifo_survivor() {
        let now = Instant::now();
        let mut capacity = CapacityWaiters::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let wakers = [log_waker(0, &log), log_waker(1, &log), log_waker(2, &log)];
        let mut registrations = [None, None, None];
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut registrations[0],
                0,
                Some(now + Duration::from_millis(10)),
                &wakers[0],
            ),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut registrations[1],
                0,
                Some(now + Duration::from_millis(20)),
                &wakers[1],
            ),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(
            poll_capacity(
                &mut capacity,
                &mut registrations[2],
                0,
                &wakers[2],
            ),
            CapacityAdmissionKind::Queued
        );

        reconcile_capacity(&mut capacity, 1);
        assert_eq!(*log.lock(), vec![0]);
        assert_eq!(capacity.reserved(), 1);
        assert_eq!(
            capacity.next_deadline(now),
            Some(Duration::from_millis(10))
        );

        let mut actions = Vec::new();
        capacity.expire(now + Duration::from_millis(15), 1, &mut actions);
        wake_batch(actions);
        assert_eq!(*log.lock(), vec![0, 1]);
        assert!(matches!(
            capacity.live_state(registrations[0].unwrap()),
            Some(CapacityState::Expired)
        ));
        assert!(matches!(
            capacity.live_state(registrations[1].unwrap()),
            Some(CapacityState::Granted { .. })
        ));
        assert_eq!(capacity.queued(), 1);
        assert_eq!(capacity.reserved(), 1);
        assert_eq!(
            capacity.next_deadline(now + Duration::from_millis(15)),
            Some(Duration::from_millis(5))
        );

        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut registrations[0],
                1,
                Some(now + Duration::from_millis(10)),
                &wakers[0],
            ),
            CapacityAdmissionKind::Expired
        );
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut registrations[1],
                1,
                Some(now + Duration::from_millis(20)),
                &wakers[1],
            ),
            CapacityAdmissionKind::Granted
        );
        cancel_capacity(&mut capacity, registrations[2].unwrap(), 0);
        assert_eq!(capacity.registered(), 0);
    }

    #[test]
    fn test_capacity_deadline_tombstones_compact_behind_live_root() {
        let now = Instant::now();
        let mut capacity = CapacityWaiters::new();
        let waker = futures::task::noop_waker();
        let mut anchor = None;
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut anchor,
                0,
                Some(now + Duration::from_secs(1)),
                &waker,
            ),
            CapacityAdmissionKind::Queued
        );

        for offset in 0..256 {
            let mut churn = None;
            assert_eq!(
                poll_capacity_with_deadline(
                    &mut capacity,
                    &mut churn,
                    0,
                    Some(now + Duration::from_secs(2) + Duration::from_millis(offset)),
                    &waker,
                ),
                CapacityAdmissionKind::Queued
            );
            cancel_capacity(&mut capacity, churn.unwrap(), 0);
        }

        assert!(capacity.deadlines.len() < 64);
        assert!(capacity.deadline_tombstones < 64);
        assert_eq!(capacity.registered(), 1);
        assert_eq!(capacity.arena_len(), 2);
        cancel_capacity(&mut capacity, anchor.unwrap(), 0);
        assert_eq!(capacity.next_deadline(now), None);
        assert!(capacity.deadlines.is_empty());
    }

    #[test]
    fn test_capacity_timeout_precedes_later_close() {
        let now = Instant::now();
        let mut capacity = CapacityWaiters::new();
        let waker = futures::task::noop_waker();
        let mut expired = None;
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut expired,
                0,
                Some(now + Duration::from_millis(1)),
                &waker,
            ),
            CapacityAdmissionKind::Queued
        );
        let mut actions = Vec::new();
        capacity.expire(now + Duration::from_millis(2), 0, &mut actions);
        wake_batch(actions);
        for waker in capacity.close() {
            waker.wake();
        }
        assert_eq!(
            poll_capacity_with_deadline(
                &mut capacity,
                &mut expired,
                0,
                Some(now + Duration::from_millis(1)),
                &waker,
            ),
            CapacityAdmissionKind::Expired
        );

        let mut closed = None;
        let mut fresh = CapacityWaiters::new();
        assert_eq!(
            poll_capacity_with_deadline(
                &mut fresh,
                &mut closed,
                0,
                Some(now + Duration::from_secs(1)),
                &waker,
            ),
            CapacityAdmissionKind::Queued
        );
        drop(fresh.close());
        assert_eq!(
            poll_capacity_with_deadline(
                &mut fresh,
                &mut closed,
                0,
                Some(now + Duration::from_secs(1)),
                &waker,
            ),
            CapacityAdmissionKind::Closed
        );
    }

    unsafe fn count_clone(data: *const ()) -> RawWaker {
        // SAFETY: the test keeps the referenced atomic alive until every
        // waker using this static vtable has been dropped.
        let clones = unsafe { &*data.cast::<AtomicUsize>() };
        clones.fetch_add(1, Ordering::AcqRel);
        RawWaker::new(data, &COUNT_CLONE_VTABLE)
    }

    static COUNT_CLONE_VTABLE: RawWakerVTable =
        RawWakerVTable::new(count_clone, noop_wake, noop_wake_by_ref, noop_drop);

    #[test]
    fn test_capacity_granted_cancellation_hands_permit_to_fifo_head() {
        let mut capacity = CapacityWaiters::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let first_waker = log_waker(0, &log);
        let second_waker = log_waker(1, &log);
        let mut first = None;
        let mut second = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut first, 0, &first_waker),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut second, 0, &second_waker),
            CapacityAdmissionKind::Queued
        );

        reconcile_capacity(&mut capacity, 1);
        cancel_capacity(&mut capacity, first.unwrap(), 1);
        assert_eq!(*log.lock(), vec![0, 1]);
        assert_eq!(capacity.reserved(), 1);
        assert_eq!(capacity.queued(), 0);
        assert_eq!(capacity.registered(), 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut second, 1, &second_waker),
            CapacityAdmissionKind::Granted
        );
    }

    #[test]
    fn test_capacity_queued_head_middle_tail_cancellation_preserves_links() {
        let mut capacity = CapacityWaiters::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut registrations = [None, None, None, None, None];
        let wakers: Vec<_> = (0..registrations.len())
            .map(|id| log_waker(id, &log))
            .collect();
        for (registration, waker) in registrations.iter_mut().zip(&wakers) {
            assert_eq!(
                poll_capacity(&mut capacity, registration, 0, waker),
                CapacityAdmissionKind::Queued
            );
        }

        cancel_capacity(&mut capacity, registrations[0].unwrap(), 0);
        cancel_capacity(&mut capacity, registrations[2].unwrap(), 0);
        cancel_capacity(&mut capacity, registrations[4].unwrap(), 0);
        assert_eq!(capacity.queued(), 2);
        reconcile_capacity(&mut capacity, 2);
        assert_eq!(*log.lock(), vec![1, 3]);
        assert_eq!(capacity.reserved(), 2);
    }

    #[test]
    fn test_capacity_stale_generation_cannot_cancel_reused_node() {
        let mut capacity = CapacityWaiters::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        let old_waker = log_waker(0, &log);
        let new_waker = log_waker(1, &log);
        let mut old = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut old, 0, &old_waker),
            CapacityAdmissionKind::Queued
        );
        let stale = old.unwrap();
        cancel_capacity(&mut capacity, stale, 0);

        let mut new = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut new, 0, &new_waker),
            CapacityAdmissionKind::Queued
        );
        let current = new.unwrap();
        assert_eq!(stale.index, current.index);
        assert_ne!(stale.generation, current.generation);
        cancel_capacity(&mut capacity, stale, 0);
        assert_eq!(capacity.registered(), 1);
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(*log.lock(), vec![1]);
        assert_eq!(capacity.reserved(), 1);

        // The same stale ID also cannot revoke the reused node after grant.
        cancel_capacity(&mut capacity, stale, 1);
        assert_eq!(capacity.reserved(), 1);
        assert_eq!(capacity.registered(), 1);
    }

    #[test]
    fn test_capacity_queued_repoll_replaces_waker_without_reordering() {
        let mut capacity = CapacityWaiters::new();
        let old = Arc::new(CountWaker(AtomicUsize::new(0)));
        let new = Arc::new(CountWaker(AtomicUsize::new(0)));
        let old_waker = arc_waker(Arc::clone(&old));
        let new_waker = arc_waker(Arc::clone(&new));
        let mut registration = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut registration, 0, &old_waker),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut registration, 0, &new_waker),
            CapacityAdmissionKind::Queued
        );
        assert_eq!(capacity.queued(), 1);
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(old.0.load(Ordering::Acquire), 0);
        assert_eq!(new.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_capacity_queued_repoll_with_same_waker_retains_registration() {
        let mut capacity = CapacityWaiters::new();
        let clone_count = AtomicUsize::new(0);
        // SAFETY: clone_count outlives the waker and the capacity arena. The
        // vtable treats its pointer as an AtomicUsize and never owns it.
        let waker = unsafe {
            Waker::from_raw(RawWaker::new(
                std::ptr::from_ref(&clone_count).cast(),
                &COUNT_CLONE_VTABLE,
            ))
        };
        let mut registration = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut registration, 0, &waker),
            CapacityAdmissionKind::Queued
        );
        let clones = clone_count.load(Ordering::Acquire);

        assert_eq!(
            poll_capacity(&mut capacity, &mut registration, 0, &waker),
            CapacityAdmissionKind::Queued
        );
        // Polling clones before entering the affine Ops borrow. The arena
        // recognizes the equivalent waker and defers that clone's drop rather
        // than replacing the stored registration.
        assert_eq!(clone_count.load(Ordering::Acquire), clones + 1);
        assert_eq!(capacity.queued(), 1);

        cancel_capacity(
            &mut capacity,
            registration.expect("capacity registration missing"),
            0,
        );
    }

    #[test]
    fn test_capacity_close_preserves_terminal_ownership() {
        let mut capacity = CapacityWaiters::new();
        let counts: Vec<_> = (0..3)
            .map(|_| Arc::new(CountWaker(AtomicUsize::new(0))))
            .collect();
        let wakers: Vec<_> = counts.iter().cloned().map(arc_waker).collect();
        let mut registrations = [None, None, None];
        for (registration, waker) in registrations.iter_mut().zip(&wakers) {
            assert_eq!(
                poll_capacity(&mut capacity, registration, 0, waker),
                CapacityAdmissionKind::Queued
            );
        }
        let mut grant_actions = Vec::new();
        capacity.reconcile(2, &mut grant_actions);
        wake_batch(grant_actions);
        assert_eq!(capacity.reserved(), 2);
        assert_eq!(capacity.queued(), 1);

        let closed = capacity.close();
        assert_eq!(closed.len(), 1);
        assert!(closed[0].will_wake(&wakers[2]));
        assert_eq!(capacity.registered(), 3);
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.queued(), 0);
        assert_eq!(capacity.arena_len(), 3);
        for waker in closed {
            waker.wake();
        }
        assert!(
            counts
                .iter()
                .all(|count| count.0.load(Ordering::Acquire) == 1)
        );

        // Owner or mailbox cancellation recycles each closure tombstone once.
        for id in registrations.into_iter().flatten() {
            cancel_capacity(&mut capacity, id, 2);
        }
        assert_eq!(capacity.registered(), 0);
    }

    #[test]
    fn test_capacity_wake_count_is_linear_in_waiter_count() {
        const WAITERS: usize = 128;
        let mut capacity = CapacityWaiters::new();
        let count = Arc::new(CountWaker(AtomicUsize::new(0)));
        let waker = arc_waker(Arc::clone(&count));
        let mut registrations = vec![None; WAITERS];
        for registration in &mut registrations {
            assert_eq!(
                poll_capacity(&mut capacity, registration, 0, &waker),
                CapacityAdmissionKind::Queued
            );
        }

        for registration in &mut registrations {
            reconcile_capacity(&mut capacity, 1);
            assert_eq!(
                poll_capacity(&mut capacity, registration, 1, &waker),
                CapacityAdmissionKind::Granted
            );
        }
        assert_eq!(count.0.load(Ordering::Acquire), WAITERS);
        assert_eq!(capacity.registered(), 0);
        assert_eq!(capacity.arena_len(), WAITERS);
    }

    unsafe fn panic_clone(_: *const ()) -> RawWaker {
        panic!("waker clone panic");
    }

    unsafe fn noop_wake(_: *const ()) {}

    unsafe fn noop_wake_by_ref(_: *const ()) {}

    unsafe fn noop_drop(_: *const ()) {}

    static PANIC_CLONE_VTABLE: RawWakerVTable =
        RawWakerVTable::new(panic_clone, noop_wake, noop_wake_by_ref, noop_drop);

    fn panic_clone_waker() -> Waker {
        // SAFETY: the vtable never dereferences the null data pointer. Clone
        // panics deliberately, and wake and drop are no-ops.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &PANIC_CLONE_VTABLE)) }
    }

    /// RawWaker state that orphans one waiter from its drop callback.
    struct ReentrantOrphan {
        handle: Handle,
        waiter: Cell<Option<WaiterId>>,
    }

    unsafe fn clone_reentrant_orphan(data: *const ()) -> RawWaker {
        RawWaker::new(data, &REENTRANT_ORPHAN_VTABLE)
    }

    unsafe fn wake_reentrant_orphan(data: *const ()) {
        // SAFETY: every waker built by `reentrant_orphan_waker` points to a
        // ReentrantOrphan that outlives all of its raw waker clones.
        unsafe { drop_reentrant_orphan(data) };
    }

    unsafe fn wake_by_ref_reentrant_orphan(_: *const ()) {}

    unsafe fn drop_reentrant_orphan(data: *const ()) {
        // SAFETY: every waker built by `reentrant_orphan_waker` points to a
        // ReentrantOrphan that outlives all of its raw waker clones.
        let state = unsafe { &*data.cast::<ReentrantOrphan>() };
        if let Some(waiter_id) = state.waiter.take() {
            orphan_waiter(&state.handle, waiter_id);
        }
    }

    static REENTRANT_ORPHAN_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_reentrant_orphan,
        wake_reentrant_orphan,
        wake_by_ref_reentrant_orphan,
        drop_reentrant_orphan,
    );

    fn reentrant_orphan_waker(state: &ReentrantOrphan) -> Waker {
        // SAFETY: the test keeps `state` alive until the original waker and
        // every clone stored in driver state have been dropped.
        unsafe {
            Waker::from_raw(RawWaker::new(
                std::ptr::from_ref(state).cast(),
                &REENTRANT_ORPHAN_VTABLE,
            ))
        }
    }

    #[test]
    fn test_op_waker_reentrant_drop_runs_after_ops_borrow() {
        let handle = Handle::new(2, RingWaker::new().unwrap());
        let target = handle.with(|ops| {
            ops.waiters
                .insert(recv_request(), futures::task::noop_waker())
        });
        let state = ReentrantOrphan {
            handle: handle.clone(),
            waiter: Cell::new(Some(target)),
        };
        let reentrant = reentrant_orphan_waker(&state);
        let mut reentrant_cx = Context::from_waker(&reentrant);
        let mut op = Op::new(&handle, recv_request());
        assert!(Pin::new(&mut op).poll(&mut reentrant_cx).is_pending());

        let noop = futures::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut op).poll(&mut noop_cx)
        }));
        assert!(matches!(result, Ok(Poll::Pending)));
        assert!(state.waiter.get().is_none());
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(target),
                StageOutcome::Complete { freed: true, .. }
            ));
        });

        let op_id = match op.state {
            OpState::Waiting(id) => id,
            _ => panic!("op did not retain its waiter"),
        };
        drop(op);
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(op_id),
                StageOutcome::Complete { freed: true, .. }
            ));
            assert!(ops.waiters.is_empty());
        });
    }

    #[test]
    fn test_ticket_waker_reentrant_drop_runs_after_ops_borrow() {
        let handle = Handle::new(2, RingWaker::new().unwrap());
        let target = handle.with(|ops| {
            ops.waiters
                .insert(recv_request(), futures::task::noop_waker())
        });
        let state = ReentrantOrphan {
            handle: handle.clone(),
            waiter: Cell::new(Some(target)),
        };
        let reentrant = reentrant_orphan_waker(&state);
        let (completion_id, ticket_waiter) = handle.with(|ops| {
            let mut incoming = Some(reentrant.clone());
            let (completions, waiters) = (&mut ops.completions, &mut ops.waiters);
            completions.insert_pending_deferred(&mut incoming, |completion_id| {
                waiters.insert_ticket(recv_request(), completion_id)
            })
        });

        let noop = futures::task::noop_waker();
        let mut cx = Context::from_waker(&noop);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_ticket_completion(&handle, completion_id, &mut cx)
        }));
        assert!(matches!(result, Ok(Poll::Pending)));
        assert!(state.waiter.get().is_none());
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(target),
                StageOutcome::Complete { freed: true, .. }
            ));
        });

        drop(Ticket {
            handle: handle.clone(),
            state: TicketState::Waiting(completion_id),
        });
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(ticket_waiter),
                StageOutcome::Complete { freed: true, .. }
            ));
            assert!(ops.waiters.is_empty());
            assert!(ops.completions.is_empty());
        });
    }

    #[test]
    fn test_pending_op_clone_panic_preserves_observer() {
        let handle = Handle::new(1, RingWaker::new().unwrap());
        let noop = futures::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        let mut op = Op::new(&handle, recv_request());
        assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());

        let panicking = panic_clone_waker();
        let mut panic_cx = Context::from_waker(&panicking);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut op).poll(&mut panic_cx)
        }));
        assert!(result.is_err());
        assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());

        let waiter_id = match op.state {
            OpState::Waiting(id) => id,
            _ => panic!("op lost its waiter after clone panic"),
        };
        drop(op);
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(waiter_id),
                StageOutcome::Complete { freed: true, .. }
            ));
        });
    }

    #[test]
    fn test_pending_ticket_clone_panic_preserves_observer() {
        let handle = Handle::new(1, RingWaker::new().unwrap());
        let noop = futures::task::noop_waker();
        let (completion_id, waiter_id) = handle.with(|ops| {
            let mut incoming = Some(noop.clone());
            let (completions, waiters) = (&mut ops.completions, &mut ops.waiters);
            completions.insert_pending_deferred(&mut incoming, |completion_id| {
                waiters.insert_ticket(recv_request(), completion_id)
            })
        });

        let panicking = panic_clone_waker();
        let mut panic_cx = Context::from_waker(&panicking);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_ticket_completion(&handle, completion_id, &mut panic_cx)
        }));
        assert!(result.is_err());
        let mut noop_cx = Context::from_waker(&noop);
        assert!(poll_ticket_completion(&handle, completion_id, &mut noop_cx).is_pending());

        drop(Ticket {
            handle: handle.clone(),
            state: TicketState::Waiting(completion_id),
        });
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(waiter_id),
                StageOutcome::Complete { freed: true, .. }
            ));
            assert!(ops.completions.is_empty());
        });
    }

    #[test]
    fn test_granted_admission_clone_panic_preserves_reservation_for_retry() {
        let handle = Handle::new(1, RingWaker::new().unwrap());
        let blocker = handle.with(|ops| {
            ops.waiters
                .insert(recv_request(), futures::task::noop_waker())
        });
        let mut op = Op::new(&handle, recv_request());
        let noop = futures::task::noop_waker();
        let mut noop_cx = Context::from_waker(&noop);
        assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());
        handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 0);
        });

        let actions = handle.with(|ops| {
            assert!(matches!(
                ops.waiters.mark_orphaned(blocker).0,
                DropOutcome::Cancel {
                    needs_sqe: false,
                    ..
                }
            ));
            assert!(matches!(
                ops.waiters.stage(blocker),
                StageOutcome::Complete { freed: true, .. }
            ));
            let mut actions = Vec::new();
            ops.capacity.reconcile(ops.waiters.free_len(), &mut actions);
            actions
        });
        wake_batch(actions);
        handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        let panicking = panic_clone_waker();
        let mut panic_cx = Context::from_waker(&panicking);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Pin::new(&mut op).poll(&mut panic_cx);
        }));
        assert!(result.is_err());
        handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 0);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 0);
            assert_eq!(ops.capacity.reserved(), 1);
        });

        // The same Op can consume its original grant on a later valid poll.
        assert!(Pin::new(&mut op).poll(&mut noop_cx).is_pending());
        let waiter_id = match op.state {
            OpState::Waiting(id) => id,
            _ => panic!("retried op did not publish waiter ownership"),
        };
        handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.capacity.registered(), 0);
            assert_eq!(ops.capacity.reserved(), 0);
        });
        drop(op);
        handle.with(|ops| {
            assert!(matches!(
                ops.waiters.stage(waiter_id),
                StageOutcome::Complete { freed: true, .. }
            ));
            assert_eq!(ops.waiters.len(), 0);
        });
    }

    #[test]
    fn test_pending_orphan_with_queued_successor_keeps_actions_inline() {
        let handle = Handle::new(1, RingWaker::new().unwrap());
        let blocker = handle.with(|ops| {
            ops.waiters
                .insert(recv_request(), futures::task::noop_waker())
        });
        let mut successor = Op::new(&handle, recv_request());
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut successor).poll(&mut cx).is_pending());

        let actions = handle.with(|ops| {
            assert_eq!(ops.capacity.queued(), 1);
            let mut actions = CapacityActions::new();
            wind_down_orphan(ops, blocker, &mut actions);

            assert_eq!(actions.inline_len, 1);
            assert!(actions.overflow.is_empty());
            assert_eq!(actions.overflow.capacity(), 0);
            assert_eq!(ops.capacity.queued(), 1);
            assert_eq!(ops.capacity.reserved(), 0);
            assert!(ops.pending_cancels.is_empty());
            assert!(ops.released_deadlines.is_empty());
            actions
        });
        wake_batch(actions);
        drop(successor);
    }

    #[test]
    fn test_recv_rejects_offset_past_end_before_admission() {
        let handle = Handle::new(1, RingWaker::new().unwrap());
        let (left, _right) = UnixStream::pair().unwrap();
        let mut recv = Box::pin(handle.recv(
            Arc::new(left.into()),
            IoBufMut::with_capacity(1),
            1,
            0,
            false,
            Instant::now(),
        ));
        let noop = futures::task::noop_waker();
        let mut cx = Context::from_waker(&noop);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = recv.as_mut().poll(&mut cx);
        }));
        assert!(result.is_err());
        handle.with(|ops| {
            assert!(ops.waiters.is_empty());
            assert!(ops.backlog.is_empty());
            assert_eq!(ops.capacity.registered(), 0);
        });
    }

    #[test]
    fn test_queued_ticket_admission_fails_after_close() {
        let handle = Handle::new(1, RingWaker::new().unwrap());
        let (blocker_left, _blocker_right) = UnixStream::pair().unwrap();
        let mut blocker = Box::pin(handle.recv(
            Arc::new(blocker_left.into()),
            IoBufMut::with_capacity(1),
            0,
            1,
            false,
            Instant::now() + Duration::from_secs(3600),
        ));
        let (left, _right) = UnixStream::pair().unwrap();
        let file = Arc::new(File::from(OwnedFd::from(left)));
        let mut admission = Box::pin(handle.start_sync(file));
        let noop = futures::task::noop_waker();
        let mut cx = Context::from_waker(&noop);
        assert!(blocker.as_mut().poll(&mut cx).is_pending());
        assert!(admission.as_mut().poll(&mut cx).is_pending());
        handle.with(|ops| {
            assert_eq!(ops.waiters.len(), 1);
            assert_eq!(ops.backlog.len(), 1);
            assert_eq!(ops.capacity.registered(), 1);
            assert_eq!(ops.capacity.queued(), 1);
        });

        for waker in handle.close() {
            waker.wake();
        }
        let Poll::Ready(mut ticket) = admission.as_mut().poll(&mut cx) else {
            panic!("closed ticket admission remained pending");
        };
        assert!(matches!(
            Pin::new(&mut ticket).poll(&mut cx),
            Poll::Ready(Err(Error::Closed))
        ));
        handle.with(|ops| {
            assert_eq!(ops.capacity.registered(), 0);
            assert_eq!(ops.capacity.reserved(), 0);
        });
    }

    unsafe fn clone_panicking_drop(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &PANICKING_DROP_VTABLE)
    }

    unsafe fn panic_on_drop(_: *const ()) {
        panic!("waker drop panic");
    }

    static PANICKING_DROP_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_panicking_drop,
        noop_wake,
        noop_wake_by_ref,
        panic_on_drop,
    );

    fn panicking_drop_waker() -> Waker {
        // SAFETY: the vtable never dereferences the null data pointer. Drop
        // panics deliberately, while clone and wake preserve RawWaker rules.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &PANICKING_DROP_VTABLE)) }
    }

    #[test]
    fn test_queued_drop_panic_does_not_block_next_fifo_wake() {
        let mut capacity = CapacityWaiters::new();
        let first_waker = panicking_drop_waker();
        let second = Arc::new(FlagWaker(AtomicBool::new(false)));
        let second_waker = arc_waker(Arc::clone(&second));
        let mut first_registration = None;
        let mut second_registration = None;
        let mut actions = Vec::new();
        let mut first_incoming = Some(first_waker.clone());
        assert_eq!(
            capacity
                .poll(
                    &mut first_registration,
                    0,
                    None,
                    &mut first_incoming,
                    &mut actions,
                )
                .kind(),
            CapacityAdmissionKind::Queued
        );
        let mut second_incoming = Some(second_waker.clone());
        assert_eq!(
            capacity
                .poll(
                    &mut second_registration,
                    0,
                    None,
                    &mut second_incoming,
                    &mut actions,
                )
                .kind(),
            CapacityAdmissionKind::Queued
        );
        std::mem::forget(first_waker);
        capacity.cancel(first_registration.unwrap(), 1, &mut actions);
        capacity.reconcile(1, &mut actions);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wake_batch(actions);
        }));
        assert!(result.is_err());
        assert!(second.0.load(Ordering::Acquire));
        assert_eq!(capacity.registered(), 1);
        assert_eq!(capacity.queued(), 0);
        assert_eq!(capacity.reserved(), 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut second_registration, 1, &second_waker),
            CapacityAdmissionKind::Granted
        );
    }

    struct PanicPayload;

    impl Drop for PanicPayload {
        fn drop(&mut self) {
            panic!("panic payload dropped");
        }
    }

    unsafe fn clone_payload_panicking_drop(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &PAYLOAD_PANICKING_DROP_VTABLE)
    }

    unsafe fn panic_payload_on_drop(_: *const ()) {
        std::panic::panic_any(PanicPayload);
    }

    static PAYLOAD_PANICKING_DROP_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_payload_panicking_drop,
        noop_wake,
        noop_wake_by_ref,
        panic_payload_on_drop,
    );

    fn payload_panicking_drop_waker() -> Waker {
        // SAFETY: the vtable never dereferences the null data pointer. Drop
        // panics deliberately, while clone and wake preserve RawWaker rules.
        unsafe {
            Waker::from_raw(RawWaker::new(
                std::ptr::null(),
                &PAYLOAD_PANICKING_DROP_VTABLE,
            ))
        }
    }

    struct PayloadPanicWaker;

    impl ArcWake for PayloadPanicWaker {
        fn wake_by_ref(_: &Arc<Self>) {
            std::panic::panic_any(PanicPayload);
        }
    }

    #[test]
    fn test_wake_batch_forgets_secondary_panics_and_runs_remaining_actions() {
        let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        let actions = [
            WakerAction::Wake(arc_waker(Arc::new(PayloadPanicWaker))),
            WakerAction::Wake(arc_waker(Arc::new(PayloadPanicWaker))),
            WakerAction::Wake(arc_waker(Arc::clone(&flag))),
        ];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wake_batch(actions);
        }));
        let payload = result.expect_err("wake batch should resume first panic");
        std::mem::forget(payload);
        assert!(flag.0.load(Ordering::Acquire));
    }

    #[test]
    fn test_wake_batch_forgets_secondary_drop_panic_and_runs_remaining_actions() {
        let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        let actions = [
            WakerAction::Drop(payload_panicking_drop_waker()),
            WakerAction::Drop(payload_panicking_drop_waker()),
            WakerAction::Wake(arc_waker(Arc::clone(&flag))),
        ];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wake_batch(actions);
        }));
        let payload = result.expect_err("wake batch should resume first panic");
        std::mem::forget(payload);
        assert!(flag.0.load(Ordering::Acquire));
    }

}
