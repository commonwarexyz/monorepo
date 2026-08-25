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

use super::{
    Tick,
    request::{
        AcceptRequest, Cache, ConnectRequest, IOVEC_BATCH_SIZE, Output, RawSocketAddr,
        ReadAtRequest, RecvRequest, Request, SendRequest, SyncRequest, WriteAtRequest,
        WriteAtState,
    },
    waiter::{
        CompletionDropOutcome, CompletionId, DropOutcome, TicketCompletions, WaiterId, Waiters,
    },
    waker::Waker as RingWaker,
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
        Self::pinned(thread::current().id(), cell)
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
            thread::current().id() == self.owner,
            "io_uring runtime operations must run on the runtime thread"
        );
        f(&self.cell)
    }

    /// Access the contents if the calling thread is the owner.
    ///
    /// Returns `None` off-thread. Used on drop paths, which must not panic.
    fn try_with<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        (thread::current().id() == self.owner).then(|| f(&self.cell))
    }
}

/// The in-flight op table shared between futures and the event loop.
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
    /// Wheel ticks released by dropped tickets, awaiting removal by the loop
    /// (the timeout wheel is loop-owned, so drop paths cannot touch it).
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
/// The driver uses its reusable action vector. Future poll and drop paths use
/// a fixed batch because one state transition can drop at most one stored
/// waker and transfer at most one permit.
pub(super) trait CapacityActionSink {
    fn reserve(&mut self, additional: usize);
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

/// Allocation-free waker batch for one capacity transition.
pub(super) struct CapacityActions {
    actions: [Option<WakerAction>; 2],
    len: usize,
}

impl CapacityActions {
    pub(super) const fn new() -> Self {
        Self {
            actions: [None, None],
            len: 0,
        }
    }
}

impl CapacityActionSink for CapacityActions {
    fn reserve(&mut self, additional: usize) {
        assert!(
            self.len + additional <= self.actions.len(),
            "capacity action batch overflow"
        );
    }

    fn push(&mut self, action: WakerAction) {
        self.reserve(1);
        self.actions[self.len] = Some(action);
        self.len += 1;
    }
}

impl IntoIterator for CapacityActions {
    type Item = WakerAction;
    type IntoIter = std::iter::Flatten<std::array::IntoIter<Option<WakerAction>, 2>>;

    fn into_iter(self) -> Self::IntoIter {
        self.actions.into_iter().flatten()
    }
}

/// Run every detached waker action, then resume the first panic if any action
/// panicked.
///
/// Capacity state changes are committed before their wakers leave [Ops]. A
/// panic from an earlier callback must therefore not strand later callbacks
/// whose queued or granted state already changed. Stored wakers can also run
/// user RawWaker code on drop, so their destruction follows the same ordering
/// and unwind isolation.
pub(super) fn wake_batch(actions: impl IntoIterator<Item = WakerAction>) {
    let mut first_panic = None;
    for action in actions {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || match action {
            WakerAction::Drop(waker) => drop(waker),
            WakerAction::Wake(waker) => waker.wake(),
        }));
        if let Err(payload) = result {
            if first_panic.is_none() {
                first_panic = Some(payload);
            } else {
                // Dropping an adversarial secondary payload could panic and
                // prevent the remaining actions from running.
                std::mem::forget(payload);
            }
        }
    }
    if let Some(payload) = first_panic {
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
    nodes: Vec<CapacityNode>,
    head: Option<usize>,
    tail: Option<usize>,
    free: Option<usize>,
    /// Number of live [CapacityState::Granted] nodes.
    reserved: usize,
    /// Reusable clone buffer for transactional FIFO grant publication.
    scratch_wakes: Vec<Waker>,
}

/// Generation-validated registration in [CapacityWaiters].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CapacityId {
    index: usize,
    generation: u64,
}

struct CapacityNode {
    generation: u64,
    state: CapacityState,
}

enum CapacityState {
    Free {
        next: Option<usize>,
    },
    Queued {
        prev: Option<usize>,
        next: Option<usize>,
        waker: Waker,
    },
    Granted {
        waker: Waker,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapacityAdmission {
    Direct,
    Granted,
    Queued,
}

impl CapacityWaiters {
    const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            head: None,
            tail: None,
            free: None,
            reserved: 0,
            scratch_wakes: Vec::new(),
        }
    }

    /// Return whether this poll can consume capacity without queue mutation.
    fn can_admit(&self, registration: Option<CapacityId>, free_len: usize) -> bool {
        assert!(
            self.reserved <= free_len,
            "capacity reservations exceed waiter free slots"
        );
        match registration.and_then(|id| self.live_state(id)) {
            Some(CapacityState::Granted { .. }) => true,
            Some(CapacityState::Queued { .. }) => false,
            Some(CapacityState::Free { .. }) => unreachable!("free capacity node reported live"),
            None => self.head.is_none() && self.reserved < free_len,
        }
    }

    /// Poll one admission against the authoritative free-slot count.
    fn poll(
        &mut self,
        registration: &mut Option<CapacityId>,
        free_len: usize,
        waker: &Waker,
        actions: &mut impl CapacityActionSink,
    ) -> CapacityAdmission {
        assert!(
            self.reserved <= free_len,
            "capacity reservations exceed waiter free slots"
        );

        if let Some(id) = *registration {
            let Some(state) = self.live_state(id) else {
                *registration = None;
                return self.poll(registration, free_len, waker, actions);
            };
            match state {
                CapacityState::Queued { waker: stored, .. } => {
                    if !stored.will_wake(waker) {
                        actions.reserve(1);
                        let replacement = waker.clone();
                        let CapacityState::Queued { waker: stored, .. } =
                            &mut self.nodes[id.index].state
                        else {
                            unreachable!("capacity state changed during waker clone")
                        };
                        let old = std::mem::replace(stored, replacement);
                        actions.push(WakerAction::Drop(old));
                    }
                    return CapacityAdmission::Queued;
                }
                CapacityState::Granted { .. } => {
                    actions.reserve(1);
                    let CapacityState::Granted { waker } = self
                        .take_live(id)
                        .expect("validated capacity grant disappeared")
                    else {
                        unreachable!("validated capacity grant changed state")
                    };
                    self.reserved = self
                        .reserved
                        .checked_sub(1)
                        .expect("capacity reservation underflow");
                    *registration = None;
                    actions.push(WakerAction::Drop(waker));
                    return CapacityAdmission::Granted;
                }
                CapacityState::Free { .. } => unreachable!("free capacity node reported live"),
            }
        }

        if self.head.is_none() && self.reserved < free_len {
            return CapacityAdmission::Direct;
        }

        let id = self.push_back(waker.clone());
        *registration = Some(id);
        CapacityAdmission::Queued
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
        let was_granted = matches!(state, CapacityState::Granted { .. });
        actions.reserve(1 + usize::from(was_granted && self.head.is_some()));
        match self
            .take_live(id)
            .expect("validated capacity registration disappeared")
        {
            CapacityState::Queued {
                prev, next, waker, ..
            } => {
                self.unlink(prev, next);
                actions.push(WakerAction::Drop(waker));
            }
            CapacityState::Granted { waker } => {
                self.reserved = self
                    .reserved
                    .checked_sub(1)
                    .expect("capacity reservation underflow");
                actions.push(WakerAction::Drop(waker));
                self.reconcile(free_len, actions);
            }
            CapacityState::Free { .. } => unreachable!("free capacity node reported live"),
        }
    }

    /// Reserve authoritative free slots for FIFO heads and collect their wakes.
    pub(super) fn reconcile(&mut self, free_len: usize, actions: &mut impl CapacityActionSink) {
        assert!(
            self.reserved <= free_len,
            "capacity reservations exceed waiter free slots"
        );
        let mut grants = 0;
        let mut cursor = self.head;
        while grants < free_len - self.reserved {
            let Some(index) = cursor else {
                break;
            };
            let CapacityState::Queued { next, .. } = &self.nodes[index].state else {
                panic!("capacity FIFO contains a non-queued node")
            };
            cursor = *next;
            grants += 1;
        }
        actions.reserve(grants);
        assert!(self.scratch_wakes.is_empty());
        self.scratch_wakes.reserve(grants);
        let mut cursor = self.head;
        for _ in 0..grants {
            let index = cursor.expect("counted capacity FIFO head disappeared");
            let CapacityState::Queued { next, waker, .. } = &self.nodes[index].state else {
                panic!("capacity FIFO contains a non-queued node")
            };
            let clone = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.clone()));
            match clone {
                Ok(waker) => self.scratch_wakes.push(waker),
                Err(payload) => {
                    while let Some(waker) = self.scratch_wakes.pop() {
                        if let Err(drop_payload) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker)))
                        {
                            // Preserve the clone panic without allowing an
                            // adversarial cleanup payload to replace it.
                            std::mem::forget(drop_payload);
                        }
                    }
                    std::panic::resume_unwind(payload);
                }
            }
            cursor = *next;
        }

        // Pop cloned wakes in FIFO order only after the complete prefix is
        // clone-safe. No externally controlled callback can interrupt commit.
        self.scratch_wakes.reverse();
        for _ in 0..grants {
            let Some(index) = self.head else {
                unreachable!("counted capacity FIFO head disappeared")
            };
            let wake = self
                .scratch_wakes
                .pop()
                .expect("capacity wake clone disappeared before commit");
            let CapacityState::Queued { next, waker, .. } = std::mem::replace(
                &mut self.nodes[index].state,
                CapacityState::Free { next: None },
            ) else {
                unreachable!("capacity FIFO head changed state")
            };
            self.head = next;
            match next {
                Some(next) => {
                    let CapacityState::Queued { prev, .. } = &mut self.nodes[next].state else {
                        panic!("capacity FIFO successor is not queued")
                    };
                    *prev = None;
                }
                None => self.tail = None,
            }
            self.nodes[index].state = CapacityState::Granted { waker };
            self.reserved += 1;
            actions.push(WakerAction::Wake(wake));
        }
        assert!(self.scratch_wakes.is_empty());
    }

    /// Invalidate every live registration and return all stored wakers.
    fn close(&mut self) -> Vec<Waker> {
        let mut wakers = Vec::with_capacity(self.registered());
        self.head = None;
        self.tail = None;
        self.free = None;
        self.reserved = 0;
        for index in (0..self.nodes.len()).rev() {
            let next = self.free;
            let state =
                std::mem::replace(&mut self.nodes[index].state, CapacityState::Free { next });
            match state {
                CapacityState::Free { .. } => {}
                CapacityState::Queued { waker, .. } | CapacityState::Granted { waker } => {
                    self.nodes[index].generation = self.nodes[index]
                        .generation
                        .checked_add(1)
                        .expect("capacity generation overflowed");
                    wakers.push(waker);
                }
            }
            self.free = Some(index);
        }
        wakers
    }

    fn live_state(&self, id: CapacityId) -> Option<&CapacityState> {
        let node = self.nodes.get(id.index)?;
        if node.generation != id.generation || matches!(node.state, CapacityState::Free { .. }) {
            return None;
        }
        Some(&node.state)
    }

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

    fn push_back(&mut self, waker: Waker) -> CapacityId {
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
            waker,
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
        id
    }

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
    pub(super) fn registered(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| !matches!(node.state, CapacityState::Free { .. }))
            .count()
    }

    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| matches!(node.state, CapacityState::Queued { .. }))
            .count()
    }

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
/// foreign-thread drop cannot clear its slot (drop must not panic), so the
/// entry is discarded by the next drain, consistent with the documented
/// policy that op futures must not move to other threads.
struct Registration<'a> {
    handle: &'a Handle,
    slot: Option<CapacityId>,
}

impl<'a> Registration<'a> {
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
            self.handle.orphans.push(Orphan::Capacity(slot));
            return;
        };
        wake_batch(actions);
    }
}

/// Thread-affine handle to the driver's op state, cloned by the network and
/// storage front-ends and held by the event loop itself.
///
/// All access goes through the affinity-checked [Affine] cell.
#[derive(Clone)]
pub(crate) struct Handle {
    ops: Arc<Affine<RefCell<Ops>>>,
    /// Cross-thread wind-down mailbox for foreign-thread drops.
    pub(super) orphans: Arc<OrphanMailbox>,
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
pub(super) struct OrphanMailbox {
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
    pub(super) fn take(&self) -> Vec<Orphan> {
        if !self.pending.load(Ordering::Acquire) {
            return Vec::new();
        }
        self.pending.store(false, Ordering::Relaxed);
        std::mem::take(&mut *self.orphans.lock())
    }
}

impl Handle {
    /// Create the op state for a driver whose slab tracks at most `capacity`
    /// requests, waking the loop through `waker` for foreign-thread drops.
    ///
    /// The calling thread becomes the owning (runtime) thread.
    pub(crate) fn new(capacity: usize, waker: RingWaker) -> Self {
        Self {
            ops: Arc::new(Affine::new(RefCell::new(Ops {
                waiters: Waiters::new(capacity),
                completions: TicketCompletions::new(),
                backlog: VecDeque::with_capacity(capacity),
                pending_cancels: VecDeque::with_capacity(capacity),
                released_deadlines: Vec::new(),
                capacity: CapacityWaiters::new(),
                closed: false,
            }))),
            orphans: Arc::new(OrphanMailbox {
                pending: AtomicBool::new(false),
                orphans: Mutex::new(Vec::new()),
                waker,
            }),
        }
    }

    /// Access the shared op state from the runtime thread.
    ///
    /// The borrow is a leaf section: callers must not invoke wakers or user
    /// code inside `f`.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> R {
        self.ops.with(|cell| f(&mut cell.borrow_mut()))
    }

    /// Assert that the caller is running on the driver's owning thread.
    ///
    /// Front-ends call this before validation, no-op, or synchronous paths
    /// that would otherwise bypass the affinity check in op admission.
    pub(crate) fn assert_owner(&self) {
        self.ops.with(|_| ());
    }

    /// Access the shared op state if called on the runtime thread.
    fn try_with<R>(&self, f: impl FnOnce(&mut Ops) -> R) -> Option<R> {
        self.ops.try_with(|cell| f(&mut cell.borrow_mut()))
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

/// Poll one admission attempt for `request`.
///
/// On a closed driver the request resolves immediately to its kind-specific
/// failure (returned as `Err`). On a full slab the task parks on the capacity
/// wait list through `registration` (one slot per attempt, refreshed on
/// re-polls and released here once the attempt resolves). Otherwise the
/// request is admitted: the slab owns it (along with the task waker) and its
/// id is pushed onto the backlog for the loop.
fn poll_admission(
    handle: &Handle,
    request: &mut Option<Request>,
    registration: &mut Registration<'_>,
    cx: &mut Context<'_>,
) -> (Poll<Result<WaiterId, Output>>, CapacityActions) {
    let mut actions = CapacityActions::new();
    let outcome = handle.with(|ops| {
        if ops.closed {
            if let Some(slot) = registration.slot.take() {
                ops.capacity
                    .cancel(slot, ops.waiters.free_len(), &mut actions);
            }
            return Admission::Closed;
        }
        // Clone the observer before a grant is consumed. An adversarial
        // RawWaker clone panic must leave the CapacityId and reservation live
        // so the same admission can retry without losing its FIFO permit.
        let observer_waker = ops
            .capacity
            .can_admit(registration.slot, ops.waiters.free_len())
            .then(|| cx.waker().clone());
        match ops.capacity.poll(
            &mut registration.slot,
            ops.waiters.free_len(),
            cx.waker(),
            &mut actions,
        ) {
            CapacityAdmission::Queued => return Admission::Full,
            CapacityAdmission::Direct | CapacityAdmission::Granted => {}
        }
        let request = request.take().expect("request consumed before admission");
        let id = ops.waiters.insert(
            request,
            observer_waker.expect("admission missing precloned observer waker"),
        );
        assert!(ops.capacity.reserved <= ops.waiters.free_len());
        ops.backlog.push_back(id);
        Admission::Admitted(id)
    });
    let poll = match outcome {
        Admission::Admitted(id) => Poll::Ready(Ok(id)),
        Admission::Full => Poll::Pending,
        Admission::Closed => {
            let request = request.take().expect("request lost on closed driver");
            Poll::Ready(Err(request.fail()))
        }
    };
    (poll, actions)
}

/// Poll one detached-ticket admission attempt.
///
/// Closed and full handling matches ordinary op admission. Once capacity is
/// available, the completion and waiter are bound under one op-state borrow,
/// and the ticket receives only the independently generational completion ID.
fn poll_ticket_admission(
    handle: &Handle,
    request: &mut Option<Request>,
    registration: &mut Registration<'_>,
    cx: &mut Context<'_>,
) -> (Poll<Result<CompletionId, Output>>, CapacityActions) {
    let mut actions = CapacityActions::new();
    let outcome = handle.with(|ops| {
        if ops.closed {
            if let Some(slot) = registration.slot.take() {
                ops.capacity
                    .cancel(slot, ops.waiters.free_len(), &mut actions);
            }
            return TicketAdmission::Closed;
        }
        let observer_waker = ops
            .capacity
            .can_admit(registration.slot, ops.waiters.free_len())
            .then(|| cx.waker().clone());
        match ops.capacity.poll(
            &mut registration.slot,
            ops.waiters.free_len(),
            cx.waker(),
            &mut actions,
        ) {
            CapacityAdmission::Queued => return TicketAdmission::Full,
            CapacityAdmission::Direct | CapacityAdmission::Granted => {}
        }
        let request = request.take().expect("request consumed before admission");
        let (completions, waiters) = (&mut ops.completions, &mut ops.waiters);
        let (completion_id, waiter_id) = completions.insert_pending(
            observer_waker.expect("ticket admission missing precloned observer waker"),
            |completion_id| waiters.insert_ticket(request, completion_id),
        );
        assert!(ops.capacity.reserved <= ops.waiters.free_len());
        ops.backlog.push_back(waiter_id);
        TicketAdmission::Admitted(completion_id)
    });
    let poll = match outcome {
        TicketAdmission::Admitted(id) => Poll::Ready(Ok(id)),
        TicketAdmission::Full => Poll::Pending,
        TicketAdmission::Closed => {
            let request = request.take().expect("request lost on closed driver");
            Poll::Ready(Err(request.fail()))
        }
    };
    (poll, actions)
}

/// Poll for the parked result of an admitted request.
///
/// Taking a result frees a slot, so capacity waiters are released (outside
/// the state borrow). A pending poll refreshes the stored task waker.
fn poll_op_completion(
    handle: &Handle,
    id: WaiterId,
    cx: &mut Context<'_>,
) -> Poll<(Output, CapacityActions)> {
    let (output, actions) = handle.with(|ops| {
        let mut actions = CapacityActions::new();
        let output = ops.waiters.poll_take(id, cx.waker());
        if output.is_some() {
            ops.capacity.reconcile(ops.waiters.free_len(), &mut actions);
        }
        (output, actions)
    });
    output.map_or(Poll::Pending, |output| Poll::Ready((output, actions)))
}

/// Poll a detached ticket's completion entry.
fn poll_ticket_completion(handle: &Handle, id: CompletionId, cx: &mut Context<'_>) -> Poll<Output> {
    handle
        .with(|ops| ops.completions.poll_take(id, cx.waker()))
        .map_or(Poll::Pending, Poll::Ready)
}

/// Apply the orphan wind-down for `id` on the op table.
pub(super) fn wind_down_orphan(ops: &mut Ops, id: WaiterId, actions: &mut impl CapacityActionSink) {
    match ops.waiters.mark_orphaned(id) {
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

/// Apply detached-ticket wind-down after generation-validating its completion
/// ID. Pending entries yield their active waiter for request-kind-specific
/// cancellation or detach. Ready entries drop only their output because the
/// waiter was already recycled at terminal completion.
pub(super) fn wind_down_ticket(
    ops: &mut Ops,
    id: CompletionId,
    actions: &mut impl CapacityActionSink,
) -> Option<Waker> {
    match ops.completions.mark_orphaned(id) {
        CompletionDropOutcome::Pending { waiter_id, waker } => {
            wind_down_orphan(ops, waiter_id, actions);
            waker
        }
        CompletionDropOutcome::Ready => None,
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
        handle.orphans.push(Orphan::Waiter(id));
        return;
    };
    wake_batch(actions);
}

/// Wind down a detached ticket using only its completion ID.
fn orphan_ticket(handle: &Handle, id: CompletionId) {
    let Some((waker, actions)) = handle.try_with(|ops| {
        let mut actions = CapacityActions::new();
        let waker = wind_down_ticket(ops, id, &mut actions);
        (waker, actions)
    }) else {
        handle.orphans.push(Orphan::Completion(id));
        return;
    };
    let actions = waker.map(WakerAction::Drop).into_iter().chain(actions);
    wake_batch(actions);
}

/// Outcome of one admission attempt.
enum Admission {
    Admitted(WaiterId),
    Full,
    Closed,
}

/// Outcome of one detached-ticket admission attempt.
enum TicketAdmission {
    Admitted(CompletionId),
    Full,
    Closed,
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
    /// Admitted: the slot owns the request, the future holds the reservation.
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
                let (admission, actions) =
                    poll_admission(this.handle, request, &mut this.registration, cx);
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
                let (output, actions) = std::task::ready!(poll_op_completion(this.handle, *id, cx));
                this.state = OpState::Done;
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
    /// Admit `request`, parking on slab capacity, and return the reservation.
    async fn admit(handle: &Handle, request: Request) -> Self {
        let mut request = Some(request);
        // The guard lives outside the poll closure so cancelling this future
        // while parked releases its capacity slot.
        let mut registration = Registration::new(handle);
        let (state, actions) = std::future::poll_fn(|cx| {
            let (admission, actions) =
                poll_ticket_admission(handle, &mut request, &mut registration, cx);
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
    ) -> CapacityAdmission {
        let mut actions = Vec::new();
        let admission = capacity.poll(registration, free_len, waker, &mut actions);
        wake_batch(actions);
        admission
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
            CapacityAdmission::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[1], 0, &wakers[1]),
            CapacityAdmission::Queued
        );
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(capacity.reserved(), 1);

        // One free slot is already reserved for the oldest waiter. A new poll
        // joins behind the remaining queued waiter instead of taking it.
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
            CapacityAdmission::Queued
        );
        assert_eq!(capacity.queued(), 2);
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[0], 1, &wakers[0]),
            CapacityAdmission::Granted
        );

        // Simulate insertion consuming the free waiter, then two terminal
        // removals. The older queued registration is always granted first.
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[1], 1, &wakers[1]),
            CapacityAdmission::Granted
        );
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut registrations[2], 1, &wakers[2]),
            CapacityAdmission::Granted
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
                CapacityAdmission::Queued
            );
        }

        reconcile_capacity(&mut capacity, 3);
        assert_eq!(*log.lock(), vec![0, 1, 2]);
        assert_eq!(capacity.reserved(), 3);
        assert_eq!(capacity.queued(), 2);
        assert_eq!(capacity.registered(), 5);
    }

    unsafe fn panic_on_second_clone(data: *const ()) -> RawWaker {
        // SAFETY: the test keeps the referenced atomic alive until every
        // waker using this static vtable has been dropped.
        let clones = unsafe { &*data.cast::<AtomicUsize>() };
        if clones.fetch_add(1, Ordering::AcqRel) == 1 {
            panic!("second waker clone panic");
        }
        RawWaker::new(data, &PANIC_ON_SECOND_CLONE_VTABLE)
    }

    static PANIC_ON_SECOND_CLONE_VTABLE: RawWakerVTable = RawWakerVTable::new(
        panic_on_second_clone,
        noop_wake,
        noop_wake_by_ref,
        noop_drop,
    );

    #[test]
    fn test_capacity_reconcile_second_clone_panic_is_transactional() {
        let clone_count = AtomicUsize::new(0);
        // SAFETY: clone_count outlives the original waker, the capacity arena,
        // and every clone. The vtable treats its pointer as an AtomicUsize.
        let second_waker = unsafe {
            Waker::from_raw(RawWaker::new(
                std::ptr::from_ref(&clone_count).cast(),
                &PANIC_ON_SECOND_CLONE_VTABLE,
            ))
        };
        let mut capacity = CapacityWaiters::new();
        let first_waker = futures::task::noop_waker();
        let mut first = None;
        let mut second = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut first, 0, &first_waker),
            CapacityAdmission::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut second, 0, &second_waker),
            CapacityAdmission::Queued
        );

        let mut actions = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            capacity.reconcile(2, &mut actions);
        }));
        assert!(result.is_err());
        assert!(actions.is_empty());
        assert!(matches!(
            capacity.live_state(first.unwrap()),
            Some(CapacityState::Queued { .. })
        ));
        assert!(matches!(
            capacity.live_state(second.unwrap()),
            Some(CapacityState::Queued { .. })
        ));
        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.queued(), 2);

        capacity.reconcile(2, &mut actions);
        wake_batch(actions);
        assert_eq!(capacity.reserved(), 2);
        assert_eq!(capacity.queued(), 0);
    }

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
            CapacityAdmission::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut second, 0, &second_waker),
            CapacityAdmission::Queued
        );

        reconcile_capacity(&mut capacity, 1);
        cancel_capacity(&mut capacity, first.unwrap(), 1);
        assert_eq!(*log.lock(), vec![0, 1]);
        assert_eq!(capacity.reserved(), 1);
        assert_eq!(capacity.queued(), 0);
        assert_eq!(capacity.registered(), 1);
        assert_eq!(
            poll_capacity(&mut capacity, &mut second, 1, &second_waker),
            CapacityAdmission::Granted
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
                CapacityAdmission::Queued
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
            CapacityAdmission::Queued
        );
        let stale = old.unwrap();
        cancel_capacity(&mut capacity, stale, 0);

        let mut new = None;
        assert_eq!(
            poll_capacity(&mut capacity, &mut new, 0, &new_waker),
            CapacityAdmission::Queued
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
            CapacityAdmission::Queued
        );
        assert_eq!(
            poll_capacity(&mut capacity, &mut registration, 0, &new_waker),
            CapacityAdmission::Queued
        );
        assert_eq!(capacity.queued(), 1);
        reconcile_capacity(&mut capacity, 1);
        assert_eq!(old.0.load(Ordering::Acquire), 0);
        assert_eq!(new.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_capacity_close_invalidates_mixed_queued_and_granted_nodes() {
        let mut capacity = CapacityWaiters::new();
        let counts: Vec<_> = (0..3)
            .map(|_| Arc::new(CountWaker(AtomicUsize::new(0))))
            .collect();
        let wakers: Vec<_> = counts.iter().cloned().map(arc_waker).collect();
        let mut registrations = [None, None, None];
        for (registration, waker) in registrations.iter_mut().zip(&wakers) {
            assert_eq!(
                poll_capacity(&mut capacity, registration, 0, waker),
                CapacityAdmission::Queued
            );
        }
        let mut grant_actions = Vec::new();
        capacity.reconcile(2, &mut grant_actions);
        drop(grant_actions);
        assert_eq!(capacity.reserved(), 2);
        assert_eq!(capacity.queued(), 1);

        let closed = capacity.close();
        assert_eq!(closed.len(), 3);
        assert_eq!(capacity.registered(), 0);
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

        // IDs invalidated by close remain harmless on later owner or mailbox
        // cancellation paths.
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
                CapacityAdmission::Queued
            );
        }

        for registration in &mut registrations {
            reconcile_capacity(&mut capacity, 1);
            assert_eq!(
                poll_capacity(&mut capacity, registration, 1, &waker),
                CapacityAdmission::Granted
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
                ops.waiters.mark_orphaned(blocker),
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
    fn test_granted_drop_panic_still_hands_permit_to_fifo_head() {
        let mut capacity = CapacityWaiters::new();
        let first_waker = panicking_drop_waker();
        let second = Arc::new(FlagWaker(AtomicBool::new(false)));
        let second_waker = arc_waker(Arc::clone(&second));
        let mut first_registration = None;
        let mut second_registration = None;
        let mut actions = Vec::new();
        assert_eq!(
            capacity.poll(&mut first_registration, 0, &first_waker, &mut actions),
            CapacityAdmission::Queued
        );
        assert_eq!(
            capacity.poll(&mut second_registration, 0, &second_waker, &mut actions),
            CapacityAdmission::Queued
        );
        std::mem::forget(first_waker);
        capacity.reconcile(1, &mut actions);
        wake_batch(actions.drain(..));

        capacity.cancel(first_registration.unwrap(), 1, &mut actions);
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
            CapacityAdmission::Granted
        );
    }

    struct PanicPayload;

    impl Drop for PanicPayload {
        fn drop(&mut self) {
            panic!("panic payload dropped");
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
        assert!(result.is_err());
        assert!(flag.0.load(Ordering::Acquire));
        std::mem::forget(result.expect_err("wake batch should resume first panic"));
    }
}
