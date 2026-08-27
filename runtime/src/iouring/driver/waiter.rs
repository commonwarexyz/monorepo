//! Waiter identity and lifecycle state for tracked io_uring requests.
//!
//! A waiter combines [`WaiterState`], [`Lifecycle`], and [`Observer`] as
//! independent axes of one tracked operation:
//!
//! ```text
//! admit
//!   |
//!   v
//! Lifecycle::Pending(Request) + WaiterState::Active + Observer::Op/Ticket
//!   +-- pre-stage cancellation or expired deadline -> local terminal --+
//!   +-- otherwise                                                       |
//!       | future deadline: record timeout tick                          |
//!       | stage SQE: in_flight = true                                   |
//!       v                                                               |
//! waiter owns Request, kernel may reference it
//!   | operation CQE delivery: in_flight = false
//!   +-- nonterminal --> backlog --> stage again
//!   +-- terminal -----------------------------------------------+
//!   |                                                           |
//!   +-- timeout or shutdown --> WaiterState::CancelRequested    |
//!   +-- observer drop --------> Observer::Orphaned               |
//!       +-- stop --> WaiterState::CancelRequested                |
//!       +-- detach: remain active until terminal ----------------+
//! WaiterState::CancelRequested                                  |
//!   +-- idle: complete locally ----------------------------------+
//!   +-- in flight: cancel SQE, then operation CQE                |
//!       +-- terminal ---------------------------------------------+
//!       +-- nonterminal --> backlog --> complete locally --------+
//!                                                                   v
//! terminal retention follows Observer
//!   +-- Observer::Op --> Lifecycle::Ready(RequestOutput) --> op poll --> recycle waiter
//!   +-- Observer::Ticket --> Lifecycle::TicketComplete
//!                             | publish
//!                             v
//!                       TicketArena: Ready(RequestOutput)
//!                             |                    |
//!                             v                    v
//!                       recycle waiter      ticket poll, recycle entry
//!   +-- Observer::Orphaned --> drop output --> recycle waiter
//! ```
//!
//! [`Lifecycle::Pending`] owns every request resource throughout this flow.
//! While `in_flight` is true, the kernel may still reference those resources.
//! A cancel CQE only acknowledges cancellation. Kernel referenceability ends
//! with operation CQE delivery, or with local completion when no SQE is in
//! flight. Terminal output is retained only by its selected owner: in the
//! waiter for an op, or in [`TicketArena`] for a ticket.

use super::{
    Tick, UserData,
    request::{RequestOutput, Request},
};
use crate::Error;
use io_uring::squeue::Entry as SqueueEntry;
use std::task::Waker;
use tracing::warn;

/// Install an already-cloned observer waker and detach the superseded clone.
///
/// The caller owns `incoming` outside the driver-state borrow. This helper
/// only moves wakers, so RawWaker clone and drop callbacks remain outside the
/// waiter and ticket arenas.
fn replace_waker(stored: &mut Option<Waker>, incoming: &mut Option<Waker>) -> Waker {
    let next = incoming.as_ref().expect("poll missing incoming waker");
    let current = stored.as_ref().expect("pending observer missing waker");
    if current.will_wake(next) {
        return incoming.take().expect("poll waker consumed twice");
    }
    stored
        .replace(incoming.take().expect("poll waker consumed twice"))
        .expect("pending observer missing waker")
}

/// Callback-free result of refreshing a pending waker or taking ready output.
pub(super) enum DeferredPoll {
    /// The terminal output was removed from its arena.
    Ready(RequestOutput),
    /// One waker must be dropped outside the driver-state borrow.
    Pending(Waker),
}

/// Callback-free first phase of polling a waiter or ticket entry.
pub enum PollState {
    /// The terminal output was removed from its arena.
    Ready(RequestOutput),
    /// The stored waker already wakes the current task.
    PendingCurrent,
    /// A different waker must be cloned outside the driver-state borrow.
    PendingNeedsWaker,
}

/// Stable waiter identity packed into SQE/CQE `user_data`.
///
/// Layout:
/// - bits 0..31: slot index
/// - bits 32..62: generation (31 bits, wraps at 2^31)
/// - bit 63: reserved as cancel-tag in completion `user_data`
///
/// The generation counter detects stale CQEs that arrive after a slot has been
/// recycled. In normal (non-cancel) operation this cannot happen: a slot is
/// only freed after its CQE is processed, so the slot cannot be reused before
/// the CQE is consumed. With cancellation, the original op CQE can arrive
/// before the cancel CQE. When this happens the slot is freed and may be
/// recycled while the cancel CQE is still pending. The generation check
/// discards that stale cancel CQE. The 31-bit generation wraps after ~2 billion
/// reuses of the same slot, but cancellation is run synchronously on the kernel
/// side (a CQE is always generated by the time the cancel request has been
/// submitted, see
/// <https://man7.org/linux/man-pages/man3/io_uring_prep_cancel.3.html#NOTES>),
/// so a wrap-around collision is not feasible in practice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaiterId(UserData);

impl WaiterId {
    /// Number of low-order bits reserved for the waiter slot index.
    const INDEX_BITS: u32 = 32;
    /// Number of bits reserved for the generation field.
    const GENERATION_BITS: u32 = 31;
    /// Bitmask that extracts the waiter slot index from packed user data.
    const INDEX_MASK: UserData = (1u64 << Self::INDEX_BITS) - 1;
    /// Bitmask that extracts the 31-bit generation from packed user data.
    const GENERATION_MASK: UserData = (1u64 << Self::GENERATION_BITS) - 1;
    /// High-bit tag used to mark cancellation CQE user data.
    const CANCEL_TAG: UserData = 1u64 << 63;

    /// Build a waiter id from slot index and generation components.
    pub const fn new(index: u32, generation: u32) -> Self {
        let index = index as UserData;
        let generation = generation as UserData;
        Self((generation & Self::GENERATION_MASK) << Self::INDEX_BITS | index)
    }

    /// Return the slot index component of this waiter id.
    pub const fn index(self) -> u32 {
        (self.0 & Self::INDEX_MASK) as u32
    }

    /// Return the generation component of this waiter id.
    const fn generation(self) -> u32 {
        ((self.0 >> Self::INDEX_BITS) & Self::GENERATION_MASK) as u32
    }

    /// Return the waiter id for the same slot with incremented generation.
    const fn next_generation(self) -> Self {
        let generation = ((self.generation() as UserData).wrapping_add(1)) & Self::GENERATION_MASK;
        Self::new(self.index(), generation as u32)
    }

    /// Encode this waiter id as `user_data` for the operation SQE/CQE.
    ///
    /// This value contains only the packed waiter identity (slot + generation),
    /// with the cancel tag bit clear.
    pub const fn user_data(self) -> UserData {
        self.0
    }

    /// Encode this waiter id as `user_data` for the cancel SQE/CQE.
    ///
    /// This preserves the waiter identity and sets the high cancel-tag bit so
    /// completion handling can distinguish cancel CQEs from operation CQEs.
    pub const fn cancel_user_data(self) -> UserData {
        self.0 | Self::CANCEL_TAG
    }

    /// Decode `user_data` into waiter identity and cancel-tag state.
    ///
    /// The returned waiter id always has the cancel-tag bit stripped. The
    /// boolean reports whether that bit was set in the input value.
    const fn from_user_data(user_data: UserData) -> (Self, bool) {
        let is_cancel = (user_data & Self::CANCEL_TAG) != 0;
        (Self(user_data & !Self::CANCEL_TAG), is_cancel)
    }
}

/// Identity for a detached ticket entry.
///
/// A ticket keeps this ID after admission and never observes the waiter ID
/// that carries its request through the kernel. Ticket IDs remain
/// userspace-only and are recycled only when their sole ticket polls or drops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TicketId(u32);

impl TicketId {
    /// Build a ticket ID from its slot index.
    const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Return the ticket-arena slot index.
    const fn index(self) -> u32 {
        self.0
    }
}

/// Why a request's cancellation was requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelReason {
    /// The request's deadline elapsed: the observer sees [Error::Timeout].
    ///
    /// Also used for drop-orphaned requests, whose parked result is never
    /// observed (the reason is immaterial there).
    Deadline,
    /// The runtime is shutting down: the observer sees [Error::Closed],
    /// distinguishing shutdown from an ordinary operation timeout or a
    /// genuine kernel failure.
    Shutdown,
}

impl CancelReason {
    /// The error a cancelled request surfaces to its observer.
    pub const fn into_error(self) -> Error {
        match self {
            Self::Deadline => Error::Timeout,
            Self::Shutdown => Error::Closed,
        }
    }
}

/// Lifecycle state of a tracked request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaiterState {
    /// Request is still tracked and has not transitioned to cancellation.
    Active {
        /// Absolute wheel tick by which the request must complete.
        ///
        /// If completion has not been observed by this tick, cancellation is
        /// requested. `None` means this request has no scheduled deadline yet,
        /// either because it carries none or because its first staging has not
        /// converted the deadline to a wheel tick.
        target_tick: Option<Tick>,
    },
    /// Cancellation was requested.
    ///
    /// If the request still has an operation SQE in flight, the loop stages an
    /// async cancel. If the request is only parked in the backlog, the loop
    /// completes it locally with the reason's error when that entry is
    /// revisited.
    CancelRequested {
        /// Why cancellation was requested (selects the observer's error).
        reason: CancelReason,
    },
}

/// Progress state of the logical request stored in a slot.
enum Lifecycle {
    /// The request is still progressing and owns all operation resources.
    Pending(Request),
    /// The terminal result is parked until the owning ordinary op takes it.
    ///
    /// The kernel has fully retired the operation before this state is
    /// entered, so the buffers inside the output are exclusively
    /// userspace-owned again.
    Ready(RequestOutput),
    /// A detached ticket's output has left the waiter and is ready to publish
    /// in its ticket entry.
    ///
    /// This state exists only while the driver holds the op-state borrow that
    /// performs the terminal transition. The waiter is recycled before any
    /// external waker can run.
    TicketComplete,
}

/// Observer that owns the eventual result of a waiter.
enum Observer {
    /// An ordinary op future. Its waker stays with the waiter because its
    /// result is consumed from that same slot.
    Op(Option<Waker>),
    /// A detached ticket. Its waker lives in the separate ticket arena,
    /// and terminal output moves there when the waiter completes.
    Ticket(TicketId),
    /// The observer was dropped. Requests whose orphan policy stops progress
    /// cancel, while storage writes and syncs detach and keep running.
    Orphaned,
}

/// Non-orphaned terminal output after its waiter state is committed.
enum FinishedOutput {
    /// Request output parked in an ordinary op waiter.
    Op { waker: Option<Waker> },
    /// Request output leaving the waiter for a detached ticket entry.
    Ticket {
        ticket_id: TicketId,
        output: RequestOutput,
    },
}

/// State for one tracked logical request.
struct Waiter {
    /// Stable identity of this waiter slot instance.
    id: WaiterId,
    /// Lifecycle state for the logical request stored in this slot.
    state: WaiterState,
    /// Whether the logical request currently has an operation SQE in flight.
    in_flight: bool,
    /// Owner of the eventual output.
    observer: Observer,
    /// Progress state and owned resources.
    lifecycle: Lifecycle,
}

/// Outcome produced when staging the next SQE for a waiter.
pub enum StageOutcome {
    /// The waiter was canceled while parked in the backlog and completed
    /// locally without emitting an SQE. This covers local deadline expiry
    /// (the observer sees timeout) and local shutdown (the observer sees
    /// closed).
    Ready {
        /// Waker to invoke outside any state borrow, when an ordinary op still
        /// observes the parked result.
        waker: Option<Waker>,
    },
    /// The waiter was canceled after its observer was dropped, so its slot was
    /// freed locally without emitting an SQE.
    Freed,
    /// A detached ticket reached a terminal state without emitting an SQE.
    /// Its output must be published before this waiter is recycled.
    Ticket {
        /// Waiter whose request reached the terminal state.
        waiter_id: WaiterId,
        /// Detached ticket entry that receives the output.
        ticket_id: TicketId,
        /// Terminal request output.
        output: RequestOutput,
    },
    /// The waiter is still active and produced an SQE for submission.
    Submit(SqueueEntry),
}

/// Outcome produced when handling an operation CQE for a waiter.
pub enum CqeOutcome {
    /// The CQE belonged to an async cancel SQE and was handled internally.
    Cancel,
    /// The logical request needs another SQE and should be placed back in the
    /// backlog.
    Requeue(WaiterId),
    /// An ordinary op reached a terminal state and parked its result in the
    /// waiter.
    Ready {
        /// Waker to invoke outside any state borrow, if an op is waiting.
        waker: Option<Waker>,
        /// Active deadline tracking to remove from the timeout wheel, when
        /// completion happened before cancellation was requested.
        target_tick: Option<Tick>,
    },
    /// An orphaned request reached a terminal state, so its output was dropped
    /// and its waiter slot freed.
    Freed {
        /// Active deadline tracking to remove from the timeout wheel, when
        /// completion happened before cancellation was requested.
        target_tick: Option<Tick>,
    },
    /// A detached ticket reached a terminal state.
    ///
    /// The driver publishes `output` into `ticket_id`, removes timeout
    /// accounting, and recycles `waiter_id` before invoking any waker.
    Ticket {
        /// Waiter whose kernel-owned request state is terminal.
        waiter_id: WaiterId,
        /// Detached ticket entry that receives the output.
        ticket_id: TicketId,
        /// Terminal request output.
        output: RequestOutput,
        /// Active deadline tracking to remove from the timeout wheel.
        target_tick: Option<Tick>,
    },
}

/// Outcome produced when a waiter's observer is dropped.
pub enum DropOutcome {
    /// The parked result was dropped and the slot freed.
    Freed,
    /// The request was transitioned to cancellation.
    Cancel {
        /// Whether an async-cancel SQE must be staged because an operation
        /// SQE is in flight.
        needs_sqe: bool,
        /// Scheduled deadline tick leaving active timeout tracking, if any.
        target_tick: Option<Tick>,
    },
    /// The request keeps running to completion without an observer (storage
    /// writes and syncs preserve durability semantics on caller drop).
    Detached,
}

/// Waiter transitioned to shutdown cancellation.
pub(super) struct CancelledWaiter {
    /// Waiter whose active request was cancelled.
    pub(super) id: WaiterId,
    /// Scheduled deadline tick leaving active timeout tracking, if any.
    pub(super) target_tick: Option<Tick>,
    /// Whether an async-cancel SQE is needed for an operation in flight.
    pub(super) needs_cancel_sqe: bool,
}

/// Outcome produced when a detached ticket is dropped.
pub enum TicketDropOutcome {
    /// The request is still active in `waiter_id` and must follow its
    /// request-kind-specific orphan path.
    Pending {
        /// Active waiter linked from the removed ticket entry.
        waiter_id: WaiterId,
        /// Stored task waker to drop after waiter wind-down is committed.
        waker: Option<Waker>,
    },
    /// The terminal output was dropped and the ticket slot recycled.
    Ready,
}

/// Lifecycle of a detached ticket entry.
enum TicketEntryState {
    /// The waiter still owns the active request and its kernel resources.
    Pending {
        /// Waiter slot that owns the request until terminal completion.
        waiter_id: WaiterId,
        /// Ticket task waker retained until the output is published or dropped.
        waker: Option<Waker>,
    },
    /// Terminal userspace-owned output, independent from the recycled waiter slot.
    Ready(RequestOutput),
}

/// Arena for detached tickets, separate from waiter storage.
///
/// The arena grows only to its high-water mark. Dropped or consumed entries
/// return to a free list and reuse their existing vector storage.
pub struct TicketArena {
    /// Ticket entries indexed by [`TicketId::index`]. A live entry is
    /// `Pending` while its waiter owns the request, then `Ready` while this
    /// arena owns the terminal output.
    entries: Vec<Option<TicketEntryState>>,
    /// Stack of IDs for recycled ticket slots.
    free: Vec<TicketId>,
    /// Number of entries in the `Ready` state. Pending entries are represented
    /// by their waiter and therefore are not counted here.
    ready: usize,
}

impl TicketArena {
    /// Create an empty ticket arena with no allocated slots.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            ready: 0,
        }
    }

    /// Allocate a pending ticket entry and admit its associated waiter.
    ///
    /// `insert_waiter` receives the ticket ID before the ticket entry
    /// is installed. It must insert a waiter that stores that ID as its reverse
    /// link. The waiter owns the request while the ticket entry owns the
    /// ticket waker until publication or drop.
    ///
    /// A recycled slot keeps its vector allocation.
    pub fn insert_pending_deferred(
        &mut self,
        incoming_waker: &mut Option<Waker>,
        insert_waiter: impl FnOnce(TicketId) -> WaiterId,
    ) -> (TicketId, WaiterId) {
        let id = self.free.last().copied().unwrap_or_else(|| {
            let index = u32::try_from(self.entries.len()).expect("ticket slot index overflow");
            TicketId::new(index)
        });
        let index = id.index() as usize;
        if index == self.entries.len() {
            self.entries.reserve(1);
        } else {
            assert_eq!(
                self.free.last(),
                Some(&id),
                "ticket free list order changed"
            );
            assert!(
                self.entries[index].is_none(),
                "free ticket slot still occupied"
            );
        }
        let waiter_id = insert_waiter(id);
        let entry = TicketEntryState::Pending {
            waiter_id,
            waker: Some(
                incoming_waker
                    .take()
                    .expect("ticket waker consumed twice"),
            ),
        };
        if index == self.entries.len() {
            self.entries.push(Some(entry));
        } else {
            self.free.pop();
            self.entries[index] = Some(entry);
        }
        (id, waiter_id)
    }

    /// Convenience wrapper that transfers an owned waker into a ticket entry.
    #[cfg(test)]
    pub fn insert_pending(
        &mut self,
        waker: Waker,
        insert_waiter: impl FnOnce(TicketId) -> WaiterId,
    ) -> (TicketId, WaiterId) {
        let mut incoming = Some(waker);
        self.insert_pending_deferred(&mut incoming, insert_waiter)
    }

    /// Publish a ticket's terminal output and return its task waker.
    ///
    /// The entry changes from `Pending` to `Ready`, transferring output
    /// ownership from the waiter to this arena. The associated waiter remains
    /// tracked until the caller removes deadline accounting and recycles it
    /// before invoking the returned waker.
    ///
    /// Panics if `ticket_id` is untracked, if the entry is already ready,
    /// or if its linked waiter does not equal `waiter_id`.
    pub fn publish_ready(
        &mut self,
        ticket_id: TicketId,
        waiter_id: WaiterId,
        output: RequestOutput,
    ) -> Option<Waker> {
        let entry = self.entry_mut(ticket_id, "publish_ready");
        let TicketEntryState::Pending {
            waiter_id: pending_waiter,
            ..
        } = &entry
        else {
            panic!("publish_ready called for ready ticket");
        };
        assert_eq!(
            *pending_waiter, waiter_id,
            "publish_ready called with wrong waiter id"
        );
        let TicketEntryState::Pending { waker, .. } =
            std::mem::replace(entry, TicketEntryState::Ready(output))
        else {
            unreachable!("ticket entry verified pending above");
        };
        self.ready += 1;
        waker
    }

    /// Poll without invoking a RawWaker vtable function.
    ///
    /// Ready output is removed immediately. Pending state only compares waker
    /// identity, allowing the caller to avoid a clone when the stored waker is
    /// already current.
    pub fn poll_state(&mut self, ticket_id: TicketId, waker: &Waker) -> PollState {
        let entry = self.entry_mut(ticket_id, "poll_state");
        match entry {
            TicketEntryState::Pending { waker: stored, .. } => {
                let stored = stored.as_ref().expect("pending ticket missing waker");
                if stored.will_wake(waker) {
                    PollState::PendingCurrent
                } else {
                    PollState::PendingNeedsWaker
                }
            }
            TicketEntryState::Ready(_) => {
                let TicketEntryState::Ready(output) = self.take(ticket_id) else {
                    unreachable!("ticket entry verified ready above");
                };
                PollState::Ready(output)
            }
        }
    }

    /// Take a ready output, or refresh the pending ticket waker.
    ///
    /// Taking a ready output recycles its ticket slot. A pending entry
    /// remains linked to its waiter and stores the latest task waker. Pending
    /// returns the one detached waker that must be dropped after releasing the
    /// driver-state borrow.
    ///
    /// Panics if `ticket_id` is untracked.
    pub fn poll_take_deferred(
        &mut self,
        ticket_id: TicketId,
        incoming_waker: &mut Option<Waker>,
    ) -> DeferredPoll {
        let entry = self.entry_mut(ticket_id, "poll_take");
        match entry {
            TicketEntryState::Pending { waker: stored, .. } => {
                DeferredPoll::Pending(replace_waker(stored, incoming_waker))
            }
            TicketEntryState::Ready(_) => {
                let TicketEntryState::Ready(output) = self.take(ticket_id) else {
                    unreachable!("ticket entry verified ready above");
                };
                DeferredPoll::Ready(output)
            }
        }
    }

    /// Test-only convenience wrapper around [Self::poll_take_deferred].
    #[cfg(test)]
    pub fn poll_take(&mut self, ticket_id: TicketId, waker: &Waker) -> Option<RequestOutput> {
        let mut incoming = Some(waker.clone());
        match self.poll_take_deferred(ticket_id, &mut incoming) {
            DeferredPoll::Ready(output) => {
                drop(incoming);
                Some(output)
            }
            DeferredPoll::Pending(detached) => {
                drop(detached);
                None
            }
        }
    }

    /// Remove a ticket entry and recycle its slot.
    ///
    /// A Pending entry returns its stored waker so the caller can first
    /// commit the linked waiter's orphan transition, then drop the waker
    /// outside the owner-state borrow. A Ready entry drops its output and
    /// returns `Ready`.
    ///
    /// Panics if `ticket_id` is untracked.
    pub fn mark_orphaned(&mut self, ticket_id: TicketId) -> TicketDropOutcome {
        let _ = self.entry(ticket_id, "mark_orphaned");
        match self.take(ticket_id) {
            TicketEntryState::Pending { waiter_id, waker } => {
                TicketDropOutcome::Pending { waiter_id, waker }
            }
            TicketEntryState::Ready(_) => TicketDropOutcome::Ready,
        }
    }

    /// Return the waiter linked from a pending ticket entry, or `None` when its
    /// output is already ready.
    ///
    /// Panics if `ticket_id` is untracked.
    pub fn pending_waiter(&self, ticket_id: TicketId) -> Option<WaiterId> {
        match self.entry(ticket_id, "pending_waiter") {
            TicketEntryState::Pending { waiter_id, .. } => Some(*waiter_id),
            TicketEntryState::Ready(_) => None,
        }
    }

    /// Return the number of terminal outputs retained by tickets.
    pub const fn ready(&self) -> usize {
        self.ready
    }

    /// Return the ticket arena's high-water size.
    #[cfg(test)]
    pub const fn arena_len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether every ticket slot is recyclable.
    #[cfg(test)]
    pub const fn is_empty(&self) -> bool {
        self.entries.len() == self.free.len()
    }

    /// Look up a live ticket entry by slot ID.
    ///
    /// `operation` is included in invariant-failure messages. Panics when the
    /// slot is empty or out of bounds.
    fn entry(&self, id: TicketId, operation: &str) -> &TicketEntryState {
        self.entries
            .get(id.index() as usize)
            .and_then(Option::as_ref)
            .unwrap_or_else(|| panic!("{operation} called for untracked ticket"))
    }

    /// Mutably look up a live ticket entry by slot ID.
    ///
    /// `operation` is included in invariant-failure messages. Panics when the
    /// slot is empty or out of bounds.
    fn entry_mut(&mut self, id: TicketId, operation: &str) -> &mut TicketEntryState {
        self.entries
            .get_mut(id.index() as usize)
            .and_then(Option::as_mut)
            .unwrap_or_else(|| panic!("{operation} called for untracked ticket"))
    }

    /// Remove a live entry and recycle its slot ID.
    ///
    /// The caller must validate the slot with [`Self::entry`] or
    /// [`Self::entry_mut`] first. This helper decrements the ready count when
    /// needed and panics if the slot is out of bounds or empty.
    fn take(&mut self, id: TicketId) -> TicketEntryState {
        let entry = self.entries[id.index() as usize]
            .take()
            .expect("tracked ticket missing");
        if matches!(entry, TicketEntryState::Ready(_)) {
            self.ready -= 1;
        }
        self.free.push(id);
        entry
    }
}

/// Tracks logical requests and the state needed to complete them.
pub struct Waiters {
    /// Waiters indexed by slot index.
    ///
    /// Free slots have no waiter (`None`).
    entries: Vec<Option<Waiter>>,
    /// Stack of reusable waiter IDs. Removing a slot advances its generation
    /// before the ID is returned here, rejecting late CQEs for its old owner.
    free: Vec<WaiterId>,
    /// Number of tracked waiters still in [Lifecycle::Pending].
    pending: usize,
}

impl Waiters {
    /// Create an empty waiter set that can track at most `capacity` logical
    /// requests at once.
    pub fn new(capacity: usize) -> Self {
        let mut entries = Vec::with_capacity(capacity);
        entries.resize_with(capacity, || None);

        let mut free = Vec::with_capacity(capacity);
        free.extend((0..capacity).rev().map(|index| {
            let index = u32::try_from(index).expect("slot index overflow");
            WaiterId::new(index, 0)
        }));

        Self {
            entries,
            free,
            pending: 0,
        }
    }

    /// Return the number of currently tracked waiters.
    pub const fn len(&self) -> usize {
        self.entries.len() - self.free.len()
    }

    /// Return whether there are no tracked waiters.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn is_empty(&self) -> bool {
        self.entries.len() == self.free.len()
    }

    /// Return the number of tracked waiters whose request is still
    /// progressing (staged, in flight, or awaiting cancellation).
    ///
    /// Parked ordinary op results are excluded because they hold no kernel
    /// resources. Ticket results leave the waiter entirely, so drain
    /// termination keys on this count rather than [Self::len].
    pub const fn pending(&self) -> usize {
        self.pending
    }

    /// Return whether all waiter slots are currently occupied.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn is_full(&self) -> bool {
        self.free.is_empty()
    }

    /// Return the authoritative number of free waiter slots.
    ///
    /// Capacity reservations reconcile against this value after every waiter
    /// removal so userspace grants cannot drift from the slab.
    pub const fn free_len(&self) -> usize {
        self.free.len()
    }

    /// Insert an ordinary request and return its generation-stamped waiter ID.
    ///
    /// The waiter owns the request and the supplied task waker. Deadline
    /// scheduling happens separately at first staging, and terminal output is
    /// parked in this waiter until the same op future takes it.
    ///
    /// Panics if no free slot is available.
    #[inline]
    #[cfg(test)]
    pub fn insert(&mut self, request: Request, waker: Waker) -> WaiterId {
        let mut incoming = Some(waker);
        self.insert_deferred(request, &mut incoming)
    }

    /// Insert an ordinary request from an outer-owned waker slot.
    ///
    /// Capacity and slot invariants are checked before taking the waker, so an
    /// invariant panic cannot run its RawWaker destructor under the Ops borrow.
    #[inline]
    pub fn insert_deferred(
        &mut self,
        request: Request,
        incoming_waker: &mut Option<Waker>,
    ) -> WaiterId {
        let id = self.prepare_insert();
        let observer = Observer::Op(Some(
            incoming_waker.take().expect("waiter waker consumed twice"),
        ));
        self.insert_prepared(id, request, observer)
    }

    /// Insert a request owned by a detached ticket.
    ///
    /// The waiter stores `ticket_id` as its reverse link. The ticket waker
    /// remains in [`TicketArena`] while pending, and terminal output is
    /// transferred there before this waiter slot is recycled.
    ///
    /// Panics if no free slot is available.
    pub fn insert_ticket(&mut self, request: Request, ticket_id: TicketId) -> WaiterId {
        let id = self.prepare_insert();
        self.insert_prepared(id, request, Observer::Ticket(ticket_id))
    }

    /// Insert a pending request with the observer that will own its output.
    ///
    /// The next generation-stamped free slot starts active, without an SQE in
    /// flight, and with a pending request lifecycle. This shared helper also
    /// updates the tracked and progressing counts used by capacity and drain
    /// accounting.
    ///
    /// Panics if no free slot is available.
    fn prepare_insert(&self) -> WaiterId {
        let id = *self
            .free
            .last()
            .expect("waiters should not exceed configured capacity");
        let index = id.index() as usize;
        assert!(
            self.entries[index].is_none(),
            "free slot should not contain waiter"
        );
        id
    }

    /// Commit a waiter after [Self::prepare_insert] validated its slot.
    fn insert_prepared(&mut self, id: WaiterId, request: Request, observer: Observer) -> WaiterId {
        let popped = self.free.pop().expect("prepared waiter slot disappeared");
        debug_assert_eq!(popped, id);
        let index = id.index() as usize;
        self.entries[index] = Some(Waiter {
            id,
            state: WaiterState::Active { target_tick: None },
            in_flight: false,
            observer,
            lifecycle: Lifecycle::Pending(request),
        });
        self.pending += 1;
        id
    }

    /// Free the slot at `index`, returning its final lifecycle state.
    ///
    /// Panics if `index` is out of bounds or the slot is empty. Callers must
    /// already have validated that the slot still belongs to the expected
    /// waiter.
    fn take(&mut self, index: usize) -> Lifecycle {
        let slot = self.entries[index].take().expect("tracked waiter missing");
        self.free.push(slot.id.next_generation());
        if matches!(slot.lifecycle, Lifecycle::Pending(_)) {
            self.pending -= 1;
        }
        slot.lifecycle
    }

    /// Return the deadline that still needs wheel scheduling for a waiter.
    ///
    /// This is `Some` only for the first staging of a request that carries a
    /// deadline: later stagings observe the recorded tick.
    pub fn deadline_to_schedule(&self, waiter_id: WaiterId) -> Option<std::time::Instant> {
        let slot = self
            .entries
            .get(waiter_id.index() as usize)
            .and_then(Option::as_ref)?;
        if slot.id != waiter_id {
            return None;
        }
        let WaiterState::Active { target_tick: None } = slot.state else {
            return None;
        };
        let Lifecycle::Pending(request) = &slot.lifecycle else {
            return None;
        };
        request.deadline()
    }

    /// Record the scheduled wheel tick for a waiter's deadline.
    ///
    /// Panics if the waiter is not tracked, already scheduled, or already
    /// cancel-requested.
    pub fn set_target_tick(&mut self, waiter_id: WaiterId, tick: Tick) {
        let slot = self
            .entries
            .get_mut(waiter_id.index() as usize)
            .and_then(Option::as_mut)
            .expect("set_target_tick called for untracked waiter");
        assert_eq!(slot.id, waiter_id, "set_target_tick with stale waiter id");
        assert!(
            matches!(slot.state, WaiterState::Active { target_tick: None }),
            "set_target_tick called for scheduled or cancelled waiter"
        );
        slot.state = WaiterState::Active {
            target_tick: Some(tick),
        };
    }

    /// Expire an active waiter and request deadline cancellation.
    ///
    /// Returns `true` when the waiter was successfully transitioned to
    /// cancel-requested. Returns `false` when the waiter id is stale, not
    /// present, already cancel-requested, or already completed.
    pub fn expire(&mut self, waiter_id: WaiterId) -> bool {
        let Some(slot) = self.entries.get_mut(waiter_id.index() as usize) else {
            return false;
        };
        let Some(slot) = slot.as_mut() else {
            return false;
        };
        if slot.id != waiter_id {
            // Slot was reused, this CQE belongs to an older waiter generation.
            return false;
        }
        if !matches!(slot.lifecycle, Lifecycle::Pending(_)) {
            // The parked result is no longer cancellable.
            return false;
        }
        match slot.state {
            WaiterState::Active { .. } => {
                slot.state = WaiterState::CancelRequested {
                    reason: CancelReason::Deadline,
                };
                true
            }
            WaiterState::CancelRequested { .. } => false,
        }
    }

    /// Request shutdown cancellation for every progressing waiter.
    ///
    /// Returns, for each transitioned waiter, its id, its deadline tick (so
    /// the caller can release timeout-wheel accounting), and whether it has an
    /// operation SQE in flight (requiring an async-cancel SQE). Waiters that
    /// are not in flight retire locally when restaged.
    pub fn cancel_for_shutdown(&mut self) -> Vec<CancelledWaiter> {
        let mut cancelled = Vec::new();
        for slot in self.entries.iter_mut().filter_map(Option::as_mut) {
            if !matches!(slot.lifecycle, Lifecycle::Pending(_)) {
                continue;
            }
            let WaiterState::Active { target_tick } = slot.state else {
                continue;
            };
            slot.state = WaiterState::CancelRequested {
                reason: CancelReason::Shutdown,
            };
            cancelled.push(CancelledWaiter {
                id: slot.id,
                target_tick,
                needs_cancel_sqe: slot.in_flight,
            });
        }
        cancelled
    }

    /// Stage the next SQE for a waiter.
    ///
    /// This either returns the next SQE to issue, or resolves the waiter
    /// locally:
    ///
    /// - [`StageOutcome::Submit`] leaves the waiter tracked and yields the next SQE.
    /// - [`StageOutcome::Ready`] completes an observed waiter locally (deadline
    ///   expiry or shutdown) without emitting an SQE.
    /// - [`StageOutcome::Freed`] retires an orphaned waiter locally.
    /// - [`StageOutcome::Ticket`] returns terminal ticket output for publication
    ///   before its waiter is recycled.
    ///
    /// When this returns [`StageOutcome::Submit`], the waiter is marked as having an
    /// operation SQE outstanding immediately, so [`Waiters::is_in_flight`] will return
    /// `true` for that waiter.
    ///
    /// Panics if `waiter_id` does not refer to a currently tracked pending
    /// waiter or if the waiter already has an operation SQE outstanding.
    #[inline]
    pub fn stage(&mut self, waiter_id: WaiterId) -> StageOutcome {
        let index = waiter_id.index() as usize;
        let slot = self
            .entries
            .get_mut(index)
            .and_then(Option::as_mut)
            .expect("stage called for untracked waiter");
        assert_eq!(slot.id, waiter_id, "stage called with stale waiter id");
        let Lifecycle::Pending(request) = &mut slot.lifecycle else {
            panic!("stage called for completed waiter");
        };

        match slot.state {
            WaiterState::CancelRequested { reason } => {
                // Cancellation marked while the request sat in the backlog:
                // an in-flight request is never restaged (its CQE requeues it
                // with `in_flight` already cleared), and freeing an in-flight
                // slot below would release kernel-referenced buffers.
                assert!(
                    !slot.in_flight,
                    "stage called for cancelled waiter with op in flight"
                );
                if matches!(slot.observer, Observer::Orphaned) {
                    // Nobody can take the parked result, so free the slot.
                    let _ = self.take(index);
                    StageOutcome::Freed
                } else {
                    // The output moves the owned buffer out of the request,
                    // so the emptied shell drops in place. The reason selects
                    // what the observer sees: a deadline expiry surfaces as
                    // timeout, a shutdown as closed.
                    let output = request.interrupt(reason.into_error());
                    match self.finish_output_at(waiter_id, output) {
                        FinishedOutput::Op { waker } => StageOutcome::Ready { waker },
                        FinishedOutput::Ticket {
                            ticket_id,
                            output,
                        } => StageOutcome::Ticket {
                            waiter_id,
                            ticket_id,
                            output,
                        },
                    }
                }
            }
            WaiterState::Active { .. } => {
                // An orphaned request whose kind stops on orphaning is moved
                // to `CancelRequested` by `mark_orphaned` before it can ever
                // be staged again, so it must never surface here: retiring it
                // from this arm would silently resurrect stale wind-down
                // logic if the state machine drifts.
                assert!(
                    !matches!(slot.observer, Observer::Orphaned)
                        || !request.orphan_stops_progress(),
                    "orphan-stopping request staged while active"
                );
                assert!(
                    !slot.in_flight,
                    "stage called for waiter with op already in flight"
                );
                slot.in_flight = true;
                StageOutcome::Submit(request.build_sqe(waiter_id))
            }
        }
    }

    /// Process one CQE for a waiter.
    ///
    /// Cancel CQEs are handled internally. Operation CQEs drive the request
    /// state machine and return a high-level loop action. Terminal results are
    /// parked for an ordinary op, transferred toward a ticket completion
    /// entry, or dropped when the observer is already gone.
    ///
    /// Panics if a non-cancel CQE does not refer to a currently tracked waiter,
    /// if it uses a stale waiter generation, or if the waiter has no operation
    /// SQE outstanding.
    #[inline]
    pub fn on_completion(&mut self, user_data: UserData, result: i32) -> CqeOutcome {
        let (waiter_id, is_cancel) = WaiterId::from_user_data(user_data);
        let index = waiter_id.index() as usize;

        let Some(slot) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            assert!(is_cancel, "operation CQE for untracked waiter");
            return CqeOutcome::Cancel;
        };
        if slot.id != waiter_id {
            assert!(is_cancel, "operation CQE for stale waiter generation");
            return CqeOutcome::Cancel;
        }

        if is_cancel {
            if result == 0 {
                // Cancellation successful.
            } else if result == -libc::EALREADY {
                // Cancellation is no longer possible at this stage. The target
                // operation CQE should follow shortly.
            } else if result == -libc::ENOENT {
                // Not found can mean the target already completed (common race) or
                // stale/invalid user_data.
            } else if result == -libc::EINVAL {
                panic!("async cancel SQE rejected by kernel: EINVAL");
            } else {
                warn!(result, "unexpected async cancel CQE result");
            }

            // Cancel CQEs acknowledge cancel requests but do not complete waiters.
            return CqeOutcome::Cancel;
        }

        let Lifecycle::Pending(request) = &mut slot.lifecycle else {
            panic!("operation CQE for completed waiter");
        };

        // The operation CQE retires the currently in-flight SQE, regardless of
        // whether the request completes or is requeued for another one.
        assert!(slot.in_flight);
        slot.in_flight = false;

        let state = slot.state;
        let orphaned = matches!(slot.observer, Observer::Orphaned);
        let orphan_stops = request.orphan_stops_progress();
        let output = request.on_cqe(state, result);
        if output.is_none() && !(orphaned && orphan_stops) {
            return CqeOutcome::Requeue(waiter_id);
        }

        // Either the request reached a terminal state, or the current SQE
        // made non-terminal progress for a ticket that is already gone. In
        // both cases, stop issuing SQEs for this waiter now.
        let target_tick = match state {
            WaiterState::Active { target_tick } => target_tick,
            WaiterState::CancelRequested { .. } => None,
        };

        if orphaned {
            // Free the slot (dropping the request shell in place) and drop
            // the output: closing any owned resources (e.g. an accepted fd)
            // without an observer.
            let _ = self.take(index);
            drop(output);
            CqeOutcome::Freed { target_tick }
        } else {
            let output = output.expect("non-orphaned completion is terminal");
            match self.finish_output_at(waiter_id, output) {
                FinishedOutput::Op { waker } => CqeOutcome::Ready { waker, target_tick },
                FinishedOutput::Ticket {
                    ticket_id,
                    output,
                } => CqeOutcome::Ticket {
                    waiter_id,
                    ticket_id,
                    output,
                    target_tick,
                },
            }
        }
    }

    /// Commit a non-orphaned terminal output to its owner.
    fn finish_output_at(&mut self, waiter_id: WaiterId, output: RequestOutput) -> FinishedOutput {
        let index = waiter_id.index() as usize;
        let slot = self.entries[index]
            .as_mut()
            .expect("tracked waiter missing");
        assert_eq!(slot.id, waiter_id, "finish_output_at with stale waiter id");
        match &mut slot.observer {
            Observer::Op(waker) => {
                slot.lifecycle = Lifecycle::Ready(output);
                self.pending -= 1;
                FinishedOutput::Op {
                    waker: waker.take(),
                }
            }
            Observer::Ticket(ticket_id) => {
                let ticket_id = *ticket_id;
                slot.lifecycle = Lifecycle::TicketComplete;
                self.pending -= 1;
                FinishedOutput::Ticket {
                    ticket_id,
                    output,
                }
            }
            Observer::Orphaned => panic!("orphaned output reached observer publication"),
        }
    }

    /// Take the parked result for an ordinary op, freeing the slot, or refresh
    /// the stored waker when the request is still progressing.
    ///
    /// Panics if the waiter is not tracked or the id is stale: only the owning
    /// ordinary op frees a non-orphaned slot, so a miss is an invariant
    /// violation.
    #[inline]
    pub fn poll_take_deferred(
        &mut self,
        waiter_id: WaiterId,
        incoming_waker: &mut Option<Waker>,
    ) -> DeferredPoll {
        let index = waiter_id.index() as usize;
        let slot = self
            .entries
            .get_mut(index)
            .and_then(Option::as_mut)
            .expect("poll_take called for untracked waiter");
        assert_eq!(slot.id, waiter_id, "poll_take called with stale waiter id");
        assert!(
            matches!(slot.observer, Observer::Op(_)),
            "poll_take called for ticket waiter"
        );

        match &mut slot.lifecycle {
            Lifecycle::Ready(_) => {
                let Lifecycle::Ready(output) = self.take(index) else {
                    unreachable!("lifecycle verified ready above");
                };
                DeferredPoll::Ready(output)
            }
            Lifecycle::Pending(_) => {
                let Observer::Op(stored) = &mut slot.observer else {
                    unreachable!("observer verified op above");
                };
                DeferredPoll::Pending(replace_waker(stored, incoming_waker))
            }
            Lifecycle::TicketComplete => panic!("op waiter reached ticket terminal state"),
        }
    }

    /// Poll without invoking a RawWaker vtable function.
    ///
    /// Ready output is removed immediately. Pending state only compares waker
    /// identity, allowing the caller to clone after releasing Ops when an
    /// update is actually required.
    #[inline]
    pub fn poll_state(&mut self, waiter_id: WaiterId, waker: &Waker) -> PollState {
        let index = waiter_id.index() as usize;
        let slot = self
            .entries
            .get_mut(index)
            .and_then(Option::as_mut)
            .expect("poll_state called for untracked waiter");
        assert_eq!(slot.id, waiter_id, "poll_state called with stale waiter id");
        assert!(
            matches!(slot.observer, Observer::Op(_)),
            "poll_state called for ticket waiter"
        );

        match &slot.lifecycle {
            Lifecycle::Ready(_) => {
                let Lifecycle::Ready(output) = self.take(index) else {
                    unreachable!("lifecycle verified ready above");
                };
                PollState::Ready(output)
            }
            Lifecycle::Pending(_) => {
                let Observer::Op(stored) = &slot.observer else {
                    unreachable!("observer verified op above");
                };
                let stored = stored.as_ref().expect("pending op waiter missing waker");
                if stored.will_wake(waker) {
                    PollState::PendingCurrent
                } else {
                    PollState::PendingNeedsWaker
                }
            }
            Lifecycle::TicketComplete => panic!("op waiter reached ticket terminal state"),
        }
    }

    /// Test-only convenience wrapper around [Self::poll_take_deferred].
    #[cfg(test)]
    pub fn poll_take(&mut self, waiter_id: WaiterId, waker: &Waker) -> Option<RequestOutput> {
        let mut incoming = Some(waker.clone());
        match self.poll_take_deferred(waiter_id, &mut incoming) {
            DeferredPoll::Ready(output) => {
                drop(incoming);
                Some(output)
            }
            DeferredPoll::Pending(detached) => {
                drop(detached);
                None
            }
        }
    }

    /// Recycle a terminal ticket waiter after its output is published.
    pub fn finish_ticket(&mut self, waiter_id: WaiterId, ticket_id: TicketId) {
        let index = waiter_id.index() as usize;
        let slot = self
            .entries
            .get(index)
            .and_then(Option::as_ref)
            .expect("finish_ticket called for untracked waiter");
        assert_eq!(
            slot.id, waiter_id,
            "finish_ticket called with stale waiter id"
        );
        assert!(
            matches!(slot.lifecycle, Lifecycle::TicketComplete),
            "finish_ticket called before terminal ticket output"
        );
        let Observer::Ticket(stored_completion) = slot.observer else {
            panic!("finish_ticket called for non-ticket waiter");
        };
        assert_eq!(
            stored_completion, ticket_id,
            "finish_ticket called with wrong ticket id"
        );
        let _ = self.take(index);
    }

    /// Classify how a waiter's slot will wind down when its observer is dropped.
    ///
    /// Panics if the waiter is not tracked, the id is stale, or its observer
    /// was already dropped.
    pub fn classify_orphan(&self, waiter_id: WaiterId) -> DropOutcome {
        let slot = self
            .entries
            .get(waiter_id.index() as usize)
            .and_then(Option::as_ref)
            .expect("classify_orphan called for untracked waiter");
        assert_eq!(
            slot.id, waiter_id,
            "classify_orphan called with stale waiter id"
        );
        assert!(
            !matches!(slot.observer, Observer::Orphaned),
            "classify_orphan called for orphaned waiter"
        );

        let Lifecycle::Pending(request) = &slot.lifecycle else {
            assert!(
                matches!(slot.lifecycle, Lifecycle::Ready(_)),
                "ticket-terminal waiter escaped driver commit"
            );
            return DropOutcome::Freed;
        };
        if !request.orphan_stops_progress() {
            return DropOutcome::Detached;
        }
        match slot.state {
            WaiterState::Active { target_tick } => DropOutcome::Cancel {
                needs_sqe: slot.in_flight,
                target_tick,
            },
            WaiterState::CancelRequested { .. } => DropOutcome::Cancel {
                needs_sqe: false,
                target_tick: None,
            },
        }
    }

    /// Mark a waiter's observer as dropped using its classified wind-down.
    ///
    /// Parked results are dropped and their slot freed immediately. Requests
    /// whose kind stops progressing without an observer transition to
    /// cancellation. Storage writes and syncs detach and keep running.
    ///
    /// Returns the stored ordinary-op waker, if any, so its destruction can
    /// run only after the caller releases the op-state borrow. The caller must
    /// classify the waiter and reserve all fallible destinations before
    /// calling this method while retaining exclusive access to the waiter
    /// table.
    ///
    /// Panics if the waiter is not tracked, the id is stale, or its observer
    /// was already dropped.
    pub fn mark_orphaned(&mut self, waiter_id: WaiterId, outcome: &DropOutcome) -> Option<Waker> {
        let index = waiter_id.index() as usize;
        let slot = self
            .entries
            .get_mut(index)
            .and_then(Option::as_mut)
            .expect("mark_orphaned called for untracked waiter");
        assert_eq!(
            slot.id, waiter_id,
            "mark_orphaned called with stale waiter id"
        );

        let waker = match &mut slot.observer {
            Observer::Op(waker) => waker.take(),
            Observer::Ticket(_) => None,
            Observer::Orphaned => panic!("mark_orphaned called for orphaned waiter"),
        };

        if matches!(outcome, DropOutcome::Freed) {
            slot.observer = Observer::Orphaned;
            let _ = self.take(index);
            return waker;
        }

        slot.observer = Observer::Orphaned;
        if matches!(outcome, DropOutcome::Cancel { .. })
            && matches!(slot.state, WaiterState::Active { .. })
        {
            // The ticket is gone, so the parked result (and its reason) is
            // never observed.
            slot.state = WaiterState::CancelRequested {
                reason: CancelReason::Deadline,
            };
        }
        waker
    }

    /// Return whether a waiter currently has an operation SQE in flight.
    pub fn is_in_flight(&self, waiter_id: WaiterId) -> bool {
        let index = waiter_id.index() as usize;
        self.entries
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|slot| slot.id == waiter_id && slot.in_flight)
    }
}

#[cfg(test)]
#[path = "waiter_tests.rs"]
mod tests;
