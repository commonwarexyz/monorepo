//! FIFO admission control for the driver's waiter table.
//!
//! A task that cannot claim an unreserved waiter slot registers here without
//! transferring its request to the waiter table. Grants are FIFO and reserve
//! real waiter capacity until consumed or cancelled, so a fresh task cannot
//! barge ahead. Generation-stamped nodes make late cancellation and deadline
//! entries harmless after slot reuse. Waker callbacks are deferred until the
//! surrounding driver-state borrow is released.

use super::callbacks::{WakerAction, WakerActionSink};
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    task::Waker,
    time::{Duration, Instant},
};

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
}

/// Result of one atomic capacity-admission transition.
///
/// Successful variants leave the cloned observer waker in the caller-owned
/// slot. The caller can then publish the waiter and retain the observer without
/// a second external clone.
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
pub(super) enum CapacityAdmission {
    /// Admit directly from an unreserved authoritative free slot.
    Direct,
    /// Consume the caller's previously reserved FIFO grant.
    Granted,
    /// Keep or create a FIFO registration and wait for a grant.
    Queued,
}

impl CapacityWaiters {
    /// Construct an empty FIFO and arena without allocating.
    pub(super) const fn new() -> Self {
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
    pub(super) fn poll(
        &mut self,
        registration: &mut Option<CapacityId>,
        free_len: usize,
        deadline: Option<Instant>,
        incoming_waker: &mut Option<Waker>,
        actions: &mut impl WakerActionSink,
    ) -> CapacityAdmission {
        assert!(
            self.reserved <= free_len,
            "capacity reservations exceed waiter free slots"
        );

        if let Some(id) = *registration {
            let Some(state) = self.live_state(id) else {
                *registration = None;
                return self.poll(registration, free_len, deadline, incoming_waker, actions);
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

    /// Expire every queued or granted registration due at or before `now`.
    ///
    /// Each expired node is recycled after leaving the FIFO or releasing its
    /// grant. A granted expiry returns its reservation before capacity is
    /// reconciled. Any waker runs only after the surrounding
    /// [`super::handle::Ops`] borrow is released.
    pub(super) fn expire(
        &mut self,
        now: Instant,
        free_len: usize,
        actions: &mut impl WakerActionSink,
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
            match self
                .take_live(id)
                .expect("live capacity deadline disappeared")
            {
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
                CapacityState::Free { .. } => {
                    unreachable!("free capacity deadline reported live")
                }
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
        actions: &mut impl WakerActionSink,
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
            CapacityState::Free { .. } => unreachable!("free capacity node reported live"),
        }
    }

    /// Reserve authoritative free slots for FIFO heads and defer their effects.
    ///
    /// Each transition moves the queued waker into a deferred wake action and
    /// leaves a payload-free grant behind. No RawWaker vtable function runs
    /// while the capacity arena is borrowed.
    pub(super) fn reconcile(&mut self, free_len: usize, actions: &mut impl WakerActionSink) {
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

    /// Recycle every live registration and return queued owner wakers.
    pub(super) fn close(&mut self) -> Vec<Waker> {
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
        for index in (0..self.nodes.len()).rev() {
            let id = CapacityId {
                index,
                generation: self.nodes[index].generation,
            };
            let Some(state) = self.take_live(id) else {
                continue;
            };
            match state {
                CapacityState::Queued { waker, .. } => wakers.push(waker),
                CapacityState::Granted { .. } => {}
                CapacityState::Free { .. } => unreachable!("free capacity node reported live"),
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
        // Reserve every allocation that may be needed before consuming the
        // incoming waker or mutating the free list and FIFO links. Allocation
        // failure therefore leaves all ownership and intrusive state intact.
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
    pub(super) const fn reserved(&self) -> usize {
        self.reserved
    }

    /// Size of the slot arena, including recyclable entries.
    #[cfg(test)]
    pub(super) const fn arena_len(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests;
