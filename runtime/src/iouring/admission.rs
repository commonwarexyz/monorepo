//! FIFO admission to a worker's bounded io_uring waiter table.
//!
//! Requests keep their buffers until admitted. This queue stores their wakers
//! and deadlines in a growable slab, so callers can still register, time out,
//! and cancel when the waiter table is full.
//!
//! Available waiter slots are reserved for the oldest queued callers before
//! waking them:
//!
//! ```text
//! register -> Queued -> Granted -> consume -> waiter table
//!                |         |
//!                +---------+----> cancel or expire -> recycle slot
//! ```
//!
//! A grant reserves one slot until consumed, cancelled, or expired. The worker
//! reconciles the queue whenever free capacity or reservations change, so new
//! callers only use capacity left after queued callers receive their grants.
//!
//! Deadlines remain active after a grant. A minimum heap tracks them separately
//! from admitted operations, with generational IDs to reject stale entries.
//! Stale deadlines are pruned at the heap's head and periodically compacted.
//!
//! Detached wakers are returned or appended to caller-provided buffers. The
//! worker wakes or drops them after releasing its local borrow.

use super::slab::{Id, Slab};
use std::{cmp::Reverse, collections::BinaryHeap, task::Waker, time::Instant};

/// Generational identity for an admission registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AdmissionId(Id);

/// Whether a registration is queued or holds a reservation.
enum State {
    /// Waiting in the FIFO for unreserved waiter capacity.
    Queued {
        /// Older queued registration, if any.
        prev: Option<Id>,
        /// Newer queued registration, if any.
        next: Option<Id>,
    },
    /// One free waiter slot is reserved for this caller.
    Granted,
}

/// One live admission registration.
struct Entry {
    /// FIFO placement or reservation.
    state: State,
    /// Latest caller waker, detached when a grant or expiry wakes the caller.
    waker: Option<Waker>,
    /// Whether this registration contributes to the live deadline count.
    has_deadline: bool,
}

/// FIFO admissions and reserved capacity owned by one worker.
#[derive(Default)]
pub struct Admissions {
    /// Growable storage independent of the bounded waiter table.
    entries: Slab<Entry>,
    /// Oldest queued registration.
    head: Option<Id>,
    /// Newest queued registration.
    tail: Option<Id>,
    /// Deadlines ordered earliest first, including stale entries.
    deadlines: BinaryHeap<Reverse<(Instant, AdmissionId)>>,
    /// Number of live registrations with a deadline.
    timed: usize,
    /// Number of free waiter slots reserved by granted registrations.
    reserved: usize,
}

impl Admissions {
    /// Whether a new caller can use a waiter slot immediately.
    ///
    /// Call [`Self::reconcile`] first with the current free waiter count. The
    /// owner consumes capacity before releasing its local borrow, preventing a
    /// later caller from overtaking a queued registration.
    pub fn can_admit(&self, free_waiter_slots: usize) -> bool {
        assert!(self.reserved <= free_waiter_slots);
        self.head.is_none() && self.reserved < free_waiter_slots
    }

    /// Append a caller to the queue with its original deadline.
    ///
    /// The caller checks closure and expiry before registering. Repeated polls
    /// use [`Self::refresh`] instead of allocating another registration.
    pub fn register(&mut self, deadline: Option<Instant>, waker: Waker) -> AdmissionId {
        // Every caller starts queued. Reconciliation grants capacity in FIFO order.
        let id = AdmissionId(self.entries.insert(Entry {
            state: State::Queued {
                prev: self.tail,
                next: None,
            },
            waker: Some(waker),
            has_deadline: deadline.is_some(),
        }));

        // Link the previous tail forward, or establish the head of an empty queue.
        if let Some(tail) = self.tail {
            let entry = self.entries.get_mut(tail).expect("admission tail missing");
            let State::Queued { next, .. } = &mut entry.state else {
                unreachable!("admission tail is not queued");
            };
            *next = Some(id.0);
        } else {
            self.head = Some(id.0);
        }
        self.tail = Some(id.0);

        // Track expiry independently of queue position, including after a grant.
        if let Some(deadline) = deadline {
            self.deadlines.push(Reverse((deadline, id)));
            self.timed += 1;
        }

        id
    }

    /// Replace a live registration's waker, returning the displaced waker.
    ///
    /// A stale ID returns the incoming waker.
    pub fn refresh(&mut self, id: AdmissionId, waker: Waker) -> Result<Option<Waker>, Waker> {
        let Some(entry) = self.entries.get_mut(id.0) else {
            return Err(waker);
        };
        Ok(entry.waker.replace(waker))
    }

    /// Whether a queued registration is already waiting with an equivalent waker.
    pub fn is_waiting(&self, id: AdmissionId, waker: &Waker) -> bool {
        self.entries.get(id.0).is_some_and(|entry| {
            matches!(entry.state, State::Queued { .. })
                && entry
                    .waker
                    .as_ref()
                    .is_some_and(|registered| registered.will_wake(waker))
        })
    }

    /// Consume a grant, returning any waker stored since it was granted.
    ///
    /// An ungranted or stale ID returns `Err(())`. On success the owner
    /// must insert the request into a free waiter before releasing its borrow.
    pub fn take_grant(&mut self, id: AdmissionId) -> Result<Option<Waker>, ()> {
        if !self.is_granted(id) {
            return Err(());
        }

        let waker = self.remove(id.0);
        self.compact();
        Ok(waker)
    }

    /// Cancel a queued or granted registration and detach its waker.
    ///
    /// Stale cancellation is harmless. The caller immediately reconciles the
    /// queue before releasing its borrow, so cancelling a grant cannot strand
    /// its reserved capacity.
    pub fn cancel(&mut self, id: AdmissionId) -> Option<Waker> {
        if !self.contains(id) {
            return None;
        }

        let waker = self.remove(id.0);
        self.compact();
        waker
    }

    /// Expire registrations, then reserve available waiter slots in FIFO order.
    ///
    /// `free_waiter_slots` includes slots already reserved by this queue. Each
    /// appended waker must be invoked outside the local borrow.
    pub fn reconcile(&mut self, now: Instant, free_waiter_slots: usize, wakes: &mut Vec<Waker>) {
        assert!(self.reserved <= free_waiter_slots);

        // Expire first so timed-out grants release their reservations before
        // we distribute capacity. next_deadline also prunes stale heap entries.
        while let Some(deadline) = self.next_deadline() {
            if deadline > now {
                break;
            }
            let Reverse((_, id)) = self.deadlines.pop().unwrap();
            if let Some(waker) = self.remove(id.0) {
                wakes.push(waker);
            }
        }

        // Reserve unpromised capacity for queued callers, oldest first.
        while self.reserved < free_waiter_slots {
            let Some(id) = self.head else {
                break;
            };

            // A grant leaves the FIFO but stays in the slab and deadline heap
            // until consumed, cancelled, or expired.
            self.unlink(id);
            let entry = self.entries.get_mut(id).unwrap();
            entry.state = State::Granted;
            self.reserved += 1;

            // The worker invokes these wakers after the borrow ends, once
            // every reservation is committed.
            if let Some(waker) = entry.waker.take() {
                wakes.push(waker);
            }
        }

        // Bound stale heap entries left by cancellations and consumed grants.
        self.compact();
    }

    /// Return the earliest live deadline, pruning stale heap entries.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(&Reverse((deadline, id))) = self.deadlines.peek() {
            if self.contains(id) {
                return Some(deadline);
            }
            self.deadlines.pop();
        }
        None
    }

    /// Remove every registration during worker closure, detaching its waker.
    pub fn clear(&mut self, drops: &mut Vec<Waker>) {
        drops.reserve(self.entries.len());
        for index in 0..self.entries.slots() {
            if let Some(id) = self.entries.id_at(index)
                && let Some(waker) = self.remove(id)
            {
                drops.push(waker);
            }
        }
        self.deadlines.clear();
    }

    /// Whether an ID still refers to a live registration.
    fn contains(&self, id: AdmissionId) -> bool {
        self.entries.get(id.0).is_some()
    }

    /// Whether a live registration owns reserved waiter capacity.
    fn is_granted(&self, id: AdmissionId) -> bool {
        self.entries
            .get(id.0)
            .is_some_and(|entry| matches!(entry.state, State::Granted))
    }

    /// Unlink a queued node without touching its waker or deadline.
    fn unlink(&mut self, id: Id) {
        let State::Queued { prev, next } = self.entries.get(id).unwrap().state else {
            unreachable!("unlink requires a queued admission");
        };

        // Bypass this node in the forward chain. Without a predecessor, its
        // successor becomes the new head.
        if let Some(prev) = prev {
            let entry = self
                .entries
                .get_mut(prev)
                .expect("admission predecessor missing");
            let State::Queued { next: link, .. } = &mut entry.state else {
                unreachable!("admission predecessor is not queued");
            };
            *link = next;
        } else {
            self.head = next;
        }

        // Repair the backward chain. Without a successor, its predecessor
        // becomes the new tail. Removing the only node clears both ends.
        if let Some(next) = next {
            let entry = self
                .entries
                .get_mut(next)
                .expect("admission successor missing");
            let State::Queued { prev: link, .. } = &mut entry.state else {
                unreachable!("admission successor is not queued");
            };
            *link = prev;
        } else {
            self.tail = prev;
        }
    }

    /// Retire one live registration and return its owned waker.
    fn remove(&mut self, id: Id) -> Option<Waker> {
        // Release either the queue position or the reserved waiter slot.
        match self.entries.get(id).unwrap().state {
            State::Queued { .. } => self.unlink(id),
            State::Granted => self.reserved -= 1,
        }

        let entry = self.entries.remove(id).unwrap();

        // Count only live deadlines. Any remaining heap record is now stale.
        if entry.has_deadline {
            self.timed -= 1;
        }

        entry.waker
    }

    /// Bound stale deadline storage without adding a second index structure.
    fn compact(&mut self) {
        // Each live timed registration has one heap record. The rest are stale.
        let stale = self.deadlines.len() - self.timed;

        // Allow a small backlog, and wait until it exceeds the live registration
        // count as well. This amortizes heap scans across removals.
        if stale <= 64 || stale <= self.entries.len() {
            return;
        }

        // Generations reject records left by earlier registrations in reused slots.
        let entries = &self.entries;
        self.deadlines
            .retain(|&Reverse((_, id))| entries.get(id.0).is_some());
        self.deadlines.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::slab::tests::set_generation;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
        time::Duration,
    };

    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn waker() -> (Arc<Counter>, Waker) {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        (counter.clone(), Waker::from(counter))
    }

    #[test]
    fn test_fifo_grants_reserve_capacity_before_waking() {
        let now = Instant::now();
        let mut admissions = Admissions::default();
        let mut wakes = Vec::new();
        assert!(!admissions.can_admit(0));
        assert!(admissions.can_admit(1));
        assert_eq!(admissions.next_deadline(), None);

        let (first_counter, first_waker) = waker();
        let (second_counter, second_waker) = waker();
        let (third_counter, third_waker) = waker();
        let first = admissions.register(None, first_waker);
        let second = admissions.register(None, second_waker);
        let third = admissions.register(None, third_waker);
        assert!(!admissions.can_admit(1));

        // The first caller owns the free slot before its waker is invoked.
        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.reserved, 1);
        assert!(!admissions.can_admit(1));
        assert!(admissions.is_granted(first));
        assert!(!admissions.is_granted(second));
        assert!(admissions.take_grant(second).is_err());
        assert_eq!(first_counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(wakes.len(), 1);

        wakes.pop().unwrap().wake();
        assert_eq!(first_counter.0.load(Ordering::Relaxed), 1);
        assert!(admissions.take_grant(first).unwrap().is_none());

        // Consuming the grant fills the waiter. Further grants wait for capacity.
        admissions.reconcile(now, 0, &mut wakes);
        assert!(wakes.is_empty());

        admissions.reconcile(now, 3, &mut wakes);
        assert_eq!(admissions.reserved, 2);
        assert!(admissions.is_granted(second));
        assert!(admissions.is_granted(third));
        assert!(admissions.can_admit(3));
        assert_eq!(wakes.len(), 2);

        for waker in wakes.drain(..) {
            waker.wake();
        }
        assert_eq!(second_counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(third_counter.0.load(Ordering::Relaxed), 1);
        assert!(admissions.take_grant(second).is_ok());
        assert!(admissions.take_grant(third).is_ok());
        assert_eq!(admissions.reserved, 0);
        assert!(admissions.can_admit(1));
    }

    #[test]
    fn test_refresh_returns_displaced_wakers() {
        let mut admissions = Admissions::default();
        let (first_counter, first_waker) = waker();
        let (second_counter, second_waker) = waker();
        let id = admissions.register(None, first_waker);
        assert!(!admissions.is_waiting(id, &second_waker));

        let displaced = admissions.refresh(id, second_waker).unwrap();
        assert_eq!(admissions.entries.len(), 1);
        assert_eq!(Arc::strong_count(&first_counter), 2);

        // Refresh returns the old waker so its destructor can run later.
        drop(displaced);
        assert_eq!(Arc::strong_count(&first_counter), 1);

        let mut wakes = Vec::new();
        admissions.reconcile(Instant::now(), 1, &mut wakes);
        wakes.pop().unwrap().wake();
        assert_eq!(second_counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(first_counter.0.load(Ordering::Relaxed), 0);

        // A grant has detached its waker. A later refresh is returned on consumption.
        let (third_counter, third_waker) = waker();
        assert!(!admissions.is_waiting(id, &third_waker));
        assert!(
            admissions
                .refresh(id, third_waker.clone())
                .unwrap()
                .is_none()
        );

        // An equivalent waker must not leave a granted caller waiting.
        assert!(!admissions.is_waiting(id, &third_waker));
        drop(third_waker);
        let retained = admissions.take_grant(id).unwrap().unwrap();
        assert_eq!(Arc::strong_count(&third_counter), 2);

        drop(retained);
        assert_eq!(Arc::strong_count(&third_counter), 1);
        assert_eq!(third_counter.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_cancellation_redistributes_fifo_capacity() {
        let mut admissions = Admissions::default();
        let now = Instant::now();
        let mut wakes = Vec::new();
        let first = admissions.register(None, Waker::noop().clone());
        let middle = admissions.register(None, Waker::noop().clone());
        let last = admissions.register(None, Waker::noop().clone());

        // Reusing a middle slot places the new caller at the tail.
        assert!(admissions.cancel(middle).is_some());
        let reused = admissions.register(None, Waker::noop().clone());
        assert_eq!(middle.0.index, reused.0.index);

        // Removing a queued tail must leave its predecessor as the new tail.
        let tail = admissions.register(None, Waker::noop().clone());
        assert!(admissions.cancel(tail).is_some());
        assert_eq!(admissions.tail, Some(reused.0));

        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.reserved, 1);

        // Cancelling the grant releases capacity to the next original caller.
        assert!(admissions.cancel(first).is_none());
        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.reserved, 1);
        assert!(!admissions.is_granted(reused));
        assert!(admissions.take_grant(last).is_ok());

        admissions.reconcile(now, 1, &mut wakes);
        assert!(admissions.take_grant(reused).is_ok());
        assert_eq!(admissions.entries.len(), 0);
        assert!(admissions.head.is_none());
        assert!(admissions.tail.is_none());
        assert!(admissions.cancel(first).is_none());
    }

    #[test]
    fn test_queued_and_granted_deadlines_expire_without_waiter_progress() {
        let now = Instant::now();
        let soon = now + Duration::from_secs(1);
        let later = now + Duration::from_secs(2);
        let mut admissions = Admissions::default();
        let first = admissions.register(Some(soon), Waker::noop().clone());
        let second = admissions.register(Some(soon), Waker::noop().clone());
        let third = admissions.register(Some(later), Waker::noop().clone());
        let mut wakes = Vec::new();

        admissions.reconcile(now, 1, &mut wakes);
        assert!(admissions.is_granted(first));
        assert_eq!(admissions.next_deadline(), Some(soon));
        wakes.clear();

        // Expiry releases the grant and removes its queued sibling at the same deadline.
        admissions.reconcile(soon, 1, &mut wakes);
        assert!(!admissions.contains(first));
        assert!(!admissions.contains(second));
        assert_eq!(wakes.len(), 2);
        assert_eq!(admissions.reserved, 1);
        assert_eq!(admissions.next_deadline(), Some(later));
        assert!(admissions.take_grant(third).is_ok());
        assert_eq!(admissions.next_deadline(), None);

        // Queued deadlines also expire with no free waiters.
        let expired = admissions.register(Some(soon), Waker::noop().clone());
        admissions.reconcile(soon, 0, &mut wakes);
        assert!(!admissions.contains(expired));
        assert_eq!(admissions.entries.len(), 0);
    }

    #[test]
    fn test_stale_ids_and_deadlines_do_not_affect_reused_slots() {
        let now = Instant::now();
        let soon = now + Duration::from_secs(1);
        let later = now + Duration::from_secs(2);
        let mut admissions = Admissions::default();
        let old = admissions.register(Some(soon), Waker::noop().clone());
        drop(admissions.cancel(old));

        let (_, current_waker) = waker();
        let current = admissions.register(Some(later), current_waker.clone());
        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old.0.generation, current.0.generation);

        // Delayed cancellation and refresh must leave the new registration intact.
        assert!(admissions.cancel(old).is_none());
        let rejected = admissions.refresh(old, current_waker.clone()).unwrap_err();
        assert!(rejected.will_wake(&current_waker));
        assert!(admissions.contains(current));
        assert!(admissions.is_waiting(current, &current_waker));
        assert!(!admissions.is_waiting(old, &current_waker));

        // The old deadline must leave the new registration eligible for a grant.
        let mut wakes = Vec::new();
        admissions.reconcile(soon, 1, &mut wakes);
        assert_eq!(admissions.next_deadline(), Some(later));
        assert!(admissions.is_granted(current));
        assert!(!admissions.is_granted(old));
        assert!(admissions.take_grant(old).is_err());
        assert_eq!(admissions.reserved, 1);
        drop(admissions.take_grant(current).unwrap());
        assert_eq!(admissions.next_deadline(), None);
    }

    #[test]
    fn test_exhausted_generation_retires_slot() {
        let mut admissions = Admissions::default();
        let current = admissions.register(None, Waker::noop().clone());

        // Grant first so no FIFO links retain the generation we overwrite.
        let mut wakes = Vec::new();
        admissions.reconcile(Instant::now(), 1, &mut wakes);
        let exhausted = AdmissionId(set_generation(&mut admissions.entries, current.0, u64::MAX));

        drop(admissions.cancel(exhausted));
        let next = admissions.register(None, Waker::noop().clone());
        assert_ne!(exhausted.0.index, next.0.index);
        assert!(!admissions.contains(exhausted));
    }

    #[test]
    fn test_cancellation_churn_bounds_stale_deadlines() {
        let now = Instant::now();

        // Exercise both the fixed allowance and the bound proportional to live entries.
        for live in [1, 100] {
            let mut admissions = Admissions::default();
            for _ in 0..live {
                admissions.register(Some(now), Waker::noop().clone());
            }

            for _ in 0..1000 {
                let id =
                    admissions.register(Some(now + Duration::from_secs(1)), Waker::noop().clone());
                drop(admissions.cancel(id));
                assert!(admissions.deadlines.len() <= admissions.timed + live.max(64));
            }

            // Compaction must retain every live deadline.
            let mut wakes = Vec::new();
            assert_eq!(admissions.next_deadline(), Some(now));
            admissions.reconcile(now, 0, &mut wakes);
            assert_eq!(wakes.len(), live);
            assert_eq!(admissions.entries.len(), 0);
            assert_eq!(admissions.next_deadline(), None);
        }
    }

    #[test]
    fn test_clear_returns_wakers_and_releases_reservations() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut admissions = Admissions::default();
        let (counter, registered_waker) = waker();
        let granted = admissions.register(Some(deadline), registered_waker);
        let queued = admissions.register(Some(deadline), Waker::noop().clone());
        let mut wakes = Vec::new();

        admissions.reconcile(now, 1, &mut wakes);
        assert!(
            admissions
                .refresh(granted, Waker::from(counter.clone()))
                .unwrap()
                .is_none()
        );

        let mut drops = Vec::new();
        admissions.clear(&mut drops);
        assert_eq!(drops.len(), 2);
        assert_eq!(admissions.reserved, 0);
        assert_eq!(admissions.timed, 0);
        assert_eq!(admissions.entries.len(), 0);
        assert!(admissions.head.is_none());
        assert!(admissions.tail.is_none());
        assert!(admissions.deadlines.is_empty());
        assert!(admissions.cancel(granted).is_none());
        assert!(admissions.cancel(queued).is_none());

        // Clearing detaches wakers without invoking or destroying them.
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&counter), 3);
        drop(drops);
        drop(wakes);
        assert_eq!(Arc::strong_count(&counter), 1);

        let mut drops = Vec::new();
        admissions.clear(&mut drops);
        assert!(drops.is_empty());
    }
}
