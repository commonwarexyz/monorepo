//! Owner-local admission to the bounded io_uring waiter table.
//!
//! Requests retain their buffers in their futures until admission succeeds. This
//! queue stores only their wakers and absolute deadlines, so a full waiter table
//! cannot prevent a caller from registering a timeout or cancelling its place.
//!
//! # Reservations
//!
//! Registrations form an intrusive FIFO in a growable slab. Released waiter
//! capacity is reserved for the oldest queued callers before waking them:
//!
//! ```text
//! register -> Queued -> Granted -> consume -> waiter table
//!                |         |
//!                +---------+----> cancel or expire -> recycle slot
//! ```
//!
//! A grant remains reserved until consumed, cancelled, or expired. Fresh callers
//! cannot consume reserved capacity, even if a grantee has not been polled yet.
//! The owner reconciles the queue whenever waiter capacity or reservations change.
//!
//! Deadlines use a separate minimum heap, independent of admitted operations.
//! Heap entries and foreign cancellation messages carry full-width generations.
//! Stale heap entries are pruned and periodically compacted. A slot whose
//! generation is exhausted is permanently retired instead of wrapping.
//!
//! All methods execute under the owning worker's local borrow. They move wakers
//! into caller-owned storage without cloning, invoking, or destroying them. The
//! caller runs these actions only after releasing that borrow.

use super::slab::{Id, Slab};
use std::{cmp::Reverse, collections::BinaryHeap, task::Waker, time::Instant};

/// Full-width identity for one admission registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct AdmissionId(Id);

/// Placement of a live registration in the FIFO or reserved capacity.
enum AdmissionState {
    /// Waiting in the FIFO for unreserved waiter capacity.
    Queued {
        /// Older queued registration, if any.
        prev: Option<usize>,
        /// Younger queued registration, if any.
        next: Option<usize>,
    },
    /// One free waiter slot is reserved for this caller.
    Granted,
}

/// One live admission registration.
struct Entry {
    /// FIFO placement or reservation.
    state: AdmissionState,
    /// Latest caller waker, detached when a grant or expiry wakes the caller.
    waker: Option<Waker>,
    /// Original absolute deadline, retained after granting capacity.
    deadline: Option<Instant>,
}

/// FIFO admissions and reserved capacity owned by one worker.
#[derive(Default)]
pub(super) struct Admissions {
    /// Growable storage independent of the bounded waiter table.
    entries: Slab<Entry>,
    /// Oldest queued registration.
    head: Option<usize>,
    /// Youngest queued registration.
    tail: Option<usize>,
    /// Earliest-first deadlines, including lazily removed stale entries.
    deadlines: BinaryHeap<Reverse<(Instant, AdmissionId)>>,
    /// Number of live registrations with a deadline.
    timed: usize,
    /// Number of free waiter slots already promised to grantees.
    reserved: usize,
}

impl Admissions {
    /// Create an empty queue without allocating storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return whether a fresh caller can use one waiter slot immediately.
    ///
    /// Call [`Self::reconcile`] first with the current free waiter count. The
    /// owner consumes capacity before releasing its local borrow, preventing a
    /// later caller from overtaking a queued registration.
    pub fn can_admit(&self, free_waiter_slots: usize) -> bool {
        assert!(self.reserved <= free_waiter_slots);
        self.head.is_none() && self.reserved < free_waiter_slots
    }

    /// Append one caller to the FIFO with its original absolute deadline.
    ///
    /// The caller checks closure and expiry before registering. Repeated polls
    /// use [`Self::refresh`] instead of allocating another registration.
    pub fn register(&mut self, deadline: Option<Instant>, waker: Waker) -> AdmissionId {
        let id = AdmissionId(self.entries.insert(Entry {
            state: AdmissionState::Queued {
                prev: self.tail,
                next: None,
            },
            waker: Some(waker),
            deadline,
        }));
        let index = id.0.index;
        if let Some(tail) = self.tail {
            let AdmissionState::Queued { next, .. } = &mut self.entries[tail].state else {
                unreachable!("admission tail is not queued");
            };
            *next = Some(index);
        } else {
            self.head = Some(index);
        }
        self.tail = Some(index);
        if let Some(deadline) = deadline {
            self.deadlines.push(Reverse((deadline, id)));
            self.timed += 1;
        }
        id
    }

    /// Replace a live registration's waker, returning the displaced waker.
    ///
    /// A stale identity returns the incoming waker untouched. Neither path
    /// destroys a waker while the worker is borrowed.
    pub fn refresh(&mut self, id: AdmissionId, waker: Waker) -> Result<Option<Waker>, Waker> {
        if !self.contains(id) {
            return Err(waker);
        }
        Ok(self.entries[id.0.index].waker.replace(waker))
    }

    /// Whether a live registration owns reserved waiter capacity.
    pub fn is_granted(&self, id: AdmissionId) -> bool {
        self.contains(id) && matches!(self.entries[id.0.index].state, AdmissionState::Granted)
    }

    /// Whether a live registration already holds an equivalent observer.
    pub fn will_wake(&self, id: AdmissionId, waker: &Waker) -> bool {
        self.contains(id)
            && self.entries[id.0.index]
                .waker
                .as_ref()
                .is_some_and(|registered| registered.will_wake(waker))
    }

    /// Consume a reserved grant and detach any refreshed waker.
    ///
    /// An ungranted or stale identity returns `Err(())`. On success the owner
    /// must insert the request into a free waiter before releasing its borrow,
    /// then reconcile using the updated free waiter count.
    pub fn take_grant(&mut self, id: AdmissionId) -> Result<Option<Waker>, ()> {
        if !self.contains(id) || !matches!(self.entries[id.0.index].state, AdmissionState::Granted)
        {
            return Err(());
        }
        let waker = self.remove(id.0.index);
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
        let waker = self.remove(id.0.index);
        self.compact();
        waker
    }

    /// Expire registrations, then reserve available waiter slots in FIFO order.
    ///
    /// `free_waiter_slots` includes slots already reserved by this queue. Each
    /// returned waker must be invoked outside the local borrow. Expired callers
    /// check their original request deadlines before inspecting the stale ID.
    pub fn reconcile(&mut self, now: Instant, free_waiter_slots: usize, wakes: &mut Vec<Waker>) {
        assert!(self.reserved <= free_waiter_slots);
        while let Some(deadline) = self.next_deadline() {
            if deadline > now {
                break;
            }
            let Reverse((_, id)) = self.deadlines.pop().unwrap();
            if let Some(waker) = self.remove(id.0.index) {
                wakes.push(waker);
            }
        }
        while self.reserved < free_waiter_slots {
            let Some(index) = self.head else {
                break;
            };
            self.unlink(index);
            self.entries[index].state = AdmissionState::Granted;
            self.reserved += 1;
            // Commit the reservation before detaching its wake. A reentrant
            // caller must observe this capacity as unavailable.
            if let Some(waker) = self.entries[index].waker.take() {
                wakes.push(waker);
            }
        }
        self.compact();
    }

    /// Return the earliest live queued or granted deadline.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(&Reverse((deadline, id))) = self.deadlines.peek() {
            if self.contains(id) && self.entries[id.0.index].deadline == Some(deadline) {
                return Some(deadline);
            }
            self.deadlines.pop();
        }
        None
    }

    /// Remove every registration during worker closure, detaching its waker.
    ///
    /// The owner closes local registration first and drops these wakers outside
    /// the borrow, under its normal cleanup panic isolation.
    pub fn clear(&mut self, drops: &mut Vec<Waker>) {
        drops.reserve(self.entries.len());
        for index in 0..self.entries.slots_len() {
            if self.entries.id_at(index).is_some()
                && let Some(waker) = self.remove(index)
            {
                drops.push(waker);
            }
        }
        self.deadlines.clear();
    }

    /// Check slot presence and the complete generation before accessing it.
    fn contains(&self, id: AdmissionId) -> bool {
        self.entries.get(id.0).is_some()
    }

    /// Unlink a queued node without touching its waker or deadline.
    fn unlink(&mut self, index: usize) {
        let AdmissionState::Queued { prev, next } = self.entries[index].state else {
            unreachable!("unlink requires a queued admission");
        };
        if let Some(prev) = prev {
            let AdmissionState::Queued { next: link, .. } = &mut self.entries[prev].state else {
                unreachable!("admission predecessor is not queued");
            };
            *link = next;
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            let AdmissionState::Queued { prev: link, .. } = &mut self.entries[next].state else {
                unreachable!("admission successor is not queued");
            };
            *link = prev;
        } else {
            self.tail = prev;
        }
    }

    /// Retire one live registration and return its owned waker.
    fn remove(&mut self, index: usize) -> Option<Waker> {
        match self.entries[index].state {
            AdmissionState::Queued { .. } => self.unlink(index),
            AdmissionState::Granted => self.reserved -= 1,
        }
        let id = self
            .entries
            .id_at(index)
            .expect("removing a free admission");
        let entry = self.entries.remove(id).unwrap();
        if entry.deadline.is_some() {
            self.timed -= 1;
        }
        entry.waker
    }

    /// Bound stale deadline storage without adding a second index structure.
    fn compact(&mut self) {
        let stale = self.deadlines.len() - self.timed;
        if stale <= 64 || stale <= self.entries.len() {
            return;
        }
        let entries = &self.entries;
        self.deadlines.retain(|&Reverse((deadline, id))| {
            entries
                .get(id.0)
                .is_some_and(|entry| entry.deadline == Some(deadline))
        });
        self.deadlines.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn fifo_grants_reserve_capacity_before_waking() {
        let now = Instant::now();
        let mut admissions = Admissions::new();
        let mut wakes = Vec::new();
        let (first_counter, first_waker) = waker();
        let (second_counter, second_waker) = waker();
        let first = admissions.register(None, first_waker);
        let second = admissions.register(None, second_waker);
        assert!(!admissions.can_admit(1));
        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.reserved, 1);
        assert!(!admissions.can_admit(1));
        assert!(admissions.take_grant(second).is_err());
        assert_eq!(first_counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(wakes.len(), 1);
        wakes.pop().unwrap().wake();
        assert_eq!(first_counter.0.load(Ordering::Relaxed), 1);
        assert!(admissions.take_grant(first).unwrap().is_none());
        admissions.reconcile(now, 0, &mut wakes);
        assert!(wakes.is_empty());
        admissions.reconcile(now, 1, &mut wakes);
        wakes.pop().unwrap().wake();
        assert_eq!(second_counter.0.load(Ordering::Relaxed), 1);
        assert!(admissions.take_grant(second).is_ok());
        assert!(admissions.can_admit(1));
    }

    #[test]
    fn repeated_poll_replaces_waker_without_duplicating_registration() {
        let mut admissions = Admissions::new();
        let (first_counter, first_waker) = waker();
        let (second_counter, second_waker) = waker();
        let id = admissions.register(None, first_waker);
        let displaced = admissions.refresh(id, second_waker).unwrap();
        assert_eq!(admissions.entries.len(), 1);
        assert_eq!(Arc::strong_count(&first_counter), 2);
        drop(displaced);
        assert_eq!(Arc::strong_count(&first_counter), 1);
        let mut wakes = Vec::new();
        admissions.reconcile(Instant::now(), 1, &mut wakes);
        wakes.pop().unwrap().wake();
        assert_eq!(second_counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(first_counter.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn queued_and_granted_cancellation_redistribute_fifo_capacity() {
        let mut admissions = Admissions::new();
        let now = Instant::now();
        let mut wakes = Vec::new();
        let first = admissions.register(None, Waker::noop().clone());
        let middle = admissions.register(None, Waker::noop().clone());
        let last = admissions.register(None, Waker::noop().clone());
        assert!(admissions.cancel(middle).is_some());
        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.reserved, 1);
        assert!(admissions.cancel(first).is_none());
        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.reserved, 1);
        assert!(admissions.take_grant(last).is_ok());
        assert_eq!(admissions.entries.len(), 0);
        assert!(admissions.head.is_none());
        assert!(admissions.tail.is_none());
        assert!(admissions.cancel(first).is_none());
    }

    #[test]
    fn queued_and_granted_deadlines_expire_without_waiter_progress() {
        let now = Instant::now();
        let soon = now + Duration::from_secs(1);
        let later = now + Duration::from_secs(2);
        let mut admissions = Admissions::new();
        let first = admissions.register(Some(soon), Waker::noop().clone());
        let second = admissions.register(Some(soon), Waker::noop().clone());
        let third = admissions.register(Some(later), Waker::noop().clone());
        let mut wakes = Vec::new();
        admissions.reconcile(now, 1, &mut wakes);
        assert_eq!(admissions.next_deadline(), Some(soon));
        wakes.clear();
        admissions.reconcile(soon, 1, &mut wakes);
        assert!(!admissions.contains(first));
        assert!(!admissions.contains(second));
        assert_eq!(wakes.len(), 2);
        assert_eq!(admissions.reserved, 1);
        assert_eq!(admissions.next_deadline(), Some(later));
        assert!(admissions.take_grant(third).is_ok());
        assert_eq!(admissions.next_deadline(), None);

        let expired = admissions.register(Some(soon), Waker::noop().clone());
        admissions.reconcile(soon, 0, &mut wakes);
        assert!(!admissions.contains(expired));
        assert_eq!(admissions.entries.len(), 0);
    }

    #[test]
    fn stale_ids_and_generation_exhaustion_never_alias() {
        let mut admissions = Admissions::new();
        let old = admissions.register(None, Waker::noop().clone());
        drop(admissions.cancel(old));
        let current = admissions.register(None, Waker::noop().clone());
        assert_eq!(old.0.index, current.0.index);
        assert_ne!(old.0.generation, current.0.generation);
        assert!(admissions.cancel(old).is_none());
        assert!(admissions.refresh(old, Waker::noop().clone()).is_err());
        assert!(admissions.contains(current));

        let exhausted = AdmissionId(admissions.entries.set_generation(current.0, u64::MAX));
        drop(admissions.cancel(exhausted));
        let next = admissions.register(None, Waker::noop().clone());
        assert_ne!(exhausted.0.index, next.0.index);
        assert!(!admissions.contains(exhausted));
    }

    #[test]
    fn cancellation_churn_bounds_stale_deadlines() {
        let mut admissions = Admissions::new();
        let now = Instant::now();
        let oldest = admissions.register(Some(now), Waker::noop().clone());
        for _ in 0..1000 {
            let id = admissions.register(Some(now + Duration::from_secs(1)), Waker::noop().clone());
            drop(admissions.cancel(id));
            assert!(admissions.deadlines.len() <= admissions.timed + 64);
        }
        assert_eq!(admissions.entries.slots_len(), 2);
        assert_eq!(admissions.next_deadline(), Some(now));
        drop(admissions.cancel(oldest));
        assert_eq!(admissions.next_deadline(), None);
    }

    #[test]
    fn closure_detaches_wakers_and_releases_every_reservation() {
        let mut admissions = Admissions::new();
        let (counter, registered_waker) = waker();
        let queued = admissions.register(None, registered_waker);
        let granted = admissions.register(None, Waker::noop().clone());
        let mut wakes = Vec::new();
        admissions.reconcile(Instant::now(), 1, &mut wakes);
        drop(
            admissions
                .refresh(queued, Waker::from(counter.clone()))
                .unwrap(),
        );
        let mut drops = Vec::new();
        admissions.clear(&mut drops);
        assert_eq!(drops.len(), 2);
        assert_eq!(admissions.reserved, 0);
        assert_eq!(admissions.entries.len(), 0);
        assert!(admissions.cancel(granted).is_none());
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&counter), 3);
        drop(drops);
        drop(wakes);
        assert_eq!(Arc::strong_count(&counter), 1);
    }
}
