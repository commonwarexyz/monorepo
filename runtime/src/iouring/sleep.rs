//! Owner-local deadlines for sleeping tasks.
//!
//! Sleep registrations are independent of ring waiters and admission capacity.
//! The worker services this minimum heap on busy turns and includes its earliest
//! deadline when choosing either a timed futex wait or a ring wait. A saturated
//! ring therefore cannot prevent local timeouts from waking their tasks.
//!
//! [`Timers`] owns one replaceable waker per registration in a growable slab.
//! A full-width [`TimerId`] distinguishes reused slots from delayed foreign
//! cancellation messages and stale heap entries. Generation exhaustion retires
//! the slot permanently. Cancellation removes the registration immediately,
//! leaving only its numeric heap entry for lazy pruning or bounded compaction.
//!
//! The worker calls these methods under its local borrow. Waker replacement,
//! expiry, cancellation, and closure always return owned wakers or append them
//! to caller-owned action storage. Waking and destruction happen only after
//! releasing that borrow, with the worker's normal cleanup panic isolation.

use std::{cmp::Reverse, collections::BinaryHeap, task::Waker, time::Instant};

/// Full-width identity for one sleeper registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct TimerId {
    /// Slab slot containing this registration.
    index: usize,
    /// Slot incarnation, checked before every lookup.
    generation: u64,
}

/// Live deadline and the sleeping caller's latest waker.
struct Registration {
    /// Absolute monotonic deadline, fixed when the sleep is created.
    deadline: Instant,
    /// Waker to detach when the deadline expires or the caller cancels.
    waker: Waker,
}

/// One reusable timer slot.
struct Entry {
    /// Current incarnation of this slot.
    generation: u64,
    /// Present only while the timer is live.
    registration: Option<Registration>,
    /// Next reusable slot when vacant and not generation-exhausted.
    next_free: Option<usize>,
}

/// Growable timer registrations and their earliest-first deadline heap.
#[derive(Default)]
pub(super) struct Timers {
    /// Slots owned exclusively by this worker.
    entries: Vec<Entry>,
    /// Head of the reusable slot list.
    free: Option<usize>,
    /// Deadline records, including lazily removed stale registrations.
    deadlines: BinaryHeap<Reverse<(Instant, TimerId)>>,
    /// Number of live registrations.
    len: usize,
}

impl Timers {
    /// Create an empty timer queue without allocating storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a future deadline using a waker cloned before borrowing Local.
    ///
    /// Already elapsed sleeps complete in their first poll without registration.
    /// Repeated pending polls refresh this registration instead of inserting a
    /// second timer or changing the original absolute deadline.
    pub fn insert(&mut self, deadline: Instant, waker: Waker) -> TimerId {
        if self.free.is_none() {
            self.entries.reserve(1);
        }
        self.deadlines.reserve(1);
        let index = if let Some(index) = self.free {
            self.free = self.entries[index].next_free;
            index
        } else {
            let index = self.entries.len();
            self.entries.push(Entry {
                generation: 0,
                registration: None,
                next_free: None,
            });
            index
        };
        let entry = &mut self.entries[index];
        let id = TimerId {
            index,
            generation: entry.generation,
        };
        entry.registration = Some(Registration { deadline, waker });
        entry.next_free = None;
        self.deadlines.push(Reverse((deadline, id)));
        self.len += 1;
        id
    }

    /// Refresh a registered sleeper's waker and return the displaced waker.
    ///
    /// A missing registration returns the incoming waker untouched. The sleep
    /// future first checks its deadline and worker closure, so a missing live
    /// registration after those checks is an invariant failure.
    pub fn refresh(&mut self, id: TimerId, waker: Waker) -> Result<Waker, Waker> {
        if !self.contains(id) {
            return Err(waker);
        }
        let registration = self.entries[id.index].registration.as_mut().unwrap();
        Ok(std::mem::replace(&mut registration.waker, waker))
    }

    /// Remove a live registration and return its waker for deferred destruction.
    ///
    /// A delayed cancellation for an expired or recycled timer is harmless.
    pub fn cancel(&mut self, id: TimerId) -> Option<Waker> {
        if !self.contains(id) {
            return None;
        }
        let waker = self.remove(id.index);
        self.compact();
        Some(waker)
    }

    /// Remove every due timer and append its waker for deferred invocation.
    ///
    /// The worker supplies the same monotonic sample used by its operation and
    /// admission deadline service. All removals commit before any task can be
    /// woken or register another timer.
    pub fn expire(&mut self, now: Instant, wakes: &mut Vec<Waker>) {
        while let Some(deadline) = self.next_deadline() {
            if deadline > now {
                break;
            }
            // Reserve before detaching the waker. Pending future timers do
            // not need action storage until a service pass expires them.
            wakes.reserve(1);
            let Reverse((_, id)) = self.deadlines.pop().unwrap();
            wakes.push(self.remove(id.index));
        }
        self.compact();
    }

    /// Return the earliest live deadline, pruning stale heap heads.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(&Reverse((deadline, id))) = self.deadlines.peek() {
            if self.contains(id) {
                return Some(deadline);
            }
            self.deadlines.pop();
        }
        None
    }

    /// Remove every registration at worker closure and detach its waker.
    ///
    /// Closure owns registration cleanup even when a sleep future escapes its
    /// worker. The caller drops each detached waker after releasing Local.
    pub fn clear(&mut self, drops: &mut Vec<Waker>) {
        drops.reserve(self.len);
        for index in 0..self.entries.len() {
            if self.entries[index].registration.is_some() {
                drops.push(self.remove(index));
            }
        }
        self.deadlines.clear();
    }

    /// Validate both presence and the complete slot generation.
    fn contains(&self, id: TimerId) -> bool {
        self.entries
            .get(id.index)
            .is_some_and(|entry| entry.generation == id.generation && entry.registration.is_some())
    }

    /// Retire a live slot without invoking its waker.
    fn remove(&mut self, index: usize) -> Waker {
        let entry = &mut self.entries[index];
        let registration = entry.registration.take().unwrap();
        if let Some(generation) = entry.generation.checked_add(1) {
            entry.generation = generation;
            entry.next_free = self.free;
            self.free = Some(index);
        }
        self.len -= 1;
        registration.waker
    }

    /// Rebuild once stale entries exceed both 64 and the live timer count.
    fn compact(&mut self) {
        let stale = self.deadlines.len() - self.len;
        if stale <= 64 || stale <= self.len {
            return;
        }
        let entries = &self.entries;
        self.deadlines.retain(|&Reverse((deadline, id))| {
            let entry = &entries[id.index];
            entry.generation == id.generation
                && entry
                    .registration
                    .as_ref()
                    .is_some_and(|registration| registration.deadline == deadline)
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

    #[test]
    fn due_timers_are_removed_before_deferred_wakes() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let mut timers = Timers::new();
        let future = timers.insert(later, Waker::from(counter.clone()));
        let due = timers.insert(now, Waker::from(counter.clone()));
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        assert_eq!(wakes.len(), 1);
        assert!(!timers.contains(due));
        assert!(timers.contains(future));
        assert_eq!(timers.next_deadline(), Some(later));
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        wakes.pop().unwrap().wake();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        timers.expire(later, &mut wakes);
        assert_eq!(timers.next_deadline(), None);
        assert_eq!(timers.len, 0);
        wakes.pop().unwrap().wake();
        assert_eq!(counter.0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn repeated_poll_refreshes_only_the_waker() {
        let now = Instant::now();
        let first = Arc::new(Counter(AtomicUsize::new(0)));
        let second = Arc::new(Counter(AtomicUsize::new(0)));
        let mut timers = Timers::new();
        let id = timers.insert(now, Waker::from(first.clone()));
        let displaced = timers.refresh(id, Waker::from(second.clone())).unwrap();
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(timers.len, 1);
        assert_eq!(timers.deadlines.len(), 1);
        drop(displaced);
        assert_eq!(Arc::strong_count(&first), 1);
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        wakes.pop().unwrap().wake();
        assert_eq!(first.0.load(Ordering::Relaxed), 0);
        assert_eq!(second.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn timer_count_is_independent_of_ring_capacity() {
        let now = Instant::now();
        let mut timers = Timers::new();
        for _ in 0..1024 {
            timers.insert(now, Waker::noop().clone());
        }
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        assert_eq!(wakes.len(), 1024);
        assert_eq!(timers.len, 0);
        assert_eq!(timers.next_deadline(), None);
    }

    #[test]
    fn stale_ids_and_heap_entries_do_not_cancel_reused_slots() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut timers = Timers::new();
        let old = timers.insert(now, Waker::noop().clone());
        drop(timers.cancel(old));
        let current = timers.insert(later, Waker::noop().clone());
        assert_eq!(old.index, current.index);
        assert_ne!(old.generation, current.generation);
        assert!(timers.cancel(old).is_none());
        assert!(timers.refresh(old, Waker::noop().clone()).is_err());
        assert_eq!(timers.next_deadline(), Some(later));
        let mut wakes = Vec::new();
        timers.expire(now, &mut wakes);
        assert!(wakes.is_empty());
        assert!(timers.contains(current));
    }

    #[test]
    fn generation_exhaustion_retires_the_slot() {
        let now = Instant::now();
        let mut timers = Timers::new();
        let id = timers.insert(now, Waker::noop().clone());
        timers.entries[id.index].generation = u64::MAX;
        let exhausted = TimerId {
            index: id.index,
            generation: u64::MAX,
        };
        drop(timers.cancel(exhausted));
        let next = timers.insert(now, Waker::noop().clone());
        assert_ne!(exhausted.index, next.index);
        assert!(!timers.contains(exhausted));
    }

    #[test]
    fn cancellation_churn_bounds_stale_heap_storage() {
        let now = Instant::now();
        let mut timers = Timers::new();
        let oldest = timers.insert(now, Waker::noop().clone());
        for _ in 0..1000 {
            let id = timers.insert(now + Duration::from_secs(1), Waker::noop().clone());
            drop(timers.cancel(id));
            assert!(timers.deadlines.len() <= timers.len + 64);
        }
        assert_eq!(timers.entries.len(), 2);
        assert_eq!(timers.next_deadline(), Some(now));
        drop(timers.cancel(oldest));
        assert_eq!(timers.next_deadline(), None);
    }

    #[test]
    fn far_future_deadline_and_closure_detach_wakers() {
        let now = Instant::now();
        let far_future = now
            .checked_add(Duration::from_secs(30 * 365 * 24 * 60 * 60))
            .unwrap();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let mut timers = Timers::new();
        let id = timers.insert(far_future, Waker::from(counter.clone()));
        let mut actions = Vec::new();
        timers.expire(now, &mut actions);
        assert!(actions.is_empty());
        assert_eq!(timers.next_deadline(), Some(far_future));
        timers.clear(&mut actions);
        assert_eq!(actions.len(), 1);
        assert_eq!(timers.next_deadline(), None);
        assert_eq!(timers.len, 0);
        assert!(timers.cancel(id).is_none());
        assert_eq!(Arc::strong_count(&counter), 2);
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        drop(actions);
        assert_eq!(Arc::strong_count(&counter), 1);
    }
}
