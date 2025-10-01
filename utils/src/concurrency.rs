//! Utilities for managing concurrency.

use core::{
    hash::Hash,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

/// Limit the concurrency of some operation without blocking.
pub struct Limiter {
    max: usize,
    current: Arc<AtomicUsize>,
}

impl Limiter {
    /// Create a limiter that allows up to `max` concurrent reservations.
    pub fn new(max: NonZeroUsize) -> Self {
        Self {
            max: max.get(),
            current: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Attempt to reserve a slot. Returns `None` when the limiter is saturated.
    pub fn try_acquire(&self) -> Option<Reservation> {
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                (current < self.max).then_some(current + 1)
            })
            .map(|_| Reservation {
                current: self.current.clone(),
            })
            .ok()
    }
}

/// A reservation for a slot in the [Limiter].
pub struct Reservation {
    current: Arc<AtomicUsize>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.current.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Limit the concurrency of some keyed operation without blocking.
pub struct KeyedLimiter<K: Eq + Hash + Clone> {
    max: usize,
    current: Arc<Mutex<HashSet<K>>>,
}

impl<K: Eq + Hash + Clone> KeyedLimiter<K> {
    /// Create a limiter that allows up to `max` concurrent reservations.
    pub fn new(max: NonZeroUsize) -> Self {
        Self {
            max: max.get(),
            current: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Attempt to reserve a slot for a given key. Returns `None` when the limiter is saturated or
    /// the key is already reserved.
    pub fn try_acquire(&self, key: K) -> Option<KeyedReservation<K>> {
        let mut current = self.current.lock().unwrap();
        if current.len() >= self.max {
            return None;
        }
        if !current.insert(key.clone()) {
            return None;
        }
        drop(current);

        Some(KeyedReservation {
            key,
            current: self.current.clone(),
        })
    }
}

/// A reservation for a slot in the [KeyedLimiter].
pub struct KeyedReservation<K: Eq + Hash + Clone> {
    key: K,
    current: Arc<Mutex<HashSet<K>>>,
}

impl<K: Eq + Hash + Clone> Drop for KeyedReservation<K> {
    fn drop(&mut self) {
        self.current.lock().unwrap().remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NZUsize;
    use std::{
        sync::{mpsc, Arc, Barrier},
        thread,
    };

    #[test]
    fn allows_reservations_up_to_max() {
        let limiter = Limiter::new(NZUsize!(2));

        let first = limiter
            .try_acquire()
            .expect("first reservation should succeed");
        let second = limiter
            .try_acquire()
            .expect("second reservation should succeed");

        assert!(limiter.try_acquire().is_none());

        drop(second);
        let third = limiter
            .try_acquire()
            .expect("reservation after drop should succeed");

        drop(third);
        drop(first);
    }

    #[test]
    fn does_not_exceed_max_under_contention() {
        let limiter = Arc::new(Limiter::new(NZUsize!(3)));
        let thread_count = 16;
        let barrier = Arc::new(Barrier::new(thread_count));
        let (tx, rx) = mpsc::channel();

        let mut handles = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            let tx = tx.clone();

            handles.push(thread::spawn(move || {
                barrier.wait();
                let reservation = limiter.try_acquire();
                tx.send(reservation).expect("receiver alive");
            }));
        }
        drop(tx);

        for handle in handles {
            handle.join().expect("thread join");
        }

        let mut reservations = Vec::new();
        for reservation in rx {
            let Some(reservation) = reservation else {
                continue;
            };
            reservations.push(reservation);
        }
        assert_eq!(reservations.len(), 3);

        assert!(limiter.try_acquire().is_none());
        drop(reservations);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn allows_reservations_up_to_max_for_key() {
        let limiter = KeyedLimiter::new(NZUsize!(2));

        let first = limiter
            .try_acquire(0)
            .expect("first reservation should succeed");
        let second = limiter
            .try_acquire(1)
            .expect("second reservation should succeed");
        assert!(limiter.try_acquire(2).is_none());

        drop(second);
        let third = limiter
            .try_acquire(2)
            .expect("third reservation should succeed");

        drop(third);
        drop(first);
    }

    #[test]
    fn blocks_conflicting_reservations_for_key() {
        let limiter = KeyedLimiter::new(NZUsize!(2));

        let first = limiter
            .try_acquire(0)
            .expect("first reservation should succeed");
        assert!(limiter.try_acquire(0).is_none());

        drop(first);
        let second = limiter
            .try_acquire(0)
            .expect("second reservation should succeed");

        drop(second);
    }
}
