//! Utilities for managing concurrency.

use core::{
    hash::Hash,
    num::NonZeroU32,
    sync::atomic::{AtomicU32, Ordering},
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

/// Limit the concurrency of some operation without blocking.
pub struct Limiter {
    max: u32,
    current: Arc<AtomicU32>,
}

impl Limiter {
    /// Create a limiter that allows up to `max` concurrent reservations.
    pub fn new(max: NonZeroU32) -> Self {
        Self {
            max: max.get(),
            current: Arc::new(AtomicU32::new(0)),
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
    current: Arc<AtomicU32>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.current.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Limit the concurrency of some keyed operation without blocking.
pub struct KeyedLimiter<K: Eq + Hash + Clone> {
    max: u32,
    current: Arc<Mutex<HashSet<K>>>,
}

impl<K: Eq + Hash + Clone> KeyedLimiter<K> {
    /// Create a limiter that allows up to `max` concurrent reservations.
    pub fn new(max: NonZeroU32) -> Self {
        Self {
            max: max.get(),
            current: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Attempt to reserve a slot for a given key. Returns `None` when the limiter is saturated or
    /// the key is already reserved.
    pub fn try_acquire(&self, key: K) -> Option<KeyedReservation<K>> {
        let mut current = self.current.lock().unwrap();
        if current.len() >= self.max as usize {
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
    use crate::NZU32;

    #[test]
    fn allows_reservations_up_to_max() {
        let limiter = Limiter::new(NZU32!(2));

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
    fn allows_reservations_up_to_max_for_key() {
        let limiter = KeyedLimiter::new(NZU32!(2));

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
        let limiter = KeyedLimiter::new(NZU32!(2));

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
