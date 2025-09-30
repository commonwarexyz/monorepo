//! Utilities for managing concurrency.

use core::{
    num::NonZeroU32,
    sync::atomic::{AtomicU32, Ordering},
};
use std::sync::Arc;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NZU32;
    use std::{
        sync::{mpsc, Arc, Barrier},
        thread,
    };

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
    fn does_not_exceed_max_under_contention() {
        let limiter = Arc::new(Limiter::new(NZU32!(3)));
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
}
