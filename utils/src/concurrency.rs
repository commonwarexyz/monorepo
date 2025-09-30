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
