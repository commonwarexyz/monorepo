//! Utilities for safely moving runtime contexts in and out of long-lived actors.
//!
//! `ContextSlot` owns a runtime context but allows temporarily leasing it (e.g.
//! to spawn a task) without cloning. The lease is an RAII guard—dropping it
//! without returning the context panics so mistakes are caught immediately.

use rand::{CryptoRng, Rng, RngCore};
use std::ops::{Deref, DerefMut};

/// Wrapper around a runtime context that supports leasing.
#[derive(Debug)]
pub struct ContextSlot<E> {
    context: Option<E>,
}

/// Lease that must be returned to the slot.
#[must_use = "the leased context must be returned via `ContextSlot::put`"]
#[derive(Debug)]
pub struct ContextLease {
    returned: bool,
}

impl<E> ContextSlot<E> {
    /// Create a new slot containing `context`.
    pub fn new(context: E) -> Self {
        Self {
            context: Some(context),
        }
    }

    /// Temporarily remove the context from the slot, returning it together with
    /// an RAII guard that must put the context back.
    ///
    /// # Panics
    ///
    /// Panics if the slot is already empty (which indicates a logic bug).
    pub fn take(&mut self) -> (E, ContextLease) {
        let context = self.context.take().expect("context slot already taken");
        (context, ContextLease { returned: false })
    }

    /// Return the leased context to the slot.
    ///
    /// # Panics
    ///
    /// Panics if the lease has already been consumed or the slot already holds a
    /// context.
    pub fn put(&mut self, context: E, mut lease: ContextLease) {
        assert!(self.context.is_none(), "context slot already filled");
        assert!(!lease.returned, "context lease already returned");
        self.context = Some(context);
        lease.returned = true;
    }

    /// Returns `true` if the slot currently holds a context.
    pub fn is_present(&self) -> bool {
        self.context.is_some()
    }
}

impl Drop for ContextLease {
    fn drop(&mut self) {
        if !self.returned {
            panic!("context lease dropped without returning context");
        }
    }
}

impl<E> From<E> for ContextSlot<E> {
    fn from(context: E) -> Self {
        Self::new(context)
    }
}

impl<E> Deref for ContextSlot<E> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        self.context.as_ref().expect("context slot is empty")
    }
}

impl<E> DerefMut for ContextSlot<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.context.as_mut().expect("context slot is empty")
    }
}

impl<E: RngCore> RngCore for ContextSlot<E> {
    fn next_u32(&mut self) -> u32 {
        self.context
            .as_mut()
            .expect("context slot is empty")
            .next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.context
            .as_mut()
            .expect("context slot is empty")
            .next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.context
            .as_mut()
            .expect("context slot is empty")
            .fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.context
            .as_mut()
            .expect("context slot is empty")
            .try_fill_bytes(dest)
    }
}

impl<E: CryptoRng> CryptoRng for ContextSlot<E> {}

#[macro_export]
macro_rules! spawn_ref {
    ($owner:ident . $field:ident, | $actor:ident | $body:expr) => {
        $crate::spawn_ref!(@impl $owner, $field, $actor, , $body)
    };
    ($owner:ident . $field:ident, | mut $actor:ident | $body:expr) => {
        $crate::spawn_ref!(@impl $owner, $field, $actor, mut, $body)
    };
    (@impl $owner:ident, $field:ident, $actor:ident, $($mut:tt)?, $body:expr) => {{
        let (__context_handle, __context_lease) = $owner.$field.take();
        __context_handle.spawn(move |__runtime_context| {
            let $($mut)? $actor = $owner;
            $actor.$field.put(__runtime_context, __context_lease);
            $body
        })
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_put_restores_context() {
        let mut slot = ContextSlot::new(42);
        let (ctx, lease) = slot.take();
        assert_eq!(ctx, 42);
        slot.put(7, lease);
        assert_eq!(*slot, 7);
        assert!(slot.is_present());
    }

    #[test]
    #[should_panic(expected = "context lease dropped without returning context")]
    fn dropping_lease_without_return_panics() {
        let mut slot = ContextSlot::new(1);
        let (_ctx, _lease) = slot.take();
        // `_lease` dropped here without returning context
    }
}
