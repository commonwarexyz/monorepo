//! Utilities for storing runtime contexts that must be temporarily moved.
//!
//! `ContextSlot` wraps a runtime context so it can be "taken" for spawning tasks
//! and later restored without forcing call sites to handle `Option` or `Result`
//! manually. The type implements `Deref`/`DerefMut`, so existing code that expects
//! direct access to the underlying context can continue to call methods on it
//! transparently.

use std::ops::{Deref, DerefMut};

/// Guard returned when leasing a context.
///
/// Dropping the lease without returning the context will panic, ensuring
/// callers use the lease API correctly.
#[must_use = "the lease must be used to return the context"]
#[derive(Debug)]
pub struct ContextLease<E> {
    returned: bool,
    _marker: std::marker::PhantomData<fn() -> E>,
}

/// Wrapper that allows temporarily removing a runtime context and later
/// replacing it without cloning.
#[derive(Debug)]
pub struct ContextSlot<E> {
    context: Option<E>,
}

impl<E> ContextSlot<E> {
    /// Store a new context inside the slot.
    pub fn new(context: E) -> Self {
        Self {
            context: Some(context),
        }
    }

    /// Lease the context out of the slot.
    ///
    /// Returns the leased context and a guard that must be used to restore the
    /// context. Dropping the guard without returning the context will panic.
    ///
    /// # Panics
    /// Panics if the context has already been taken.
    pub fn take(&mut self) -> (E, ContextLease<E>) {
        let context = self.context.take().expect("context slot already taken");
        (
            context,
            ContextLease {
                returned: false,
                _marker: std::marker::PhantomData,
            },
        )
    }

    /// Put a context back into the slot.
    ///
    /// # Panics
    /// Panics if a context is already present. This indicates a logic error where
    /// more than one `put` was attempted without a matching `take`.
    pub fn put(&mut self, context: E) {
        assert!(
            self.context.replace(context).is_none(),
            "context slot already filled"
        );
    }
}

impl<E> From<E> for ContextSlot<E> {
    fn from(context: E) -> Self {
        Self::new(context)
    }
}

impl<E: Clone> Clone for ContextSlot<E> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
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

impl<E> ContextLease<E> {
    /// Return the leased context to the provided slot.
    ///
    /// # Panics
    /// Panics if the lease has already been returned.
    pub fn put(&mut self, slot: &mut ContextSlot<E>, context: E) {
        assert!(!self.returned, "context lease already returned");
        slot.put(context);
        self.returned = true;
    }
}

impl<E> Drop for ContextLease<E> {
    fn drop(&mut self) {
        if !self.returned {
            panic!("context lease dropped without returning context");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_put_restores_context() {
        let mut slot = ContextSlot::new(42);
        let (ctx, mut lease) = slot.take();
        assert_eq!(ctx, 42);
        lease.put(&mut slot, 7);
        assert_eq!(*slot, 7);
    }

    #[test]
    #[should_panic(expected = "context lease dropped without returning context")]
    fn dropping_lease_without_return_panics() {
        let mut slot = ContextSlot::new(1);
        let (_ctx, _lease) = slot.take();
        // `_lease` dropped here without returning context
    }
}
