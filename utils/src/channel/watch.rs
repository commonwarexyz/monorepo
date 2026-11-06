//! Watch channels whose change notifications take part in the cooperative
//! polling budget.
//!
//! These wrap tokio's watch channel. Waiting for a change with
//! [`Receiver::changed`] or [`Receiver::wait_for`] checks
//! [`crate::coop::exhausted`] before each poll and spends one unit when it
//! completes. A task that loops on `changed` while another task keeps
//! publishing therefore yields once per [`crate::coop::BUDGET`] changes under
//! an executor that installs a budget, instead of holding its worker for as
//! long as the publisher keeps up. On tokio, the tokio channel inside spends
//! tokio's own budget instead. [`Receiver::has_changed`] and the `borrow`
//! methods are never budgeted, so they are the way to check without waiting.
//!
//! The sender is wrapped too, so that [`Sender::subscribe`] hands out budgeted
//! receivers. Sending never waits, so it spends no budget.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "these wrappers are the budgeted interface to tokio's channel"
)]

use crate::coop;
pub use inner::{Ref, error};
use std::{
    fmt,
    future::{Future, poll_fn},
    pin::pin,
};
use tokio::sync::watch as inner;

/// Create a watch channel holding `init`, whose receivers take part in the
/// cooperative budget.
pub fn channel<T>(init: T) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = inner::channel(init);
    (Sender { inner: sender }, Receiver { inner: receiver })
}

/// Sending half of a watch channel.
pub struct Sender<T> {
    /// Tokio sender that every operation forwards to.
    inner: inner::Sender<T>,
}

impl<T> Sender<T> {
    /// Create a sender holding `init` with no receivers yet.
    pub fn new(init: T) -> Self {
        Self {
            inner: inner::Sender::new(init),
        }
    }

    /// Replace the value and notify the receivers, or return the value if
    /// every receiver is gone.
    pub fn send(&self, value: T) -> Result<(), error::SendError<T>> {
        self.inner.send(value)
    }

    /// Modify the value in place and notify the receivers, even without any
    /// receiver.
    pub fn send_modify<F>(&self, modify: F)
    where
        F: FnOnce(&mut T),
    {
        self.inner.send_modify(modify)
    }

    /// Modify the value in place and notify the receivers only if `modify`
    /// returns true. Returns what `modify` returned.
    pub fn send_if_modified<F>(&self, modify: F) -> bool
    where
        F: FnOnce(&mut T) -> bool,
    {
        self.inner.send_if_modified(modify)
    }

    /// Replace the value, notify the receivers, and return the old value,
    /// even without any receiver.
    pub fn send_replace(&self, value: T) -> T {
        self.inner.send_replace(value)
    }

    /// Borrow the current value.
    pub fn borrow(&self) -> Ref<'_, T> {
        self.inner.borrow()
    }

    /// Whether every receiver is gone.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Wait until every receiver is gone.
    pub async fn closed(&self) {
        self.inner.closed().await
    }

    /// Create a receiver that sees the current value as already seen.
    pub fn subscribe(&self) -> Receiver<T> {
        Receiver {
            inner: self.inner.subscribe(),
        }
    }

    /// Receivers of this channel.
    pub fn receiver_count(&self) -> usize {
        self.inner.receiver_count()
    }

    /// Senders of this channel.
    pub fn sender_count(&self) -> usize {
        self.inner.sender_count()
    }

    /// Whether both handles belong to the same channel.
    pub fn same_channel(&self, other: &Self) -> bool {
        self.inner.same_channel(&other.inner)
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Default> Default for Sender<T> {
    fn default() -> Self {
        Self {
            inner: inner::Sender::default(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Receiving half of a watch channel.
pub struct Receiver<T> {
    /// Tokio receiver that every operation forwards to.
    inner: inner::Receiver<T>,
}

impl<T> Receiver<T> {
    /// Borrow the current value without marking it seen.
    pub fn borrow(&self) -> Ref<'_, T> {
        self.inner.borrow()
    }

    /// Borrow the current value and mark it seen.
    pub fn borrow_and_update(&mut self) -> Ref<'_, T> {
        self.inner.borrow_and_update()
    }

    /// Whether the value changed since it was last seen, whatever the
    /// cooperative budget. Errors once the sender is gone.
    pub fn has_changed(&self) -> Result<bool, error::RecvError> {
        self.inner.has_changed()
    }

    /// Mark the current value as not yet seen.
    pub fn mark_changed(&mut self) {
        self.inner.mark_changed()
    }

    /// Mark the current value as seen.
    pub fn mark_unchanged(&mut self) {
        self.inner.mark_unchanged()
    }

    /// Wait until the value changes after it was last seen, and mark it
    /// seen. Errors once the sender is gone. Cancel safe. Each completion
    /// spends one unit of the cooperative budget, and a spent budget defers
    /// it to the next poll.
    pub async fn changed(&mut self) -> Result<(), error::RecvError> {
        let mut changed = pin!(self.inner.changed());
        poll_fn(|cx| coop::poll_counted(cx, |cx| changed.as_mut().poll(cx))).await
    }

    /// Wait until the value satisfies `f`, and mark it seen. Errors once the
    /// sender is gone. Its completion spends one unit of the cooperative
    /// budget, and a spent budget defers it to the next poll.
    pub async fn wait_for(
        &mut self,
        f: impl FnMut(&T) -> bool,
    ) -> Result<Ref<'_, T>, error::RecvError> {
        let mut waiting = pin!(self.inner.wait_for(f));
        poll_fn(|cx| coop::poll_counted(cx, |cx| waiting.as_mut().poll(cx))).await
    }

    /// Whether both handles belong to the same channel.
    pub fn same_channel(&self, other: &Self) -> bool {
        self.inner.same_channel(&other.inner)
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::pin,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn test_published_loop_yields_once_per_budget() {
        // A receiver with a change waiting.
        let (sender, mut receiver) = channel(0u32);
        let mut cx = Context::from_waker(Waker::noop());
        let _scope = coop::Scope::enter();

        // Each completed wait for a change spends one unit.
        for value in 1..=coop::BUDGET {
            sender.send(value).unwrap();
            let mut changed = pin!(receiver.changed());
            assert!(matches!(
                changed.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
        }

        // With the budget spent, a published change defers to the next poll.
        sender.send(0).unwrap();
        assert!(pin!(receiver.changed()).poll(&mut cx).is_pending());
        assert!(receiver.has_changed().unwrap());
    }

    #[test]
    fn test_subscribed_receivers_are_budgeted() {
        // A receiver created from the sender, with a change waiting.
        let (sender, _receiver) = channel(0u32);
        let mut subscribed = sender.subscribe();
        sender.send(1).unwrap();
        let mut cx = Context::from_waker(Waker::noop());

        // A spent budget defers it too.
        let _scope = coop::Scope::enter();
        for _ in 0..coop::BUDGET {
            coop::charge();
        }
        assert!(pin!(subscribed.changed()).poll(&mut cx).is_pending());
        assert_eq!(*subscribed.borrow_and_update(), 1);
    }

    #[test]
    fn test_unconstrained_outside_a_scope() {
        // Many changes, each awaited with no budget in force.
        let (sender, mut receiver) = channel(0u32);
        let mut cx = Context::from_waker(Waker::noop());
        for value in 1..=10 * coop::BUDGET {
            sender.send(value).unwrap();

            // Every wait completes at once.
            assert!(matches!(
                pin!(receiver.changed()).poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
        }
    }
}
