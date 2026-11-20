//! One-shot channels whose receive takes part in the cooperative polling
//! budget.
//!
//! These wrap tokio's oneshot channel. The receiver is a future that checks
//! [`crate::coop::exhausted`] before each poll and spends one unit when it
//! completes, with a value or because the sender was dropped. A task that
//! awaits a long run of oneshots that are already complete, such as replies to
//! requests answered while it was busy, therefore yields once per
//! [`crate::coop::BUDGET`] of them under an executor that installs a budget.
//! On tokio, the tokio channel inside spends tokio's own budget instead.
//! [`Receiver::try_recv`] is never budgeted, so it is the way to check for a
//! value without waiting.
//!
//! Senders are tokio's own type, re-exported unchanged. Sending never waits,
//! so it spends no budget.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "these wrappers are the budgeted interface to tokio's channel"
)]

use crate::coop;
pub use inner::{Sender, error};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::oneshot as inner;

/// Create a one-shot channel whose receiver takes part in the cooperative
/// budget.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = inner::channel();
    (sender, Receiver { inner: receiver })
}

/// Receiving half of a one-shot channel.
///
/// Awaiting it yields the sent value, or an error once the sender is dropped
/// without sending.
pub struct Receiver<T> {
    /// Tokio receiver that every operation forwards to.
    inner: inner::Receiver<T>,
}

impl<T> Receiver<T> {
    /// Receive the value if it was sent, whatever the cooperative budget.
    pub fn try_recv(&mut self) -> Result<T, error::TryRecvError> {
        self.inner.try_recv()
    }

    /// Stop the sender from sending. A value sent before stays receivable.
    pub fn close(&mut self) {
        self.inner.close()
    }

    /// Whether the value was received or the channel closed, so a further
    /// poll would never complete.
    pub fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }

    /// Whether no value is waiting to be received.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Receive the value, blocking the calling thread until it is sent or
    /// the sender is dropped, whatever the cooperative budget.
    ///
    /// # Panics
    ///
    /// Panics when called inside a tokio runtime context.
    pub fn blocking_recv(self) -> Result<T, error::RecvError> {
        self.inner.blocking_recv()
    }

    /// Poll for the value without spending the cooperative budget of
    /// [`crate::coop`], for plumbing that only carries the result of another
    /// operation, such as a runtime's task handle or a forwarded completion.
    /// Inside a tokio runtime, tokio's own budget still applies, as it does to
    /// tokio's receiver.
    pub fn poll_unbudgeted(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, error::RecvError>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

impl<T> Future for Receiver<T> {
    type Output = Result<T, error::RecvError>;

    #[inline(always)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        coop::poll_counted(cx, |cx| Pin::new(inner).poll(cx))
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
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Wake, Waker},
    };

    /// Counts the wakes it receives.
    #[derive(Default)]
    struct Wakes(
        /// Wakes received so far.
        AtomicUsize,
    );

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_receive_spends_one_unit() {
        // A value waits in the channel.
        let (sender, receiver) = channel::<u32>();
        sender.send(7).unwrap();
        let mut receiver = pin!(receiver);
        let mut cx = Context::from_waker(Waker::noop());

        // Receiving it in a budgeted poll spends one unit.
        let _scope = coop::Scope::enter();
        for _ in 0..coop::BUDGET - 1 {
            coop::charge();
        }
        assert_eq!(receiver.as_mut().poll(&mut cx), Poll::Ready(Ok(7)));
        assert!(coop::exhausted());
    }

    #[test]
    fn test_spent_budget_defers_and_keeps_the_value() {
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);

        // A value waits, and the poll has spent its budget.
        let (sender, mut receiver) = channel::<u32>();
        sender.send(7).unwrap();
        let scope = coop::Scope::enter();
        for _ in 0..coop::BUDGET {
            coop::charge();
        }

        // The receive defers with a wake and leaves the value in place.
        assert!(Pin::new(&mut receiver).poll(&mut cx).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(!receiver.is_empty());
        drop(scope);

        // The next poll's fresh budget delivers it.
        let _scope = coop::Scope::enter();
        assert_eq!(Pin::new(&mut receiver).poll(&mut cx), Poll::Ready(Ok(7)));
    }

    #[test]
    fn test_dropped_sender_spends_one_unit() {
        // The sender is dropped without sending.
        let (sender, receiver) = channel::<u32>();
        drop(sender);
        let mut receiver = pin!(receiver);
        let mut cx = Context::from_waker(Waker::noop());

        // Reporting the closed channel spends one unit like a value.
        let _scope = coop::Scope::enter();
        assert!(matches!(
            receiver.as_mut().poll(&mut cx),
            Poll::Ready(Err(error::RecvError { .. }))
        ));
        for _ in 0..coop::BUDGET - 1 {
            coop::charge();
        }
        assert!(coop::exhausted());
    }

    #[test]
    fn test_try_recv_ignores_a_spent_budget() {
        // A value waits, and the poll has spent its budget.
        let (sender, mut receiver) = channel::<u32>();
        sender.send(7).unwrap();
        let _scope = coop::Scope::enter();
        for _ in 0..coop::BUDGET {
            coop::charge();
        }

        // try_recv still takes it.
        assert_eq!(receiver.try_recv(), Ok(7));
    }

    #[test]
    fn test_unconstrained_outside_a_scope() {
        // Many completed receivers, polled with no budget in force.
        let mut cx = Context::from_waker(Waker::noop());
        for value in 0..10 * coop::BUDGET {
            let (sender, mut receiver) = channel::<u32>();
            sender.send(value).unwrap();

            // Every one completes at once.
            assert_eq!(
                Pin::new(&mut receiver).poll(&mut cx),
                Poll::Ready(Ok(value))
            );
        }
    }
}
