//! Utilities for providing acknowledgement.

use core::{
    fmt::Debug,
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};
use futures::task::AtomicWaker;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Acknowledgement cancellation error.
#[derive(Debug, thiserror::Error)]
#[error("acknowledgement was cancelled")]
pub struct Canceled;

/// A mechanism for acknowledging the completion of a task.
pub trait Acknowledgement: Clone + Send + Sync + Debug + 'static {
    /// Future resolved once the acknowledgement is handled.
    type Waiter: Future<Output = Result<(), Self::Error>> + Send + Sync + Unpin + 'static;

    /// Error produced if the acknowledgement is not handled.
    type Error: Debug + Send + Sync + 'static;

    /// Create a new acknowledgement handle paired with the waiter.
    fn handle() -> (Self, Self::Waiter);

    /// Fulfill the acknowledgement.
    fn acknowledge(self);
}

/// [Acknowledgement] that returns after all instances are acknowledged.
///
/// If any acknowledgement is not handled, the acknowledgement will be cancelled.
pub struct Exact {
    state: Arc<ExactState>,
    acknowledged: bool,
}

impl Debug for Exact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exact")
            .field("acknowledged", &self.acknowledged)
            .finish()
    }
}

impl Clone for Exact {
    fn clone(&self) -> Self {
        // Because acknowledge consumes self, we know that there is no way for there
        // to remain 0 references before the last acknowledgement has been cloned (i.e.
        // the acknowledgement won't resolve while we are still creating new clones).
        self.state.increment();

        // Create a new acknowledgement with acknowledged set to false (the acknowledgement
        // we are cloning from will also be false because it hasn't been consumed but we do it
        // manually to be explicit).
        Self {
            state: self.state.clone(),
            acknowledged: false,
        }
    }
}

impl Drop for Exact {
    fn drop(&mut self) {
        if self.acknowledged {
            return;
        }

        // If not yet acknowledged, cancel the acknowledgement.
        self.state.cancel();
        self.acknowledged = true;
    }
}

impl Acknowledgement for Exact {
    type Error = Canceled;
    type Waiter = ExactWaiter;

    fn handle() -> (Self, Self::Waiter) {
        // When created, ExactState has a remaining count of 1 already.
        let state = Arc::new(ExactState::new());
        (
            Self {
                state: state.clone(),
                acknowledged: false,
            },
            ExactWaiter { state },
        )
    }

    fn acknowledge(mut self) {
        self.state.acknowledge();
        self.acknowledged = true;
    }
}

/// Future that waits for an [Exact] acknowledgement to complete or be canceled.
pub struct ExactWaiter {
    state: Arc<ExactState>,
}

impl Unpin for ExactWaiter {}

impl Future for ExactWaiter {
    type Output = Result<(), Canceled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.state.waker.register(cx.waker());

        if self.state.canceled.load(Ordering::Acquire) {
            return Poll::Ready(Err(Canceled));
        }

        if self.state.remaining.load(Ordering::Acquire) == 0 {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

/// State for the [Exact] acknowledgement.
struct ExactState {
    remaining: AtomicUsize,
    canceled: AtomicBool,
    waker: AtomicWaker,
}

impl ExactState {
    /// Create a new acknowledgement state with a remaining count of 1.
    const fn new() -> Self {
        Self {
            remaining: AtomicUsize::new(1),
            canceled: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Acknowledge the completion of a task.
    fn acknowledge(&self) {
        // Decrement the remaining count and check if it was the last acknowledgement.
        if self.remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }

        // On last acknowledgement, wake the waiter.
        self.waker.wake();
    }

    /// Increment the remaining count.
    fn increment(&self) {
        self.remaining.fetch_add(1, Ordering::AcqRel);
    }

    /// Cancel the acknowledgement.
    fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        self.waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::{Acknowledgement, Exact};
    use futures::{future::FusedFuture, FutureExt};
    use std::sync::atomic::Ordering;

    #[test]
    fn acknowledges_after_all_listeners() {
        let (ack1, waiter) = Exact::handle();
        let waiter = waiter.fuse();
        let ack2 = ack1.clone();
        ack1.acknowledge();
        assert!(!waiter.is_terminated());
        ack2.acknowledge();
        assert!(waiter.now_or_never().unwrap().is_ok());
    }

    #[test]
    fn cancels_on_drop() {
        let (ack, waiter) = Exact::handle();
        drop(ack);
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    fn cancels_on_drop_before_acknowledgement() {
        let (ack, waiter) = Exact::handle();
        let ack2 = ack.clone();
        drop(ack2);
        ack.acknowledge();
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    fn cancels_on_drop_after_acknowledgement() {
        let (ack, waiter) = Exact::handle();
        let ack2 = ack.clone();
        ack.acknowledge();
        drop(ack2);
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    fn dropping_waiter_does_not_interfere_with_acknowledgement() {
        let (ack, waiter) = Exact::handle();
        let state = ack.state.clone();
        drop(waiter);

        let ack2 = ack.clone();
        ack.acknowledge();
        ack2.acknowledge();

        assert_eq!(state.remaining.load(Ordering::Acquire), 0);
        assert!(!state.canceled.load(Ordering::Acquire));
    }
}
