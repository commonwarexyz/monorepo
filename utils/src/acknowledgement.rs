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

/// [Acknowledgement] that returns once exactly `N` acknowledgements are received.
///
/// If any acknowledgement is not handled, the acknowledgement will be cancelled.
pub struct Exact<const N: usize = 1> {
    state: Arc<AckState<N>>,
    acknowledged: bool,
}

impl<const N: usize> Clone for Exact<N> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            acknowledged: false,
        }
    }
}

impl<const N: usize> std::fmt::Debug for Exact<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exact").field("listeners", &N).finish()
    }
}

impl<const N: usize> Drop for Exact<N> {
    fn drop(&mut self) {
        // This should never happen, but we handle it for completeness.
        if self.acknowledged {
            return;
        }

        // If not yet acknowledged, cancel the acknowledgement.
        self.state.cancel();
        self.acknowledged = true;
    }
}

impl<const N: usize> Acknowledgement for Exact<N> {
    type Error = Canceled;
    type Waiter = ExactWaiter<N>;

    fn handle() -> (Self, Self::Waiter) {
        assert!(N > 0, "requires N > 0 listeners");
        let state = Arc::new(AckState::new());
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

/// Future that waits for a an [Exact] acknowledgement to complete or be canceled.
pub struct ExactWaiter<const N: usize> {
    state: Arc<AckState<N>>,
}

impl<const N: usize> Unpin for ExactWaiter<N> {}

impl<const N: usize> Future for ExactWaiter<N> {
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
struct AckState<const N: usize> {
    remaining: AtomicUsize,
    canceled: AtomicBool,
    waker: AtomicWaker,
}

impl<const N: usize> AckState<N> {
    /// Create a new acknowledgement state.
    fn new() -> Self {
        Self {
            remaining: AtomicUsize::new(N),
            canceled: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Acknowledge the completion of a task.
    fn acknowledge(&self) {
        // If not the last acknowledgement, do nothing.
        match self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                if remaining == 0 {
                    None
                } else {
                    Some(remaining - 1)
                }
            }) {
            Ok(1) => {
                // On last acknowledgement, wake the waiter.
                self.waker.wake();
            }
            Ok(_) => (),
            Err(_) => unreachable!("exceeded permitted acknowledgements"),
        }
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

    #[test]
    fn acknowledges_after_all_listeners() {
        let (ack1, waiter) = Exact::<2>::handle();
        let waiter = waiter.fuse();
        let ack2 = ack1.clone();
        ack1.acknowledge();
        assert!(!waiter.is_terminated());
        ack2.acknowledge();
        assert!(waiter.now_or_never().unwrap().is_ok());
    }

    #[test]
    fn cancels_on_drop_before_ack() {
        let (ack, waiter) = Exact::<1>::handle();
        drop(ack);
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    #[should_panic(expected = "exceeded permitted acknowledgements")]
    fn extra_acknowledgements_noop() {
        let (ack, waiter) = Exact::<1>::handle();
        ack.clone().acknowledge();
        ack.acknowledge(); // should fail
        waiter.now_or_never().unwrap().unwrap(); // won't get here
    }
}
