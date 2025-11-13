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

pub trait Splittable: Sized {
    fn split(self) -> (Self, Self);
}

/// A mechanism for acknowledging the completion of a task.
pub trait Acknowledgement: Splittable + Send + Sync + Debug + 'static {
    /// Future resolved once the acknowledgement is handled.
    type Waiter: Future<Output = Result<(), Self::Error>> + Send + Sync + Unpin + 'static;
    /// Error produced if the acknowledgement is not handled.
    type Error: Debug + Send + Sync + 'static;

    /// Create a new acknowledgement handle paired with the waiter.
    fn handle() -> (Self, Self::Waiter);

    /// Fulfill the acknowledgement.
    fn acknowledge(self);
}

/// [`Acknowledgement`] that returns once as many acknowledgments are received as `Exact` was split.
///
/// If any acknowledgement is not handled, the acknowledgement will be cancelled.
///
/// Notice that `Exact` cannot be cloned. The only way to get another `Exact`
/// is to use [`Splittable::split`].
pub struct Exact {
    state: Arc<AckState>,
    acknowledged: bool,
    split: bool,
}

impl std::fmt::Debug for Exact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exact").finish()
    }
}

impl Drop for Exact {
    fn drop(&mut self) {
        if self.acknowledged || self.split {
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
        let state = Arc::new(AckState::new());
        (
            Self {
                state: state.clone(),
                acknowledged: false,
                split: false,
            },
            ExactWaiter { state },
        )
    }

    fn acknowledge(mut self) {
        self.state.acknowledge();
        self.acknowledged = true;
    }
}

impl Splittable for Exact {
    fn split(mut self) -> (Self, Self) {
        self.split = true;

        let state = self.state.clone();

        let (left, right) = state.split();

        let left = Self {
            acknowledged: false,
            split: false,
            state: left,
        };
        let right = Self {
            acknowledged: false,
            split: false,
            state: right,
        };

        (left, right)
    }
}

/// Future that waits for an [`Exact`] acknowledgement to complete or be canceled.
pub struct ExactWaiter {
    state: Arc<AckState>,
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

/// State for the [`Exact`] acknowledgement.
struct AckState {
    remaining: AtomicUsize,
    canceled: AtomicBool,
    waker: AtomicWaker,
}

impl AckState {
    /// Create a new acknowledgement state.
    fn new() -> Self {
        Self {
            remaining: AtomicUsize::new(1),
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

    /// Split the ack state by incrementing the required remaining acknowledgments by 1.
    fn split(self: Arc<Self>) -> (Arc<Self>, Arc<Self>) {
        let right = self.clone();
        right
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_add(1)
            })
            .expect("None should never be hit, realistically");
        (self, right)
    }
}

#[cfg(test)]
mod tests {
    use super::{Acknowledgement, Exact, Splittable};
    use futures::{future::FusedFuture, FutureExt};

    #[test]
    fn acknowledges_after_all_listeners() {
        let (ack1, waiter) = Exact::handle();
        let waiter = waiter.fuse();
        let (ack1, ack2) = ack1.split();
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
        let (ack1, waiter) = Exact::handle();
        let (ack1, ack2) = ack1.split();
        drop(ack2);
        ack1.acknowledge();
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    fn cancels_on_drop_after_acknowledgement() {
        let (ack1, waiter) = Exact::handle();
        let (ack1, ack2) = ack1.split();
        ack1.acknowledge();
        drop(ack2);
        assert!(waiter.now_or_never().unwrap().is_err());
    }
}
