//! Utilities for providing acknowledgement.

use core::fmt::Debug;
use futures::channel::oneshot;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

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

/// [Acknowledgement] that returns once a minimum number of acknowledgements are received.
///
/// If any acknowledgement is not handled (before the minimum number of acknowledgements is received), the acknowledgement will be cancelled.
pub struct Min<const N: usize = 1> {
    state: Arc<AckState<N>>,
    acknowledged: bool,
}

impl<const N: usize> Clone for Min<N> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            acknowledged: false,
        }
    }
}

impl<const N: usize> std::fmt::Debug for Min<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Min").field("listeners", &N).finish()
    }
}

impl<const N: usize> Drop for Min<N> {
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

impl<const N: usize> Acknowledgement for Min<N> {
    type Error = oneshot::Canceled;
    type Waiter = oneshot::Receiver<()>;

    fn handle() -> (Self, Self::Waiter) {
        assert!(N > 0, "requires N > 0 listeners");
        let (tx, rx) = oneshot::channel();
        (
            Self {
                state: Arc::new(AckState::new(tx)),
                acknowledged: false,
            },
            rx,
        )
    }

    fn acknowledge(mut self) {
        self.state.acknowledge();
        self.acknowledged = true;
    }
}

/// State for the [Min] acknowledgement.
struct AckState<const N: usize> {
    sender: Mutex<Option<oneshot::Sender<()>>>,
    remaining: AtomicUsize,
}

impl<const N: usize> AckState<N> {
    /// Create a new acknowledgement state.
    fn new(sender: oneshot::Sender<()>) -> Self {
        Self {
            sender: Mutex::new(Some(sender)),
            remaining: AtomicUsize::new(N),
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
                // On last acknowledgement, fallthrough to send.
            }
            Ok(_) | Err(_) => return,
        }

        // Send the acknowledgement to the waiter.
        if let Some(tx) = self.sender.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }

    /// Cancel the acknowledgement.
    fn cancel(&self) {
        if let Some(tx) = self.sender.lock().unwrap().take() {
            drop(tx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Acknowledgement, Min};
    use futures::{future::FusedFuture, FutureExt};

    #[test]
    fn acknowledges_after_all_listeners() {
        let (ack1, waiter) = Min::<2>::handle();
        let waiter = waiter.fuse();
        let ack2 = ack1.clone();
        ack1.acknowledge();
        assert!(!waiter.is_terminated());
        ack2.acknowledge();
        assert!(waiter.now_or_never().unwrap().is_ok());
    }

    #[test]
    fn cancels_on_drop_before_ack() {
        let (ack, waiter) = Min::<1>::handle();
        drop(ack);
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    fn extra_acknowledgements_noop() {
        let (ack, waiter) = Min::<1>::handle();
        ack.clone().acknowledge();
        ack.acknowledge(); // should be idempotent
        assert!(waiter.now_or_never().unwrap().is_ok());
    }
}
