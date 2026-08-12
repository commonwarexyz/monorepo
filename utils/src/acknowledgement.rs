//! Utilities for providing acknowledgement.

use crate::sync::Mutex;
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
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
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
/// Dropping an acknowledgement cancels the waiter.
pub struct Exact {
    state: Arc<ExactState>,
    acknowledged: bool,
}

impl Exact {
    /// Delay `self` until every clone of `later` is acknowledged.
    ///
    /// Cancellation propagates from `later` to `self`. Registering the same
    /// dependency more than once is a no-op. Dependencies must be acyclic.
    ///
    /// # Panics
    ///
    /// Panics if `self` and `later` refer to the same acknowledgement or a
    /// different dependency remains attached to `later`.
    pub fn defer_until(&self, later: &Self) {
        assert!(
            !Arc::ptr_eq(&self.state, &later.state),
            "an acknowledgement cannot depend on itself",
        );
        later.state.defer(self.state.clone());
    }
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
        self.acknowledged = true;
        ExactState::cancel_chain(&self.state);
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
        self.acknowledged = true;
        ExactState::acknowledge_chain(&self.state);
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
    deferred: OnceLock<Box<Mutex<Option<Arc<Self>>>>>,
}

impl ExactState {
    /// Create a new acknowledgement state with a remaining count of 1.
    const fn new() -> Self {
        Self {
            remaining: AtomicUsize::new(1),
            canceled: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            deferred: OnceLock::new(),
        }
    }

    /// Increment the remaining count.
    fn increment(&self) {
        self.remaining.fetch_add(1, Ordering::AcqRel);
    }

    fn defer(&self, predecessor: Arc<Self>) {
        let deferred = self.deferred.get_or_init(|| Box::new(Mutex::new(None)));
        let mut deferred = deferred.lock();
        if self.canceled.load(Ordering::Acquire) {
            drop(deferred);
            Self::cancel_chain(&predecessor);
            return;
        }
        if let Some(existing) = deferred.as_ref() {
            assert!(
                Arc::ptr_eq(existing, &predecessor),
                "different acknowledgement dependency already set",
            );
            return;
        }
        predecessor.increment();
        *deferred = Some(predecessor);
    }

    fn take_deferred(&self) -> Option<Arc<Self>> {
        self.deferred
            .get()
            .and_then(|deferred| deferred.lock().take())
    }

    fn acknowledge_chain(root: &Arc<Self>) {
        if root.remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let Some(mut state) = root.take_deferred() else {
            root.waker.wake();
            return;
        };

        let mut completed = vec![root.clone()];
        loop {
            if state.remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
                break;
            }
            let predecessor = state.take_deferred();
            completed.push(state);
            let Some(predecessor) = predecessor else {
                break;
            };
            state = predecessor;
        }

        // Every linked state is complete before the FIFO head wakes.
        for state in completed.into_iter().rev() {
            state.waker.wake();
        }
    }

    fn cancel_chain(root: &Arc<Self>) {
        root.canceled.store(true, Ordering::Release);
        let Some(mut state) = root.take_deferred() else {
            root.waker.wake();
            return;
        };

        let mut canceled = vec![root.clone()];
        loop {
            state.canceled.store(true, Ordering::Release);
            let predecessor = state.take_deferred();
            canceled.push(state);
            let Some(predecessor) = predecessor else {
                break;
            };
            state = predecessor;
        }

        // Every linked state is canceled before the FIFO head wakes.
        for state in canceled.into_iter().rev() {
            state.waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Acknowledgement, Exact};
    use futures::{FutureExt, future::FusedFuture};
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
    fn deferred_acknowledgement_waits_for_all_later_clones() {
        let (first, mut first_waiter) = Exact::handle();
        let (second, mut second_waiter) = Exact::handle();
        let second_clone = second.clone();
        first.defer_until(&second);

        first.acknowledge();
        second.acknowledge();
        assert!((&mut first_waiter).now_or_never().is_none());
        assert!((&mut second_waiter).now_or_never().is_none());

        second_clone.acknowledge();
        assert!((&mut first_waiter).now_or_never().unwrap().is_ok());
        assert!((&mut second_waiter).now_or_never().unwrap().is_ok());
    }

    #[test]
    fn canceling_later_acknowledgement_cancels_deferred_acknowledgement() {
        let (first, mut first_waiter) = Exact::handle();
        let (second, mut second_waiter) = Exact::handle();
        let (third, mut third_waiter) = Exact::handle();
        first.defer_until(&second);
        second.defer_until(&third);

        first.acknowledge();
        second.acknowledge();
        drop(third);
        assert!((&mut first_waiter).now_or_never().unwrap().is_err());
        assert!((&mut second_waiter).now_or_never().unwrap().is_err());
        assert!((&mut third_waiter).now_or_never().unwrap().is_err());
    }

    #[test]
    fn deferred_acknowledgement_inherits_existing_cancellation() {
        let (first, mut first_waiter) = Exact::handle();
        let (second, mut second_waiter) = Exact::handle();
        drop(second.clone());

        first.defer_until(&second);
        first.acknowledge();
        assert!((&mut first_waiter).now_or_never().unwrap().is_err());
        assert!((&mut second_waiter).now_or_never().unwrap().is_err());
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
