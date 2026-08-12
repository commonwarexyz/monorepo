//! Utilities for providing acknowledgement.

use crate::sync::Mutex;
use core::{
    fmt::Debug,
    mem,
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
    /// Hold an extra acknowledgement of `self` until `later` completes.
    ///
    /// Every clone of `later` must be acknowledged before the extra acknowledgement is released.
    /// Canceling `later` cancels `self`. Chaining acknowledgements in order lets a FIFO consumer
    /// observe the chain as one ready prefix. Dependencies must be acyclic.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
    /// use futures::FutureExt as _;
    ///
    /// let (first, mut first_waiter) = Exact::handle();
    /// let (second, second_waiter) = Exact::handle();
    /// first.defer_until(&second);
    /// first.acknowledge();
    /// assert!((&mut first_waiter).now_or_never().is_none());
    /// second.acknowledge();
    /// assert!((&mut first_waiter).now_or_never().unwrap().is_ok());
    /// assert!(second_waiter.now_or_never().unwrap().is_ok());
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `self` and `later` refer to the same acknowledgement.
    pub fn defer_until(&self, later: &Self) {
        assert!(
            !Arc::ptr_eq(&self.state, &later.state),
            "an acknowledgement cannot depend on itself",
        );
        self.state.increment();
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
        ExactState::cancel_chain(self.state.clone());
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
        ExactState::acknowledge_chain(self.state.clone());
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
    /// Predecessor states whose extra acknowledgement is owned by this state.
    deferred: OnceLock<Box<Mutex<Vec<Arc<Self>>>>>,
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

    /// Acknowledge the completion of a task.
    fn acknowledge(&self) -> Option<Vec<Arc<Self>>> {
        // Decrement the remaining count and check if it was the last acknowledgement.
        if self.remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return None;
        }

        Some(self.take_deferred())
    }

    /// Increment the remaining count.
    fn increment(&self) {
        self.remaining.fetch_add(1, Ordering::AcqRel);
    }

    /// Hold `acknowledgement` until this state completes or is canceled.
    fn defer(&self, predecessor: Arc<Self>) {
        let deferred = self
            .deferred
            .get_or_init(|| Box::new(Mutex::new(Vec::new())));
        let mut deferred = deferred.lock();
        if self.canceled.load(Ordering::Acquire) {
            drop(deferred);
            Self::cancel_chain(predecessor);
            return;
        }
        deferred.push(predecessor);
    }

    fn take_deferred(&self) -> Vec<Arc<Self>> {
        self.deferred
            .get()
            .map_or_else(Vec::new, |deferred| mem::take(&mut *deferred.lock()))
    }

    /// Cancel the acknowledgement and return acknowledgements linked to its completion.
    fn cancel(&self) -> Vec<Arc<Self>> {
        self.canceled.store(true, Ordering::Release);
        self.take_deferred()
    }

    fn acknowledge_chain(state: Arc<Self>) {
        let Some(mut pending) = state.acknowledge() else {
            return;
        };
        if pending.is_empty() {
            state.waker.wake();
            return;
        }

        let mut completed = vec![state];
        while let Some(state) = pending.pop() {
            if let Some(mut deferred) = state.acknowledge() {
                completed.push(state);
                pending.append(&mut deferred);
            }
        }
        // Every linked state is complete before any waiter can observe the chain.
        for state in completed.into_iter().rev() {
            state.waker.wake();
        }
    }

    fn cancel_chain(state: Arc<Self>) {
        let mut pending = state.cancel();
        if pending.is_empty() {
            state.waker.wake();
            return;
        }
        let mut canceled = vec![state];
        while let Some(state) = pending.pop() {
            let mut deferred = state.cancel();
            canceled.push(state);
            pending.append(&mut deferred);
        }
        // Every linked state is canceled before any waiter can observe the chain.
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
    fn deferred_chain_wakes_fifo_head_after_the_tail() {
        struct TailObserver {
            waiters: crate::sync::Mutex<[super::ExactWaiter; 2]>,
        }

        impl std::task::Wake for TailObserver {
            fn wake(self: std::sync::Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                for waiter in &mut *self.waiters.lock() {
                    assert!(
                        waiter.now_or_never().unwrap().is_ok(),
                        "waking the FIFO head must expose the deferred tail",
                    );
                }
            }
        }

        let (first, mut first_waiter) = Exact::handle();
        let (second, second_waiter) = Exact::handle();
        let (third, third_waiter) = Exact::handle();
        first.defer_until(&second);
        second.defer_until(&third);
        let observer = std::sync::Arc::new(TailObserver {
            waiters: crate::sync::Mutex::new([second_waiter, third_waiter]),
        });
        let waker = std::task::Waker::from(observer);
        let mut context = std::task::Context::from_waker(&waker);
        assert!(
            std::pin::Pin::new(&mut first_waiter)
                .poll(&mut context)
                .is_pending()
        );

        first.acknowledge();
        second.acknowledge();
        third.acknowledge();
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
