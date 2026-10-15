//! Monotonic epoch readiness signal.
//!
//! A [`Fence`] marks epochs as ready and its [`Gate`] waits for them. The
//! [`reshare::Actor`] marks an epoch once its [`Registrar::register`] call for
//! that epoch resolves, and the [`orchestrator::Actor`] enters an epoch only
//! after the gate reaches it.
//!
//! [`reshare::Actor`]: super::reshare::Actor
//! [`Registrar::register`]: super::Registrar::register
//! [`orchestrator::Actor`]: super::orchestrator::Actor

use commonware_consensus::types::Epoch;
use futures::task::AtomicWaker;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

/// The [`Fence`] was dropped before the requested epoch was ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("epoch fence closed")]
pub struct Closed;

/// Producer side of an epoch readiness signal.
///
/// Dropping the fence closes its [`Gate`].
pub struct Fence {
    state: Arc<State>,
}

impl Fence {
    /// Creates a fence and its gate with every epoch at or below `epoch` ready.
    ///
    /// The orchestrator may enter such an epoch without waiting, so the
    /// consensus provider must already hold a scheme for any of them it can
    /// start in (for example, the genesis epoch or the state-synced epoch).
    pub fn new(epoch: Epoch) -> (Self, Gate) {
        let state = Arc::new(State::new(epoch));
        (
            Self {
                state: state.clone(),
            },
            Gate { state },
        )
    }

    /// Returns the highest ready epoch.
    pub fn epoch(&self) -> Epoch {
        self.state.epoch()
    }

    /// Marks every epoch at or below `epoch` as ready and returns the highest ready epoch.
    ///
    /// Marking an epoch at or below the highest ready epoch has no effect.
    pub fn mark(&self, epoch: Epoch) -> Epoch {
        self.state.mark(epoch)
    }
}

impl Drop for Fence {
    fn drop(&mut self) {
        self.state.close();
    }
}

/// Consumer side of an epoch readiness signal.
pub struct Gate {
    state: Arc<State>,
}

impl Gate {
    /// Returns the highest ready epoch.
    pub fn epoch(&self) -> Epoch {
        self.state.epoch()
    }

    /// Returns a future that resolves once `epoch` is ready.
    ///
    /// The future returns [`Closed`] if the [`Fence`] is dropped before `epoch` is
    /// ready. An epoch that is already ready still resolves successfully after the
    /// fence is dropped.
    pub const fn wait(&mut self, epoch: Epoch) -> Waiter<'_> {
        Waiter { gate: self, epoch }
    }
}

/// Future returned by [`Gate::wait`].
pub struct Waiter<'a> {
    gate: &'a Gate,
    epoch: Epoch,
}

impl Future for Waiter<'_> {
    type Output = Result<(), Closed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.gate.state.waker.register(cx.waker());

        let closed = self.gate.state.closed.load(Ordering::Acquire);
        if self.epoch <= self.gate.state.epoch() {
            return Poll::Ready(Ok(()));
        }

        if closed {
            Poll::Ready(Err(Closed))
        } else {
            Poll::Pending
        }
    }
}

struct State {
    epoch: AtomicU64,
    closed: AtomicBool,
    waker: AtomicWaker,
}

impl State {
    const fn new(epoch: Epoch) -> Self {
        Self {
            epoch: AtomicU64::new(epoch.get()),
            closed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    fn epoch(&self) -> Epoch {
        Epoch::new(self.epoch.load(Ordering::Acquire))
    }

    fn mark(&self, epoch: Epoch) -> Epoch {
        let previous = self.epoch.fetch_max(epoch.get(), Ordering::AcqRel);
        let latest = Epoch::new(previous.max(epoch.get()));
        if epoch.get() > previous {
            self.waker.wake();
        }
        latest
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::{Closed, Fence};
    use commonware_consensus::types::Epoch;
    use commonware_macros::test_async;
    use futures::task::{ArcWake, waker_ref};
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    struct WakeCounter(AtomicUsize);

    impl WakeCounter {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicUsize::new(0)))
        }

        fn count(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl ArcWake for WakeCounter {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test_async]
    async fn resolves_immediately_for_ready_epoch() {
        let (_fence, mut gate) = Fence::new(Epoch::new(2));
        gate.wait(Epoch::new(2)).await.unwrap();
    }

    #[test_async]
    async fn resolves_after_mark() {
        let (fence, mut gate) = Fence::new(Epoch::zero());
        assert_eq!(fence.mark(Epoch::new(1)), Epoch::new(1));
        assert_eq!(fence.epoch(), Epoch::new(1));
        assert_eq!(gate.epoch(), Epoch::new(1));

        gate.wait(Epoch::new(1)).await.unwrap();
    }

    #[test_async]
    async fn resolves_sequential_waiters() {
        let (fence, mut gate) = Fence::new(Epoch::zero());

        let first = gate.wait(Epoch::new(1));
        fence.mark(Epoch::new(1));
        first.await.unwrap();

        let second = gate.wait(Epoch::new(2));
        fence.mark(Epoch::new(2));
        second.await.unwrap();
    }

    #[test]
    fn waits_for_requested_epoch() {
        let (fence, mut gate) = Fence::new(Epoch::zero());
        let mut waiter = Box::pin(gate.wait(Epoch::new(2)));
        let second_wakes = WakeCounter::new();

        let second_waker = waker_ref(&second_wakes);
        let mut second_context = Context::from_waker(&second_waker);
        assert!(waiter.as_mut().poll(&mut second_context).is_pending());

        fence.mark(Epoch::new(1));

        assert!(waiter.as_mut().poll(&mut second_context).is_pending());

        fence.mark(Epoch::new(2));

        assert!(waiter.as_mut().poll(&mut second_context).is_ready());
        assert!(second_wakes.count() > 0);
    }

    #[test]
    fn producer_drop_wakes_waiter_with_closed() {
        let (fence, mut gate) = Fence::new(Epoch::zero());
        let mut waiter = Box::pin(gate.wait(Epoch::new(1)));
        let wakes = WakeCounter::new();

        let waker = waker_ref(&wakes);
        let mut context = Context::from_waker(&waker);
        assert!(waiter.as_mut().poll(&mut context).is_pending());

        drop(fence);

        assert_eq!(wakes.count(), 1);
        assert_eq!(waiter.as_mut().poll(&mut context), Poll::Ready(Err(Closed)));
    }

    #[test_async]
    async fn ready_epoch_still_resolves_after_producer_drop() {
        let (fence, mut gate) = Fence::new(Epoch::new(1));

        drop(fence);

        gate.wait(Epoch::new(1)).await.unwrap();
    }

    #[test_async]
    async fn mark_does_not_regress_epoch() {
        let (fence, mut gate) = Fence::new(Epoch::new(2));

        assert_eq!(fence.mark(Epoch::new(1)), Epoch::new(2));
        assert_eq!(fence.epoch(), Epoch::new(2));
        gate.wait(Epoch::new(2)).await.unwrap();
    }
}
