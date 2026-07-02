//! Epoch readiness gate used to synchronize the [`Provider`] and the [`orchestrator::Actor`].
//!
//! [`Provider`]: commonware_cryptography::certificate::Provider
//! [`orchestrator::Actor`]: super::orchestrator::Actor

use commonware_consensus::types::Epoch;
use futures::task::AtomicWaker;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

pub struct Fence {
    state: Arc<State>,
}

impl Fence {
    pub fn new(epoch: Epoch) -> (Self, Gate) {
        let state = Arc::new(State::new(epoch));
        (
            Self {
                state: state.clone(),
            },
            Gate { state },
        )
    }

    pub fn epoch(&self) -> Epoch {
        self.state.epoch()
    }

    pub fn mark(&self, epoch: Epoch) -> Epoch {
        self.state.mark(epoch)
    }
}

pub struct Gate {
    state: Arc<State>,
}

impl Gate {
    pub fn epoch(&self) -> Epoch {
        self.state.epoch()
    }

    pub const fn wait(&mut self, epoch: Epoch) -> Waiter<'_> {
        Waiter { gate: self, epoch }
    }
}

pub struct Waiter<'a> {
    gate: &'a Gate,
    epoch: Epoch,
}

impl Future for Waiter<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.gate.state.waker.register(cx.waker());

        if self.epoch <= self.gate.state.epoch() {
            return Poll::Ready(());
        }

        Poll::Pending
    }
}

struct State {
    epoch: AtomicU64,
    waker: AtomicWaker,
}

impl State {
    const fn new(epoch: Epoch) -> Self {
        Self {
            epoch: AtomicU64::new(epoch.get()),
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
}

#[cfg(test)]
mod tests {
    use super::Fence;
    use commonware_consensus::types::Epoch;
    use commonware_macros::test_async;
    use futures::task::{waker_ref, ArcWake};
    use std::{
        future::Future,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::Context,
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
        gate.wait(Epoch::new(2)).await;
    }

    #[test_async]
    async fn resolves_after_mark() {
        let (fence, mut gate) = Fence::new(Epoch::zero());
        assert_eq!(fence.mark(Epoch::new(1)), Epoch::new(1));
        assert_eq!(fence.epoch(), Epoch::new(1));
        assert_eq!(gate.epoch(), Epoch::new(1));

        gate.wait(Epoch::new(1)).await;
    }

    #[test_async]
    async fn resolves_sequential_waiters() {
        let (fence, mut gate) = Fence::new(Epoch::zero());

        let first = gate.wait(Epoch::new(1));
        fence.mark(Epoch::new(1));
        first.await;

        let second = gate.wait(Epoch::new(2));
        fence.mark(Epoch::new(2));
        second.await;
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

    #[test_async]
    async fn mark_does_not_regress_epoch() {
        let (fence, mut gate) = Fence::new(Epoch::new(2));

        assert_eq!(fence.mark(Epoch::new(1)), Epoch::new(2));
        assert_eq!(fence.epoch(), Epoch::new(2));
        gate.wait(Epoch::new(2)).await;
    }
}
