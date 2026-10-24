//! Monotonic epoch readiness signal.
//!
//! A [`Fence`] marks epochs as ready and its [`Gate`] waits for them. No epoch
//! is ready until the first mark, not even epoch zero. The [`reshare::Actor`]
//! marks an epoch once its [`Registrar::register`] call for that epoch
//! resolves, and the [`orchestrator::Actor`] waits on the gate before entering
//! any epoch, including the one it starts in. The orchestrator therefore reads
//! an epoch's scheme only after the reshare actor has registered it.
//!
//! [`reshare::Actor`]: super::reshare::Actor
//! [`Registrar::register`]: super::Registrar::register
//! [`orchestrator::Actor`]: super::orchestrator::Actor

use commonware_consensus::types::Epoch;
use commonware_utils::sync::Mutex;
use futures::task::AtomicWaker;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
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
    /// Creates a fence and its gate with no epoch ready.
    pub fn new() -> (Self, Gate) {
        let state = Arc::new(State::new());
        (
            Self {
                state: state.clone(),
            },
            Gate { state },
        )
    }

    /// Marks every epoch at or below `epoch` as ready.
    ///
    /// Marking an epoch at or below the highest ready epoch has no effect.
    pub fn mark(&self, epoch: Epoch) {
        self.state.mark(epoch);
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
    /// Returns a future that resolves once the fence marks `epoch` or a later
    /// epoch.
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
        if self
            .gate
            .state
            .ready
            .lock()
            .is_some_and(|ready| self.epoch <= ready)
        {
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
    ready: Mutex<Option<Epoch>>,
    closed: AtomicBool,
    waker: AtomicWaker,
}

impl State {
    const fn new() -> Self {
        Self {
            ready: Mutex::new(None),
            closed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    fn mark(&self, epoch: Epoch) {
        let mut ready = self.ready.lock();
        if ready.is_some_and(|ready| ready >= epoch) {
            return;
        }
        *ready = Some(epoch);
        drop(ready);
        self.waker.wake();
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
    use futures::{
        FutureExt as _,
        task::{ArcWake, waker_ref},
    };
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

    #[test]
    fn waits_for_first_mark() {
        let (fence, mut gate) = Fence::new();

        // No epoch is ready before the first mark, not even epoch zero.
        let mut waiter = Box::pin(gate.wait(Epoch::zero()));
        let wakes = WakeCounter::new();
        let waker = waker_ref(&wakes);
        let mut context = Context::from_waker(&waker);
        assert!(waiter.as_mut().poll(&mut context).is_pending());
        assert_eq!(wakes.count(), 0);

        // The first mark wakes the waiter and readies epoch zero.
        fence.mark(Epoch::zero());
        assert_eq!(wakes.count(), 1);
        assert_eq!(waiter.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    }

    #[test_async]
    async fn resolves_sequential_waiters() {
        let (fence, mut gate) = Fence::new();

        let first = gate.wait(Epoch::new(1));
        fence.mark(Epoch::new(1));
        first.await.unwrap();

        let second = gate.wait(Epoch::new(2));
        fence.mark(Epoch::new(2));
        second.await.unwrap();
    }

    #[test]
    fn waits_for_requested_epoch() {
        let (fence, mut gate) = Fence::new();
        let mut waiter = Box::pin(gate.wait(Epoch::new(2)));
        let second_wakes = WakeCounter::new();

        let second_waker = waker_ref(&second_wakes);
        let mut second_context = Context::from_waker(&second_waker);
        assert!(waiter.as_mut().poll(&mut second_context).is_pending());

        fence.mark(Epoch::new(1));

        assert!(waiter.as_mut().poll(&mut second_context).is_pending());

        let wakes_before = second_wakes.count();
        fence.mark(Epoch::new(2));

        assert!(waiter.as_mut().poll(&mut second_context).is_ready());
        assert!(second_wakes.count() > wakes_before);
    }

    #[test]
    fn producer_drop_wakes_waiter_with_closed() {
        let (fence, mut gate) = Fence::new();
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
        let (fence, mut gate) = Fence::new();
        fence.mark(Epoch::new(1));

        drop(fence);

        gate.wait(Epoch::new(1)).await.unwrap();
    }

    #[test]
    fn mark_does_not_regress_epoch() {
        let (fence, mut gate) = Fence::new();
        fence.mark(Epoch::new(2));
        fence.mark(Epoch::new(1));

        assert_eq!(gate.wait(Epoch::new(2)).now_or_never(), Some(Ok(())));
    }
}
