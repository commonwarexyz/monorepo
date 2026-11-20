//! Bounded and unbounded channels whose receives take part in the
//! cooperative polling budget.
//!
//! These wrap tokio's receivers. Tokio makes a task yield after a budget of
//! channel operations only inside a tokio runtime. Elsewhere a task fed by a
//! fast producer never yields, holds its worker, and delays every other task
//! on it. Every receive poll here asks [`crate::coop::exhausted`] first and
//! charges one unit for every ready result, a value or the end of the
//! channel. Under an executor that installs a [`crate::coop`] budget around
//! each task poll, a poll therefore completes at most [`crate::coop::BUDGET`]
//! receives before its receives return pending. On tokio, the tokio channel
//! inside spends tokio's own budget instead, which is why these receivers do
//! not use [`crate::coop::poll_budgeted`]. [`Receiver::try_recv`] and
//! [`UnboundedReceiver::try_recv`] are never budgeted, so they are the way to
//! probe a receiver without waiting.
//!
//! A receive returns a named future whose poll is always inlined, so a task
//! awaiting it calls tokio's receive directly, as it would with tokio's own
//! receiver, and finds the value where tokio wrote it. The charge that
//! follows a ready result is a load and a store with no call that could
//! unwind while the value is held.
//!
//! Senders, permits and weak senders are tokio's own types, re-exported
//! unchanged. Sends spend no budget. A bounded send waits only while the
//! channel is full, so a send loop is not bounded by the budget.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "these wrappers are the budgeted interface to tokio's channel"
)]

use crate::coop;
pub use inner::{
    OwnedPermit, Permit, PermitIterator, Sender, UnboundedSender, WeakSender, WeakUnboundedSender,
    error,
};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc as inner;

/// Create a bounded channel whose receiver takes part in the cooperative
/// budget.
///
/// # Panics
///
/// Panics if `buffer` is zero, as tokio's channel does.
pub fn channel<T>(buffer: usize) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = inner::channel(buffer);
    (sender, Receiver { inner: receiver })
}

/// Create an unbounded channel whose receiver takes part in the cooperative
/// budget.
pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (sender, receiver) = inner::unbounded_channel();
    (sender, UnboundedReceiver { inner: receiver })
}

/// Receiving half of a bounded channel.
pub struct Receiver<T> {
    /// Tokio receiver that every operation forwards to.
    inner: inner::Receiver<T>,
}

impl<T> Receiver<T> {
    /// Receive the next value, or `None` once every sender is dropped and the
    /// channel is drained. Cancel safe: dropping the future before it
    /// completes loses no value.
    #[inline(always)]
    pub const fn recv(&mut self) -> Recv<'_, T> {
        Recv { receiver: self }
    }

    /// Poll for the next value. Once the current poll's cooperative budget
    /// is spent, this wakes the task and returns pending without taking a
    /// value. Each ready result, a value or the end of the channel, spends
    /// one unit of the budget.
    #[inline(always)]
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        coop::poll_counted(cx, |cx| self.inner.poll_recv(cx))
    }

    /// Receive a value if one is queued right now, whatever the cooperative
    /// budget.
    pub fn try_recv(&mut self) -> Result<T, error::TryRecvError> {
        self.inner.try_recv()
    }

    /// Receive the next value, blocking the calling thread until one arrives
    /// or every sender is dropped, whatever the cooperative budget.
    ///
    /// # Panics
    ///
    /// Panics when called inside a tokio runtime context.
    pub fn blocking_recv(&mut self) -> Option<T> {
        self.inner.blocking_recv()
    }

    /// Stop accepting values while draining what is queued.
    pub fn close(&mut self) {
        self.inner.close()
    }

    /// Whether every sender is dropped or [`Self::close`] was called. Values
    /// sent before may still be queued.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Queued values.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether no value is queued.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Future returned by [`Receiver::recv`].
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Recv<'a, T> {
    /// Receiver polled on each poll of this future.
    receiver: &'a mut Receiver<T>,
}

impl<T> Future for Recv<'_, T> {
    type Output = Option<T>;

    #[inline(always)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}

impl<T> fmt::Debug for Recv<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recv").finish_non_exhaustive()
    }
}

/// Receiving half of an unbounded channel.
pub struct UnboundedReceiver<T> {
    /// Tokio receiver that every operation forwards to.
    inner: inner::UnboundedReceiver<T>,
}

impl<T> UnboundedReceiver<T> {
    /// Receive the next value, or `None` once every sender is dropped and the
    /// channel is drained. Cancel safe: dropping the future before it
    /// completes loses no value.
    #[inline(always)]
    pub const fn recv(&mut self) -> UnboundedRecv<'_, T> {
        UnboundedRecv { receiver: self }
    }

    /// Poll for the next value. Once the current poll's cooperative budget
    /// is spent, this wakes the task and returns pending without taking a
    /// value. Each ready result, a value or the end of the channel, spends
    /// one unit of the budget.
    #[inline(always)]
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        coop::poll_counted(cx, |cx| self.inner.poll_recv(cx))
    }

    /// Receive a value if one is queued right now, whatever the cooperative
    /// budget.
    pub fn try_recv(&mut self) -> Result<T, error::TryRecvError> {
        self.inner.try_recv()
    }

    /// Receive the next value, blocking the calling thread until one arrives
    /// or every sender is dropped, whatever the cooperative budget.
    ///
    /// # Panics
    ///
    /// Panics when called inside a tokio runtime context.
    pub fn blocking_recv(&mut self) -> Option<T> {
        self.inner.blocking_recv()
    }

    /// Stop accepting values while draining what is queued.
    pub fn close(&mut self) {
        self.inner.close()
    }

    /// Whether every sender is dropped or [`Self::close`] was called. Values
    /// sent before may still be queued.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Queued values.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether no value is queued.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T> fmt::Debug for UnboundedReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Future returned by [`UnboundedReceiver::recv`].
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct UnboundedRecv<'a, T> {
    /// Receiver polled on each poll of this future.
    receiver: &'a mut UnboundedReceiver<T>,
}

impl<T> Future for UnboundedRecv<'_, T> {
    type Output = Option<T>;

    #[inline(always)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}

impl<T> fmt::Debug for UnboundedRecv<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnboundedRecv").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::poll_fn,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Wake, Waker},
    };

    /// Poll `future` once with a no-op waker.
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let mut cx = Context::from_waker(Waker::noop());
        future.poll(&mut cx)
    }

    /// Poll `future` to completion, entering a fresh cooperative scope for
    /// each poll as an executor does, and count how many times it returns
    /// pending.
    fn drive_in_scope<F: Future>(mut future: Pin<&mut F>) -> (F::Output, usize) {
        let mut suspensions = 0;
        loop {
            let _scope = coop::Scope::enter();
            match poll_once(future.as_mut()) {
                Poll::Ready(output) => return (output, suspensions),
                Poll::Pending => suspensions += 1,
            }
        }
    }

    #[test]
    fn test_receiver_yields_after_budget() {
        // Queue more than one budget of values.
        let (sender, mut receiver) = channel::<u32>(coop::BUDGET as usize + 8);
        for value in 0..coop::BUDGET + 4 {
            sender.try_send(value).unwrap();
        }

        let _scope = coop::Scope::enter();
        // The budget worth of values arrives without yielding.
        for expected in 0..coop::BUDGET {
            assert_eq!(
                poll_once(pin!(receiver.recv())),
                Poll::Ready(Some(expected))
            );
        }
        // The next receive yields, and keeps yielding until the poll ends.
        assert!(poll_once(pin!(receiver.recv())).is_pending());
        assert!(poll_once(pin!(receiver.recv())).is_pending());

        // A fresh poll delivers the next value.
        drop(_scope);
        let _scope = coop::Scope::enter();
        assert_eq!(
            poll_once(pin!(receiver.recv())),
            Poll::Ready(Some(coop::BUDGET))
        );
    }

    /// Two receivers that never run dry, drained by one future the way a
    /// select over channels does, cannot keep their task inside one poll.
    #[test]
    fn test_two_ready_receivers_still_suspend_the_task() {
        // Fill two receivers with many budgets of values each.
        let (first_tx, mut first) = unbounded_channel::<u32>();
        let (second_tx, mut second) = unbounded_channel::<u32>();
        let total = 10 * coop::BUDGET;
        for value in 0..total {
            first_tx.send(value).unwrap();
            second_tx.send(value).unwrap();
        }

        // Drain both from one future.
        let mut received = 0;
        let drain = poll_fn(|cx| {
            // Alternate receivers, moving on when one is pending, as a
            // biased select does. Both return pending only once the budget
            // is spent.
            loop {
                let mut progressed = false;
                if let Poll::Ready(Some(_)) = first.poll_recv(cx) {
                    received += 1;
                    progressed = true;
                }
                if let Poll::Ready(Some(_)) = second.poll_recv(cx) {
                    received += 1;
                    progressed = true;
                }
                if received == 2 * total {
                    return Poll::Ready(());
                }
                if !progressed {
                    return Poll::Pending;
                }
            }
        });
        let ((), suspensions) = drive_in_scope(pin!(drain));

        assert_eq!(received, 2 * total);
        // Every poll delivered at most a budget of values.
        assert!(
            suspensions >= (2 * total / coop::BUDGET) as usize - 1,
            "{suspensions}"
        );
    }

    /// Receivers that find nothing spend nothing, so a ready receiver behind
    /// many empty ones is still served within the same poll.
    #[test]
    fn test_empty_receivers_spend_no_budget() {
        // Create more empty receivers than one budget, and one ready receiver.
        let mut empty: Vec<Receiver<u32>> = Vec::new();
        let mut senders = Vec::new();
        for _ in 0..2 * coop::BUDGET {
            let (sender, receiver) = channel::<u32>(1);
            senders.push(sender);
            empty.push(receiver);
        }
        let (ready_tx, mut ready) = channel::<u32>(1);
        ready_tx.try_send(7).unwrap();

        // Poll every empty receiver in one poll.
        let _scope = coop::Scope::enter();
        for receiver in &mut empty {
            assert!(poll_once(pin!(receiver.recv())).is_pending());
        }

        // The ready receiver is still served.
        assert_eq!(poll_once(pin!(ready.recv())), Poll::Ready(Some(7)));
    }

    /// A receive loop that keeps polling a closed channel cannot hold its
    /// task: the end of the channel spends budget like a value.
    #[test]
    fn test_closed_receives_spend_the_budget() {
        // Close one bounded and one unbounded channel.
        let (sender, mut bounded) = channel::<u32>(1);
        drop(sender);
        let (sender, mut unbounded) = unbounded_channel::<u32>();
        drop(sender);

        // Each closed receive spends one unit, half the budget on each channel.
        let _scope = coop::Scope::enter();
        for _ in 0..coop::BUDGET / 2 {
            assert_eq!(poll_once(pin!(bounded.recv())), Poll::Ready(None));
            assert_eq!(poll_once(pin!(unbounded.recv())), Poll::Ready(None));
        }

        // The spent budget now refuses both until the next poll.
        assert!(coop::exhausted());
        assert!(poll_once(pin!(bounded.recv())).is_pending());
        assert!(poll_once(pin!(unbounded.recv())).is_pending());
    }

    #[test]
    fn test_unbounded_receiver_yields_after_budget() {
        // Queue one value more than a budget.
        let (sender, mut receiver) = unbounded_channel::<u32>();
        for value in 0..coop::BUDGET + 1 {
            sender.send(value).unwrap();
        }

        // One poll delivers the budget and then yields.
        let _scope = coop::Scope::enter();
        for expected in 0..coop::BUDGET {
            assert_eq!(
                poll_once(pin!(receiver.recv())),
                Poll::Ready(Some(expected))
            );
        }
        assert!(poll_once(pin!(receiver.recv())).is_pending());

        // A fresh poll delivers the rest.
        drop(_scope);
        let _scope = coop::Scope::enter();
        assert_eq!(
            poll_once(pin!(receiver.recv())),
            Poll::Ready(Some(coop::BUDGET))
        );
    }

    /// Without a scope nothing yields.
    #[test]
    fn test_unconstrained_outside_an_executor_scope() {
        // Queue several budgets of values.
        let (sender, mut receiver) = unbounded_channel::<u32>();
        for value in 0..4 * coop::BUDGET {
            sender.send(value).unwrap();
        }

        // Every receive is ready.
        for expected in 0..4 * coop::BUDGET {
            assert_eq!(
                poll_once(pin!(receiver.recv())),
                Poll::Ready(Some(expected))
            );
        }
    }

    /// Counts the wakes it receives.
    struct CountingWaker(
        /// Wakes received so far.
        AtomicUsize,
    );

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A receive refused for a spent budget wakes its task and leaves the
    /// value queued for the next poll.
    #[test]
    fn test_spent_budget_wakes_and_keeps_the_value() {
        // Queue one value more than a budget and count wakes.
        let (sender, mut receiver) = channel::<u32>(coop::BUDGET as usize + 1);
        for value in 0..=coop::BUDGET {
            sender.try_send(value).unwrap();
        }
        let wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);

        // Spend the budget on delivered values.
        let scope = coop::Scope::enter();
        for expected in 0..coop::BUDGET {
            assert_eq!(
                pin!(receiver.recv()).poll(&mut cx),
                Poll::Ready(Some(expected))
            );
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        // The refused receive wakes once and keeps the value queued.
        assert!(pin!(receiver.recv()).poll(&mut cx).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(receiver.len(), 1);

        // A fresh poll delivers the kept value.
        drop(scope);
        let _scope = coop::Scope::enter();
        assert_eq!(
            pin!(receiver.recv()).poll(&mut cx),
            Poll::Ready(Some(coop::BUDGET))
        );
    }

    /// A manual receive poll in a spent poll is pending, and a nested
    /// `block_on` of a receive completes while it holds the thread's
    /// [`coop::Ownership`].
    #[test]
    fn test_spent_poll_and_block_on_under_ownership() {
        // Queue a value and spend the budget.
        let (sender, mut receiver) = unbounded_channel::<u32>();
        sender.send(7).unwrap();
        let _scope = coop::Scope::enter();
        for _ in 0..coop::BUDGET {
            coop::charge();
        }
        assert!(coop::exhausted());

        // A plain poll is refused.
        assert!(poll_once(pin!(receiver.recv())).is_pending());

        // A nested executor under ownership receives the value.
        let value = {
            let _ownership = coop::Ownership::take();
            futures::executor::block_on(receiver.recv())
        };
        assert_eq!(value, Some(7));
        assert!(coop::exhausted(), "the spent budget is back");
    }

    /// A refill starts a fresh budget for the next poll, and a receiver
    /// probed with try_recv ignores a spent one.
    #[test]
    fn test_refill_and_try_recv_ignore_a_spent_budget() {
        // Queue more than two budgets of values.
        let (sender, mut receiver) = unbounded_channel::<u32>();
        for value in 0..2 * coop::BUDGET + 1 {
            sender.send(value).unwrap();
        }

        // Spend the budget on delivered values.
        let _scope = coop::Scope::enter();
        for expected in 0..coop::BUDGET {
            assert_eq!(
                poll_once(pin!(receiver.recv())),
                Poll::Ready(Some(expected))
            );
        }
        assert!(poll_once(pin!(receiver.recv())).is_pending());

        // try_recv still delivers under a spent budget.
        assert_eq!(receiver.try_recv(), Ok(coop::BUDGET));
        assert!(coop::exhausted(), "try_recv neither charges nor refunds");

        // A refill lets receives deliver again.
        coop::refill();
        assert_eq!(
            poll_once(pin!(receiver.recv())),
            Poll::Ready(Some(coop::BUDGET + 1))
        );
    }

    #[test]
    fn test_named_receive_futures_keep_auto_traits_for_pinned_payloads() {
        fn assert_traits<T: Send + Sync + Unpin>() {}

        assert_traits::<Recv<'static, std::marker::PhantomPinned>>();
        assert_traits::<UnboundedRecv<'static, std::marker::PhantomPinned>>();
    }

    #[test]
    fn test_bounded_recv_can_be_recreated_after_empty_pending() {
        // Two wakers for two receive futures created one after the other.
        let (sender, mut receiver) = channel::<u32>(1);
        let first = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let second = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);

        // Park a receive with each waker, dropping each future.
        let _scope = coop::Scope::enter();
        {
            let mut receive = receiver.recv();
            assert!(Pin::new(&mut receive).poll(&mut first_cx).is_pending());
        }
        {
            let mut receive = receiver.recv();
            assert!(Pin::new(&mut receive).poll(&mut second_cx).is_pending());
        }

        // A send wakes only the latest registered waker.
        sender.try_send(7).unwrap();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);

        // A new receive future gets the value.
        let mut receive = receiver.recv();
        assert_eq!(
            Pin::new(&mut receive).poll(&mut second_cx),
            Poll::Ready(Some(7))
        );
    }

    #[test]
    fn test_unbounded_recv_can_be_recreated_after_empty_pending() {
        // Two wakers for two receive futures created one after the other.
        let (sender, mut receiver) = unbounded_channel::<u32>();
        let first = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let second = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);

        // Park a receive with each waker, dropping each future.
        let _scope = coop::Scope::enter();
        {
            let mut receive = receiver.recv();
            assert!(Pin::new(&mut receive).poll(&mut first_cx).is_pending());
        }
        {
            let mut receive = receiver.recv();
            assert!(Pin::new(&mut receive).poll(&mut second_cx).is_pending());
        }

        // A send wakes only the latest registered waker.
        sender.send(7).unwrap();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);

        // A new receive future gets the value.
        let mut receive = receiver.recv();
        assert_eq!(
            Pin::new(&mut receive).poll(&mut second_cx),
            Poll::Ready(Some(7))
        );
    }
}
