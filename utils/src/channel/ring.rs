//! A bounded mpsc channel that drops the oldest item when full instead of applying backpressure.
//!
//! This is useful for scenarios where you want to keep the most recent items and can
//! tolerate losing older ones, such as real-time data streams or status updates where
//! only the latest values matter.
//!
//! # Example
//!
//! ```
//! use futures::executor::block_on;
//! use futures::{SinkExt, StreamExt};
//! use commonware_utils::{NZUsize, channel::ring};
//!
//! block_on(async {
//!     let (mut sender, mut receiver) = ring::channel::<u32>(NZUsize!(2));
//!
//!     // Fill the channel
//!     sender.send(1).await.unwrap();
//!     sender.send(2).await.unwrap();
//!
//!     // This will drop the oldest item (1) and insert 3
//!     sender.send(3).await.unwrap();
//!
//!     // Receive the remaining items
//!     assert_eq!(receiver.next().await, Some(2));
//!     assert_eq!(receiver.next().await, Some(3));
//! });
//! ```

use crate::{coop, sync::Mutex};
use core::num::NonZeroUsize;
use futures::{Sink, Stream, stream::FusedStream};
use std::{
    collections::VecDeque,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use thiserror::Error;

/// Error returned when sending to a channel whose receiver has been dropped.
#[derive(Debug, Error)]
#[error("channel closed")]
pub struct ChannelClosed;

/// Error returned by [`Receiver::try_recv`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TryRecvError {
    /// The channel currently has no buffered items, but senders still exist.
    #[error("channel empty")]
    Empty,
    /// The channel is empty and all senders have been dropped.
    #[error("channel closed")]
    Disconnected,
}

/// State shared by the senders and the receiver of a channel.
///
/// Never drop items or run waker callbacks while holding the mutex protecting this state.
/// They can drop a [Sender], which tries to take the same lock and deadlocks.
#[derive(Debug)]
struct Shared<T> {
    buffer: VecDeque<T>,
    capacity: usize,
    receiver_waker: Option<Waker>,
    sender_count: usize,
    receiver_dropped: bool,
}

/// The sending half of a ring channel.
///
/// Implements [`Sink`] for sending items. Use [`SinkExt::send`](futures::SinkExt::send)
/// to send items asynchronously.
///
/// This type can be cloned to create multiple producers for the same channel.
/// The channel remains open until all senders are dropped.
#[derive(Debug)]
pub struct Sender<T> {
    shared: Arc<Mutex<Shared<T>>>,
}

impl<T> Sender<T> {
    /// Returns whether the receiver has been dropped.
    ///
    /// If this returns `true`, subsequent sends will fail with [`ChannelClosed`].
    pub fn is_closed(&self) -> bool {
        let shared = self.shared.lock();
        shared.receiver_dropped
    }

    /// Sends an item, dropping the oldest buffered item if the channel is full.
    ///
    /// Returns `false` once the receiver has been dropped.
    pub fn send_lossy(&self, item: T) -> bool {
        let mut shared = self.shared.lock();

        // Nothing will ever read a buffered item once the receiver is gone.
        if shared.receiver_dropped {
            return false;
        }

        // Make room by evicting the oldest item rather than blocking the sender.
        let old_item = if shared.buffer.len() >= shared.capacity {
            shared.buffer.pop_front()
        } else {
            None
        };

        // Buffer the item and take the receiver's waker so it can be woken
        // once the lock is released.
        shared.buffer.push_back(item);
        let waker = shared.receiver_waker.take();
        drop(shared);

        // Drop the old item after the lock is released.
        drop(old_item);

        // Wake a receiver parked on an empty buffer.
        if let Some(w) = waker {
            w.wake();
        }

        true
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let mut shared = self.shared.lock();
        shared.sender_count += 1;
        drop(shared);

        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let mut shared = self.shared.lock();
        shared.sender_count -= 1;
        let waker = if shared.sender_count == 0 {
            shared.receiver_waker.take()
        } else {
            None
        };
        drop(shared);

        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl<T> Sink<T> for Sender<T> {
    type Error = ChannelClosed;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let shared = self.shared.lock();
        if shared.receiver_dropped {
            return Poll::Ready(Err(ChannelClosed));
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.send_lossy(item).then_some(()).ok_or(ChannelClosed)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // No buffering in the sender - items are sent immediately to the shared buffer
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Closing is handled by Drop
        Poll::Ready(Ok(()))
    }
}

/// The receiving half of a ring channel.
///
/// Implements [`Stream`] and [`FusedStream`] for receiving items. Use
/// [`StreamExt::next`](futures::StreamExt::next) to receive items asynchronously.
///
/// The stream terminates (returns `None`) when all senders have been dropped
/// and all buffered items have been consumed.
///
/// Each ready result of [`Stream::poll_next`], an item or the end of the
/// stream, spends one unit of the cooperative budget that bounds the current
/// task poll (see [`crate::coop`]): the commonware budget on the io_uring and
/// deterministic runtimes, tokio's own budget on tokio. Once that budget is
/// spent the receiver returns pending without removing an item and the task
/// is woken again, so the item stays buffered for the next poll. An empty
/// receiver costs nothing, and [`Receiver::try_recv`] is never budgeted.
#[derive(Debug)]
pub struct Receiver<T> {
    shared: Arc<Mutex<Shared<T>>>,
}

impl<T> Receiver<T> {
    /// Receives the next item from the channel.
    #[inline]
    pub async fn recv(&mut self) -> Option<T> {
        futures::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Attempts to receive an item without waiting, whatever the cooperative
    /// budget.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let mut shared = self.shared.lock();
        if let Some(item) = shared.buffer.pop_front() {
            return Ok(item);
        }
        if shared.sender_count == 0 {
            return Err(TryRecvError::Disconnected);
        }
        Err(TryRecvError::Empty)
    }

    /// Polls for the next item without consulting the cooperative budget.
    ///
    /// Returns `None` once every sender is gone and the buffer is empty.
    /// Otherwise registers the waker of `cx` when the buffer is empty.
    #[inline(always)]
    fn poll_next_inner(&self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        // Cloning a waker runs its callback, so clone before taking the lock.
        let waker = cx.waker().clone();

        // Deliver the oldest buffered item, or end the stream once every sender is gone.
        let mut shared = self.shared.lock();
        if let Some(item) = shared.buffer.pop_front() {
            return Poll::Ready(Some(item));
        }
        if shared.sender_count == 0 {
            return Poll::Ready(None);
        }

        // Register under the same lock that found the channel empty and open, so the next send or
        // the last sender's drop wakes this task. The replaced waker is destroyed after unlocking.
        let replaced = shared.receiver_waker.replace(waker);
        drop(shared);
        drop(replaced);
        Poll::Pending
    }
}

impl<T> Stream for Receiver<T> {
    type Item = T;

    #[inline(always)]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // The budget is checked before the buffer is touched, so a spent
        // budget never removes an item. Nothing was registered or removed, so
        // the wake a spent budget issues is all the next poll needs. An item
        // or the end of the stream spends one unit, an empty receiver nothing.
        coop::poll_budgeted(cx, |cx| self.poll_next_inner(cx))
    }
}

impl<T> FusedStream for Receiver<T> {
    fn is_terminated(&self) -> bool {
        let shared = self.shared.lock();
        shared.sender_count == 0 && shared.buffer.is_empty()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut shared = self.shared.lock();
        shared.receiver_dropped = true;

        // Nothing reads the unread items or the waker once the receiver is gone, and a sender owned
        // by either one keeps the channel open until they are released.
        let buffer = mem::take(&mut shared.buffer);
        let waker = shared.receiver_waker.take();
        drop(shared);
        drop(buffer);
        drop(waker);
    }
}

/// Creates a new ring channel with the specified capacity.
///
/// Returns a ([`Sender`], [`Receiver`]) pair. The sender can be cloned to create
/// multiple producers.
pub fn channel<T>(capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Mutex::new(Shared {
        buffer: VecDeque::with_capacity(capacity.get()),
        capacity: capacity.get(),
        receiver_waker: None,
        sender_count: 1,
        receiver_dropped: false,
    }));

    let sender = Sender {
        shared: shared.clone(),
    };
    let receiver = Receiver { shared };

    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NZUsize;
    use futures::{SinkExt, StreamExt, executor::block_on};
    use std::{sync::Weak, task::Wake};

    #[test]
    fn test_basic_send_recv() {
        block_on(async {
            let (mut sender, mut receiver) = channel::<i32>(NZUsize!(10));

            sender.send(1).await.unwrap();
            sender.send(2).await.unwrap();
            sender.send(3).await.unwrap();

            assert_eq!(receiver.next().await, Some(1));
            assert_eq!(receiver.next().await, Some(2));
            assert_eq!(receiver.next().await, Some(3));
        });
    }

    #[test]
    fn test_overflow_drops_oldest() {
        block_on(async {
            let (mut sender, mut receiver) = channel::<i32>(NZUsize!(2));

            sender.send(1).await.unwrap();
            sender.send(2).await.unwrap();
            sender.send(3).await.unwrap(); // Should drop 1
            sender.send(4).await.unwrap(); // Should drop 2

            assert_eq!(receiver.next().await, Some(3));
            assert_eq!(receiver.next().await, Some(4));
        });
    }

    #[test]
    fn test_send_after_receiver_dropped() {
        block_on(async {
            let (mut sender, receiver) = channel::<i32>(NZUsize!(10));
            drop(receiver);

            let err = sender.send(1).await.unwrap_err();
            assert!(matches!(err, ChannelClosed));
        });
    }

    #[test]
    fn test_recv_after_sender_dropped() {
        block_on(async {
            let (mut sender, mut receiver) = channel::<i32>(NZUsize!(10));

            sender.send(1).await.unwrap();
            sender.send(2).await.unwrap();
            drop(sender);

            assert_eq!(receiver.next().await, Some(1));
            assert_eq!(receiver.next().await, Some(2));
            assert_eq!(receiver.next().await, None);
        });
    }

    #[test]
    fn test_stream_collect() {
        block_on(async {
            let (mut sender, receiver) = channel::<i32>(NZUsize!(10));

            sender.send(1).await.unwrap();
            sender.send(2).await.unwrap();
            sender.send(3).await.unwrap();
            drop(sender);

            let items: Vec<_> = receiver.collect().await;
            assert_eq!(items, vec![1, 2, 3]);
        });
    }

    #[test]
    fn test_clone_sender() {
        block_on(async {
            let (mut sender1, mut receiver) = channel::<i32>(NZUsize!(10));
            let mut sender2 = sender1.clone();

            sender1.send(1).await.unwrap();
            sender2.send(2).await.unwrap();

            assert_eq!(receiver.next().await, Some(1));
            assert_eq!(receiver.next().await, Some(2));
        });
    }

    #[test]
    fn test_sender_drop_with_clones() {
        block_on(async {
            let (sender1, mut receiver) = channel::<i32>(NZUsize!(10));
            let mut sender2 = sender1.clone();

            drop(sender1);

            // Channel should still be open because sender2 exists
            sender2.send(1).await.unwrap();
            assert_eq!(receiver.next().await, Some(1));

            drop(sender2);
            // Now channel should be closed
            assert_eq!(receiver.next().await, None);
        });
    }

    #[test]
    fn test_capacity_one() {
        block_on(async {
            let (mut sender, mut receiver) = channel::<i32>(NZUsize!(1));

            sender.send(1).await.unwrap();
            sender.send(2).await.unwrap(); // Drops 1

            assert_eq!(receiver.next().await, Some(2));

            sender.send(1).await.unwrap();
            sender.send(2).await.unwrap(); // Drops 1
            sender.send(3).await.unwrap(); // Drops 2

            assert_eq!(receiver.next().await, Some(3));
        });
    }

    #[test]
    fn test_send_all() {
        block_on(async {
            let (mut sender, receiver) = channel::<i32>(NZUsize!(10));

            let items = futures::stream::iter(vec![1, 2, 3]);
            sender.send_all(&mut items.map(Ok)).await.unwrap();
            drop(sender);

            let received: Vec<_> = receiver.collect().await;
            assert_eq!(received, vec![1, 2, 3]);
        });
    }

    #[test]
    fn test_fused_stream() {
        use futures::stream::FusedStream;

        block_on(async {
            let (mut sender, mut receiver) = channel::<i32>(NZUsize!(10));

            assert!(!receiver.is_terminated());

            sender.send(1).await.unwrap();
            assert!(!receiver.is_terminated());

            drop(sender);
            assert!(!receiver.is_terminated()); // Still has item in buffer

            assert_eq!(receiver.next().await, Some(1));
            assert!(receiver.is_terminated()); // Now terminated

            // Calling next after termination returns None
            assert_eq!(receiver.next().await, None);
            assert!(receiver.is_terminated());
        });
    }

    #[test]
    fn test_is_closed() {
        block_on(async {
            let (sender, receiver) = channel::<i32>(NZUsize!(10));

            assert!(!sender.is_closed());

            drop(receiver);
            assert!(sender.is_closed());
        });
    }

    /// A value that owns a sender, as a task waiting on the receiver might. While the channel holds
    /// a probe as a buffered item or as the receiver's waker, the probe's sender keeps the channel
    /// open, so only dropping the receiver can release it.
    ///
    /// A probe dropped while the channel lock is held fails the test.
    struct Probe(Option<Sender<Arc<Self>>>);

    impl Probe {
        fn new(sender: &Sender<Arc<Self>>) -> Arc<Self> {
            Arc::new(Self(Some(sender.clone())))
        }
    }

    #[expect(clippy::manual_noop_waker, reason = "a probe waker must own a sender")]
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            // The sender's destructor takes the channel lock. A probe that finds the lock held
            // leaks its sender and fails, since dropping the sender would deadlock.
            let sender = self.0.take().expect("a probe must still own its sender");
            if sender.shared.try_lock().is_none() {
                mem::forget(sender);
                panic!("senders must be dropped outside the channel lock");
            }
        }
    }

    /// Parks `receiver` on a fresh [Probe] waker that only the channel holds, and returns a handle
    /// that upgrades until the channel releases the waker.
    fn register(sender: &Sender<Arc<Probe>>, receiver: &mut Receiver<Arc<Probe>>) -> Weak<Probe> {
        let probe = Probe::new(sender);
        let weak = Arc::downgrade(&probe);
        let waker = Waker::from(probe);
        assert!(
            receiver
                .poll_next_unpin(&mut Context::from_waker(&waker))
                .is_pending(),
            "an empty open channel must be pending"
        );
        drop(waker);
        assert!(
            weak.upgrade().is_some(),
            "a pending receiver must register its waker"
        );
        weak
    }

    #[test]
    fn test_receiver_drop_releases_unread_items() {
        let (sender, receiver) = channel(NZUsize!(1));
        let item = Probe::new(&sender);
        let weak = Arc::downgrade(&item);
        assert!(sender.send_lossy(item));

        drop(receiver);
        assert!(
            weak.upgrade().is_none(),
            "receiver drop must release unread items"
        );
    }

    #[test]
    fn test_receiver_drop_releases_waker() {
        let (sender, mut receiver) = channel(NZUsize!(1));
        let shared = Arc::downgrade(&sender.shared);
        let waker = register(&sender, &mut receiver);

        drop(receiver);
        assert!(
            waker.upgrade().is_none(),
            "receiver drop must release its waker"
        );

        // With the waker's sender gone, dropping the last sender frees the channel.
        drop(sender);
        assert!(
            shared.upgrade().is_none(),
            "the channel must not outlive its handles"
        );
    }

    #[test]
    fn test_replaced_waker_dropped_outside_lock() {
        let (sender, mut receiver) = channel(NZUsize!(1));
        let first = register(&sender, &mut receiver);

        // Registering a second waker destroys the first.
        let second = register(&sender, &mut receiver);
        assert!(
            first.upgrade().is_none(),
            "a replaced waker must be released"
        );

        // The send wakes the second waker, consuming it outside the lock, and buffers the item.
        assert!(sender.send_lossy(Probe::new(&sender)));
        assert!(
            second.upgrade().is_none(),
            "a send must consume the registered waker"
        );
        assert!(
            receiver.try_recv().is_ok(),
            "the channel must deliver after its waker is replaced"
        );
    }
}

#[cfg(test)]
mod coop_tests {
    use super::*;
    use crate::NZUsize;
    use futures::task::{ArcWake, waker_ref};
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// A waker that counts how often it is woken.
    #[derive(Default)]
    struct Wakes(
        /// Number of wakes so far.
        AtomicUsize,
    );

    impl Wakes {
        /// Returns the number of wakes so far.
        fn count(&self) -> usize {
            self.0.load(Ordering::Acquire)
        }
    }

    impl ArcWake for Wakes {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Polls `receiver` once with a waker that counts into `wakes`.
    fn poll<T>(receiver: &mut Receiver<T>, wakes: &Arc<Wakes>) -> Poll<Option<T>> {
        let waker = waker_ref(wakes);
        let mut cx = Context::from_waker(&waker);
        Pin::new(receiver).poll_next(&mut cx)
    }

    /// Spend the whole budget of the current scope.
    fn exhaust() {
        for _ in 0..coop::BUDGET {
            coop::charge();
        }
        assert!(coop::exhausted());
    }

    #[test]
    fn test_unconstrained_outside_a_scope() {
        // Buffer ten budgets of items without entering a scope.
        let total = 10 * coop::BUDGET as usize;
        let (sender, mut receiver) = channel::<usize>(NZUsize!(total));
        for value in 0..total {
            assert!(sender.send_lossy(value));
        }
        let wakes = Arc::new(Wakes::default());

        // Every item is delivered without a yield.
        for value in 0..total {
            assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(value)));
        }
        assert_eq!(wakes.count(), 0);
    }

    #[test]
    fn test_exhaustion_preserves_buffer_and_order() {
        // Buffer three items.
        let (sender, mut receiver) = channel::<u32>(NZUsize!(4));
        for value in 1..=3 {
            assert!(sender.send_lossy(value));
        }
        let wakes = Arc::new(Wakes::default());

        {
            let _scope = coop::Scope::enter();
            exhaust();

            // A spent budget removes nothing, however often it is asked.
            for _ in 0..3 {
                assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
            }
            assert_eq!(receiver.shared.lock().buffer.len(), 3);

            // The non-polling path is not bounded by the budget.
            assert_eq!(receiver.try_recv(), Ok(1));
        }

        // A fresh poll delivers what was kept, in order.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(2)));
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(3)));
    }

    #[test]
    fn test_exhaustion_wakes_the_polling_task_each_time() {
        // Buffer an item and spend the budget.
        let (sender, mut receiver) = channel::<u32>(NZUsize!(2));
        assert!(sender.send_lossy(7));
        let wakes = Arc::new(Wakes::default());
        let _scope = coop::Scope::enter();
        exhaust();
        assert_eq!(wakes.count(), 0);

        // Every exhausted poll wakes the task once.
        assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
        assert_eq!(wakes.count(), 1);
        assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
        assert_eq!(wakes.count(), 2);

        // The exhausted path parks nothing: no waker was registered.
        assert!(receiver.shared.lock().receiver_waker.is_none());
    }

    #[test]
    fn test_exhausted_poll_keeps_a_registered_waker_working() {
        let (sender, mut receiver) = channel::<u32>(NZUsize!(2));
        let wakes = Arc::new(Wakes::default());
        {
            let _scope = coop::Scope::enter();
            // Park on an empty channel, then run out of budget in a later poll.
            assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
            assert_eq!(wakes.count(), 0);
        }

        {
            let _scope = coop::Scope::enter();
            exhaust();
            assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
            assert_eq!(wakes.count(), 1);
        }

        // A send still wakes the parked waker, so no wake is lost.
        assert!(sender.send_lossy(1));
        assert_eq!(wakes.count(), 2);

        // The next poll receives the item.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(1)));
    }

    #[test]
    fn test_refill_makes_progress_without_loss() {
        // Buffer more than three budgets of items and close the channel.
        let budget = coop::BUDGET as usize;
        let total = 3 * budget + 5;
        let (sender, mut receiver) = channel::<usize>(NZUsize!(total));
        for value in 0..total {
            assert!(sender.send_lossy(value));
        }
        drop(sender);
        let wakes = Arc::new(Wakes::default());

        // Poll until the stream ends, as an executor would.
        let mut received = Vec::new();
        let mut polls = 0;
        loop {
            // One task poll, one fresh budget.
            let _scope = coop::Scope::enter();
            polls += 1;
            let mut delivered = 0;
            let done = loop {
                match poll(&mut receiver, &wakes) {
                    Poll::Ready(Some(value)) => {
                        received.push(value);
                        delivered += 1;
                    }
                    Poll::Ready(None) => break true,
                    Poll::Pending => break false,
                }
            };
            assert!(delivered <= budget);
            if done {
                break;
            }
        }

        // Every item arrived, in order.
        assert_eq!(received, (0..total).collect::<Vec<_>>());

        // Every full budget ended in one self-wake.
        assert_eq!(wakes.count(), 3);
        assert_eq!(polls, 4);
    }

    #[test]
    fn test_empty_receiver_does_not_charge() {
        let budget = coop::BUDGET as usize;
        let (sender, mut receiver) = channel::<usize>(NZUsize!(budget));
        let wakes = Arc::new(Wakes::default());
        let _scope = coop::Scope::enter();

        // Poll the empty receiver well past one budget.
        for _ in 0..10 * budget {
            assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
        }

        // Parking is not progress: no budget spent and no self-wake.
        assert!(!coop::exhausted());
        assert_eq!(wakes.count(), 0);

        // The whole budget is still there for the receiver that has work.
        for value in 0..budget {
            assert!(sender.send_lossy(value));
        }
        // The sends woke the parked waker once.
        assert_eq!(wakes.count(), 1);

        // Exactly one budget of items is delivered.
        for value in 0..budget {
            assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(value)));
        }
        assert!(coop::exhausted());
    }

    #[test]
    fn test_closed_empty_receiver_spends_the_budget() {
        let (sender, mut receiver) = channel::<u32>(NZUsize!(2));
        drop(sender);
        let wakes = Arc::new(Wakes::default());
        let _scope = coop::Scope::enter();

        // End the stream once per unit of the budget.
        for _ in 0..coop::BUDGET {
            assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(None));
        }

        // The budget is spent, so the next poll defers with a self-wake.
        assert!(coop::exhausted());
        assert_eq!(wakes.count(), 0);
        assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
        assert_eq!(wakes.count(), 1);
    }

    #[test]
    fn test_exhaustion_keeps_buffered_items_of_a_closed_channel() {
        // Buffer two items and close the channel.
        let (sender, mut receiver) = channel::<u32>(NZUsize!(2));
        assert!(sender.send_lossy(1));
        assert!(sender.send_lossy(2));
        drop(sender);
        let wakes = Arc::new(Wakes::default());

        {
            let _scope = coop::Scope::enter();
            exhaust();

            // Neither an item nor the end of the stream is delivered.
            assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
            assert_eq!(wakes.count(), 1);
            assert!(!receiver.is_terminated());
        }

        // A fresh budget delivers both items, then the end of the stream.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(1)));
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(2)));
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(None));
        assert!(receiver.is_terminated());
    }

    #[test]
    fn test_overflow_while_exhausted_still_drops_oldest() {
        // Fill the channel.
        let (sender, mut receiver) = channel::<u32>(NZUsize!(2));
        assert!(sender.send_lossy(1));
        assert!(sender.send_lossy(2));
        let wakes = Arc::new(Wakes::default());

        {
            let _scope = coop::Scope::enter();
            exhaust();

            // Senders are not charged and eviction is unchanged.
            assert!(sender.send_lossy(3));
            assert_eq!(poll(&mut receiver, &wakes), Poll::Pending);
        }

        // The oldest item was evicted and the two newest remain.
        let _scope = coop::Scope::enter();
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(2)));
        assert_eq!(poll(&mut receiver, &wakes), Poll::Ready(Some(3)));
    }

    #[test]
    fn test_recv_loop_yields_once_per_budget() {
        // Buffer three budgets of items and close the channel.
        let budget = coop::BUDGET as usize;
        let total = 3 * budget;
        let (sender, mut receiver) = channel::<usize>(NZUsize!(total));
        for value in 0..total {
            assert!(sender.send_lossy(value));
        }
        drop(sender);

        // Drive an ordinary receive loop to completion.
        let mut future = std::pin::pin!(async move {
            let mut received = 0;
            while let Some(value) = receiver.recv().await {
                assert_eq!(value, received);
                received += 1;
            }
            received
        });
        let wakes = Arc::new(Wakes::default());
        let waker = waker_ref(&wakes);
        let mut cx = Context::from_waker(&waker);
        let mut suspensions = 0;
        let received = loop {
            // An executor enters one scope per task poll.
            let _scope = coop::Scope::enter();
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(received) => break received,
                Poll::Pending => suspensions += 1,
            }
        };

        // The loop yielded once per budget, each time with a self-wake.
        assert_eq!(received, total);
        assert_eq!(suspensions, 3);
        assert_eq!(wakes.count(), 3);
    }

    /// Outside a commonware scope, receives spend tokio's own budget, so a fed
    /// receive loop on tokio still yields.
    #[test]
    fn test_tokio_budget_bounds_receives_outside_a_commonware_scope() {
        // Buffer more items than tokio lets one poll take, and close the channel.
        let total = 1024;
        let (sender, mut receiver) = channel::<usize>(NZUsize!(total));
        for value in 0..total {
            assert!(sender.send_lossy(value));
        }
        drop(sender);

        // Drain them from a tokio task, counting the items each poll receives.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let per_poll = runtime.block_on(async move {
            tokio::spawn(async move {
                let mut per_poll = Vec::new();
                futures::future::poll_fn(|cx| {
                    per_poll.push(0);
                    loop {
                        match Pin::new(&mut receiver).poll_next(cx) {
                            Poll::Ready(Some(_)) => *per_poll.last_mut().unwrap() += 1,
                            Poll::Ready(None) => return Poll::Ready(()),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                })
                .await;
                per_poll
            })
            .await
            .unwrap()
        });

        // Every item arrived, over several polls that each stayed within
        // tokio's budget of 128.
        assert_eq!(per_poll.iter().sum::<usize>(), total);
        assert!(per_poll.len() > 1, "{per_poll:?}");
        assert!(per_poll.iter().all(|&count| count <= 128), "{per_poll:?}");
    }
}
