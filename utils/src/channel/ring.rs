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

use crate::sync::Mutex;
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
/// Buffered items and the receiver's waker may own a [Sender]. A sender's destructor locks this
/// state, so waker callbacks and the destructors of items and wakers run only while the lock is
/// released.
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
#[derive(Debug)]
pub struct Receiver<T> {
    shared: Arc<Mutex<Shared<T>>>,
}

impl<T> Receiver<T> {
    /// Receives the next item from the channel.
    pub async fn recv(&mut self) -> Option<T> {
        futures::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Attempts to receive an item without waiting.
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
}

impl<T> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Cloning a waker runs its callback, so clone before taking the lock.
        let waker = cx.waker().clone();

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
