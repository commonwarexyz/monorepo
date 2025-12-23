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
//! use commonware_utils::{NZUsize, channels::ring};
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

use core::num::NonZeroUsize;
use futures::{stream::FusedStream, Sink, Stream};
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use thiserror::Error;

/// Error returned when sending to a channel whose receiver has been dropped.
#[derive(Debug, Error)]
#[error("channel closed")]
pub struct ChannelClosed;

struct Shared<T: Send + Sync> {
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
pub struct Sender<T: Send + Sync> {
    shared: Arc<Mutex<Shared<T>>>,
}

impl<T: Send + Sync> Sender<T> {
    /// Returns whether the receiver has been dropped.
    ///
    /// If this returns `true`, subsequent sends will fail with [`ChannelClosed`].
    pub fn is_closed(&self) -> bool {
        let shared = self.shared.lock().unwrap();
        shared.receiver_dropped
    }
}

impl<T: Send + Sync> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let mut shared = self.shared.lock().unwrap();
        shared.sender_count += 1;
        drop(shared);

        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T: Send + Sync> Drop for Sender<T> {
    fn drop(&mut self) {
        let Ok(mut shared) = self.shared.lock() else {
            return;
        };
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

impl<T: Send + Sync> Sink<T> for Sender<T> {
    type Error = ChannelClosed;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let shared = self.shared.lock().unwrap();
        if shared.receiver_dropped {
            return Poll::Ready(Err(ChannelClosed));
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let mut shared = self.shared.lock().unwrap();

        if shared.receiver_dropped {
            return Err(ChannelClosed);
        }

        let old_item = if shared.buffer.len() >= shared.capacity {
            shared.buffer.pop_front()
        } else {
            None
        };

        shared.buffer.push_back(item);
        let waker = shared.receiver_waker.take();
        drop(shared);

        // Drop the old item after the lock is released to avoid potential mutex poisoning
        drop(old_item);

        if let Some(w) = waker {
            w.wake();
        }

        Ok(())
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
pub struct Receiver<T: Send + Sync> {
    shared: Arc<Mutex<Shared<T>>>,
}

impl<T: Send + Sync> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut shared = self.shared.lock().unwrap();

        if let Some(item) = shared.buffer.pop_front() {
            return Poll::Ready(Some(item));
        }

        if shared.sender_count == 0 {
            return Poll::Ready(None);
        }

        if !shared
            .receiver_waker
            .as_ref()
            .is_some_and(|w| w.will_wake(cx.waker()))
        {
            shared.receiver_waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl<T: Send + Sync> FusedStream for Receiver<T> {
    fn is_terminated(&self) -> bool {
        let shared = self.shared.lock().unwrap();
        shared.sender_count == 0 && shared.buffer.is_empty()
    }
}

impl<T: Send + Sync> Drop for Receiver<T> {
    fn drop(&mut self) {
        let Ok(mut shared) = self.shared.lock() else {
            return;
        };
        shared.receiver_dropped = true;
    }
}

/// Creates a new ring channel with the specified capacity.
///
/// Returns a ([`Sender`], [`Receiver`]) pair. The sender can be cloned to create
/// multiple producers.
pub fn channel<T: Send + Sync>(capacity: NonZeroUsize) -> (Sender<T>, Receiver<T>) {
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
    use futures::{executor::block_on, SinkExt, StreamExt};

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
}
