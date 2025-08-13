//! Utilities for working with channels.

use futures::{
    channel::mpsc::{self, Receiver, SendError, Sender, TrySendError},
    SinkExt, Stream, StreamExt,
};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

/// A guard that tracks message delivery. When all clones are dropped, the message is marked as delivered.
#[derive(Clone)]
pub struct DeliveryGuard {
    _inner: Arc<DeliveryGuardInner>,
}

struct DeliveryGuardInner {
    sequence: u64,
    _batch_id: Option<u64>,
    tracker: Arc<DeliveryTrackerState>,
}

struct DeliveryTrackerState {
    watermark: Arc<AtomicU64>,
    batch_counts: Arc<Mutex<HashMap<u64, usize>>>,
    pending_sequences: Arc<Mutex<HashMap<u64, bool>>>,
}

impl Drop for DeliveryGuardInner {
    fn drop(&mut self) {
        let mut pending = self.tracker.pending_sequences.lock().unwrap();
        if let Some(delivered) = pending.get_mut(&self.sequence) {
            *delivered = true;
        }

        // Update batch count if this message had a batch ID
        if let Some(bid) = self._batch_id {
            let mut batch_counts = self.tracker.batch_counts.lock().unwrap();
            if let Some(count) = batch_counts.get_mut(&bid) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    batch_counts.remove(&bid);
                }
            }
        }

        // Update watermark if possible
        let mut current_watermark = self.tracker.watermark.load(Ordering::Acquire);
        while let Some(delivered) = pending.get(&(current_watermark + 1)) {
            if *delivered {
                pending.remove(&(current_watermark + 1));
                current_watermark += 1;
                self.tracker
                    .watermark
                    .store(current_watermark, Ordering::Release);
            } else {
                break;
            }
        }
    }
}

/// A tracked message containing the actual data and a delivery guard.
pub struct TrackedMessage<T> {
    pub data: T,
    pub guard: DeliveryGuard,
}

/// Tracks delivery state across all messages.
///
/// Note on sequence overflow: Using u64 for sequence numbers provides ample headroom.
/// At 100 messages per nanosecond, it would take ~5.85 years to overflow.
/// For systems requiring longer uptime without restart, consider implementing
/// sequence number wrapping with careful watermark handling.
#[derive(Clone)]
struct DeliveryTracker {
    state: Arc<DeliveryTrackerState>,
    next_sequence: Arc<AtomicU64>,
}

impl DeliveryTracker {
    fn new() -> Self {
        Self {
            state: Arc::new(DeliveryTrackerState {
                watermark: Arc::new(AtomicU64::new(0)),
                batch_counts: Arc::new(Mutex::new(HashMap::new())),
                pending_sequences: Arc::new(Mutex::new(HashMap::new())),
            }),
            next_sequence: Arc::new(AtomicU64::new(1)),
        }
    }

    fn create_guard(&self, batch_id: Option<u64>) -> DeliveryGuard {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);

        // Track this sequence as not yet delivered
        self.state
            .pending_sequences
            .lock()
            .unwrap()
            .insert(sequence, false);

        // Update batch count if provided
        if let Some(bid) = batch_id {
            let mut batch_counts = self.state.batch_counts.lock().unwrap();
            *batch_counts.entry(bid).or_insert(0) += 1;
        }

        DeliveryGuard {
            _inner: Arc::new(DeliveryGuardInner {
                sequence,
                _batch_id: batch_id,
                tracker: self.state.clone(),
            }),
        }
    }
}

/// A sender that wraps `Sender` and tracks message delivery.
pub struct TrackedSender<T> {
    inner: Sender<TrackedMessage<T>>,
    tracker: DeliveryTracker,
}

impl<T> TrackedSender<T> {
    /// Sends a message with an optional batch ID and returns a delivery guard.
    pub async fn send(
        &mut self,
        msg: T,
        batch_id: Option<u64>,
    ) -> Result<DeliveryGuard, SendError> {
        let guard = self.tracker.create_guard(batch_id);
        let tracked_msg = TrackedMessage {
            data: msg,
            guard: guard.clone(),
        };

        self.inner.send(tracked_msg).await?;

        Ok(guard)
    }

    /// Tries to send a message without blocking.
    pub fn try_send(
        &mut self,
        msg: T,
        batch_id: Option<u64>,
    ) -> Result<DeliveryGuard, TrySendError<TrackedMessage<T>>> {
        let guard = self.tracker.create_guard(batch_id);
        let tracked_msg = TrackedMessage {
            data: msg,
            guard: guard.clone(),
        };

        self.inner.try_send(tracked_msg)?;

        Ok(guard)
    }

    /// Returns the current delivery watermark (highest sequence number where all messages up to and including it have been delivered).
    pub fn watermark(&self) -> u64 {
        self.tracker.state.watermark.load(Ordering::Acquire)
    }

    /// Returns the number of pending messages for a specific batch ID.
    pub fn batch_pending_count(&self, batch_id: u64) -> usize {
        self.tracker
            .state
            .batch_counts
            .lock()
            .unwrap()
            .get(&batch_id)
            .copied()
            .unwrap_or(0)
    }
}

impl<T> Clone for TrackedSender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tracker: self.tracker.clone(),
        }
    }
}

/// A receiver that wraps `Receiver` and provides tracked messages.
pub struct TrackedReceiver<T> {
    inner: Receiver<TrackedMessage<T>>,
}

impl<T> TrackedReceiver<T> {
    /// Receives the next message.
    pub async fn recv(&mut self) -> Option<TrackedMessage<T>> {
        self.inner.next().await
    }

    /// Tries to receive a message without blocking.
    pub fn try_recv(&mut self) -> Option<TrackedMessage<T>> {
        self.inner.try_next().ok().flatten()
    }
}

impl<T> Stream for TrackedReceiver<T> {
    type Item = TrackedMessage<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Creates a new tracked bounded channel.
///
/// This channel provides reliable delivery tracking of messages. Each sent message
/// returns a `DeliveryGuard` that can be cloned. When ALL clones of the guard
/// (including the one sent with the message) are dropped, the message is marked as delivered.
///
/// # Features
/// - **Watermark tracking**: Get the highest sequence number where all messages up to it have been delivered
/// - **Batch tracking**: Assign batch IDs to messages and track pending counts per batch
/// - **Clonable guards**: Guards can be cloned and shared; delivery happens when all clones are dropped
///
/// # Sequence Number Overflow
/// Uses u64 for sequence numbers. At 100 messages per nanosecond, overflow would occur after ~5.85 years.
/// For most applications this is sufficient. Systems requiring longer continuous operation should
/// implement periodic resets or use external sequence management.
///
/// # Example
/// ```
/// # use futures::executor::block_on;
/// # use commonware_utils::futures::tracked_channel;
/// # block_on(async {
/// let (mut sender, mut receiver) = tracked_channel::<String>(10);
///
/// // Send a message with batch ID
/// let guard = sender.send("hello".to_string(), Some(1)).await.unwrap();
///
/// // Check pending messages
/// assert_eq!(sender.batch_pending_count(1), 1);
/// assert_eq!(sender.watermark(), 0);
///
/// // Receive and process
/// let msg = receiver.recv().await.unwrap();
/// assert_eq!(msg.data, "hello");
///
/// // Drop both guards to mark as delivered
/// drop(msg.guard);
/// drop(guard);
///
/// assert_eq!(sender.batch_pending_count(1), 0);
/// assert_eq!(sender.watermark(), 1);
/// # });
/// ```
pub fn tracked_channel<T>(buffer: usize) -> (TrackedSender<T>, TrackedReceiver<T>) {
    let (tx, rx) = mpsc::channel(buffer);
    let sender = TrackedSender {
        inner: tx,
        tracker: DeliveryTracker::new(),
    };
    let receiver = TrackedReceiver { inner: rx };
    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn test_tracked_channel_basic() {
        block_on(async move {
            let (mut sender, mut receiver) = tracked_channel::<i32>(10);

            // Send a message without batch ID
            let guard = sender.send(42, None).await.unwrap();
            assert_eq!(sender.watermark(), 0);

            // Receive the message but don't drop the guard yet
            let msg = receiver.recv().await.unwrap();
            assert_eq!(msg.data, 42);
            assert_eq!(sender.watermark(), 0);

            // Drop the guard to mark as delivered
            drop(msg.guard);
            drop(guard);
            assert_eq!(sender.watermark(), 1);
        });
    }

    #[test]
    fn test_tracked_channel_batch_tracking() {
        block_on(async move {
            let (mut sender, mut receiver) = tracked_channel::<String>(10);

            // Send messages with different batch IDs
            let guard1 = sender.send("msg1".to_string(), Some(100)).await.unwrap();
            let guard2 = sender.send("msg2".to_string(), Some(100)).await.unwrap();
            let guard3 = sender.send("msg3".to_string(), Some(200)).await.unwrap();

            assert_eq!(sender.batch_pending_count(100), 2);
            assert_eq!(sender.batch_pending_count(200), 1);
            assert_eq!(sender.batch_pending_count(300), 0);

            // Receive and process first message
            let msg1 = receiver.recv().await.unwrap();
            assert_eq!(msg1.data, "msg1");
            drop(msg1.guard);
            drop(guard1); // Need to drop both sender and receiver guards

            assert_eq!(sender.batch_pending_count(100), 1);
            assert_eq!(sender.batch_pending_count(200), 1);

            // Receive and process remaining messages
            let msg2 = receiver.recv().await.unwrap();
            let msg3 = receiver.recv().await.unwrap();
            drop(msg2.guard);
            drop(guard2);
            drop(msg3.guard);
            drop(guard3);

            assert_eq!(sender.batch_pending_count(100), 0);
            assert_eq!(sender.batch_pending_count(200), 0);
        });
    }

    #[test]
    fn test_watermark_progression() {
        block_on(async move {
            let (mut sender, mut receiver) = tracked_channel::<i32>(10);

            // Send multiple messages and immediately receive them
            let guard1 = sender.send(1, None).await.unwrap();
            let msg1 = receiver.recv().await.unwrap();

            let guard2 = sender.send(2, None).await.unwrap();
            let msg2 = receiver.recv().await.unwrap();

            let guard3 = sender.send(3, None).await.unwrap();
            let msg3 = receiver.recv().await.unwrap();

            let guard4 = sender.send(4, None).await.unwrap();
            let msg4 = receiver.recv().await.unwrap();

            assert_eq!(sender.watermark(), 0);

            // Drop guards out of order (both sender and receiver side)
            drop(guard2);
            drop(msg2.guard);
            assert_eq!(sender.watermark(), 0); // Can't advance past undelivered guard1

            drop(guard1);
            drop(msg1.guard);
            assert_eq!(sender.watermark(), 2); // Advances to 2 since guard2 was already dropped

            drop(guard4);
            drop(msg4.guard);
            assert_eq!(sender.watermark(), 2); // Can't advance past undelivered guard3

            drop(guard3);
            drop(msg3.guard);
            assert_eq!(sender.watermark(), 4); // All delivered
        });
    }

    #[test]
    fn test_cloned_guards() {
        block_on(async move {
            let (mut sender, mut receiver) = tracked_channel::<&str>(10);

            let guard = sender.send("test", Some(1)).await.unwrap();

            // Receive the message immediately
            let msg = receiver.recv().await.unwrap();
            assert_eq!(msg.data, "test");

            // The message guard and sender guard are the same
            let msg_guard_clone1 = msg.guard.clone();
            let msg_guard_clone2 = msg.guard.clone();

            assert_eq!(sender.batch_pending_count(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop sender's guard - doesn't affect delivery since message guard exists
            drop(guard);
            assert_eq!(sender.batch_pending_count(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop original and one clone
            drop(msg.guard);
            drop(msg_guard_clone1);
            assert_eq!(sender.batch_pending_count(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop last clone - now it's delivered
            drop(msg_guard_clone2);
            assert_eq!(sender.batch_pending_count(1), 0);
            assert_eq!(sender.watermark(), 1);
        });
    }

    #[test]
    fn test_try_send() {
        block_on(async move {
            let (mut sender, mut receiver) = tracked_channel::<i32>(2);

            // Try send should work when buffer has space
            let guard1 = sender.try_send(1, Some(10)).unwrap();
            let guard2 = sender.try_send(2, Some(10)).unwrap();

            assert_eq!(sender.batch_pending_count(10), 2);

            // Receive messages
            let msg1 = receiver.recv().await.unwrap();
            assert_eq!(msg1.data, 1);
            drop(msg1.guard);
            drop(guard1);

            assert_eq!(sender.batch_pending_count(10), 1);

            let msg2 = receiver.recv().await.unwrap();
            drop(msg2.guard);
            drop(guard2);

            assert_eq!(sender.batch_pending_count(10), 0);
        });
    }

    #[test]
    fn test_channel_closure() {
        block_on(async move {
            let (mut sender, receiver) = tracked_channel::<i32>(10);

            let _guard = sender.send(1, None).await.unwrap();

            // Drop receiver
            drop(receiver);

            // Next send should fail
            assert!(sender.send(2, None).await.is_err());
        });
    }
}
