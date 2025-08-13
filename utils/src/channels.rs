//! Utilities for working with channels.

use futures::{
    channel::mpsc::{self, Receiver as FutReceiver, SendError, Sender as FutSender, TrySendError},
    SinkExt, Stream, StreamExt,
};
use std::{
    collections::HashMap,
    hash::Hash,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

/// A guard that tracks message delivery. When dropped, the message is marked as delivered.
#[derive(Clone)]
pub struct Guard<B: Eq + Hash + Clone> {
    sequence: u64,
    tracker: Arc<Mutex<State<B>>>,

    _batch: Option<B>,
}

impl<B: Eq + Hash + Clone> Drop for Guard<B> {
    fn drop(&mut self) {
        // Get the state
        let mut state = self.tracker.lock().unwrap();

        // Mark the message as delivered
        *state.pending_sequences.get_mut(&self.sequence).unwrap() = true;

        // Update watermark if possible
        let mut current_watermark = state.watermark;
        while let Some(delivered) = state.pending_sequences.get(&(current_watermark + 1)) {
            // If the next message is not delivered, we can stop
            if !*delivered {
                break;
            }

            // Remove the next message from the pending list
            state.pending_sequences.remove(&(current_watermark + 1));
            current_watermark += 1;
            state.watermark = current_watermark;
        }

        // Update batch count (if necessary)
        if let Some(batch) = &self._batch {
            let count = state.batch_counts.get_mut(batch).unwrap();
            if *count > 1 {
                *count -= 1;
            } else {
                state.batch_counts.remove(batch);
            }
        }
    }
}

/// A message containing data and a [Guard] that tracks delivery.
pub struct Message<T, B: Eq + Hash + Clone> {
    /// The data of the message.
    pub data: T,
    /// The [Guard] that tracks delivery.
    ///
    /// When no outstanding references to the guard exist, the message is considered delivered.
    pub guard: Arc<Guard<B>>,
}

/// The state of the tracker.
struct State<B> {
    next_sequence: u64,
    watermark: u64,
    batch_counts: HashMap<B, usize>,
    pending_sequences: HashMap<u64, bool>,
}

/// Tracks delivery state across all messages.
///
/// Note on sequence overflow: Using u64 for sequence numbers provides ample headroom.
/// At 100 messages per nanosecond, it would take ~5.85 years to overflow.
/// For systems requiring longer uptime without restart, consider implementing
/// sequence number wrapping with careful watermark handling.
#[derive(Clone)]
struct Tracker<B: Eq + Hash + Clone> {
    state: Arc<Mutex<State<B>>>,
}

impl<B: Eq + Hash + Clone> Tracker<B> {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                next_sequence: 1,
                watermark: 0,
                batch_counts: HashMap::new(),
                pending_sequences: HashMap::new(),
            })),
        }
    }

    fn create_guard(&self, batch: Option<B>) -> Guard<B> {
        // Get state
        let mut state = self.state.lock().unwrap();

        // Get the next sequence
        let sequence = state.next_sequence;
        state.next_sequence += 1;

        // Track this sequence as not yet delivered
        state.pending_sequences.insert(sequence, false);

        // Update batch count if provided
        if let Some(batch) = &batch {
            *state.batch_counts.entry(batch.clone()).or_insert(0) += 1;
        }

        Guard {
            sequence,
            tracker: self.state.clone(),

            _batch: batch,
        }
    }
}

/// A sender that wraps `Sender` and tracks message delivery.
#[derive(Clone)]
pub struct Sender<T, B: Eq + Hash + Clone> {
    inner: FutSender<Message<T, B>>,
    tracker: Tracker<B>,
}

impl<T, B: Eq + Hash + Clone> Sender<T, B> {
    /// Sends a message with an optional batch ID and returns a delivery guard.
    pub async fn send(&mut self, batch: Option<B>, data: T) -> Result<u64, SendError> {
        // Create the guard
        let guard = Arc::new(self.tracker.create_guard(batch));
        let watermark = guard.sequence;

        // Send the message
        let msg = Message { data, guard };
        self.inner.send(msg).await?;

        Ok(watermark)
    }

    /// Tries to send a message without blocking.
    pub fn try_send(
        &mut self,
        batch: Option<B>,
        data: T,
    ) -> Result<u64, TrySendError<Message<T, B>>> {
        // Create the guard
        let guard = Arc::new(self.tracker.create_guard(batch));
        let watermark = guard.sequence;

        // Send the message
        let msg = Message { data, guard };
        self.inner.try_send(msg)?;

        Ok(watermark)
    }

    /// Returns the current delivery watermark (highest sequence number where all messages up to and including it have been delivered).
    pub fn watermark(&self) -> u64 {
        self.tracker.state.lock().unwrap().watermark
    }

    /// Returns the number of pending messages for a specific batch ID.
    pub fn batch_pending_count(&self, batch: B) -> usize {
        self.tracker
            .state
            .lock()
            .unwrap()
            .batch_counts
            .get(&batch)
            .copied()
            .unwrap_or(0)
    }
}

/// A receiver that wraps `Receiver` and provides tracked messages.
pub struct Receiver<T, B: Eq + Hash + Clone> {
    inner: FutReceiver<Message<T, B>>,
}

impl<T, B: Eq + Hash + Clone> Receiver<T, B> {
    /// Receives the next message.
    pub async fn recv(&mut self) -> Option<Message<T, B>> {
        self.inner.next().await
    }

    /// Tries to receive a message without blocking.
    pub fn try_recv(&mut self) -> Option<Message<T, B>> {
        self.inner.try_next().ok().flatten()
    }
}

impl<T, B: Eq + Hash + Clone> Stream for Receiver<T, B> {
    type Item = Message<T, B>;

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
pub fn reliable<T, B: Eq + Hash + Clone>(buffer: usize) -> (Sender<T, B>, Receiver<T, B>) {
    let (tx, rx) = mpsc::channel(buffer);
    let sender = Sender {
        inner: tx,
        tracker: Tracker::new(),
    };
    let receiver = Receiver { inner: rx };
    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn test_basic() {
        block_on(async move {
            let (mut sender, mut receiver) = reliable::<i32, u64>(10);

            // Send a message without batch ID
            let watermark = sender.send(None, 42).await.unwrap();
            assert_eq!(watermark, 1);
            assert_eq!(sender.watermark(), 0);

            // Receive the message but don't drop the guard yet
            let msg = receiver.recv().await.unwrap();
            assert_eq!(msg.data, 42);
            assert_eq!(sender.watermark(), 0);

            // Drop the guard to mark as delivered
            drop(msg.guard);
            assert_eq!(sender.watermark(), 1);
        });
    }

    #[test]
    fn test_batch_tracking() {
        block_on(async move {
            let (mut sender, mut receiver) = reliable::<String, u64>(10);

            // Send messages with different batch IDs
            let watermark1 = sender.send(Some(100), "msg1".to_string()).await.unwrap();
            let watermark2 = sender.send(Some(100), "msg2".to_string()).await.unwrap();
            let watermark3 = sender.send(Some(200), "msg3".to_string()).await.unwrap();

            assert_eq!(watermark1, 1);
            assert_eq!(watermark2, 2);
            assert_eq!(watermark3, 3);
            assert_eq!(sender.batch_pending_count(100), 2);
            assert_eq!(sender.batch_pending_count(200), 1);
            assert_eq!(sender.batch_pending_count(300), 0);

            // Receive and process first message
            let msg1 = receiver.recv().await.unwrap();
            assert_eq!(msg1.data, "msg1");
            drop(msg1.guard);

            assert_eq!(sender.batch_pending_count(100), 1);
            assert_eq!(sender.batch_pending_count(200), 1);

            // Receive and process remaining messages
            let msg2 = receiver.recv().await.unwrap();
            let msg3 = receiver.recv().await.unwrap();
            drop(msg2.guard);
            drop(msg3.guard);

            assert_eq!(sender.batch_pending_count(100), 0);
            assert_eq!(sender.batch_pending_count(200), 0);
        });
    }

    #[test]
    fn test_cloned_guards() {
        block_on(async move {
            let (mut sender, mut receiver) = reliable::<&str, u64>(10);

            let watermark = sender.send(Some(1), "test").await.unwrap();
            assert_eq!(watermark, 1);

            // Receive the message immediately
            let msg = receiver.recv().await.unwrap();
            assert_eq!(msg.data, "test");

            // The message guard and sender guard are the same
            let msg_guard_clone1 = msg.guard.clone();
            let msg_guard_clone2 = msg.guard.clone();

            assert_eq!(sender.batch_pending_count(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop original and one clone
            drop(msg.guard);
            drop(msg_guard_clone1);
            assert_eq!(sender.batch_pending_count(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop last clone
            drop(msg_guard_clone2);
            assert_eq!(sender.batch_pending_count(1), 0);
            assert_eq!(sender.watermark(), 1);
        });
    }

    #[test]
    fn test_try_send() {
        block_on(async move {
            let (mut sender, mut receiver) = reliable::<i32, u64>(2);

            // Try send should work when buffer has space
            let watermark1 = sender.try_send(Some(10), 1).unwrap();
            let watermark2 = sender.try_send(Some(10), 2).unwrap();

            assert_eq!(sender.batch_pending_count(10), 2);
            assert_eq!(watermark1, 1);
            assert_eq!(watermark2, 2);

            // Receive messages
            let msg1 = receiver.recv().await.unwrap();
            assert_eq!(msg1.data, 1);
            drop(msg1.guard);

            assert_eq!(sender.batch_pending_count(10), 1);

            let msg2 = receiver.recv().await.unwrap();
            drop(msg2.guard);

            assert_eq!(sender.batch_pending_count(10), 0);
        });
    }

    #[test]
    fn test_channel_closure() {
        block_on(async move {
            let (mut sender, receiver) = reliable::<i32, u64>(10);

            let _guard = sender.send(None, 1).await.unwrap();

            // Drop receiver
            drop(receiver);

            // Next send should fail
            assert!(sender.send(None, 2).await.is_err());
        });
    }
}
