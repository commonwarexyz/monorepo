//! A channel that tracks message delivery.
//!
//! This channel provides message delivery tracking. Each sent message includes
//! a [Guard] that tracks when the message has been fully processed. When ALL
//! references to the guard are dropped, the message is marked as delivered.
//
//! # Features
//!
//! - **Watermarks**: Get the highest sequence number where all messages up to it have been delivered
//! - **Batches**: Assign batches to messages and track pending counts per batch
//! - **Clonable Guards**: Guards can be cloned and shared; delivery happens when all clones are dropped
//
//! # Sequence Number Overflow
//!
//! Uses [u64] for sequence numbers. At 100 messages per nanosecond, overflow occurs after ~5.85 years.
//! Systems requiring more message throughput should implement periodic resets or use external sequence management.
//
//! # Example
//!
//! ```
//! use futures::executor::block_on;
//! use commonware_utils::channel::tracked;
//! block_on(async {
//!     let (sender, mut receiver) = tracked::bounded::<String, u64>(10);
//
//!     // Send a message with batch ID
//!     let sequence = sender.send(Some(1), "hello".into()).await.unwrap();
//
//!     // Check pending messages
//!     assert_eq!(sender.pending(1), 1);
//!     assert_eq!(sender.watermark(), 0);
//
//!     // Receive and process
//!     let msg = receiver.recv().await.unwrap();
//!     assert_eq!(msg.data, "hello");
//
//!     // Delivery waits until all clones are dropped
//!     let guard_clone = msg.guard.clone();
//!     drop(msg.guard);
//!     assert_eq!(sender.watermark(), 0); // Still not delivered
//
//!     // Drop the last guard reference to mark as delivered
//!     drop(guard_clone);
//!     assert_eq!(sender.pending(1), 0);
//!     assert_eq!(sender.watermark(), 1);
//! });
//! ```

use super::mpsc::{
    self,
    error::{SendError, TryRecvError, TrySendError},
};
use crate::{Widen, sync::Mutex};
use futures::Stream;
use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A guard that tracks message delivery. When all clones are dropped, the message is marked as
/// delivered.
#[derive(Clone)]
pub struct Guard<B: Eq + Hash> {
    inner: Arc<Inner<B>>,
}

/// Delivery bookkeeping shared by the clones of one [Guard].
struct Inner<B: Eq + Hash> {
    sequence: u64,
    tracker: Arc<Mutex<State<B>>>,

    batch: Option<B>,
}

impl<B: Eq + Hash> Drop for Inner<B> {
    fn drop(&mut self) {
        // Get the state
        let mut state = self.tracker.lock();

        // Mark the message as delivered
        let index = usize::try_from(self.sequence - state.watermark - 1)
            .expect("pending index must fit in usize");
        state.pending[index] = true;

        // Advance the watermark past the delivered prefix
        while state.pending.pop_front_if(|delivered| *delivered).is_some() {
            state.watermark += 1;
        }

        // Update the batch count (if necessary). `remove` drops the map's copy of the batch while
        // the lock is held, but the guard's own batch is dropped with the rest of `Inner` after
        // `state` is released. A batch destructor that runs then (for example, when the guard
        // holds the last `Arc` reference) may lock the tracker.
        if let Some(batch) = &self.batch {
            let count = state.batches.get_mut(batch).expect("batch must be tracked");
            if *count > 1 {
                *count -= 1;
            } else {
                state.batches.remove(batch);
            }
        }
    }
}

/// A message containing data and a [Guard] that tracks delivery.
pub struct Message<T, B: Eq + Hash> {
    /// The data of the message.
    pub data: T,
    /// The [Guard] that tracks delivery.
    ///
    /// When all clones of the guard are dropped, the message is considered delivered.
    pub guard: Guard<B>,
}

/// The state of the [Tracker].
struct State<B> {
    /// Every sequence up to and including the watermark has been delivered.
    watermark: u64,
    /// The number of undelivered messages in each batch.
    batches: HashMap<B, usize>,
    /// `pending[i]` records whether sequence `watermark + 1 + i` has been delivered. Every
    /// sequence issued above the watermark has a slot, so [Tracker::guard] issues
    /// `watermark + 1 + pending.len()` next.
    pending: VecDeque<bool>,
}

impl<B> Default for State<B> {
    fn default() -> Self {
        Self {
            watermark: 0,
            batches: HashMap::new(),
            pending: VecDeque::new(),
        }
    }
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
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    fn guard(&self, batch: Option<B>) -> Guard<B> {
        // Get state
        let mut state = self.state.lock();

        // Issue the next sequence and track it as not yet delivered
        let issued: u64 = Widen::widen(state.pending.len());
        let sequence = state.watermark + 1 + issued;
        state.pending.push_back(false);

        // Update batch count if provided
        if let Some(batch) = &batch {
            *state.batches.entry(batch.clone()).or_insert(0) += 1;
        }

        Guard {
            inner: Arc::new(Inner {
                sequence,
                tracker: self.state.clone(),

                batch,
            }),
        }
    }
}

/// A sender that wraps `Sender` and tracks message delivery.
#[derive(Clone)]
pub struct Sender<T, B: Eq + Hash + Clone> {
    inner: mpsc::Sender<Message<T, B>>,
    tracker: Tracker<B>,
}

impl<T, B: Eq + Hash + Clone> Sender<T, B> {
    /// Sends a message with an optional batch ID and returns a delivery guard.
    pub async fn send(&self, batch: Option<B>, data: T) -> Result<u64, SendError<Message<T, B>>> {
        // Create the guard
        let guard = self.tracker.guard(batch);
        let watermark = guard.inner.sequence;

        // Send the message
        let msg = Message { data, guard };
        self.inner.send(msg).await?;

        Ok(watermark)
    }

    /// Tries to send a message without blocking.
    pub fn try_send(&self, batch: Option<B>, data: T) -> Result<u64, TrySendError<Message<T, B>>> {
        // Create the guard
        let guard = self.tracker.guard(batch);
        let watermark = guard.inner.sequence;

        // Send the message
        let msg = Message { data, guard };
        self.inner.try_send(msg)?;

        Ok(watermark)
    }

    /// Returns the current delivery watermark (highest sequence number where all messages up to and including it have been delivered).
    pub fn watermark(&self) -> u64 {
        self.tracker.state.lock().watermark
    }

    /// Returns the number of pending messages for a specific batch.
    pub fn pending(&self, batch: B) -> usize {
        self.tracker
            .state
            .lock()
            .batches
            .get(&batch)
            .copied()
            .unwrap_or(0)
    }
}

/// A receiver that wraps [mpsc::Receiver] and provides tracked messages.
pub struct Receiver<T, B: Eq + Hash> {
    inner: mpsc::Receiver<Message<T, B>>,
}

impl<T, B: Eq + Hash> Receiver<T, B> {
    /// Receives the next message.
    pub async fn recv(&mut self) -> Option<Message<T, B>> {
        self.inner.recv().await
    }

    /// Tries to receive a message without blocking.
    pub fn try_recv(&mut self) -> Result<Message<T, B>, TryRecvError> {
        self.inner.try_recv()
    }
}

impl<T, B: Eq + Hash> Stream for Receiver<T, B> {
    type Item = Message<T, B>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_recv(cx)
    }
}

/// Create a new bounded channel with delivery tracking.
pub fn bounded<T, B: Eq + Hash + Clone>(buffer: usize) -> (Sender<T, B>, Receiver<T, B>) {
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

    /// A batch whose destructor runs a callback.
    struct CallbackBatch {
        id: u64,
        on_drop: Box<dyn Fn() + Send + Sync>,
    }

    impl PartialEq for CallbackBatch {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for CallbackBatch {}

    impl Hash for CallbackBatch {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    impl Drop for CallbackBatch {
        fn drop(&mut self) {
            (self.on_drop)();
        }
    }

    #[test]
    fn test_batch_destructor_can_read_watermark() {
        // Run the channel on a worker thread so the receive timeout below fails the test if the
        // batch destructor deadlocks on the tracker.
        let (observed, observations) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            block_on(async move {
                let (sender, mut receiver) = bounded::<(), Arc<CallbackBatch>>(1);
                let observer = sender.clone();
                let batch = Arc::new(CallbackBatch {
                    id: 1,
                    on_drop: Box::new(move || observed.send(observer.watermark()).unwrap()),
                });
                sender.send(Some(batch), ()).await.unwrap();

                // Dropping the only guard drops the last reference to the batch
                drop(receiver.recv().await.unwrap());
            });
        });
        let watermark = observations
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("batch destructor must read the watermark");
        assert_eq!(watermark, 1);
        worker.join().unwrap();
    }

    #[test]
    fn test_basic() {
        block_on(async move {
            let (sender, mut receiver) = bounded::<i32, u64>(10);

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
    fn test_out_of_order_delivery() {
        block_on(async move {
            let (sender, mut receiver) = bounded::<i32, u64>(4);
            for value in 1..=4 {
                sender.send(Some(1), value).await.unwrap();
            }
            let first = receiver.recv().await.unwrap();
            let second = receiver.recv().await.unwrap();
            let third = receiver.recv().await.unwrap();
            let fourth = receiver.recv().await.unwrap();

            // Delivering the second and fourth messages leaves the first undelivered, so the
            // watermark stays at zero
            drop(second);
            drop(fourth);
            assert_eq!(sender.watermark(), 0);
            assert_eq!(sender.pending(1), 2);

            // A message sent while delivered messages wait behind the undelivered first takes the
            // sequence after every issued message, delivered or not
            let fifth = sender.send(Some(2), 5).await.unwrap();
            assert_eq!(fifth, 5);
            assert_eq!(sender.pending(2), 1);

            // Delivering the first advances the watermark past the already delivered second
            drop(first);
            assert_eq!(sender.watermark(), 2);
            assert_eq!(sender.pending(1), 1);

            // Delivering the third advances the watermark past the already delivered fourth
            drop(third);
            assert_eq!(sender.watermark(), 4);
            assert_eq!(sender.pending(1), 0);

            // A message sent after the watermark advanced continues from the watermark
            let sixth = sender.send(Some(2), 6).await.unwrap();
            assert_eq!(sixth, 6);
            assert_eq!(sender.pending(2), 2);

            // Delivering the fifth and sixth in order advances the watermark past both
            drop(receiver.recv().await.unwrap());
            drop(receiver.recv().await.unwrap());
            assert_eq!(sender.watermark(), 6);
            assert_eq!(sender.pending(2), 0);
        });
    }

    #[test]
    fn test_batch_tracking() {
        block_on(async move {
            let (sender, mut receiver) = bounded::<String, u64>(10);

            // Send messages with different batch IDs
            let watermark1 = sender.send(Some(100), "msg1".into()).await.unwrap();
            let watermark2 = sender.send(Some(100), "msg2".into()).await.unwrap();
            let watermark3 = sender.send(Some(200), "msg3".into()).await.unwrap();

            assert_eq!(watermark1, 1);
            assert_eq!(watermark2, 2);
            assert_eq!(watermark3, 3);
            assert_eq!(sender.pending(100), 2);
            assert_eq!(sender.pending(200), 1);
            assert_eq!(sender.pending(300), 0);

            // Receive and process first message
            let msg1 = receiver.recv().await.unwrap();
            assert_eq!(msg1.data, "msg1");
            drop(msg1.guard);

            assert_eq!(sender.pending(100), 1);
            assert_eq!(sender.pending(200), 1);

            // Receive and process remaining messages
            let msg2 = receiver.recv().await.unwrap();
            let msg3 = receiver.recv().await.unwrap();
            drop(msg2.guard);
            drop(msg3.guard);

            assert_eq!(sender.pending(100), 0);
            assert_eq!(sender.pending(200), 0);
        });
    }

    #[test]
    fn test_cloned_guards() {
        block_on(async move {
            let (sender, mut receiver) = bounded::<&str, u64>(10);

            let watermark = sender.send(Some(1), "test").await.unwrap();
            assert_eq!(watermark, 1);

            // Receive the message immediately
            let msg = receiver.recv().await.unwrap();
            assert_eq!(msg.data, "test");

            // Clones of one guard share a single delivery
            let msg_guard_clone1: Guard<u64> = msg.guard.clone();
            let msg_guard_clone2: Guard<u64> = msg.guard.clone();

            assert_eq!(sender.pending(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop original and one clone
            drop(msg.guard);
            drop(msg_guard_clone1);
            assert_eq!(sender.pending(1), 1);
            assert_eq!(sender.watermark(), 0);

            // Drop last clone
            drop(msg_guard_clone2);
            assert_eq!(sender.pending(1), 0);
            assert_eq!(sender.watermark(), 1);
        });
    }

    #[test]
    fn test_try_send() {
        block_on(async move {
            let (sender, mut receiver) = bounded::<i32, u64>(2);

            // Try send should work when buffer has space
            let watermark1 = sender.try_send(Some(10), 1).unwrap();
            let watermark2 = sender.try_send(Some(10), 2).unwrap();

            assert_eq!(sender.pending(10), 2);
            assert_eq!(watermark1, 1);
            assert_eq!(watermark2, 2);

            // Receive messages
            let msg1 = receiver.recv().await.unwrap();
            assert_eq!(msg1.data, 1);
            drop(msg1.guard);

            assert_eq!(sender.pending(10), 1);

            let msg2 = receiver.recv().await.unwrap();
            drop(msg2.guard);

            assert_eq!(sender.pending(10), 0);
        });
    }

    #[test]
    fn test_channel_closure() {
        block_on(async move {
            let (sender, receiver) = bounded::<i32, u64>(10);

            let _guard = sender.send(None, 1).await.unwrap();

            // Drop receiver
            drop(receiver);

            // Next send should fail
            assert!(sender.send(None, 2).await.is_err());
        });
    }
}
