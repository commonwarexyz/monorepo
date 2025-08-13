//! Utilities for working with futures.

use futures::{
    channel::mpsc::{self, Receiver, SendError, Sender, TrySendError},
    future::{self, AbortHandle, Abortable, Aborted},
    sink::SinkExt,
    stream::{FuturesUnordered, SelectNextSome},
    Stream, StreamExt,
};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

/// A future type that can be used in `Pool`.
type PooledFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// An unordered pool of futures.
///
/// Futures can be added to the pool, and removed from the pool as they resolve.
///
/// **Note:** This pool is not thread-safe and should not be used across threads without external
/// synchronization.
pub struct Pool<T> {
    pool: FuturesUnordered<PooledFuture<T>>,
}

impl<T: Send> Default for Pool<T> {
    fn default() -> Self {
        // Insert a dummy future (that never resolves) to prevent the stream from being empty.
        // Else, the `select_next_some()` function returns `None` instantly.
        let pool = FuturesUnordered::new();
        pool.push(Self::create_dummy_future());
        Self { pool }
    }
}

impl<T: Send> Pool<T> {
    /// Returns the number of futures in the pool.
    pub fn len(&self) -> usize {
        // Subtract the dummy future.
        self.pool.len().checked_sub(1).unwrap()
    }

    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds a future to the pool.
    ///
    /// The future must be `'static` and `Send` to ensure it can be safely stored and executed.
    pub fn push(&mut self, future: impl Future<Output = T> + Send + 'static) {
        self.pool.push(Box::pin(future));
    }

    /// Returns a futures that resolves to the next future in the pool that resolves.
    ///
    /// If the pool is empty, the future will never resolve.
    pub fn next_completed(&mut self) -> SelectNextSome<'_, FuturesUnordered<PooledFuture<T>>> {
        self.pool.select_next_some()
    }

    /// Cancels all futures in the pool.
    ///
    /// Excludes the dummy future.
    pub fn cancel_all(&mut self) {
        self.pool.clear();
        self.pool.push(Self::create_dummy_future());
    }

    /// Creates a dummy future that never resolves.
    fn create_dummy_future() -> PooledFuture<T> {
        Box::pin(async { future::pending::<T>().await })
    }
}

/// A handle that can be used to abort a specific future in an [AbortablePool].
///
/// When the aborter is dropped, the associated future is aborted.
pub struct Aborter {
    inner: AbortHandle,
}

impl Drop for Aborter {
    fn drop(&mut self) {
        self.inner.abort();
    }
}

/// A future type that can be used in [AbortablePool].
type AbortablePooledFuture<T> = Pin<Box<dyn Future<Output = Result<T, Aborted>> + Send>>;

/// An unordered pool of futures that can be individually aborted.
///
/// Each future added to the pool returns an [Aborter]. When the aborter is dropped,
/// the associated future is aborted.
///
/// **Note:** This pool is not thread-safe and should not be used across threads without external
/// synchronization.
pub struct AbortablePool<T> {
    pool: FuturesUnordered<AbortablePooledFuture<T>>,
}

impl<T: Send> Default for AbortablePool<T> {
    fn default() -> Self {
        // Insert a dummy future (that never resolves) to prevent the stream from being empty.
        // Else, the `select_next_some()` function returns `None` instantly.
        let pool = FuturesUnordered::new();
        pool.push(Self::create_dummy_future());
        Self { pool }
    }
}

impl<T: Send> AbortablePool<T> {
    /// Returns the number of futures in the pool.
    pub fn len(&self) -> usize {
        // Subtract the dummy future.
        self.pool.len().checked_sub(1).unwrap()
    }

    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds a future to the pool and returns an [Aborter] that can be used to abort it.
    ///
    /// The future must be `'static` and `Send` to ensure it can be safely stored and executed.
    /// When the returned [Aborter] is dropped, the future will be aborted.
    pub fn push(&mut self, future: impl Future<Output = T> + Send + 'static) -> Aborter {
        let (handle, registration) = AbortHandle::new_pair();
        let abortable_future = Abortable::new(future, registration);
        self.pool.push(Box::pin(abortable_future));
        Aborter { inner: handle }
    }

    /// Returns a future that resolves to the next future in the pool that resolves.
    ///
    /// If the pool is empty, the future will never resolve.
    /// Returns `Ok(T)` for successful completion or `Err(Aborted)` for aborted futures.
    pub fn next_completed(
        &mut self,
    ) -> SelectNextSome<'_, FuturesUnordered<AbortablePooledFuture<T>>> {
        self.pool.select_next_some()
    }

    /// Creates a dummy future that never resolves.
    fn create_dummy_future() -> AbortablePooledFuture<T> {
        Box::pin(async { Ok(future::pending::<T>().await) })
    }
}

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
    use futures::{
        channel::oneshot,
        executor::block_on,
        future::{self, select, Either},
        pin_mut, FutureExt,
    };
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };

    /// A future that resolves after a given duration.
    fn delay(duration: Duration) -> impl Future<Output = ()> {
        let (sender, receiver) = oneshot::channel();
        thread::spawn(move || {
            thread::sleep(duration);
            sender.send(()).unwrap();
        });
        receiver.map(|_| ())
    }

    #[test]
    fn test_initialization() {
        let pool = Pool::<i32>::default();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_dummy_future_doesnt_resolve() {
        block_on(async {
            let mut pool = Pool::<i32>::default();
            let stream_future = pool.next_completed();
            let timeout_future = async {
                delay(Duration::from_millis(100)).await;
            };
            pin_mut!(stream_future);
            pin_mut!(timeout_future);
            let result = select(stream_future, timeout_future).await;
            match result {
                Either::Left((_, _)) => panic!("Stream resolved unexpectedly"),
                Either::Right((_, _)) => {
                    // Timeout occurred, which is expected
                }
            }
        });
    }

    #[test]
    fn test_adding_futures() {
        let mut pool = Pool::<i32>::default();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());

        pool.push(async { 42 });
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty(),);

        pool.push(async { 43 });
        assert_eq!(pool.len(), 2,);
    }

    #[test]
    fn test_streaming_resolved_futures() {
        block_on(async move {
            let mut pool = Pool::<i32>::default();
            pool.push(future::ready(42));
            let result = pool.next_completed().await;
            assert_eq!(result, 42,);
            assert!(pool.is_empty(),);
        });
    }

    #[test]
    fn test_multiple_futures() {
        block_on(async move {
            let mut pool = Pool::<i32>::default();

            // Futures resolve in order of completion, not addition order
            let (finisher_1, finished_1) = oneshot::channel();
            let (finisher_3, finished_3) = oneshot::channel();
            pool.push(async move {
                finished_1.await.unwrap();
                finisher_3.send(()).unwrap();
                1
            });
            pool.push(async move {
                finisher_1.send(()).unwrap();
                2
            });
            pool.push(async move {
                finished_3.await.unwrap();
                3
            });

            let first = pool.next_completed().await;
            assert_eq!(first, 2, "First resolved should be 2");
            let second = pool.next_completed().await;
            assert_eq!(second, 1, "Second resolved should be 1");
            let third = pool.next_completed().await;
            assert_eq!(third, 3, "Third resolved should be 3");
            assert!(pool.is_empty(),);
        });
    }

    #[test]
    fn test_cancel_all() {
        block_on(async move {
            let flag = Arc::new(AtomicBool::new(false));
            let flag_clone = flag.clone();
            let mut pool = Pool::<i32>::default();

            // Push a future that will set the flag to true when it resolves.
            let (finisher, finished) = oneshot::channel();
            pool.push(async move {
                finished.await.unwrap();
                flag_clone.store(true, Ordering::SeqCst);
                42
            });
            assert_eq!(pool.len(), 1);

            // Cancel all futures.
            pool.cancel_all();
            assert!(pool.is_empty());
            assert!(!flag.load(Ordering::SeqCst));

            // Send the finisher signal (should be ignored).
            let _ = finisher.send(());

            // Stream should not resolve future after cancellation.
            let stream_future = pool.next_completed();
            let timeout_future = async {
                delay(Duration::from_millis(100)).await;
            };
            pin_mut!(stream_future);
            pin_mut!(timeout_future);
            let result = select(stream_future, timeout_future).await;
            match result {
                Either::Left((_, _)) => panic!("Stream resolved after cancellation"),
                Either::Right((_, _)) => {
                    // Wait for the timeout to trigger.
                }
            }
            assert!(!flag.load(Ordering::SeqCst));

            // Push and await a new future.
            pool.push(future::ready(42));
            assert_eq!(pool.len(), 1);
            let result = pool.next_completed().await;
            assert_eq!(result, 42);
            assert!(pool.is_empty());
        });
    }

    #[test]
    fn test_many_futures() {
        block_on(async move {
            let mut pool = Pool::<i32>::default();
            let num_futures = 1000;
            for i in 0..num_futures {
                pool.push(future::ready(i));
            }
            assert_eq!(pool.len(), num_futures as usize);

            let mut sum = 0;
            for _ in 0..num_futures {
                let value = pool.next_completed().await;
                sum += value;
            }
            let expected_sum = (0..num_futures).sum::<i32>();
            assert_eq!(
                sum, expected_sum,
                "Sum of resolved values should match expected"
            );
            assert!(
                pool.is_empty(),
                "Pool should be empty after all futures resolve"
            );
        });
    }

    #[test]
    fn test_abortable_pool_initialization() {
        let pool = AbortablePool::<i32>::default();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_abortable_pool_adding_futures() {
        let mut pool = AbortablePool::<i32>::default();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());

        let _hook1 = pool.push(async { 42 });
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());

        let _hook2 = pool.push(async { 43 });
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_abortable_pool_successful_completion() {
        block_on(async move {
            let mut pool = AbortablePool::<i32>::default();
            let _hook = pool.push(future::ready(42));
            let result = pool.next_completed().await;
            assert_eq!(result, Ok(42));
            assert!(pool.is_empty());
        });
    }

    #[test]
    fn test_abortable_pool_drop_abort() {
        block_on(async move {
            let mut pool = AbortablePool::<i32>::default();

            let (sender, receiver) = oneshot::channel();
            let hook = pool.push(async move {
                receiver.await.unwrap();
                42
            });

            drop(hook);

            let result = pool.next_completed().await;
            assert!(result.is_err());
            assert!(pool.is_empty());

            let _ = sender.send(());
        });
    }

    #[test]
    fn test_abortable_pool_partial_abort() {
        block_on(async move {
            let mut pool = AbortablePool::<i32>::default();

            let _hook1 = pool.push(future::ready(1));
            let (sender, receiver) = oneshot::channel();
            let hook2 = pool.push(async move {
                receiver.await.unwrap();
                2
            });
            let _hook3 = pool.push(future::ready(3));

            assert_eq!(pool.len(), 3);

            drop(hook2);

            let mut results = Vec::new();
            for _ in 0..3 {
                let result = pool.next_completed().await;
                results.push(result);
            }

            let successful: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
            let aborted: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

            assert_eq!(successful.len(), 2);
            assert_eq!(aborted.len(), 1);
            assert!(successful.contains(&&1));
            assert!(successful.contains(&&3));
            assert!(pool.is_empty());

            let _ = sender.send(());
        });
    }

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
