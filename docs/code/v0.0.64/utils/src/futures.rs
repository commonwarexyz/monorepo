//! Utilities for working with futures.

use core::ops::{Deref, DerefMut};
use futures::{
    channel::oneshot,
    future::{self, AbortHandle, Abortable, Aborted},
    stream::{FuturesUnordered, SelectNextSome},
    StreamExt,
};
use pin_project::pin_project;
use std::{future::Future, pin::Pin, task::Poll};

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

/// A future that resolves when a [oneshot::Receiver] is dropped.
///
/// This future completes when the receiver end of the channel is dropped,
/// allowing the caller to detect when the other side is no longer interested
/// in the result.
pub struct Closed<'a, T> {
    sender: &'a mut oneshot::Sender<T>,
}

impl<'a, T> Closed<'a, T> {
    /// Creates a new future that resolves when the receiver is dropped.
    pub const fn new(sender: &'a mut oneshot::Sender<T>) -> Self {
        Self { sender }
    }
}

impl<T> Future for Closed<'_, T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.sender.poll_canceled(cx) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Extension trait to detect when a [oneshot::Receiver] is dropped.
pub trait ClosedExt<T> {
    /// Returns a future that resolves when the receiver is dropped.
    ///
    /// # Examples
    ///
    /// ```
    /// use futures::channel::oneshot;
    /// use commonware_utils::futures::ClosedExt;
    ///
    /// # futures::executor::block_on(async {
    /// let (mut tx, rx) = oneshot::channel::<i32>();
    ///
    /// let closed = tx.closed();
    /// drop(rx);
    /// closed.await;
    /// # });
    /// ```
    fn closed(&mut self) -> Closed<'_, T>;
}

impl<T> ClosedExt<T> for oneshot::Sender<T> {
    fn closed(&mut self) -> Closed<'_, T> {
        Closed::new(self)
    }
}

/// An optional future that yields [Poll::Pending] when [None]. Useful within `select!` macros,
/// where a future may be conditionally present.
///
/// Not to be confused with [futures::future::OptionFuture], which resolves to [None] immediately
/// when the inner future is `None`.
#[pin_project]
pub struct OptionFuture<F: Future>(#[pin] Option<F>);

impl<F: Future> Default for OptionFuture<F> {
    fn default() -> Self {
        Self(None)
    }
}

impl<F: Future> From<Option<F>> for OptionFuture<F> {
    fn from(opt: Option<F>) -> Self {
        Self(opt)
    }
}

impl<F: Future> Deref for OptionFuture<F> {
    type Target = Option<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Future> DerefMut for OptionFuture<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: Future> Future for OptionFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.0
            .as_pin_mut()
            .map_or_else(|| Poll::Pending, |fut| fut.poll(cx))
    }
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
    fn test_closed_on_receiver_drop() {
        block_on(async {
            let (mut tx, rx) = oneshot::channel::<i32>();

            let closed = tx.closed();
            drop(rx);

            closed.await;
        });
    }

    #[test]
    fn test_closed_pending_when_receiver_alive() {
        block_on(async {
            let (mut tx, rx) = oneshot::channel::<i32>();

            let closed = tx.closed();
            let timeout = delay(Duration::from_millis(500));

            pin_mut!(closed);
            pin_mut!(timeout);

            match select(closed, timeout).await {
                Either::Left(_) => panic!("Closed resolved while receiver still alive"),
                Either::Right(_) => {}
            }

            drop(rx);
        });
    }

    #[test]
    fn test_closed_multiple_polls() {
        block_on(async {
            let (mut tx, rx) = oneshot::channel::<i32>();

            // Setup the closed future
            let closed = tx.closed();
            pin_mut!(closed);

            // Poll the closed future
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(closed.as_mut().poll(&mut cx).is_pending());

            // Drop receiver
            drop(rx);

            // Now poll should be ready
            assert!(closed.as_mut().poll(&mut cx).is_ready());
        });
    }

    #[test]
    fn test_option_future() {
        block_on(async {
            let option_future = OptionFuture::<oneshot::Receiver<()>>::from(None);
            pin_mut!(option_future);

            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(option_future.poll(&mut cx).is_pending());

            let (tx, rx) = oneshot::channel();
            let option_future: OptionFuture<_> = Some(rx).into();
            pin_mut!(option_future);

            tx.send(1usize).unwrap();
            assert_eq!(option_future.poll(&mut cx), Poll::Ready(Ok(1)));
        });
    }
}
