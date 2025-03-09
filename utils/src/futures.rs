//! Utilities for working with futures.

use futures::{
    future,
    stream::{FuturesUnordered, SelectNextSome},
    StreamExt,
};
use std::{future::Future, pin::Pin};

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
    pub fn next_completed(&mut self) -> SelectNextSome<FuturesUnordered<PooledFuture<T>>> {
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

            // Futures resolve in order of completion time, not addition order
            pool.push(async move {
                delay(Duration::from_millis(100)).await;
                1
            });
            pool.push(async move {
                delay(Duration::from_millis(50)).await;
                2
            });
            pool.push(async move {
                delay(Duration::from_millis(150)).await;
                3
            });

            let first = pool.next_completed().await;
            assert_eq!(first, 2, "First resolved should be 2 (50ms)");
            let second = pool.next_completed().await;
            assert_eq!(second, 1, "Second resolved should be 1 (100ms)");
            let third = pool.next_completed().await;
            assert_eq!(third, 3, "Third resolved should be 3 (150ms)");
            assert!(pool.is_empty(),);
        });
    }

    #[test]
    fn test_cancel_all() {
        block_on(async move {
            let flag = Arc::new(AtomicBool::new(false));
            let flag_clone = flag.clone();
            let mut pool = Pool::<i32>::default();

            pool.push(async move {
                delay(Duration::from_millis(100)).await;
                flag_clone.store(true, Ordering::SeqCst);
                42
            });
            assert_eq!(pool.len(), 1);

            pool.cancel_all();
            assert!(pool.is_empty());

            delay(Duration::from_millis(150)).await; // Wait longer than future’s delay
            assert!(!flag.load(Ordering::SeqCst));

            // Stream should not resolve future after cancellation
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
                    // Timeout occurred, which is expected
                }
            }

            // Push and await a new future
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
}
