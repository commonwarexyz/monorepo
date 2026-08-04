//! Utilities for working with futures.

use core::ops::{Deref, DerefMut};
use futures::{
    StreamExt,
    future::{self, AbortHandle, Abortable, Aborted},
    stream::{FuturesUnordered, SelectNextSome},
};
use pin_project::pin_project;
use std::{collections::BTreeMap, future::Future, pin::Pin, task::Poll};

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

/// A consuming mutation's return value: the threaded value first, then any extra outputs.
pub trait Threaded<T> {
    /// The outputs beyond the threaded value.
    type Rest;

    /// Splits into the threaded value and the extra outputs.
    fn split(self) -> (T, Self::Rest);
}

impl<T> Threaded<T> for T {
    type Rest = ();

    fn split(self) -> (T, ()) {
        (self, ())
    }
}

impl<T, A> Threaded<T> for (T, A) {
    type Rest = A;

    fn split(self) -> (T, A) {
        self
    }
}

impl<T, A, B> Threaded<T> for (T, A, B) {
    type Rest = (A, B);

    fn split(self) -> (T, (A, B)) {
        let (value, a, b) = self;
        (value, (a, b))
    }
}

/// Threads the value in `slot` through a consuming mutation, restoring the returned
/// value and yielding the mutation's extra outputs.
///
/// On error the value stays absent, matching the contract of consuming mutators: the
/// handle is destroyed.
///
/// # Panics
///
/// Panics when `slot` is empty.
pub async fn rebind<T, Out, Fut, E>(
    slot: &mut Option<T>,
    op: impl FnOnce(T) -> Fut,
) -> Result<Out::Rest, E>
where
    Out: Threaded<T>,
    Fut: Future<Output = Result<Out, E>>,
{
    let value = slot.take().expect("cannot rebind an empty slot");
    let (value, rest) = op(value).await?.split();
    *slot = Some(value);
    Ok(rest)
}

/// Threads the value at `key` in `map` through a consuming mutation, restoring the
/// returned value and yielding the mutation's extra outputs.
///
/// On error the entry stays absent, matching the contract of consuming mutators: the
/// handle is destroyed.
///
/// # Panics
///
/// Panics when `key` is absent from `map`.
pub async fn rebind_entry<K, V, Out, Fut, E>(
    map: &mut BTreeMap<K, V>,
    key: &K,
    op: impl FnOnce(V) -> Fut,
) -> Result<Out::Rest, E>
where
    K: Ord,
    Out: Threaded<V>,
    Fut: Future<Output = Result<Out, E>>,
{
    let (key, value) = map
        .remove_entry(key)
        .expect("cannot rebind a missing entry");
    let (value, rest) = op(value).await?.split();
    map.insert(key, value);
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::oneshot;
    use futures::{
        executor::block_on,
        future::{self, Either, select},
        pin_mut,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
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
        async move {
            let _ = receiver.await;
        }
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
    fn test_abortable_pool_aborts_pre_polled_ready_future() {
        block_on(async move {
            let mut pool = AbortablePool::<i32>::default();
            let hook = pool.push(future::ready(42));
            drop(hook);
            let result = pool.next_completed().await;
            assert!(result.is_err());
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
    fn test_rebind_restores_value_and_yields_rest() {
        block_on(async {
            let mut slot = Some(1u32);
            let rest: Result<(&str, bool), &str> = rebind(&mut slot, |value| {
                future::ready(Ok((value + 1, "rest", true)))
            })
            .await;
            assert_eq!(rest, Ok(("rest", true)));
            assert_eq!(slot, Some(2));

            let rest: Result<(), &str> =
                rebind(&mut slot, |value| future::ready(Ok(value + 1))).await;
            assert_eq!(rest, Ok(()));
            assert_eq!(slot, Some(3));
        });
    }

    #[test]
    fn test_rebind_error_destroys_value() {
        block_on(async {
            let mut slot = Some(1u32);
            let rest: Result<(), &str> =
                rebind(&mut slot, |_| future::ready(Err::<u32, _>("failed"))).await;
            assert_eq!(rest, Err("failed"));
            assert_eq!(slot, None);
        });
    }

    #[test]
    #[should_panic(expected = "cannot rebind an empty slot")]
    fn test_rebind_empty_slot_panics() {
        block_on(async {
            let mut slot: Option<u32> = None;
            let _: Result<(), &str> = rebind(&mut slot, |v| future::ready(Ok(v))).await;
        });
    }

    #[test]
    fn test_rebind_entry_restores_value_and_yields_rest() {
        block_on(async {
            let mut map = BTreeMap::from([("a", 1u32), ("b", 10)]);
            let rest: Result<bool, &str> =
                rebind_entry(&mut map, &"a", |value| future::ready(Ok((value + 1, true)))).await;
            assert_eq!(rest, Ok(true));
            assert_eq!(map, BTreeMap::from([("a", 2), ("b", 10)]));
        });
    }

    #[test]
    fn test_rebind_entry_error_destroys_value() {
        block_on(async {
            let mut map = BTreeMap::from([("a", 1u32)]);
            let rest: Result<(), &str> =
                rebind_entry(&mut map, &"a", |_| future::ready(Err::<u32, _>("failed"))).await;
            assert_eq!(rest, Err("failed"));
            assert!(map.is_empty());
        });
    }

    #[test]
    #[should_panic(expected = "cannot rebind a missing entry")]
    fn test_rebind_entry_missing_entry_panics() {
        block_on(async {
            let mut map: BTreeMap<&str, u32> = BTreeMap::new();
            let _: Result<(), &str> = rebind_entry(&mut map, &"a", |v| future::ready(Ok(v))).await;
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
