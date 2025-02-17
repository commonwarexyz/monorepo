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
pub struct Pool<T> {
    pool: FuturesUnordered<PooledFuture<T>>,
}

impl<T: Send> Default for Pool<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Pool<T> {
    /// Creates a new futures pool.
    pub fn new() -> Self {
        // Insert a dummy future (that never resolves) to prevent the stream from being empty.
        // Else, the `select_next_some()` function returns `None` instantly.
        let pool = FuturesUnordered::new();
        let dummy: PooledFuture<T> = Box::pin(async { future::pending::<T>().await });
        pool.push(dummy);
        Self { pool }
    }

    /// Returns the number of futures in the pool.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        // Subtract the dummy future.
        self.pool.len().checked_sub(1).unwrap()
    }

    /// Adds a future to the pool.
    pub fn push(&mut self, future: impl Future<Output = T> + Send + 'static) {
        self.pool.push(Box::pin(future));
    }

    /// Returns a futures that resolves to the next future in the pool that resolves.
    ///
    /// If the pool is empty, the future will never resolve.
    pub fn stream(&mut self) -> SelectNextSome<FuturesUnordered<PooledFuture<T>>> {
        self.pool.select_next_some()
    }
}
