//! Abstract data parallelism over iterators and collections.
//!
//! This crate provides the [`Strategy`] trait, which abstracts over sequential and parallel
//! execution of fold and join operations. This allows algorithms to be written once and
//! executed either sequentially or in parallel depending on the chosen strategy.
//!
//! # Overview
//!
//! The core abstraction is the [`Strategy`] trait, which provides several operations:
//!
//! **Core Operations:**
//! - [`fold`](Strategy::fold): Reduces a collection to a single value
//! - [`fold_init`](Strategy::fold_init): Like `fold`, but with per-partition initialization
//! - [`join`](Strategy::join): Executes two closures, potentially in parallel
//!
//! **Convenience Methods:**
//! - [`map_collect_vec`](Strategy::map_collect_vec): Maps elements and collects into a `Vec`
//! - [`map_init_collect_vec`](Strategy::map_init_collect_vec): Like `map_collect_vec` with
//!   per-partition initialization
//!
//! Two implementations are provided:
//!
//! - [`Sequential`]: Executes operations sequentially on the current thread (works in `no_std`)
//! - [`Parallel`]: Executes operations in parallel using a rayon thread pool (requires `std`)
//!
//! # Features
//!
//! - `std` (default): Enables the [`Parallel`] strategy backed by rayon
//!
//! When the `std` feature is disabled, only [`Sequential`] is available, making this crate
//! suitable for `no_std` environments.
//!
//! # Example
//!
//! The main benefit of this crate is writing algorithms that can switch between sequential
//! and parallel execution:
//!
//! ```
//! use commonware_parallel::{Strategy, Sequential};
//!
//! fn sum_of_squares<S: Strategy>(strategy: &S, data: &[i64]) -> i64 {
//!     strategy.fold(
//!         data,
//!         || 0i64,
//!         |acc, &x| acc + x * x,
//!         |a, b| a + b,
//!     )
//! }
//!
//! let strategy = Sequential;
//! let data = vec![1, 2, 3, 4, 5];
//! let result = sum_of_squares(&strategy, &data);
//! assert_eq!(result, 55); // 1 + 4 + 9 + 16 + 25
//! ```

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(feature = "std")]
use rayon::{
    iter::{IntoParallelIterator as RIntoParallelIterator, ParallelIterator},
    ThreadPool,
};
#[cfg(feature = "std")]
use std::sync::Arc;

/// A strategy for executing fold and join operations.
///
/// This trait abstracts over sequential and parallel execution, allowing algorithms
/// to be written generically and then executed with different strategies depending
/// on the use case (e.g., sequential for testing/debugging, parallel for production).
pub trait Strategy: Clone + Send + Sync {
    /// Reduces a collection to a single value using fold and reduce operations.
    ///
    /// This method processes elements from the iterator, combining them into a single
    /// result.
    ///
    /// # Arguments
    ///
    /// - `iter`: The collection to fold over
    /// - `identity`: A closure that produces the identity value for the fold.
    /// - `fold_op`: Combines an accumulator with a single item: `(acc, item) -> acc`
    /// - `reduce_op`: Combines two accumulators: `(acc1, acc2) -> acc`.
    ///
    /// # Examples
    ///
    /// ## Sum of Elements
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    /// let numbers = vec![1, 2, 3, 4, 5];
    ///
    /// let sum = strategy.fold(
    ///     &numbers,
    ///     || 0,                    // identity
    ///     |acc, &n| acc + n,       // fold: add each number
    ///     |a, b| a + b,            // reduce: combine partial sums
    /// );
    ///
    /// assert_eq!(sum, 15);
    /// ```
    fn fold<I, R, ID, F, RD>(&self, iter: I, identity: ID, fold_op: F, reduce_op: RD) -> R
    where
        I: IntoParallelIterator + Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync;

    /// Reduces a collection to a single value with per-partition initialization.
    ///
    /// Similar to [`fold`](Self::fold), but provides a separate initialization value
    /// that is created once per partition. This is useful when the fold operation
    /// requires mutable state that should not be shared across partitions (e.g., a
    /// scratch buffer, RNG, or expensive-to-clone resource).
    ///
    /// # Arguments
    ///
    /// - `iter`: The collection to fold over
    /// - `init`: Creates the per-partition initialization value
    /// - `identity`: Creates the identity value for the accumulator
    /// - `fold_op`: Combines accumulator with init state and item: `(acc, &mut init, item) -> acc`
    /// - `reduce_op`: Combines two accumulators: `(acc1, acc2) -> acc`
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    /// let data = vec![1u32, 2, 3, 4, 5];
    ///
    /// // Use a scratch buffer to avoid allocations in the inner loop
    /// let result: Vec<String> = strategy.fold_init(
    ///     &data,
    ///     || String::with_capacity(16),  // Per-partition scratch buffer
    ///     Vec::new,                       // Identity for accumulator
    ///     |mut acc, buf, &n| {
    ///         buf.clear();
    ///         use std::fmt::Write;
    ///         write!(buf, "num:{}", n).unwrap();
    ///         acc.push(buf.clone());
    ///         acc
    ///     },
    ///     |mut a, b| { a.extend(b); a },
    /// );
    ///
    /// assert_eq!(result, vec!["num:1", "num:2", "num:3", "num:4", "num:5"]);
    /// ```
    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> R
    where
        I: IntoParallelIterator + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync;

    /// Maps each element and collects results into a `Vec`.
    ///
    /// This is a convenience method that applies `map_op` to each element and
    /// collects the results. For [`Sequential`], elements are processed in order.
    /// For [`Parallel`], elements may be processed out of order but the final
    /// vector preserves the original ordering.
    ///
    /// # Arguments
    ///
    /// - `iter`: The collection to map over
    /// - `map_op`: The mapping function to apply to each element
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    /// let data = vec![1, 2, 3, 4, 5];
    ///
    /// let squared: Vec<i32> = strategy.map_collect_vec(&data, |&x| x * x);
    /// assert_eq!(squared, vec![1, 4, 9, 16, 25]);
    /// ```
    fn map_collect_vec<I, F, T>(&self, iter: I, map_op: F) -> Vec<T>
    where
        I: IntoParallelIterator + Send,
        F: Fn(I::Item) -> T + Send + Sync,
        T: Send,
    {
        self.fold(
            iter,
            Vec::new,
            |mut acc, item| {
                acc.push(map_op(item));
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        )
    }

    /// Maps each element with per-partition state and collects results into a `Vec`.
    ///
    /// Combines [`map_collect_vec`](Self::map_collect_vec) with per-partition
    /// initialization like [`fold_init`](Self::fold_init). Useful when the mapping
    /// operation requires mutable state that should not be shared across partitions.
    ///
    /// # Arguments
    ///
    /// - `iter`: The collection to map over
    /// - `init`: Creates the per-partition initialization value
    /// - `map_op`: The mapping function: `(&mut init, item) -> result`
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    /// let data = vec![1, 2, 3, 4, 5];
    ///
    /// // Use a counter that tracks position within each partition
    /// let indexed: Vec<(usize, i32)> = strategy.map_init_collect_vec(
    ///     &data,
    ///     || 0usize, // Per-partition counter
    ///     |counter, &x| {
    ///         let idx = *counter;
    ///         *counter += 1;
    ///         (idx, x * 2)
    ///     },
    /// );
    ///
    /// assert_eq!(indexed, vec![(0, 2), (1, 4), (2, 6), (3, 8), (4, 10)]);
    /// ```
    fn map_init_collect_vec<I, INIT, T, F, R>(&self, iter: I, init: INIT, map_op: F) -> Vec<R>
    where
        I: IntoParallelIterator + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        F: Fn(&mut T, I::Item) -> R + Send + Sync,
        R: Send,
    {
        self.fold_init(
            iter,
            init,
            Vec::new,
            |mut acc, init_val, item| {
                acc.push(map_op(init_val, item));
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        )
    }

    /// Executes two closures, potentially in parallel, and returns both results.
    ///
    /// For [`Sequential`], the closures are executed one after the other on the current
    /// thread. For [`Parallel`], the closures may be executed concurrently on different
    /// threads.
    ///
    /// This is useful for divide-and-conquer algorithms where two independent subproblems
    /// can be solved in parallel.
    ///
    /// # Arguments
    ///
    /// - `left`: The first closure to execute
    /// - `right`: The second closure to execute
    ///
    /// # Returns
    ///
    /// A tuple containing the results of both closures: `(left_result, right_result)`
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    ///
    /// let (sum, product) = strategy.join(
    ///     || (1..=10).sum::<i32>(),
    ///     || (1..=10).product::<i32>(),
    /// );
    ///
    /// assert_eq!(sum, 55);
    /// assert_eq!(product, 3628800);
    /// ```
    fn join<L, LO, R, RO>(&self, left: L, right: R) -> (LO, RO)
    where
        L: FnOnce() -> LO + Send,
        R: FnOnce() -> RO + Send,
        LO: Send,
        RO: Send;
}

/// A trait for types that can be converted into a parallel iterator.
///
/// This trait extends [`IntoIterator`] to also support conversion into a parallel
/// iterator when the `std` feature is enabled. It serves as a bridge between
/// standard iterators and rayon's parallel iterators.
///
/// # Feature Flags
///
/// - With `std`: Provides [`into_par_iter`](IntoParallelIterator::into_par_iter)
///   for parallel iteration
/// - Without `std`: Acts as a marker trait with no additional methods
///
/// # Blanket Implementation
///
/// This trait is automatically implemented for all types that implement both
/// [`IntoIterator`] and rayon's `IntoParallelIterator` (when `std` is enabled).
/// This includes common collection types like `Vec<T>`, `&[T]`, ranges, etc.
///
/// # Examples
///
/// ```
/// use commonware_parallel::IntoParallelIterator;
///
/// // Vec implements IntoParallelIterator
/// let vec = vec![1, 2, 3];
/// let _iter = vec.into_iter(); // Can use as regular iterator
///
/// // Slices also implement it
/// let slice: &[i32] = &[1, 2, 3];
/// let _iter = slice.into_iter();
///
/// // Ranges work too
/// let range = 0..100;
/// let _iter = range.into_iter();
/// ```
pub trait IntoParallelIterator: IntoIterator {
    /// The parallel iterator type that this converts into.
    ///
    /// This is the type returned by [`into_par_iter`](Self::into_par_iter).
    #[cfg(feature = "std")]
    type ParIter: ParallelIterator<Item = <Self as IntoIterator>::Item>;

    /// Converts this type into a parallel iterator.
    ///
    /// This is used by [`Parallel::fold`] to enable parallel processing of the
    /// collection.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::IntoParallelIterator;
    /// use rayon::iter::ParallelIterator;
    ///
    /// let data = vec![1, 2, 3, 4, 5];
    /// let sum: i32 = data.into_par_iter().sum();
    /// assert_eq!(sum, 15);
    /// ```
    #[cfg(feature = "std")]
    fn into_par_iter(self) -> Self::ParIter;
}

#[cfg(feature = "std")]
impl<T> IntoParallelIterator for T
where
    T: IntoIterator,
    T: RIntoParallelIterator<Item = <T as IntoIterator>::Item>,
{
    type ParIter = <T as RIntoParallelIterator>::Iter;

    fn into_par_iter(self) -> Self::ParIter {
        RIntoParallelIterator::into_par_iter(self)
    }
}

#[cfg(not(feature = "std"))]
impl<T> IntoParallelIterator for T where T: IntoIterator {}

/// A sequential execution strategy.
///
/// This strategy executes all operations on the current thread without any
/// parallelism. It is useful for:
///
/// - Debugging and testing (deterministic execution)
/// - `no_std` environments where threading is unavailable
/// - Small workloads where parallelism overhead exceeds benefits
/// - Comparing sequential vs parallel performance
///
/// # Examples
///
/// ```
/// use commonware_parallel::{Strategy, Sequential};
///
/// let strategy = Sequential;
/// let data = vec![1, 2, 3, 4, 5];
///
/// let sum = strategy.fold(&data, || 0, |a, &b| a + b, |a, b| a + b);
/// assert_eq!(sum, 15);
/// ```
#[derive(Default, Debug, Clone)]
pub struct Sequential;

impl Strategy for Sequential {
    fn fold<I, T, ID, F, R>(&self, iter: I, identity: ID, fold_op: F, _reduce_op: R) -> T
    where
        I: IntoParallelIterator + Send,
        T: Send,
        ID: Fn() -> T + Send + Sync,
        F: Fn(T, I::Item) -> T + Send + Sync,
        R: Fn(T, T) -> T + Send + Sync,
    {
        iter.into_iter().fold(identity(), fold_op)
    }

    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        _reduce_op: RD,
    ) -> R
    where
        I: IntoParallelIterator + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        let mut init_val = init();
        iter.into_iter()
            .fold(identity(), |acc, item| fold_op(acc, &mut init_val, item))
    }

    fn join<L, LO, R, RO>(&self, left: L, right: R) -> (LO, RO)
    where
        L: FnOnce() -> LO + Send,
        R: FnOnce() -> RO + Send,
        LO: Send,
        RO: Send,
    {
        (left(), right())
    }
}

/// A parallel execution strategy backed by a rayon thread pool.
///
/// This strategy executes fold and join operations in parallel across multiple
/// threads. It wraps a rayon [`ThreadPool`] and uses it to schedule work.
///
/// # Thread Pool Ownership
///
/// `Parallel` holds an [`Arc<ThreadPool>`], so it can be cheaply cloned and shared
/// across threads. Multiple [`Parallel`] instances can share the same underlying
/// thread pool.
///
/// # When to Use
///
/// Use `Parallel` when:
///
/// - Processing large collections where parallelism overhead is justified
/// - The fold/reduce operations are CPU-bound
/// - You want to utilize multiple cores
///
/// Consider [`Sequential`] instead when:
///
/// - The collection is small
/// - Operations are I/O-bound rather than CPU-bound
/// - Deterministic execution order is required for debugging
///
/// # Examples
///
/// ```
/// use commonware_parallel::{Strategy, Parallel};
/// use rayon::ThreadPoolBuilder;
/// use std::sync::Arc;
///
/// let pool = Arc::new(ThreadPoolBuilder::new().num_threads(2).build().unwrap());
/// let strategy = Parallel::new(pool);
///
/// let data: Vec<i64> = (0..1000).collect();
/// let sum = strategy.fold(&data, || 0i64, |acc, &n| acc + n, |a, b| a + b);
/// assert_eq!(sum, 499500);
/// ```
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct Parallel {
    thread_pool: Arc<ThreadPool>,
}

#[cfg(feature = "std")]
impl Parallel {
    /// Creates a new [`Parallel`] strategy with the given [`ThreadPool`].
    pub const fn new(thread_pool: Arc<ThreadPool>) -> Self {
        Self { thread_pool }
    }
}

#[cfg(feature = "std")]
impl From<Arc<ThreadPool>> for Parallel {
    fn from(thread_pool: Arc<ThreadPool>) -> Self {
        Self::new(thread_pool)
    }
}

#[cfg(feature = "std")]
impl Strategy for Parallel {
    fn fold<I, T, ID, F, R>(&self, iter: I, identity: ID, fold_op: F, reduce_op: R) -> T
    where
        I: IntoParallelIterator + Send,
        T: Send,
        ID: Fn() -> T + Send + Sync,
        F: Fn(T, I::Item) -> T + Send + Sync,
        R: Fn(T, T) -> T + Send + Sync,
    {
        self.thread_pool.install(|| {
            // Use Option<T> to track whether any elements were processed.
            // This ensures empty iterators return identity() exactly once,
            // matching Sequential semantics. Without this, rayon might create
            // multiple empty partitions, each calling identity(), then reduce
            // them together (e.g., identity=1 with reduce=add gives 1+1+1+1=4).
            iter.into_par_iter()
                .fold(
                    || None,
                    |acc, x| {
                        Some(match acc {
                            Some(a) => fold_op(a, x),
                            None => fold_op(identity(), x),
                        })
                    },
                )
                .reduce(
                    || None,
                    |a, b| match (a, b) {
                        (Some(a), Some(b)) => Some(reduce_op(a, b)),
                        (i @ Some(_), None) | (None, i @ Some(_)) => i,
                        (None, None) => None,
                    },
                )
                .unwrap_or_else(identity)
        })
    }

    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> R
    where
        I: IntoParallelIterator + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        self.thread_pool.install(|| {
            // Use Option<R> to track whether any elements were processed,
            // matching the same fix applied to fold() for empty collection handling.
            iter.into_par_iter()
                .fold(
                    || (None, init()),
                    |(acc, mut init_val), item| {
                        let new_acc = Some(match acc {
                            Some(a) => fold_op(a, &mut init_val, item),
                            None => fold_op(identity(), &mut init_val, item),
                        });
                        (new_acc, init_val)
                    },
                )
                .map(|(acc, _)| acc)
                .reduce(
                    || None,
                    |a, b| match (a, b) {
                        (Some(a), Some(b)) => Some(reduce_op(a, b)),
                        (i @ Some(_), None) | (None, i @ Some(_)) => i,
                        (None, None) => None,
                    },
                )
                .unwrap_or_else(identity)
        })
    }

    fn join<L, LO, R, RO>(&self, left: L, right: R) -> (LO, RO)
    where
        L: FnOnce() -> LO + Send,
        R: FnOnce() -> RO + Send,
        LO: Send,
        RO: Send,
    {
        self.thread_pool.install(|| rayon::join(left, right))
    }
}

#[cfg(test)]
mod test {
    use crate::{Parallel, Sequential, Strategy};
    use proptest::prelude::*;
    use rayon::ThreadPoolBuilder;
    use std::sync::Arc;

    /// Creates a Parallel strategy for testing.
    fn parallel_strategy() -> Parallel {
        let thread_pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
        Parallel::new(Arc::new(thread_pool))
    }

    #[test]
    fn fold_empty_with_zero_identity() {
        let sequential = Sequential;
        let parallel = parallel_strategy();
        let empty: Vec<i64> = vec![];

        let seq_result = sequential.fold(
            &empty,
            || 0i64,
            |acc, &x| acc.wrapping_add(x),
            |a, b| a.wrapping_add(b),
        );

        let par_result = parallel.fold(
            &empty,
            || 0i64,
            |acc, &x| acc.wrapping_add(x),
            |a, b| a.wrapping_add(b),
        );

        assert_eq!(seq_result, 0i64);
        assert_eq!(par_result, 0i64);
    }

    proptest! {
        #[test]
        fn fold_range_sum(end in 0u64..10000) {
            let sequential = Sequential;
            let parallel = parallel_strategy();
            let range: Vec<u64> = (0..end).collect();

            let seq_result = sequential.fold(
                &range,
                || 0u64,
                |acc, &x| acc + x,
                |a, b| a + b,
            );

            let par_result = parallel.fold(
                &range,
                || 0u64,
                |acc, &x| acc + x,
                |a, b| a + b,
            );

            let expected = (0..end).sum::<u64>();
            prop_assert_eq!(seq_result, expected);
            prop_assert_eq!(par_result, expected);
        }

        #[test]
        fn fold_empty_returns_identity(identity in any::<i64>()) {
            let sequential = Sequential;
            let parallel = parallel_strategy();
            let empty: Vec<i64> = vec![];

            let seq_result = sequential.fold(
                &empty,
                || identity,
                |acc, &x| acc + x,
                |a, b| a + b,
            );

            let par_result = parallel.fold(
                &empty,
                || identity,
                |acc, &x| acc + x,
                |a, b| a + b,
            );

            prop_assert_eq!(seq_result, identity);
            prop_assert_eq!(par_result, identity);
        }


        #[test]
        fn fold_single_element(value in any::<i64>()) {
            let sequential = Sequential;
            let parallel = parallel_strategy();
            let single = vec![value];

            let seq_result = sequential.fold(
                &single,
                || 0i64,
                |acc, &x| acc.wrapping_add(x),
                |a, b| a.wrapping_add(b),
            );

            let par_result = parallel.fold(
                &single,
                || 0i64,
                |acc, &x| acc.wrapping_add(x),
                |a, b| a.wrapping_add(b),
            );

            prop_assert_eq!(seq_result, value);
            prop_assert_eq!(par_result, value);
        }

        #[test]
        fn fold_collect_preserves_elements(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            let seq_result: Vec<i32> = sequential.fold(
                &data,
                Vec::new,
                |mut acc, &x| { acc.push(x); acc },
                |mut a, b| { a.extend(b); a },
            );

            let par_result: Vec<i32> = parallel.fold(
                &data,
                Vec::new,
                |mut acc, &x| { acc.push(x); acc },
                |mut a, b| { a.extend(b); a },
            );

            prop_assert_eq!(seq_result, data.clone());
            prop_assert_eq!(par_result, data);
        }

        #[test]
        fn join_results_match(a in any::<i32>(), b in any::<i32>()) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            let (seq_left, seq_right) = sequential.join(
                || a.wrapping_mul(2),
                || b.wrapping_add(10),
            );

            let (par_left, par_right) = parallel.join(
                || a.wrapping_mul(2),
                || b.wrapping_add(10),
            );

            prop_assert_eq!(seq_left, par_left);
            prop_assert_eq!(seq_right, par_right);
        }

        #[test]
        fn join_nested_matches(data in prop::collection::vec(any::<i32>(), 0..100)) {
            if data.len() < 2 {
                return Ok(());
            }

            let sequential = Sequential;
            let parallel = parallel_strategy();
            let mid = data.len() / 2;
            let (left, right) = data.split_at(mid);

            // Use wrapping arithmetic to avoid overflow
            let sum_slice = |slice: &[i32]| -> i32 {
                slice.iter().fold(0i32, |a, &b| a.wrapping_add(b))
            };

            let (seq_left_sum, seq_right_sum) = sequential.join(
                || sum_slice(left),
                || sum_slice(right),
            );

            let (par_left_sum, par_right_sum) = parallel.join(
                || sum_slice(left),
                || sum_slice(right),
            );

            prop_assert_eq!(seq_left_sum, par_left_sum);
            prop_assert_eq!(seq_right_sum, par_right_sum);
        }

        #[test]
        fn join_executes_both(x in any::<u32>(), y in any::<u32>()) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            let (seq_a, seq_b) = sequential.join(|| x, || y);
            let (par_a, par_b) = parallel.join(|| x, || y);

            prop_assert_eq!(seq_a, x);
            prop_assert_eq!(seq_b, y);
            prop_assert_eq!(par_a, x);
            prop_assert_eq!(par_b, y);
        }

        #[test]
        fn fold_init_matches(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            // Use init to track running count within each partition
            let seq_result: Vec<(usize, i32)> = sequential.fold_init(
                &data,
                || 0usize,  // per-partition counter
                Vec::new,
                |mut acc, counter, &x| {
                    acc.push((*counter, x.wrapping_mul(2)));
                    *counter += 1;
                    acc
                },
                |mut a, b| { a.extend(b); a },
            );

            let par_result: Vec<(usize, i32)> = parallel.fold_init(
                &data,
                || 0usize,
                Vec::new,
                |mut acc, counter, &x| {
                    acc.push((*counter, x.wrapping_mul(2)));
                    *counter += 1;
                    acc
                },
                |mut a, b| { a.extend(b); a },
            );

            // Both should have the same length and same doubled values
            prop_assert_eq!(seq_result.len(), data.len());
            prop_assert_eq!(par_result.len(), data.len());

            // Extract just the doubled values and compare
            let seq_values: Vec<i32> = seq_result.iter().map(|(_, v)| *v).collect();
            let par_values: Vec<i32> = par_result.iter().map(|(_, v)| *v).collect();
            let expected: Vec<i32> = data.iter().map(|&x| x.wrapping_mul(2)).collect();

            prop_assert_eq!(seq_values, expected.clone());
            prop_assert_eq!(par_values, expected);
        }

        #[test]
        fn fold_init_empty_returns_identity(identity in any::<i64>()) {
            let sequential = Sequential;
            let parallel = parallel_strategy();
            let empty: Vec<i64> = vec![];

            let seq_result = sequential.fold_init(
                &empty,
                || 0usize,
                || identity,
                |acc, _, &x| acc + x,
                |a, b| a + b,
            );

            let par_result = parallel.fold_init(
                &empty,
                || 0usize,
                || identity,
                |acc, _, &x| acc + x,
                |a, b| a + b,
            );

            prop_assert_eq!(seq_result, identity);
            prop_assert_eq!(par_result, identity);
        }

        #[test]
        fn map_collect_vec_matches(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            let seq_result: Vec<i64> = sequential.map_collect_vec(
                &data,
                |&x| (x as i64).wrapping_mul(3),
            );

            let par_result: Vec<i64> = parallel.map_collect_vec(
                &data,
                |&x| (x as i64).wrapping_mul(3),
            );

            let expected: Vec<i64> = data.iter().map(|&x| (x as i64).wrapping_mul(3)).collect();

            prop_assert_eq!(seq_result, expected.clone());
            prop_assert_eq!(par_result, expected);
        }

        #[test]
        fn map_collect_vec_empty(_unused in 0..1u8) {
            let sequential = Sequential;
            let parallel = parallel_strategy();
            let empty: Vec<i32> = vec![];

            let seq_result: Vec<i64> = sequential.map_collect_vec(&empty, |&x| x as i64);
            let par_result: Vec<i64> = parallel.map_collect_vec(&empty, |&x| x as i64);

            prop_assert!(seq_result.is_empty());
            prop_assert!(par_result.is_empty());
        }

        #[test]
        fn map_init_collect_vec_matches(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            // Use init to track sum of previous elements within partition
            let seq_result: Vec<i64> = sequential.map_init_collect_vec(
                &data,
                || 0i64,  // running sum
                |sum, &x| {
                    let result = *sum + x as i64;
                    *sum = result;
                    result
                },
            );

            let par_result: Vec<i64> = parallel.map_init_collect_vec(
                &data,
                || 0i64,
                |sum, &x| {
                    let result = *sum + x as i64;
                    *sum = result;
                    result
                },
            );

            // Both should have the same length
            prop_assert_eq!(seq_result.len(), data.len());
            prop_assert_eq!(par_result.len(), data.len());

            // Sequential result should be cumulative sums
            let expected: Vec<i64> = data.iter()
                .scan(0i64, |sum, &x| {
                    *sum += x as i64;
                    Some(*sum)
                })
                .collect();
            prop_assert_eq!(seq_result, expected);
        }

        #[test]
        fn map_init_collect_vec_empty(_unused in 0..1u8) {
            let sequential = Sequential;
            let parallel = parallel_strategy();
            let empty: Vec<i32> = vec![];

            let seq_result: Vec<i64> = sequential.map_init_collect_vec(
                &empty,
                || 0usize,
                |_, &x| x as i64,
            );
            let par_result: Vec<i64> = parallel.map_init_collect_vec(
                &empty,
                || 0usize,
                |_, &x| x as i64,
            );

            prop_assert!(seq_result.is_empty());
            prop_assert!(par_result.is_empty());
        }
    }
}
