//! Abstract data parallelism over iterators and collections.
//!
//! This crate provides the [`Strategy`] trait, which abstracts over sequential and parallel
//! execution of fold operations. This allows algorithms to be written once and executed either
//! sequentially or in parallel depending on the chosen strategy.
//!
//! # Overview
//!
//! The core abstraction is the [`Strategy`] trait, which provides several operations:
//!
//! **Core Operations:**
//! - [`fold`](Strategy::fold): Reduces a collection to a single value
//! - [`fold_init`](Strategy::fold_init): Like `fold`, but with per-partition initialization
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

use cfg_if::cfg_if;
use core::fmt;

cfg_if! {
    if #[cfg(feature = "std")] {
        use rayon::{
            iter::{ParallelBridge, ParallelIterator},
            ThreadPool,
        };
        use std::sync::Arc;
    } else {
        extern crate alloc;
        use alloc::vec::Vec;
    }
}

/// A strategy for executing fold and join operations.
///
/// This trait abstracts over sequential and parallel execution, allowing algorithms
/// to be written generically and then executed with different strategies depending
/// on the use case (e.g., sequential for testing/debugging, parallel for production).
pub trait Strategy: Clone + Send + Sync + fmt::Debug + 'static {
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
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync;

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
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        self.fold_init(
            iter,
            || (),
            identity,
            |acc, _, item| fold_op(acc, item),
            reduce_op,
        )
    }

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
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
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
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
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
}

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
    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        _reduce_op: RD,
    ) -> R
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
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
}

cfg_if! {
    if #[cfg(feature = "std")] {
        /// A parallel execution strategy backed by a rayon thread pool.
        ///
        /// This strategy executes fold operations in parallel across multiple threads.
        /// It wraps a rayon [`ThreadPool`] and uses it to schedule work.
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
        #[derive(Debug, Clone)]
        pub struct Parallel {
            thread_pool: Arc<ThreadPool>,
        }

        impl Parallel {
            /// Creates a new [`Parallel`] strategy with the given [`ThreadPool`].
            pub const fn new(thread_pool: Arc<ThreadPool>) -> Self {
                Self { thread_pool }
            }
        }

        impl From<Arc<ThreadPool>> for Parallel {
            fn from(thread_pool: Arc<ThreadPool>) -> Self {
                Self::new(thread_pool)
            }
        }

        impl Strategy for Parallel {
            fn fold_init<I, INIT, T, R, ID, F, RD>(
                &self,
                iter: I,
                init: INIT,
                identity: ID,
                fold_op: F,
                reduce_op: RD,
            ) -> R
            where
                I: IntoIterator<IntoIter: Send, Item: Send> + Send,
                INIT: Fn() -> T + Send + Sync,
                T: Send,
                R: Send,
                ID: Fn() -> R + Send + Sync,
                F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
                RD: Fn(R, R) -> R + Send + Sync,
            {
                self.thread_pool.install(|| {
                    // Enumerate items to track their original positions for order preservation.
                    // par_bridge() doesn't preserve order, so we sort by index after processing.
                    let mut indexed_results: Vec<(usize, R)> = iter
                        .into_iter()
                        .enumerate()
                        .par_bridge()
                        .fold(
                            || (init(), Vec::new()),
                            |(mut init_val, mut results), (idx, item)| {
                                let single_result = fold_op(identity(), &mut init_val, item);
                                results.push((idx, single_result));
                                (init_val, results)
                            },
                        )
                        .map(|(_, results)| results)
                        .reduce(Vec::new, |mut a, b| {
                            a.extend(b);
                            a
                        });

                    // Sort by original index to restore ordering
                    indexed_results.sort_by_key(|(idx, _)| *idx);

                    // Reduce in order
                    indexed_results
                        .into_iter()
                        .map(|(_, r)| r)
                        .reduce(reduce_op)
                        .unwrap_or_else(identity)
                })
            }
        }
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

    #[test]
    fn fold_init_empty_with_zero_identity() {
        let sequential = Sequential;
        let parallel = parallel_strategy();
        let empty: Vec<i64> = vec![];

        let seq_result = sequential.fold_init(
            &empty,
            || (),
            || 0i64,
            |acc, _, &x| acc.wrapping_add(x),
            |a, b| a.wrapping_add(b),
        );

        let par_result = parallel.fold_init(
            &empty,
            || (),
            || 0i64,
            |acc, _, &x| acc.wrapping_add(x),
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
        #[allow(clippy::redundant_clone)]
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
        #[allow(clippy::redundant_clone)]
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
        #[allow(clippy::redundant_clone)]
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
