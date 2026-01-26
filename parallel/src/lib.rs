//! Parallelize fold operations with pluggable execution strategies..
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
//! - [`map_partition_collect_vec`](Strategy::map_partition_collect_vec): Maps elements, collecting
//!   successful results and tracking indices of filtered elements
//!
//! Two implementations are provided:
//!
//! - [`Sequential`]: Executes operations sequentially on the current thread (works in `no_std`)
//! - [`Rayon`]: Executes operations in parallel using a [`rayon`] thread pool (requires `std`)
//!
//! # Features
//!
//! - `std` (default): Enables the [`Rayon`] strategy backed by rayon
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
//! fn sum_of_squares(strategy: &impl Strategy, data: &[i64]) -> i64 {
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
use commonware_macros::ready;
use core::fmt;

cfg_if! {
    if #[cfg(feature = "std")] {
        use rayon::{
            iter::{IntoParallelIterator, ParallelIterator},
            ThreadPool as RThreadPool, ThreadPoolBuilder,
            ThreadPoolBuildError
        };
        use std::{num::NonZeroUsize, sync::Arc};
    } else {
        extern crate alloc;
        use alloc::vec::Vec;
    }
}

/// A strategy for executing fold operations.
///
/// This trait abstracts over sequential and parallel execution, allowing algorithms
/// to be written generically and then executed with different strategies depending
/// on the use case (e.g., sequential for testing/debugging, parallel for production).
#[ready(GAMMA)]
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
    /// For [`Rayon`], elements may be processed out of order but the final
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

    /// Maps each element, filtering out `None` results and tracking their keys.
    ///
    /// This is a convenience method that applies `map_op` to each element. The
    /// closure returns `(key, Option<value>)`. Elements where the option is `Some`
    /// have their values collected into the first vector. Elements where the option
    /// is `None` have their keys collected into the second vector.
    ///
    /// # Arguments
    ///
    /// - `iter`: The collection to map over
    /// - `map_op`: The mapping function returning `(K, Option<U>)`
    ///
    /// # Returns
    ///
    /// A tuple of `(results, filtered_keys)` where:
    /// - `results`: Values from successful mappings (where `map_op` returned `Some`)
    /// - `filtered_keys`: Keys where `map_op` returned `None`
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    /// let data = vec![1, 2, 3, 4, 5];
    ///
    /// let (evens, odd_values): (Vec<i32>, Vec<i32>) = strategy.map_partition_collect_vec(
    ///     data.iter(),
    ///     |&x| (x, if x % 2 == 0 { Some(x * 10) } else { None }),
    /// );
    ///
    /// assert_eq!(evens, vec![20, 40]);
    /// assert_eq!(odd_values, vec![1, 3, 5]);
    /// ```
    fn map_partition_collect_vec<I, F, K, U>(&self, iter: I, map_op: F) -> (Vec<U>, Vec<K>)
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        F: Fn(I::Item) -> (K, Option<U>) + Send + Sync,
        K: Send,
        U: Send,
    {
        self.fold(
            iter,
            || (Vec::new(), Vec::new()),
            |(mut results, mut filtered), item| {
                let (key, value) = map_op(item);
                match value {
                    Some(v) => results.push(v),
                    None => filtered.push(key),
                }
                (results, filtered)
            },
            |(mut r1, mut f1), (r2, f2)| {
                r1.extend(r2);
                f1.extend(f2);
                (r1, f1)
            },
        )
    }

    /// Executes two closures, potentially in parallel, and returns both results.
    ///
    /// For [`Sequential`], this executes `a` then `b` on the current thread.
    /// For [`Rayon`], this executes `a` and `b` in parallel using the thread pool.
    ///
    /// # Arguments
    ///
    /// - `a`: First closure to execute
    /// - `b`: Second closure to execute
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_parallel::{Strategy, Sequential};
    ///
    /// let strategy = Sequential;
    ///
    /// let (sum, product) = strategy.join(
    ///     || (1..=5).sum::<i32>(),
    ///     || (1..=5).product::<i32>(),
    /// );
    ///
    /// assert_eq!(sum, 15);
    /// assert_eq!(product, 120);
    /// ```
    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send;

    /// Return the number of threads that are available, as a hint to chunking.
    fn parallelism_hint(&self) -> usize;
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
#[ready(GAMMA)]
#[derive(Default, Debug, Clone)]
pub struct Sequential;

#[ready(GAMMA)]
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

    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        (a(), b())
    }

    fn parallelism_hint(&self) -> usize {
        1
    }
}

cfg_if! {
    if #[cfg(feature = "std")] {
        /// A clone-able wrapper around a [rayon]-compatible thread pool.
        #[ready(GAMMA)]
        pub type ThreadPool = Arc<RThreadPool>;

        /// A parallel execution strategy backed by a rayon thread pool.
        ///
        /// This strategy executes fold operations in parallel across multiple threads.
        /// It wraps a rayon [`ThreadPool`] and uses it to schedule work.
        ///
        /// # Thread Pool Ownership
        ///
        /// `Rayon` holds an [`Arc<ThreadPool>`], so it can be cheaply cloned and shared
        /// across threads. Multiple [`Rayon`] instances can share the same underlying
        /// thread pool.
        ///
        /// # When to Use
        ///
        /// Use `Rayon` when:
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
        /// ```rust
        /// use commonware_parallel::{Strategy, Rayon};
        /// use std::num::NonZeroUsize;
        ///
        /// let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();
        ///
        /// let data: Vec<i64> = (0..1000).collect();
        /// let sum = strategy.fold(&data, || 0i64, |acc, &n| acc + n, |a, b| a + b);
        /// assert_eq!(sum, 499500);
        /// ```
        #[ready(GAMMA)]
        #[derive(Debug, Clone)]
        pub struct Rayon {
            thread_pool: ThreadPool,
        }

        #[ready(GAMMA)]
        impl Rayon {
            /// Creates a [`Rayon`] strategy with a [`ThreadPool`] that is configured with the given
            /// number of threads.
            pub fn new(num_threads: NonZeroUsize) -> Result<Self, ThreadPoolBuildError> {
                ThreadPoolBuilder::new()
                    .num_threads(num_threads.get())
                    .build()
                    .map(|pool| Self::with_pool(Arc::new(pool)))
            }

            /// Creates a new [`Rayon`] strategy with the given [`ThreadPool`].
            pub const fn with_pool(thread_pool: ThreadPool) -> Self {
                Self { thread_pool }
            }
        }

        #[ready(GAMMA)]
        impl Strategy for Rayon {
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
                    // Collecting into a vec first enables `into_par_iter()` which provides
                    // contiguous partitions. This allows each partition to accumulate with
                    // `fold_op`, producing ~num_threads intermediate R values instead of N.
                    // The final reduce then merges ~num_threads results instead of N.
                    //
                    // Alternative approaches like `par_bridge()` don't provide contiguous
                    // partitions, which forces each item to produce its own R value that
                    // must then be reduced one-by-one.
                    let items: Vec<I::Item> = iter.into_iter().collect();
                    items
                        .into_par_iter()
                        .fold(
                            || (init(), identity()),
                            |(mut init_val, acc), item| {
                                let new_acc = fold_op(acc, &mut init_val, item);
                                (init_val, new_acc)
                            },
                        )
                        .map(|(_, acc)| acc)
                        .reduce(&identity, reduce_op)
                })
            }

            fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
            where
                A: FnOnce() -> RA + Send,
                B: FnOnce() -> RB + Send,
                RA: Send,
                RB: Send,
            {
                self.thread_pool.install(|| rayon::join(a, b))
            }

            fn parallelism_hint(&self) -> usize {
                self.thread_pool.current_num_threads()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{Rayon, Sequential, Strategy};
    use core::num::NonZeroUsize;
    use proptest::prelude::*;

    fn parallel_strategy() -> Rayon {
        Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap()
    }

    proptest! {
        #[test]
        fn parallel_fold_init_matches_sequential(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let sequential = Sequential;
            let parallel = parallel_strategy();

            let seq_result: Vec<i32> = sequential.fold_init(
                &data,
                || (),
                Vec::new,
                |mut acc, _, &x| { acc.push(x.wrapping_mul(2)); acc },
                |mut a, b| { a.extend(b); a },
            );

            let par_result: Vec<i32> = parallel.fold_init(
                &data,
                || (),
                Vec::new,
                |mut acc, _, &x| { acc.push(x.wrapping_mul(2)); acc },
                |mut a, b| { a.extend(b); a },
            );

            prop_assert_eq!(seq_result, par_result);
        }

        #[test]
        fn fold_equals_fold_init(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let s = Sequential;

            let via_fold: Vec<i32> = s.fold(
                &data,
                Vec::new,
                |mut acc, &x| { acc.push(x); acc },
                |mut a, b| { a.extend(b); a },
            );

            let via_fold_init: Vec<i32> = s.fold_init(
                &data,
                || (),
                Vec::new,
                |mut acc, _, &x| { acc.push(x); acc },
                |mut a, b| { a.extend(b); a },
            );

            prop_assert_eq!(via_fold, via_fold_init);
        }

        #[test]
        fn map_collect_vec_equals_fold(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let s = Sequential;
            let map_op = |&x: &i32| x.wrapping_mul(3);

            let via_map: Vec<i32> = s.map_collect_vec(&data, map_op);

            let via_fold: Vec<i32> = s.fold(
                &data,
                Vec::new,
                |mut acc, item| { acc.push(map_op(item)); acc },
                |mut a, b| { a.extend(b); a },
            );

            prop_assert_eq!(via_map, via_fold);
        }

        #[test]
        fn map_init_collect_vec_equals_fold_init(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let s = Sequential;

            let via_map: Vec<i32> = s.map_init_collect_vec(
                &data,
                || 0i32,
                |counter, &x| { *counter += 1; x.wrapping_add(*counter) },
            );

            let via_fold_init: Vec<i32> = s.fold_init(
                &data,
                || 0i32,
                Vec::new,
                |mut acc, counter, &x| {
                    *counter += 1;
                    acc.push(x.wrapping_add(*counter));
                    acc
                },
                |mut a, b| { a.extend(b); a },
            );

            prop_assert_eq!(via_map, via_fold_init);
        }

        #[test]
        fn map_partition_collect_vec_returns_valid_results(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let s = Sequential;

            let map_op = |&x: &i32| {
                let value = if x % 2 == 0 { Some(x.wrapping_mul(2)) } else { None };
                (x, value)
            };

            let (results, filtered) = s.map_partition_collect_vec(data.iter(), map_op);

            // Verify results contains doubled even numbers
            let expected_results: Vec<i32> = data.iter().filter(|&&x| x % 2 == 0).map(|&x| x.wrapping_mul(2)).collect();
            prop_assert_eq!(results, expected_results);

            // Verify filtered contains odd numbers
            let expected_filtered: Vec<i32> = data.iter().filter(|&&x| x % 2 != 0).copied().collect();
            prop_assert_eq!(filtered, expected_filtered);
        }
    }
}
