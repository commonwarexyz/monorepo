//! Parallelize fold operations with pluggable execution strategies.
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
//! - [`try_fold`](Strategy::try_fold): Like `fold`, but stops applying the fold operation after
//!   failures
//! - [`fold_init`](Strategy::fold_init): Like `fold`, but with per-partition initialization
//! - [`sort_by`](Strategy::sort_by): Sorts a slice with a comparator
//!
//! **Convenience Methods:**
//! - [`map_collect_vec`](Strategy::map_collect_vec): Maps elements and collects into a `Vec`
//! - [`try_map_collect_vec`](Strategy::try_map_collect_vec): Maps fallible operations and
//!   collects into a `Result<Vec<_>, _>`
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

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

commonware_macros::stability_scope!(BETA {
    use cfg_if::cfg_if;
    use core::{cmp::Ordering, fmt};

    cfg_if! {
        if #[cfg(feature = "std")] {
            use rayon::{
                iter::{IntoParallelIterator, ParallelIterator},
                slice::ParallelSliceMut,
                ThreadPool as RThreadPool, ThreadPoolBuildError, ThreadPoolBuilder,
            };
            use std::{
                collections::HashMap,
                num::NonZeroUsize,
                panic::Location,
                sync::{Arc, Mutex},
                time::{Duration, Instant},
            };
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
        #[track_caller]
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
        #[track_caller]
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

        /// Reduces a collection to a single value using a fallible fold operation.
        ///
        /// Similar to [`fold`](Self::fold), but `fold_op` may fail. Implementations may stop
        /// applying `fold_op` after an error is observed. When more than one partition fails,
        /// any error may be returned.
        ///
        /// # Arguments
        ///
        /// - `iter`: The collection to fold over
        /// - `identity`: A closure that produces the identity value for the fold.
        /// - `fold_op`: Fallibly combines an accumulator with a single item: `(acc, item) -> Result<acc, E>`
        /// - `reduce_op`: Combines two successful accumulators: `(acc1, acc2) -> acc`.
        #[track_caller]
        fn try_fold<I, R, E, ID, F, RD>(
            &self,
            iter: I,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> Result<R, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            E: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            self.fold(
                iter,
                || Ok(identity()),
                |acc, item| match acc {
                    Ok(acc) => fold_op(acc, item),
                    Err(error) => Err(error),
                },
                |a, b| match a {
                    Ok(a) => b.map(|b| reduce_op(a, b)),
                    Err(error) => Err(error),
                },
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
        #[track_caller]
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

        /// Maps each element with a fallible operation and collects results into a `Vec`.
        ///
        /// This is a convenience method that applies `map_op` to each element and
        /// collects the results into a single `Result`. Output ordering on success
        /// matches [`map_collect_vec`](Self::map_collect_vec). Implementations may stop
        /// applying `map_op` after an error is observed. When more than one element
        /// fails, any error may be returned.
        ///
        /// # Arguments
        ///
        /// - `iter`: The collection to map over
        /// - `map_op`: The fallible mapping function to apply to each element
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_parallel::{Strategy, Sequential};
        ///
        /// let strategy = Sequential;
        /// let data = vec![1, 2, 3, 4, 5];
        ///
        /// let squared: Result<Vec<i32>, ()> = strategy.try_map_collect_vec(
        ///     &data,
        ///     |&x| Ok(x * x),
        /// );
        /// assert_eq!(squared, Ok(vec![1, 4, 9, 16, 25]));
        /// ```
        #[track_caller]
        fn try_map_collect_vec<I, F, T, E>(&self, iter: I, map_op: F) -> Result<Vec<T>, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> Result<T, E> + Send + Sync,
            T: Send,
            E: Send,
        {
            self.try_fold(
                iter,
                Vec::new,
                |mut acc, item| {
                    acc.push(map_op(item)?);
                    Ok(acc)
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
        #[track_caller]
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
        #[track_caller]
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
        #[track_caller]
        fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send;

        /// Sorts a slice with a comparator, preserving the order of equal elements.
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_parallel::{Strategy, Sequential};
        ///
        /// let strategy = Sequential;
        /// let mut data = vec![3, 1, 2];
        /// strategy.sort_by(&mut data, |a, b| a.cmp(b));
        /// assert_eq!(data, vec![1, 2, 3]);
        /// ```
        #[track_caller]
        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync;

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

        fn try_fold<I, R, E, ID, F, RD>(
            &self,
            iter: I,
            identity: ID,
            fold_op: F,
            _reduce_op: RD,
        ) -> Result<R, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            E: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            let mut acc = identity();
            for item in iter {
                acc = fold_op(acc, item)?;
            }
            Ok(acc)
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

        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            items.sort_by(compare);
        }

        fn parallelism_hint(&self) -> usize {
            1
        }
    }
});
commonware_macros::stability_scope!(BETA, cfg(feature = "std") {
    /// A clone-able wrapper around a [rayon]-compatible thread pool.
    pub type ThreadPool = Arc<RThreadPool>;

    const PREFERRED_SAMPLE_INTERVAL: u32 = 8;
    const RESAMPLE_INTERVAL: u32 = 64;
    const EWMA_ALPHA: f64 = 0.2;
    const SERIAL_WIN_MARGIN: f64 = 0.95;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    enum OperationKind {
        FoldInit,
        Fold,
        TryFold,
        MapCollect,
        TryMapCollect,
        MapInitCollect,
        MapPartitionCollect,
        Join,
        Sort,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    struct PolicyKey {
        file: &'static str,
        line: u32,
        column: u32,
        kind: OperationKind,
        bucket: u8,
        parallelism: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Execution {
        Serial,
        Parallel,
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct PolicyEntry {
        serial_ns: f64,
        parallel_ns: f64,
        serial_samples: u32,
        parallel_samples: u32,
        since_probe: u32,
    }

    type PolicyEntries = HashMap<PolicyKey, PolicyEntry>;

    impl PolicyEntry {
        fn choose(&mut self) -> (Execution, bool) {
            if self.parallel_samples == 0 {
                return (Execution::Parallel, true);
            }
            if self.serial_samples == 0 {
                return (Execution::Serial, true);
            }

            let preferred = if self.serial_ns < self.parallel_ns * SERIAL_WIN_MARGIN {
                Execution::Serial
            } else {
                Execution::Parallel
            };

            self.since_probe = self.since_probe.saturating_add(1);
            if self.since_probe < RESAMPLE_INTERVAL {
                return (
                    preferred,
                    self.since_probe % PREFERRED_SAMPLE_INTERVAL == 0,
                );
            }
            self.since_probe = 0;

            match preferred {
                Execution::Serial => (Execution::Parallel, true),
                Execution::Parallel => (Execution::Serial, true),
            }
        }

        fn record(&mut self, execution: Execution, elapsed: Duration) {
            let elapsed_ns = elapsed.as_secs_f64() * 1_000_000_000.0;
            match execution {
                Execution::Serial => {
                    self.serial_ns = update_ewma(self.serial_ns, self.serial_samples, elapsed_ns);
                    self.serial_samples = self.serial_samples.saturating_add(1);
                }
                Execution::Parallel => {
                    self.parallel_ns =
                        update_ewma(self.parallel_ns, self.parallel_samples, elapsed_ns);
                    self.parallel_samples = self.parallel_samples.saturating_add(1);
                }
            }
        }
    }

    fn update_ewma(current: f64, samples: u32, next: f64) -> f64 {
        if samples == 0 {
            next
        } else {
            current.mul_add(1.0 - EWMA_ALPHA, next * EWMA_ALPHA)
        }
    }

    fn policy_entries(policy: &Mutex<PolicyEntries>) -> std::sync::MutexGuard<'_, PolicyEntries> {
        policy.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn len_bucket(len: usize) -> u8 {
        if len == 0 {
            0
        } else {
            (usize::BITS - len.leading_zeros()) as u8
        }
    }

    fn policy_key(
        kind: OperationKind,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> PolicyKey {
        PolicyKey {
            file: caller.file(),
            line: caller.line(),
            column: caller.column(),
            kind,
            bucket: len_bucket(len),
            parallelism,
        }
    }

    fn choose_execution(
        policy: &Mutex<PolicyEntries>,
        kind: OperationKind,
        caller: &'static Location<'static>,
        len: usize,
        parallelism: usize,
    ) -> (PolicyKey, Execution, bool) {
        let key = policy_key(kind, caller, len, parallelism);
        if parallelism <= 1 {
            return (key, Execution::Serial, false);
        }
        let mut entries = policy_entries(policy);
        let (execution, measure) = entries.entry(key).or_default().choose();
        (key, execution, measure)
    }

    fn record_execution(
        policy: &Mutex<PolicyEntries>,
        key: PolicyKey,
        execution: Execution,
        elapsed: Duration,
    ) {
        policy_entries(policy)
            .entry(key)
            .or_default()
            .record(execution, elapsed);
    }

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
    #[derive(Debug, Clone)]
    pub struct Rayon {
        thread_pool: ThreadPool,
        policy: Arc<Mutex<PolicyEntries>>,
    }

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
        pub fn with_pool(thread_pool: ThreadPool) -> Self {
            Self {
                thread_pool,
                policy: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn choose(
            &self,
            kind: OperationKind,
            caller: &'static Location<'static>,
            len: usize,
        ) -> (PolicyKey, Execution, Option<Instant>) {
            let (key, execution, measure) = choose_execution(
                &self.policy,
                kind,
                caller,
                len,
                self.thread_pool.current_num_threads(),
            );
            (key, execution, measure.then(Instant::now))
        }

        fn record(&self, key: PolicyKey, execution: Execution, start: Option<Instant>) {
            if let Some(start) = start {
                record_execution(&self.policy, key, execution, start.elapsed());
            }
        }

        fn fold_init_with<I, INIT, T, R, ID, F, RD>(
            &self,
            kind: OperationKind,
            caller: &'static Location<'static>,
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
            let items: Vec<I::Item> = iter.into_iter().collect();
            let (key, execution, start) = self.choose(kind, caller, items.len());
            let result = match execution {
                Execution::Serial => {
                    let mut init_val = init();
                    items
                        .into_iter()
                        .fold(identity(), |acc, item| fold_op(acc, &mut init_val, item))
                }
                Execution::Parallel => self.thread_pool.install(|| {
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
                }),
            };
            self.record(key, execution, start);
            result
        }

        fn try_fold_with<I, R, E, ID, F, RD>(
            &self,
            kind: OperationKind,
            caller: &'static Location<'static>,
            iter: I,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> Result<R, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            E: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            let (key, execution, start) = self.choose(kind, caller, items.len());
            let result = match execution {
                Execution::Serial => {
                    let mut acc = identity();
                    let mut items = items.into_iter();
                    loop {
                        match items.next() {
                            Some(item) => match fold_op(acc, item) {
                                Ok(next) => acc = next,
                                Err(error) => break Err(error),
                            },
                            None => break Ok(acc),
                        }
                    }
                }
                Execution::Parallel => self.thread_pool.install(|| {
                    items
                        .into_par_iter()
                        .try_fold(&identity, &fold_op)
                        .try_reduce(&identity, |a, b| Ok(reduce_op(a, b)))
                }),
            };
            self.record(key, execution, start);
            result
        }
    }

    impl Strategy for Rayon {
        #[track_caller]
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
            self.fold_init_with(
                OperationKind::FoldInit,
                Location::caller(),
                iter,
                init,
                identity,
                fold_op,
                reduce_op,
            )
        }

        #[track_caller]
        fn fold<I, R, ID, F, RD>(&self, iter: I, identity: ID, fold_op: F, reduce_op: RD) -> R
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> R + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            self.fold_init_with(
                OperationKind::Fold,
                Location::caller(),
                iter,
                || (),
                identity,
                |acc, _, item| fold_op(acc, item),
                reduce_op,
            )
        }

        #[track_caller]
        fn map_collect_vec<I, F, T>(&self, iter: I, map_op: F) -> Vec<T>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> T + Send + Sync,
            T: Send,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            let (key, execution, start) =
                self.choose(OperationKind::MapCollect, Location::caller(), items.len());
            let result = match execution {
                Execution::Serial => items.into_iter().map(map_op).collect(),
                Execution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map(map_op).collect()),
            };
            self.record(key, execution, start);
            result
        }

        #[track_caller]
        fn try_map_collect_vec<I, F, T, E>(&self, iter: I, map_op: F) -> Result<Vec<T>, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> Result<T, E> + Send + Sync,
            T: Send,
            E: Send,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            let (key, execution, start) =
                self.choose(OperationKind::TryMapCollect, Location::caller(), items.len());
            let result = match execution {
                Execution::Serial => items.into_iter().map(map_op).collect(),
                Execution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map(map_op).collect()),
            };
            self.record(key, execution, start);
            result
        }

        #[track_caller]
        fn map_init_collect_vec<I, INIT, T, F, R>(&self, iter: I, init: INIT, map_op: F) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            F: Fn(&mut T, I::Item) -> R + Send + Sync,
            R: Send,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            let (key, execution, start) =
                self.choose(OperationKind::MapInitCollect, Location::caller(), items.len());
            let result = match execution {
                Execution::Serial => {
                    let mut init_val = init();
                    items
                        .into_iter()
                        .map(|item| map_op(&mut init_val, item))
                        .collect()
                }
                Execution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map_init(init, map_op).collect()),
            };
            self.record(key, execution, start);
            result
        }

        #[track_caller]
        fn try_fold<I, R, E, ID, F, RD>(
            &self,
            iter: I,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> Result<R, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            R: Send,
            E: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            self.try_fold_with(
                OperationKind::TryFold,
                Location::caller(),
                iter,
                identity,
                fold_op,
                reduce_op,
            )
        }

        #[track_caller]
        fn map_partition_collect_vec<I, F, K, U>(&self, iter: I, map_op: F) -> (Vec<U>, Vec<K>)
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> (K, Option<U>) + Send + Sync,
            K: Send,
            U: Send,
        {
            self.fold_init_with(
                OperationKind::MapPartitionCollect,
                Location::caller(),
                iter,
                || (),
                || (Vec::new(), Vec::new()),
                |(mut results, mut filtered), _, item| {
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

        #[track_caller]
        fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send,
        {
            let (key, execution, start) = self.choose(OperationKind::Join, Location::caller(), 2);
            let result = match execution {
                Execution::Serial => (a(), b()),
                Execution::Parallel => self.thread_pool.install(|| rayon::join(a, b)),
            };
            self.record(key, execution, start);
            result
        }

        #[track_caller]
        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            let (key, execution, start) =
                self.choose(OperationKind::Sort, Location::caller(), items.len());
            match execution {
                Execution::Serial => items.sort_by(compare),
                Execution::Parallel => self.thread_pool.install(|| items.par_sort_by(compare)),
            }
            self.record(key, execution, start);
        }

        fn parallelism_hint(&self) -> usize {
            self.thread_pool.current_num_threads()
        }
    }
});

#[cfg(test)]
mod test {
    use crate::{Rayon, Sequential, Strategy};
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    fn parallel_strategy() -> Rayon {
        Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap()
    }

    fn policy_len(strategy: &Rayon) -> usize {
        super::policy_entries(&strategy.policy).len()
    }

    #[test]
    fn adaptive_policy_is_scoped_to_rayon() {
        let strategy = parallel_strategy();
        let other = parallel_strategy();

        let _: Vec<_> = strategy.map_collect_vec(0..16, |x| x);

        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(policy_len(&other), 0);
    }

    #[test]
    fn adaptive_policy_is_shared_by_clones() {
        let strategy = parallel_strategy();
        let clone = strategy.clone();

        let _: Vec<_> = clone.map_collect_vec(0..16, |x| x);

        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(policy_len(&clone), 1);
    }

    #[test]
    fn adaptive_policy_starts_parallel_then_probes_serial() {
        let mut entry = super::PolicyEntry::default();

        assert_eq!(entry.choose(), (super::Execution::Parallel, true));
        entry.record(super::Execution::Parallel, Duration::from_micros(100));

        assert_eq!(entry.choose(), (super::Execution::Serial, true));
    }

    #[test]
    fn adaptive_policy_prefers_serial_with_margin() {
        let mut entry = super::PolicyEntry::default();
        entry.record(super::Execution::Parallel, Duration::from_micros(100));
        entry.record(super::Execution::Serial, Duration::from_micros(80));

        assert_eq!(entry.choose(), (super::Execution::Serial, false));
    }

    #[test]
    fn adaptive_policy_keeps_parallel_without_serial_margin() {
        let mut entry = super::PolicyEntry::default();
        entry.record(super::Execution::Parallel, Duration::from_micros(100));
        entry.record(super::Execution::Serial, Duration::from_micros(98));

        assert_eq!(entry.choose(), (super::Execution::Parallel, false));
    }

    #[test]
    fn adaptive_policy_resamples_other_execution() {
        let mut entry = super::PolicyEntry::default();
        entry.record(super::Execution::Parallel, Duration::from_micros(100));
        entry.record(super::Execution::Serial, Duration::from_micros(50));

        for i in 1..super::RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (
                    super::Execution::Serial,
                    i % super::PREFERRED_SAMPLE_INTERVAL == 0
                )
            );
        }
        assert_eq!(entry.choose(), (super::Execution::Parallel, true));
    }

    #[test]
    fn adaptive_policy_resamples_serial_when_parallel_wins() {
        let mut entry = super::PolicyEntry::default();
        entry.record(super::Execution::Parallel, Duration::from_micros(100));
        entry.record(super::Execution::Serial, Duration::from_micros(110));

        for i in 1..super::RESAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (
                    super::Execution::Parallel,
                    i % super::PREFERRED_SAMPLE_INTERVAL == 0
                )
            );
        }
        assert_eq!(entry.choose(), (super::Execution::Serial, true));
    }

    #[test]
    fn adaptive_policy_refreshes_preferred_parallel_sample() {
        let mut entry = super::PolicyEntry::default();
        entry.record(super::Execution::Parallel, Duration::from_micros(100));
        entry.record(super::Execution::Serial, Duration::from_micros(110));

        for i in 1..super::PREFERRED_SAMPLE_INTERVAL {
            assert_eq!(
                entry.choose(),
                (
                    super::Execution::Parallel,
                    i % super::PREFERRED_SAMPLE_INTERVAL == 0
                )
            );
        }
        assert_eq!(entry.choose(), (super::Execution::Parallel, true));
    }

    #[test]
    fn adaptive_policy_records_all_parallel_operations() {
        let strategy = parallel_strategy();

        let _: Vec<_> = strategy.fold_init(
            0..16,
            || (),
            Vec::new,
            |mut acc, _, x| {
                acc.push(x);
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );
        let _: i32 = strategy.fold(0..16, || 0, |acc, x| acc + x, |a, b| a + b);
        let _: Result<i32, ()> = strategy.try_fold(0..16, || 0, |acc, x| Ok(acc + x), |a, b| a + b);
        let _: Vec<_> = strategy.map_collect_vec(0..16, |x| x);
        let _: Result<Vec<_>, ()> = strategy.try_map_collect_vec(0..16, Ok);
        let _: Vec<_> = strategy.map_init_collect_vec(
            0..16,
            || AtomicUsize::new(0),
            |counter, x| {
                counter.fetch_add(1, Ordering::Relaxed);
                x
            },
        );
        let _: (Vec<_>, Vec<_>) = strategy.map_partition_collect_vec(0..16, |x| {
            if x % 2 == 0 {
                (x, Some(x))
            } else {
                (x, None)
            }
        });
        let _: (i32, i32) = strategy.join(|| 1, || 2);
        let mut sortable = vec![3, 2, 1];
        strategy.sort_by(&mut sortable, |a, b| a.cmp(b));

        assert_eq!(sortable, vec![1, 2, 3]);
        assert_eq!(policy_len(&strategy), 9);
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
        fn parallel_try_fold_matches_sequential(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let sequential: Result<i32, ()> = Sequential.try_fold(
                &data,
                || 0i32,
                |acc, &x| Ok(acc.wrapping_add(x)),
                |a, b| a.wrapping_add(b),
            );
            let parallel: Result<i32, ()> = parallel_strategy().try_fold(
                &data,
                || 0i32,
                |acc, &x| Ok(acc.wrapping_add(x)),
                |a, b| a.wrapping_add(b),
            );

            prop_assert_eq!(sequential, parallel);
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
        fn try_map_collect_vec_collects_successes(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let expected: Vec<i32> = data.iter().map(|x| x.wrapping_mul(5)).collect();

            let sequential: Result<Vec<i32>, ()> =
                Sequential.try_map_collect_vec(&data, |&x| Ok(x.wrapping_mul(5)));
            prop_assert_eq!(sequential, Ok(expected.clone()));

            let parallel: Result<Vec<i32>, ()> =
                parallel_strategy().try_map_collect_vec(&data, |&x| Ok(x.wrapping_mul(5)));
            prop_assert_eq!(parallel, Ok(expected));
        }

        #[test]
        fn try_map_collect_vec_returns_first_error(data in prop::collection::vec(any::<i32>(), 0..500)) {
            let expected_error = data.iter().position(|x| x % 7 == 0);
            let result: Result<Vec<i32>, usize> =
                Sequential.try_map_collect_vec(data.iter().enumerate(), |(i, &x)| {
                    if x % 7 == 0 {
                        Err(i)
                    } else {
                        Ok(x)
                    }
                });

            match expected_error {
                Some(i) => prop_assert_eq!(result, Err(i)),
                None => prop_assert_eq!(result, Ok(data)),
            }
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

    #[test]
    fn try_map_collect_vec_sequential_short_circuits() {
        let calls = AtomicUsize::new(0);
        let result: Result<Vec<usize>, usize> = Sequential.try_map_collect_vec(0..10, |i| {
            calls.fetch_add(1, Ordering::Relaxed);
            if i == 3 {
                Err(i)
            } else {
                Ok(i)
            }
        });

        assert_eq!(result, Err(3));
        assert_eq!(calls.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn try_map_collect_vec_parallel_returns_an_error() {
        let result: Result<Vec<usize>, usize> =
            parallel_strategy().try_map_collect_vec(0..128, |i| {
                if i == 17 || i == 42 {
                    Err(i)
                } else {
                    Ok(i)
                }
            });

        assert!(matches!(result, Err(17 | 42)));
    }
}
