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
//! - [`run`](Strategy::run): Chooses between serial and parallel operation bodies
//! - [`run_batches`](Strategy::run_batches): Runs an operation over batches of its input
//! - [`run_tiles`](Strategy::run_tiles): Runs an operation over tiles of several passes over
//!   the same input
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
//! - [`Rayon`]: Adaptively executes collection operations serially or with a [`rayon`] thread pool
//!   (requires `std`)
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
    use core::{cmp::Ordering, convert::Infallible, fmt, iter, num::NonZeroUsize, ops::Range};

    cfg_if! {
        if #[cfg(any(feature = "std", test))] {
            use futures::{
                channel::oneshot,
                future::{self, Either},
            };
            use rayon::{
                ThreadPool as RThreadPool, ThreadPoolBuildError, ThreadPoolBuilder, Yield,
                iter::{IntoParallelIterator, ParallelIterator},
                slice::ParallelSliceMut,
            };
            use std::{
                panic::{self, AssertUnwindSafe, Location},
                sync::{
                    Arc,
                    atomic::{AtomicUsize, Ordering as AtomicOrdering},
                },
                time::Instant,
            };

            mod policy;
        } else {
            extern crate alloc;
            use alloc::vec::Vec;
        }
    }

    /// A strategy wrapper for manually partitioned work.
    ///
    /// Built via [`Strategy::manual`], this disables adaptive policy decisions (including spawn
    /// placement) for operations that callers have already split into partitions, and carries
    /// the parallelism used to plan those partitions.
    #[derive(Clone, Debug)]
    pub struct Manual<S> {
        strategy: S,
        parallelism: usize,
    }

    impl<S> Manual<S> {
        /// Returns the parallelism to use for manually partitioned work.
        pub const fn parallelism(&self) -> usize {
            self.parallelism
        }
    }

    /// Batches supplied for one invocation of [`Strategy::run_batches`].
    ///
    /// Consume this value to prepare and execute the batches. Preparation can borrow input
    /// slices or split mutable output buffers into disjoint slices for each batch. A
    /// whole-input run supplies one batch that executes on the calling thread.
    ///
    /// Batches cannot outlive the operation that receives them:
    ///
    /// ```compile_fail
    /// use commonware_parallel::{Sequential, Strategy};
    /// use core::num::NonZeroUsize;
    ///
    /// let batches = Sequential.run_batches(8, NonZeroUsize::MIN, 1, |batches| batches);
    /// ```
    #[derive(Debug)]
    pub struct Batches<'scope, S: Strategy> {
        strategy: &'scope S,
        ranges: Vec<Range<usize>>,
    }

    impl<'scope, S: Strategy> Batches<'scope, S> {
        /// Returns the single batch `0..len`, executed on the calling thread.
        fn whole(strategy: &'scope S, len: usize) -> Self {
            Self {
                strategy,
                ranges: iter::once(0..len).collect(),
            }
        }

        /// Prepare and map batches, collecting results in batch order.
        ///
        /// `prepare` receives ordered ranges that partition the input and must return one item per
        /// range in the same order. `map_op` may run those items in any order.
        pub fn map_collect_vec<I, P, F, R>(self, prepare: P, map_op: F) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            P: FnOnce(Vec<Range<usize>>) -> I,
            F: Fn(I::Item) -> R + Send + Sync,
            R: Send,
        {
            if self.ranges.len() == 1 {
                prepare(self.ranges).into_iter().map(map_op).collect()
            } else {
                self.strategy.map_collect_vec(prepare(self.ranges), map_op)
            }
        }

        /// Like [`map_collect_vec`](Self::map_collect_vec), but for fallible mapping.
        ///
        /// After an error, remaining items may be skipped. If multiple items fail, any of
        /// their errors may be returned. Successful results preserve batch order.
        pub fn try_map_collect_vec<I, P, F, R, E>(
            self,
            prepare: P,
            map_op: F,
        ) -> Result<Vec<R>, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            P: FnOnce(Vec<Range<usize>>) -> I,
            F: Fn(I::Item) -> Result<R, E> + Send + Sync,
            R: Send,
            E: Send,
        {
            if self.ranges.len() == 1 {
                prepare(self.ranges).into_iter().map(map_op).collect()
            } else {
                self.strategy.try_map_collect_vec(prepare(self.ranges), map_op)
            }
        }
    }

    /// How a [`Tiles`] run cuts the grid.
    #[derive(Debug)]
    enum Plan {
        /// Every row is one tile, processed on the calling thread.
        Serial,
        /// Workers start on equal shares of the cells and take halves of pending shares when they
        /// run out.
        #[cfg(any(feature = "std", test))]
        Shared { tile_cost: usize, workers: usize },
    }

    /// Tiles supplied for one invocation of [`Strategy::run_tiles`].
    ///
    /// Each tile is one row over a contiguous range of columns, and the tiles cover every cell
    /// exactly once. See [`Strategy::run_tiles`] for how a run cuts the grid.
    #[derive(Debug)]
    pub struct Tiles<'scope, S: Strategy> {
        #[cfg_attr(
            not(any(feature = "std", test)),
            expect(dead_code, reason = "only shared plans, which need std, dispatch work")
        )]
        strategy: &'scope S,
        rows: usize,
        len: usize,
        plan: Plan,
    }

    impl<'scope, S: Strategy> Tiles<'scope, S> {
        /// Makes every row one tile, processed on the calling thread.
        const fn serial(strategy: &'scope S, rows: usize, len: usize) -> Self {
            Self {
                strategy,
                rows,
                len,
                plan: Plan::Serial,
            }
        }

        /// Shares the grid among at most `workers` workers.
        #[cfg(any(feature = "std", test))]
        fn parallel(
            strategy: &'scope S,
            rows: usize,
            len: usize,
            tile_cost: NonZeroUsize,
            workers: usize,
        ) -> Self {
            assert!(rows.checked_mul(len).is_some(), "tile grid overflows usize");
            Self {
                strategy,
                rows,
                len,
                plan: Plan::Shared {
                    tile_cost: tile_cost.get(),
                    workers,
                },
            }
        }

        /// Fills every tile piece by piece with per-worker state, collecting one result per tile.
        ///
        /// `fill` receives a tile's row and the columns of each of its pieces in column order, and
        /// `finish` then ends the tile and returns its result. `init` creates state that a worker
        /// reuses across its tiles, so `finish` must leave the state ready for another tile.
        /// Results come back in no particular order, and where a parallel run cuts a row depends on
        /// timing, so combine a row's results in a way that does not depend on its cuts.
        pub fn fill_collect_vec<INIT, T, FILL, FINISH, R>(
            self,
            init: INIT,
            fill: FILL,
            finish: FINISH,
        ) -> Vec<R>
        where
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            FILL: Fn(&mut T, usize, Range<usize>) + Send + Sync,
            FINISH: Fn(&mut T, usize) -> R + Send + Sync,
            R: Send,
        {
            // An empty grid has no tiles, and `Shares` needs at least one cell to size its units.
            if self.rows == 0 || self.len == 0 {
                return Vec::new();
            }
            match self.plan {
                // One state fills every row in order, each row one tile in a single piece.
                Plan::Serial => {
                    let mut state = init();
                    (0..self.rows)
                        .map(|row| {
                            fill(&mut state, row, 0..self.len);
                            finish(&mut state, row)
                        })
                        .collect()
                }
                // Each share is one task. An idle task can take the back half of another share, so
                // a late-starting task or a costlier share does not hold up the run.
                #[cfg(any(feature = "std", test))]
                Plan::Shared { tile_cost, workers } => {
                    let shares = Shares::new(self.rows, self.len, tile_cost, workers);
                    self.strategy
                        .map_init_collect_vec(0..shares.pending.len(), init, |state, worker| {
                            shares.run(worker, self.len, state, &fill, &finish)
                        })
                        .into_iter()
                        .flatten()
                        .collect()
                }
            }
        }
    }

    /// Bits for each end of a packed range of units in [`Shares`], few enough for any `usize`.
    #[cfg(any(feature = "std", test))]
    const HALF_BITS: u32 = 16;

    /// The largest unit index a packed range can hold.
    #[cfg(any(feature = "std", test))]
    const MAX_UNITS: usize = (1 << HALF_BITS) - 1;

    /// The unclaimed cells of each worker's share in a shared [`Tiles`] run.
    ///
    /// A worker claims its own share from the front, one claim at a time, so the rest stays
    /// available. A worker whose share is empty takes the back half of the largest other share
    /// whose back half pays for a split, and stops once no share qualifies. When that cuts a row,
    /// it creates one more tile, so it only happens while the half is longer than a tile's cost.
    #[cfg(any(feature = "std", test))]
    struct Shares {
        /// Each worker's unclaimed units, packed with [`pack`] so that claiming from the front and
        /// splitting off the back are each one atomic update.
        pending: Vec<Pending>,
        /// Cells per unit, enough that every unit index fits in [`HALF_BITS`].
        unit: usize,
        /// Cells in the grid.
        cells: usize,
        /// Units in one claim.
        claim: usize,
        /// Cells a stolen half must exceed, or zero for transfers of whole rows.
        split_cost: usize,
        /// Whether any initial share has a payable split. Claims only shrink shares, and only a
        /// taken half refills one, so a run with no initial payable split never makes one.
        splittable: bool,
    }

    /// One worker's packed range of units, alone on its cache line so that neighboring workers'
    /// claims do not contend.
    #[cfg(any(feature = "std", test))]
    #[repr(align(128))]
    struct Pending(AtomicUsize);

    #[cfg(any(feature = "std", test))]
    impl Shares {
        /// Splits the grid into equal shares for at most `workers` workers, none smaller than a
        /// claim.
        ///
        /// A row shorter than two tile costs is never worth cutting, so its units are whole rows,
        /// and a share holding two of them can be split for free. Longer rows use units small
        /// enough to cut anywhere, claimed one tile's cost at a time.
        fn new(rows: usize, len: usize, tile_cost: usize, workers: usize) -> Self {
            // At most `MAX_UNITS` units cover the grid. Short rows group whole rows into a unit, so
            // moving a unit never cuts a row. Long rows claim the tile cost rounded up to units.
            let cells = rows * len;
            let (unit, claim, split_cost) = if len < tile_cost.saturating_mul(2) {
                (len * rows.div_ceil(MAX_UNITS), 1, 0)
            } else {
                let unit = cells.div_ceil(MAX_UNITS);
                (unit, tile_cost.div_ceil(unit), tile_cost)
            };
            let units = cells.div_ceil(unit);

            // A nonempty grid holds at least one whole claim, so this keeps at least one worker and
            // at most one per whole claim. Shares differ by at most one unit, the first `extra`
            // taking the larger size.
            let workers = workers.min(units / claim);
            let (per_share, extra) = (units / workers, units % workers);
            let pending = (0..workers)
                .map(|worker| {
                    let start = worker * per_share + worker.min(extra);
                    let end = start + per_share + usize::from(worker < extra);
                    Pending(AtomicUsize::new(pack(start, end)))
                })
                .collect();
            let mut shares = Self {
                pending,
                unit,
                cells,
                claim,
                split_cost,
                splittable: false,
            };
            shares.splittable = shares
                .pending
                .iter()
                .any(|pending| shares.split(pending.0.load(AtomicOrdering::Relaxed)).is_some());
            shares
        }

        /// The midpoint and actual cell count of a share whose back half pays for a split.
        fn split(&self, word: usize) -> Option<(usize, usize)> {
            // Each side of a split keeps at least one unit.
            let (start, end) = unpack(word);
            if end - start < 2 {
                return None;
            }

            // The last unit can run past the grid, so the back half's actual cells decide
            // whether the split pays, and the share's actual cells rank it among victims.
            let middle = start + (end - start) / 2;
            let stop = end.saturating_mul(self.unit).min(self.cells);
            (stop - middle * self.unit > self.split_cost)
                .then_some((middle, stop - start * self.unit))
        }

        /// Returns the next cells for `worker`, or `None` once no share is worth splitting.
        fn claim(&self, worker: usize) -> Option<Range<usize>> {
            let pending = &self.pending[worker].0;
            let mut word = pending.load(AtomicOrdering::Relaxed);
            loop {
                let (start, end) = unpack(word);
                if start == end {
                    // Refill from a steal, or stop once no share is worth splitting. Only this
                    // worker refills its own empty share, so a plain store cannot lose units.
                    word = self.steal(worker)?;
                    pending.store(word, AtomicOrdering::Relaxed);
                    continue;
                }

                // Take one claim from the front, clipped to the grid. Thieves only cut the back,
                // so a failed exchange retries with the current range. Relaxed ordering suffices,
                // since the word only divides units among workers and carries no other data.
                let stop = start + self.claim.min(end - start);
                match pending.compare_exchange_weak(
                    word,
                    pack(stop, end),
                    AtomicOrdering::Relaxed,
                    AtomicOrdering::Relaxed,
                ) {
                    Ok(_) => {
                        return Some(start * self.unit..stop.saturating_mul(self.unit).min(self.cells));
                    }
                    Err(current) => word = current,
                }
            }
        }

        /// Takes the back half of the largest share other than the thief's own, returning it
        /// packed.
        fn steal(&self, thief: usize) -> Option<usize> {
            // No share can ever pay for a split (see `splittable`).
            if !self.splittable {
                return None;
            }
            loop {
                // Pick the largest other share whose back half pays for a split, if any.
                // Halving the largest share keeps steals, and the tiles they add, few.
                let (victim, word, middle, _) = (0..self.pending.len())
                    .filter(|&worker| worker != thief)
                    .filter_map(|worker| {
                        let word = self.pending[worker].0.load(AtomicOrdering::Relaxed);
                        self.split(word)
                            .map(|(middle, cells)| (worker, word, middle, cells))
                    })
                    .max_by_key(|&(_, _, _, cells)| cells)?;

                // Keep the victim's front half if its range is still the one scanned.
                // A claim or another steal in between sends the thief back to scanning.
                let (start, end) = unpack(word);
                if self.pending[victim]
                    .0
                    .compare_exchange(
                        word,
                        pack(start, middle),
                        AtomicOrdering::Relaxed,
                        AtomicOrdering::Relaxed,
                    )
                    .is_ok()
                {
                    return Some(pack(middle, end));
                }
            }
        }

        /// Processes the cells `worker` claims, `len` to a row. A tile ends where its row ends or
        /// where the worker's next cells do not continue it.
        fn run<T, R>(
            &self,
            worker: usize,
            len: usize,
            state: &mut T,
            fill: &impl Fn(&mut T, usize, Range<usize>),
            finish: &impl Fn(&mut T, usize) -> R,
        ) -> Vec<R> {
            let mut results = Vec::new();

            // The row of the unfinished tile and the column that would continue it.
            let mut open = None;
            while let Some(cells) = self.claim(worker) {
                // Cut the claimed cells at row ends. A piece that does not continue the open tile
                // (another row, or cells from a stolen half) finishes that tile first.
                let mut start = cells.start;
                while start < cells.end {
                    let (row, column) = (start / len, start % len);
                    let end = cells.end.min((row + 1) * len);
                    if open != Some((row, column))
                        && let Some((row, _)) = open
                    {
                        results.push(finish(state, row));
                    }
                    let columns = column..column + (end - start);
                    open = Some((row, columns.end));
                    fill(state, row, columns);
                    start = end;
                }
            }

            // The last tile has no next piece to finish it.
            if let Some((row, _)) = open {
                results.push(finish(state, row));
            }
            results
        }
    }

    /// Packs a range of units into one word.
    #[cfg(any(feature = "std", test))]
    const fn pack(start: usize, end: usize) -> usize {
        start << HALF_BITS | end
    }

    /// Unpacks a range of units from one word.
    #[cfg(any(feature = "std", test))]
    const fn unpack(word: usize) -> (usize, usize) {
        (word >> HALF_BITS, word & MAX_UNITS)
    }

    /// A strategy for executing fold operations.
    ///
    /// This trait abstracts over sequential and parallel execution, allowing algorithms
    /// to be written generically and then executed with different strategies depending
    /// on the use case (e.g., sequential for testing/debugging, parallel for production).
    pub trait Strategy: Clone + Send + Sync + fmt::Debug + 'static {
        /// Returns a strategy wrapper for manually partitioned work.
        fn manual(&self) -> Manual<Self>
        where
            Self: Sized;

        /// Submit one CPU-bound job to this strategy, running it inline on the calling task when
        /// it is measured cheaper than the round trip of offloading it to the pool.
        ///
        /// `len` groups calls at a call site into size classes for those measurements, so similar
        /// `len` must mean comparable cost. An inline job runs to completion before `spawn`
        /// returns, and jobs whose measured cost exceeds a small time budget offload. To force a
        /// hand-off on a multi-worker pool, submit through [`manual`](Self::manual).
        ///
        /// The returned future resolves when the job completes. Blocking on external
        /// synchronization or I/O inside the job can occupy execution capacity until it returns.
        /// When the polling thread itself belongs to the strategy's execution resources (e.g. a
        /// runtime whose executor thread is registered as a pool worker), the job (and other
        /// pending work) may be executed inline on that thread rather than waited on.
        ///
        /// If the job panics, the panic is propagated to the caller; it never aborts the process.
        #[track_caller]
        fn spawn<F, T>(
            &self,
            len: usize,
            f: F,
        ) -> impl core::future::Future<Output = T> + Send + 'static
        where
            F: FnOnce(Self) -> T + Send + 'static,
            T: Send + 'static;

        /// Runs either a serial or parallel body.
        #[track_caller]
        fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send;

        /// Like [`run`](Self::run), but for fallible work.
        ///
        /// The strategy chooses and runs either the serial or parallel body, returning the
        /// first error produced by the chosen body. Elapsed time is only recorded on success,
        /// so abort-early error paths cannot poison the adaptive policy's estimates.
        #[track_caller]
        fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
        where
            R: Send,
            E: Send,
            SEQ: FnOnce() -> Result<R, E> + Send,
            PAR: FnOnce() -> Result<R, E> + Send;

        /// Run an operation on strategy-provided batches.
        ///
        /// `run` is called once with batches covering `0..len`. The strategy either supplies one
        /// batch that executes on the calling thread or splits the input into two or more batches
        /// no shorter than `minimum_batch_len` that may execute in parallel. An input too short to
        /// split always gets one batch.
        ///
        /// `multiplier` estimates work per input unit. Complete the operation, including
        /// preparation and result assembly, inside `run`. Both execution shapes must produce
        /// equivalent results. The default implementation runs the whole input.
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_parallel::{Sequential, Strategy};
        /// use core::num::NonZeroUsize;
        ///
        /// let values = [1u64, 2, 3, 4];
        /// let total = Sequential.run_batches(values.len(), NonZeroUsize::MIN, 1, |batches| {
        ///     batches
        ///         .map_collect_vec(
        ///             |ranges| ranges.into_iter().map(|range| &values[range]).collect::<Vec<_>>(),
        ///             |batch| batch.iter().sum::<u64>(),
        ///         )
        ///         .into_iter()
        ///         .sum::<u64>()
        /// });
        /// assert_eq!(total, 10);
        /// ```
        #[track_caller]
        fn run_batches<R, F>(
            &self,
            len: usize,
            minimum_batch_len: NonZeroUsize,
            multiplier: usize,
            run: F,
        ) -> R
        where
            R: Send,
            F: for<'scope> FnOnce(Batches<'scope, Self>) -> R + Send,
        {
            match self.try_run_batches(len, minimum_batch_len, multiplier, |batches| {
                Ok::<_, Infallible>(run(batches))
            }) {
                Ok(result) => result,
                Err(e) => match e {},
            }
        }

        /// Like [`run_batches`](Self::run_batches), but for fallible work.
        ///
        /// Adaptive strategies record elapsed time only when the complete operation succeeds.
        #[track_caller]
        fn try_run_batches<R, E, F>(
            &self,
            len: usize,
            _minimum_batch_len: NonZeroUsize,
            _multiplier: usize,
            run: F,
        ) -> Result<R, E>
        where
            R: Send,
            E: Send,
            F: for<'scope> FnOnce(Batches<'scope, Self>) -> Result<R, E> + Send,
        {
            run(Batches::whole(self, len))
        }

        /// Run an operation on strategy-provided tiles of `rows` rows over the same `len` columns.
        ///
        /// `run` is called once with tiles that cover every `(row, column)` cell exactly once, so a
        /// grid without cells has no tiles. Each tile is one row over a contiguous range of
        /// columns, supplied in pieces and then finished once.
        ///
        /// This suits several independent passes over the same input where finishing a tile has a
        /// fixed cost (such as reducing per-tile state), so cutting a pass is costly. `tile_cost`
        /// estimates that cost in cells.
        ///
        /// A serial run makes every row one tile. A parallel run starts each worker on an equal
        /// share of the cells, taken row by row. A worker that runs out takes the back half of the
        /// largest other pending share whose back half is longer than `tile_cost`, and stops once
        /// no share qualifies, so a row is only cut where the extra tile pays for itself. When rows
        /// are too short for any cut to pay, shares hold whole rows, and an idle worker takes the
        /// back half of the largest share that can be split between rows, since moving whole rows
        /// adds no tiles.
        ///
        /// When rows differ in cost, order them so that consecutive rows mix cheap and expensive
        /// ones. `rows * len` must not overflow `usize`.
        ///
        /// `multiplier` estimates work per cell. Complete the operation, including result assembly,
        /// inside `run`. Both execution shapes must produce equivalent results. The default
        /// implementation makes every row one tile on the calling thread.
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_parallel::{Sequential, Strategy};
        /// use core::num::NonZeroUsize;
        ///
        /// let rows = [[1u64, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
        /// let sums = Sequential.run_tiles(rows.len(), 4, NonZeroUsize::MIN, 1, |tiles| {
        ///     let partials = tiles.fill_collect_vec(
        ///         || 0u64,
        ///         |sum, row, columns| *sum += rows[row][columns].iter().sum::<u64>(),
        ///         |sum, row| (row, core::mem::take(sum)),
        ///     );
        ///     let mut sums = [0u64; 3];
        ///     for (row, partial) in partials {
        ///         sums[row] += partial;
        ///     }
        ///     sums
        /// });
        /// assert_eq!(sums, [10, 26, 42]);
        /// ```
        #[track_caller]
        fn run_tiles<R, F>(
            &self,
            rows: usize,
            len: usize,
            _tile_cost: NonZeroUsize,
            _multiplier: usize,
            run: F,
        ) -> R
        where
            R: Send,
            F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
        {
            run(Tiles::serial(self, rows, len))
        }

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
        /// Adaptive strategies must only record elapsed time when the fold succeeds, so
        /// abort-early error paths cannot poison the policy's estimates.
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
            RD: Fn(R, R) -> R + Send + Sync;

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

        /// Maps each element with per-partition state and a per-item work multiplier.
        #[track_caller]
        fn map_init_collect_vec_with_multiplier<I, INIT, T, F, R>(
            &self,
            iter: I,
            _multiplier: usize,
            init: INIT,
            map_op: F,
        ) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            F: Fn(&mut T, I::Item) -> R + Send + Sync,
            R: Send,
        {
            self.map_init_collect_vec(iter, init, map_op)
        }

        /// Maps each element with a per-item work multiplier.
        ///
        /// Convenience over
        /// [`map_init_collect_vec_with_multiplier`](Self::map_init_collect_vec_with_multiplier)
        /// for stateless map operations.
        #[track_caller]
        fn map_collect_vec_with_multiplier<I, F, R>(
            &self,
            iter: I,
            multiplier: usize,
            map_op: F,
        ) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> R + Send + Sync,
            R: Send,
        {
            self.map_init_collect_vec_with_multiplier(iter, multiplier, || (), |_, item| {
                map_op(item)
            })
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
        /// For [`Rayon`], this executes `a` and `b` using `rayon::join`.
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
    }

    impl<S: Strategy> Strategy for Manual<S> {
        fn manual(&self) -> Manual<Self> {
            Manual {
                strategy: self.clone(),
                parallelism: self.parallelism,
            }
        }

        #[track_caller]
        fn spawn<F, T>(
            &self,
            len: usize,
            f: F,
        ) -> impl core::future::Future<Output = T> + Send + 'static
        where
            F: FnOnce(Self) -> T + Send + 'static,
            T: Send + 'static,
        {
            let s = self.clone();
            self.strategy.spawn(len, |_| f(s))
        }

        #[track_caller]
        fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send,
        {
            self.strategy.run(len, serial, parallel)
        }

        #[track_caller]
        fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
        where
            R: Send,
            E: Send,
            SEQ: FnOnce() -> Result<R, E> + Send,
            PAR: FnOnce() -> Result<R, E> + Send,
        {
            self.strategy.try_run(len, serial, parallel)
        }

        #[track_caller]
        fn try_run_batches<R, E, F>(
            &self,
            len: usize,
            minimum_batch_len: NonZeroUsize,
            multiplier: usize,
            run: F,
        ) -> Result<R, E>
        where
            R: Send,
            E: Send,
            F: for<'scope> FnOnce(Batches<'scope, Self>) -> Result<R, E> + Send,
        {
            self.strategy.try_run_batches(len, minimum_batch_len, multiplier, |batches| {
                run(Batches {
                    strategy: self,
                    ranges: batches.ranges,
                })
            })
        }

        #[track_caller]
        fn run_tiles<R, F>(
            &self,
            rows: usize,
            len: usize,
            tile_cost: NonZeroUsize,
            multiplier: usize,
            run: F,
        ) -> R
        where
            R: Send,
            F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
        {
            self.strategy
                .run_tiles(rows, len, tile_cost, multiplier, |tiles| {
                    run(Tiles {
                        strategy: self,
                        rows: tiles.rows,
                        len: tiles.len,
                        plan: tiles.plan,
                    })
                })
        }

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
            self.strategy
                .fold_init(iter, init, identity, fold_op, reduce_op)
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
            self.strategy.try_fold(iter, identity, fold_op, reduce_op)
        }

        #[track_caller]
        fn map_collect_vec<I, F, T>(&self, iter: I, map_op: F) -> Vec<T>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> T + Send + Sync,
            T: Send,
        {
            self.strategy.map_collect_vec(iter, map_op)
        }

        #[track_caller]
        fn try_map_collect_vec<I, F, T, E>(&self, iter: I, map_op: F) -> Result<Vec<T>, E>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> Result<T, E> + Send + Sync,
            T: Send,
            E: Send,
        {
            self.strategy.try_map_collect_vec(iter, map_op)
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
            self.strategy.map_init_collect_vec(iter, init, map_op)
        }

        #[track_caller]
        fn map_init_collect_vec_with_multiplier<I, INIT, T, F, R>(
            &self,
            iter: I,
            multiplier: usize,
            init: INIT,
            map_op: F,
        ) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            F: Fn(&mut T, I::Item) -> R + Send + Sync,
            R: Send,
        {
            self.strategy
                .map_init_collect_vec_with_multiplier(iter, multiplier, init, map_op)
        }

        #[track_caller]
        fn map_partition_collect_vec<I, F, K, U>(&self, iter: I, map_op: F) -> (Vec<U>, Vec<K>)
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> (K, Option<U>) + Send + Sync,
            K: Send,
            U: Send,
        {
            self.strategy.map_partition_collect_vec(iter, map_op)
        }

        fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send,
        {
            self.strategy.join(a, b)
        }

        #[track_caller]
        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            self.strategy.sort_by(items, compare)
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
        fn manual(&self) -> Manual<Self> {
            Manual {
                strategy: Self,
                parallelism: 1,
            }
        }

        fn spawn<F, T>(
            &self,
            _len: usize,
            f: F,
        ) -> impl core::future::Future<Output = T> + Send + 'static
        where
            F: FnOnce(Self) -> T + Send + 'static,
            T: Send + 'static,
        {
            let result = f(self.clone());
            async move { result }
        }

        fn run<R, SEQ, PAR>(&self, _len: usize, serial: SEQ, _parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send,
        {
            serial()
        }

        fn try_run<R, E, SEQ, PAR>(&self, _len: usize, serial: SEQ, _parallel: PAR) -> Result<R, E>
        where
            R: Send,
            E: Send,
            SEQ: FnOnce() -> Result<R, E> + Send,
            PAR: FnOnce() -> Result<R, E> + Send,
        {
            serial()
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
            iter.into_iter().try_fold(identity(), fold_op)
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
    }
});
commonware_macros::stability_scope!(BETA, cfg(any(feature = "std", test)) {
    /// A clone-able wrapper around a [rayon]-compatible thread pool.
    pub type ThreadPool = Arc<RThreadPool>;

    /// A parallel execution strategy backed by a rayon thread pool.
    ///
    /// This strategy adaptively executes collection operations serially or through its backing
    /// pool. It records wall-clock estimates by callsite, input-size and work-size buckets, and
    /// planning parallelism so small inputs can avoid rayon scheduling overhead without disabling
    /// parallel execution for larger inputs.
    ///
    /// Nested calls at the same callsite share estimates across parent paths, so use distinct
    /// callsites (propagating `#[track_caller]` through helpers as needed) to tune them separately.
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
        // The parallelism assumed for policy decisions and manual partitioning. Defaults to the
        // pool's thread count.
        parallelism: usize,
        // `Some` enables adaptive serial-vs-parallel decisions; `None` (used by `manual`) runs the
        // parallel body whenever the parallelism exceeds one and allocates no policy state.
        policy: Option<policy::Policy>,
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
            let parallelism = thread_pool.current_num_threads().max(1);
            Self {
                thread_pool,
                parallelism,
                policy: Some(policy::Policy::default()),
            }
        }

        /// Overrides the parallelism assumed for planning decisions.
        ///
        /// This does not resize the backing pool. By default a strategy plans with the pool's
        /// thread count; override it when the strategy should expose a different parallelism
        /// (e.g. a runtime that executes strategy work inline on a single thread).
        pub const fn with_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
            self.parallelism = parallelism.get();
            self
        }

        #[track_caller]
        fn execute<R>(
            &self,
            len: usize,
            multiplier: usize,
            run: impl FnOnce(policy::RunExecution) -> R,
        ) -> R {
            match self.try_execute(len, multiplier, |execution| {
                Ok::<_, Infallible>(run(execution))
            }) {
                Ok(result) => result,
                Err(e) => match e {},
            }
        }

        #[track_caller]
        fn try_execute<R, E>(
            &self,
            len: usize,
            multiplier: usize,
            run: impl FnOnce(policy::RunExecution) -> Result<R, E>,
        ) -> Result<R, E> {
            let Some(policy) = &self.policy else {
                let execution = if self.parallelism <= 1 {
                    policy::RunExecution::Serial
                } else {
                    policy::RunExecution::Parallel
                };
                return run(execution);
            };

            let work = len.saturating_mul(multiplier);
            policy.try_run(Location::caller(), len, work, self.parallelism, run)
        }
    }

    impl Strategy for Rayon {
        fn manual(&self) -> Manual<Self> {
            Manual {
                strategy: Self {
                    thread_pool: self.thread_pool.clone(),
                    parallelism: self.parallelism,
                    policy: None,
                },
                parallelism: self.parallelism,
            }
        }

        #[track_caller]
        fn spawn<F, T>(
            &self,
            len: usize,
            f: F,
        ) -> impl core::future::Future<Output = T> + Send + 'static
        where
            F: FnOnce(Self) -> T + Send + 'static,
            T: Send + 'static,
        {
            let threads = self.thread_pool.current_num_threads();
            let caller = Location::caller();

            // A single-worker pool cannot overlap a hand-off, so the job always runs inline,
            // untimed. A manual strategy has no policy and keeps spawn's unconditional
            // hand-off. Otherwise the policy weighs the measured job cost against the offload
            // round trip.
            let ((execution, measure), policy) = if threads <= 1 {
                ((policy::SpawnExecution::Inline, false), None)
            } else {
                self.policy.as_ref().map_or(
                    ((policy::SpawnExecution::Offload, false), None),
                    |policy| (policy.choose_spawn(caller, len, threads), Some(policy)),
                )
            };

            match execution {
                policy::SpawnExecution::Inline => {
                    // Inline: run on the calling task and hand back a ready future.
                    let start = measure.then(Instant::now);
                    let result = f(self.clone());
                    if let (Some(start), Some(policy)) = (start, policy) {
                        policy.record_spawn_inline(caller, len, threads, start.elapsed());
                    }
                    Either::Left(future::ready(result))
                }
                policy::SpawnExecution::Offload => {
                    // Offload: hand the job to the pool. The worker records the job wall (so
                    // job estimates survive a dropped future), and the awaiting future records
                    // the round-trip overhead when it observes the result.
                    let spawn_start = measure.then(Instant::now);
                    let (tx, mut rx) = oneshot::channel();
                    let s = self.clone();
                    let pool = self.thread_pool.clone();
                    let recorder = if measure {
                        policy.cloned().map(|policy| (policy, caller, len, threads))
                    } else {
                        None
                    };
                    let worker_recorder = recorder.clone();
                    self.thread_pool.spawn(move || {
                        let job_start = worker_recorder.is_some().then(Instant::now);

                        // Catch the panic so a panicking job propagates to the awaiting task
                        // rather than aborting the process (rayon aborts on an uncaught panic in
                        // a spawned job).
                        let result = panic::catch_unwind(AssertUnwindSafe(|| f(s)));
                        let job = job_start.map(|start| start.elapsed());
                        let ok = result.is_ok();
                        let _ = tx.send((result, job));

                        // Record successful runs only, matching the inline arm: a panicked job's
                        // wall time says nothing about the job size. Recording after the send
                        // keeps the bookkeeping off the caller's wake path.
                        if ok
                            && let (Some((policy, caller, len, threads)), Some(job)) =
                                (worker_recorder, job)
                        {
                            policy.record_spawn_job(caller, len, threads, job);
                        }
                    });
                    Either::Right(async move {
                        // When the polling thread is itself a member of the pool, waiting on the
                        // channel could park the only worker able to run the job. Execute pending
                        // pool work inline until the job completes or another worker takes over.
                        // `yield_now` returns `None` when this thread is not a pool member, so
                        // external callers fall through to the channel immediately.
                        let (result, job) = loop {
                            if let Ok(Some(payload)) = rx.try_recv() {
                                break payload;
                            }
                            if !matches!(pool.yield_now(), Some(Yield::Executed)) {
                                break rx.await.unwrap_or_else(|_| {
                                    panic!("strategy job dropped before completion")
                                });
                            }
                        };
                        match result {
                            Ok(value) => {
                                // The round trip is everything around the job itself: hand-off
                                // setup, queueing, worker wake, result send, task wake, and this
                                // poll. A late poll inflates the sample with overlap slack, which
                                // only ever biases toward inline, and the policy's budget caps
                                // what that bias can buy.
                                if let (
                                    Some((policy, caller, len, threads)),
                                    Some(job),
                                    Some(start),
                                ) = (recorder, job, spawn_start)
                                {
                                    policy.record_spawn_overhead(
                                        caller,
                                        len,
                                        threads,
                                        start.elapsed().saturating_sub(job),
                                    );
                                }
                                value
                            }
                            Err(payload) => panic::resume_unwind(payload),
                        }
                    })
                }
            }
        }

        #[track_caller]
        fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send,
        {
            self.execute(len, 1, |execution| match execution {
                policy::RunExecution::Serial => serial(),
                policy::RunExecution::Parallel => parallel(),
            })
        }

        #[track_caller]
        fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
        where
            R: Send,
            E: Send,
            SEQ: FnOnce() -> Result<R, E> + Send,
            PAR: FnOnce() -> Result<R, E> + Send,
        {
            self.try_execute(len, 1, |execution| match execution {
                policy::RunExecution::Serial => serial(),
                policy::RunExecution::Parallel => parallel(),
            })
        }

        #[track_caller]
        fn try_run_batches<R, E, F>(
            &self,
            len: usize,
            minimum_batch_len: NonZeroUsize,
            multiplier: usize,
            run: F,
        ) -> Result<R, E>
        where
            R: Send,
            E: Send,
            F: for<'scope> FnOnce(Batches<'scope, Self>) -> Result<R, E> + Send,
        {
            let count = self.parallelism.min(len / minimum_batch_len.get());
            if count < 2 {
                return run(Batches::whole(self, len));
            }
            self.try_execute(len, multiplier, |execution| match execution {
                policy::RunExecution::Serial => run(Batches::whole(self, len)),
                policy::RunExecution::Parallel => {
                    let per_batch = len / count;
                    let extra = len % count;
                    let ranges = (0..count)
                        .map(|batch| {
                            let start = batch * per_batch + batch.min(extra);
                            start..start + per_batch + usize::from(batch < extra)
                        })
                        .collect();
                    let manual = self.manual();
                    run(Batches {
                        strategy: &manual.strategy,
                        ranges,
                    })
                }
            })
        }

        #[track_caller]
        fn run_tiles<R, F>(
            &self,
            rows: usize,
            len: usize,
            tile_cost: NonZeroUsize,
            multiplier: usize,
            run: F,
        ) -> R
        where
            R: Send,
            F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
        {
            // The policy picks the shape from the grid's estimated work.
            // A parallel run dispatches its shares through the policy-free strategy:
            // the policy would see only one item per share and could run them serially.
            self.execute(
                rows.saturating_mul(len),
                multiplier,
                |execution| match execution {
                    policy::RunExecution::Serial => run(Tiles::serial(self, rows, len)),
                    policy::RunExecution::Parallel => {
                        let manual = self.manual();
                        run(Tiles::parallel(
                            &manual.strategy,
                            rows,
                            len,
                            tile_cost,
                            self.parallelism,
                        ))
                    }
                },
            )
        }

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
            let items: Vec<I::Item> = iter.into_iter().collect();
            self.execute(items.len(), 1, |execution| match execution {
                policy::RunExecution::Serial => {
                    Sequential.fold_init(items, init, identity, fold_op, reduce_op)
                }
                policy::RunExecution::Parallel => self.thread_pool.install(|| {
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
            })
        }

        #[track_caller]
        fn map_collect_vec<I, F, T>(&self, iter: I, map_op: F) -> Vec<T>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            F: Fn(I::Item) -> T + Send + Sync,
            T: Send,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            self.execute(items.len(), 1, |execution| match execution {
                policy::RunExecution::Serial => Sequential.map_collect_vec(items, map_op),
                policy::RunExecution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map(map_op).collect()),
            })
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
            self.try_execute(items.len(), 1, |execution| match execution {
                policy::RunExecution::Serial => Sequential.try_map_collect_vec(items, map_op),
                policy::RunExecution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map(map_op).collect()),
            })
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
            self.execute(items.len(), 1, |execution| match execution {
                policy::RunExecution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
                policy::RunExecution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map_init(init, map_op).collect()),
            })
        }

        #[track_caller]
        fn map_init_collect_vec_with_multiplier<I, INIT, T, F, R>(
            &self,
            iter: I,
            multiplier: usize,
            init: INIT,
            map_op: F,
        ) -> Vec<R>
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            F: Fn(&mut T, I::Item) -> R + Send + Sync,
            R: Send,
        {
            let items: Vec<I::Item> = iter.into_iter().collect();
            self.execute(items.len(), multiplier, |execution| match execution {
                policy::RunExecution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
                policy::RunExecution::Parallel => self
                    .thread_pool
                    .install(|| items.into_par_iter().map_init(init, map_op).collect()),
            })
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
            let items: Vec<I::Item> = iter.into_iter().collect();
            self.try_execute(items.len(), 1, |execution| match execution {
                policy::RunExecution::Serial => {
                    Sequential.try_fold(items, identity, fold_op, reduce_op)
                }
                policy::RunExecution::Parallel => self.thread_pool.install(|| {
                    items
                        .into_par_iter()
                        .try_fold(&identity, &fold_op)
                        .try_reduce(&identity, |a, b| Ok(reduce_op(a, b)))
                }),
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

        #[track_caller]
        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            self.execute(items.len(), 1, |execution| match execution {
                policy::RunExecution::Serial => Sequential.sort_by(items, compare),
                policy::RunExecution::Parallel => {
                    self.thread_pool.install(|| items.par_sort_by(compare))
                }
            });
        }
    }
});
commonware_macros::stability_scope!(ALPHA, cfg(any(feature = "test-utils", test)) {
    pub mod mocks;
});

#[cfg(test)]
mod test {
    use crate::{Rayon, Sequential, Strategy};
    use core::{num::NonZeroUsize, ops::Range};
    use futures::FutureExt;
    use proptest::prelude::*;
    use rayon::ThreadPoolBuilder;
    use std::{
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    fn parallel_strategy() -> Rayon {
        Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap()
    }

    /// Call `spawn` with this helper so the policy entry is keyed by the helper's call
    /// site (both `track_caller` locations resolve to the same line).
    #[track_caller]
    fn spawn_flagged(
        strategy: &Rayon,
        panics: bool,
    ) -> (
        &'static std::panic::Location<'static>,
        impl core::future::Future<Output = usize> + Send + 'static,
    ) {
        (
            std::panic::Location::caller(),
            strategy.spawn(64, move |_| {
                if panics {
                    panic!("job panic");
                }
                7
            }),
        )
    }

    fn spawn_recorded(strategy: &Rayon, loc: &'static std::panic::Location<'static>) -> bool {
        let parallelism = strategy.manual().parallelism();
        strategy
            .policy
            .as_ref()
            .is_some_and(|policy| policy.spawn_recorded(loc, 64, parallelism))
    }

    /// A panicking offloaded job must not update the spawn policy: its wall time says
    /// nothing about the job size and would train the policy toward inlining.
    #[test]
    fn spawn_panic_records_nothing() {
        let strategy = parallel_strategy();

        let (loc, job) = spawn_flagged(&strategy, true);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(job)
        }));
        assert!(result.is_err());
        assert!(!spawn_recorded(&strategy, loc));

        let (loc, job) = spawn_flagged(&strategy, false);
        assert_eq!(futures::executor::block_on(job), 7);
        assert!(spawn_recorded(&strategy, loc));
    }

    /// Spawn honors an inline decision after cheap job and hand-off samples are recorded.
    /// Caller tracking keys the recorded samples and spawn to the same policy entry.
    #[test]
    #[track_caller]
    fn spawn_inlines_a_sub_overhead_job() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();
        let caller = std::panic::Location::caller();
        let threads = strategy.thread_pool.current_num_threads();

        for _ in 0..2 {
            assert_eq!(
                policy.choose_spawn(caller, 64, threads),
                (crate::policy::SpawnExecution::Offload, true)
            );
            policy.record_spawn_job(caller, 64, threads, std::time::Duration::from_micros(2));
            policy.record_spawn_overhead(caller, 64, threads, std::time::Duration::from_micros(50));
        }

        assert_eq!(
            futures::executor::block_on(strategy.spawn(64, |_| std::thread::current().id())),
            std::thread::current().id()
        );
    }

    /// A job measured over the inline budget keeps offloading: the calling task is never blocked
    /// on a big job even when the hand-off looks expensive.
    #[test]
    fn spawn_keeps_offloading_big_jobs() {
        let strategy = parallel_strategy();

        for _ in 0..20 {
            let on_pool = futures::executor::block_on(strategy.spawn(64, |_| {
                std::thread::sleep(std::time::Duration::from_millis(2));
                rayon::current_thread_index().is_some()
            }));
            assert!(
                on_pool,
                "a job over the inline budget ran on the calling task"
            );
        }
    }

    fn policy_len(strategy: &Rayon) -> usize {
        strategy.policy.as_ref().map_or(0, |policy| policy.len())
    }

    /// A strategy that does not split runs the whole input once as the single range `0..len` on
    /// the calling thread.
    #[test]
    fn run_batches_preserves_whole_input_without_splitting() {
        fn check(strategy: &impl Strategy, len: usize, minimum: NonZeroUsize) {
            let owned = Box::new(len);
            let calls = AtomicUsize::new(0);
            let caller = std::thread::current().id();
            let (result, items) = strategy.run_batches(len, minimum, usize::MAX, |batches| {
                calls.fetch_add(1, Ordering::Relaxed);
                (
                    *owned,
                    batches.map_collect_vec(
                        |ranges| ranges,
                        |range| (range, std::thread::current().id()),
                    ),
                )
            });
            assert_eq!(result, len);
            assert_eq!(items, [(0..len, caller)]);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }

        let one_worker = Rayon::new(NonZeroUsize::MIN).unwrap();
        let parallel = parallel_strategy();
        let minimum = NonZeroUsize::new(8).unwrap();
        for len in [0, 1, 7, 8, 15] {
            check(&Sequential, len, minimum);
            check(&one_worker, len, minimum);
            check(&parallel, len, minimum);
            check(&parallel.manual(), len, minimum);
        }
        check(&Sequential, usize::MAX, NonZeroUsize::MIN);
        check(&one_worker, usize::MAX, NonZeroUsize::MIN);
        check(&parallel, usize::MAX, NonZeroUsize::MAX);
        assert_eq!(policy_len(&one_worker), 0);
        assert_eq!(policy_len(&parallel), 0);
    }

    /// A serial policy decision on a splittable extent runs the whole input as the single range
    /// `0..len` on the calling thread. Caller tracking keys the recorded samples and the run to
    /// the same policy entry.
    #[test]
    #[track_caller]
    fn run_batches_runs_serial_decision_on_calling_thread() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();
        let caller = std::panic::Location::caller();

        // Record samples that make serial the preferred path.
        policy.record_run(
            caller,
            16,
            16,
            4,
            crate::policy::RunExecution::Parallel,
            std::time::Duration::from_micros(100),
        );
        policy.record_run(
            caller,
            16,
            16,
            4,
            crate::policy::RunExecution::Serial,
            std::time::Duration::from_micros(95),
        );

        // Run an extent that could form four batches.
        let thread = std::thread::current().id();
        let items = strategy.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
            batches.map_collect_vec(
                |ranges| ranges,
                |range| (range, std::thread::current().id()),
            )
        });
        assert_eq!(items, [(0..16, thread)]);
    }

    #[test]
    fn run_batches_supplies_ordered_balanced_ranges() {
        let strategy = Rayon::new(NonZeroUsize::MIN)
            .unwrap()
            .with_parallelism(NonZeroUsize::new(8).unwrap())
            .manual();
        for (len, minimum) in [
            (2, 1),
            (7, 1),
            (8, 1),
            (9, 1),
            (17, 1),
            (15, 7),
            (16, 8),
            (17, 8),
            (usize::MAX, 1),
            (usize::MAX, usize::MAX / 2),
        ] {
            let ranges = strategy.run_batches(
                len,
                NonZeroUsize::new(minimum).unwrap(),
                usize::MAX,
                |batches| batches.map_collect_vec(|ranges| ranges, |range| range),
            );
            assert_eq!(ranges.len(), 8.min(len / minimum));
            assert_eq!(ranges.first().unwrap().start, 0);
            assert_eq!(ranges.last().unwrap().end, len);
            assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
            assert!(ranges.iter().all(|range| range.len() >= minimum));
            let shortest = ranges.iter().map(|range| range.len()).min().unwrap();
            let longest = ranges.iter().map(|range| range.len()).max().unwrap();
            assert!(longest - shortest <= 1);
        }
        assert_eq!(policy_len(&strategy.strategy), 0);
    }

    #[test]
    fn run_batches_prepares_borrowed_outputs_once() {
        let strategy = parallel_strategy().manual();
        let input: Vec<_> = (0..17).map(|value| value * 3).collect();
        let mut output = vec![0; input.len()];
        let preparations = AtomicUsize::new(0);
        let ranges = strategy.run_batches(input.len(), NonZeroUsize::MIN, 1, |batches| {
            let owned = Rc::new(42);
            batches.map_collect_vec(
                |ranges| {
                    assert_eq!(*owned, 42);
                    drop(owned);
                    preparations.fetch_add(1, Ordering::Relaxed);
                    let mut remaining = output.as_mut_slice();
                    ranges
                        .into_iter()
                        .map(|range| {
                            let (head, tail) =
                                std::mem::take(&mut remaining).split_at_mut(range.len());
                            remaining = tail;
                            (range, head)
                        })
                        .collect::<Vec<_>>()
                },
                |(range, out)| {
                    assert!(rayon::current_thread_index().is_some());
                    out.copy_from_slice(&input[range.clone()]);
                    range
                },
            )
        });
        assert_eq!(preparations.load(Ordering::Relaxed), 1);
        assert_eq!(output, input);
        assert_eq!(ranges.first().unwrap().start, 0);
        assert_eq!(ranges.last().unwrap().end, input.len());
    }

    #[track_caller]
    fn run_batches_flagged(
        strategy: &Rayon,
        fail_mapping: bool,
        fail_assembly: bool,
    ) -> (&'static std::panic::Location<'static>, Result<usize, ()>) {
        (
            std::panic::Location::caller(),
            strategy.try_run_batches(16, NonZeroUsize::MIN, usize::MAX, |batches| {
                let total = batches
                    .try_map_collect_vec(
                        |ranges| ranges,
                        |range| {
                            if fail_mapping {
                                Err(())
                            } else {
                                Ok(range.len())
                            }
                        },
                    )?
                    .into_iter()
                    .sum();
                if fail_assembly { Err(()) } else { Ok(total) }
            }),
        )
    }

    #[test]
    fn run_batches_records_only_complete_success() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();

        let (mapping_loc, mapping) = run_batches_flagged(&strategy, true, false);
        assert_eq!(mapping, Err(()));
        assert_eq!(
            policy.get_entry(mapping_loc, 16, usize::MAX, 4),
            Some((None, None))
        );

        let (assembly_loc, assembly) = run_batches_flagged(&strategy, false, true);
        assert_eq!(assembly, Err(()));
        assert_eq!(
            policy.get_entry(assembly_loc, 16, usize::MAX, 4),
            Some((None, None))
        );

        let (success_loc, result) = run_batches_flagged(&strategy, false, false);
        assert_eq!(result, Ok(16));
        let (_, parallel) = policy.get_entry(success_loc, 16, usize::MAX, 4).unwrap();
        assert!(parallel.is_some());
        assert_eq!(policy_len(&strategy), 3);
    }

    #[test]
    fn run_batches_keeps_one_policy_decision_and_manual_execution() {
        let strategy = parallel_strategy();
        let run = |strategy: &Rayon| {
            strategy.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                batches.map_collect_vec(|ranges| ranges, |range| range.len())
            })
        };
        assert_eq!(run(&strategy).into_iter().sum::<usize>(), 16);
        assert_eq!(policy_len(&strategy), 1);

        let manual = strategy.manual();
        for _ in 0..3 {
            let on_pool = manual.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                batches
                    .map_collect_vec(|ranges| ranges, |_| rayon::current_thread_index().is_some())
            });
            assert!(on_pool.into_iter().all(|on_pool| on_pool));
        }
        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(policy_len(&manual.strategy), 0);
    }

    fn map_from_same_callsite(strategy: &Rayon, len: usize) {
        let _: Vec<_> = strategy.map_collect_vec(0..len, |x| x);
    }

    fn map_init_with_multiplier_from_same_callsite(
        strategy: &Rayon,
        len: usize,
        multiplier: usize,
    ) {
        let _: Vec<_> =
            strategy.map_init_collect_vec_with_multiplier(0..len, multiplier, || (), |_, x| x);
    }

    fn run_from_same_callsite(strategy: &Rayon, len: usize) {
        let _: usize = strategy.run(len, || 1, || 2);
    }

    fn map_partition_from_same_callsite(strategy: &Rayon, len: usize) {
        let _: (Vec<_>, Vec<_>) = strategy.map_partition_collect_vec(0..len, |x| {
            if x % 2 == 0 { (x, Some(x)) } else { (x, None) }
        });
    }

    #[test]
    fn adaptive_policy_is_scoped_to_rayon() {
        let strategy = parallel_strategy();
        let other = parallel_strategy();

        let _: Vec<_> = strategy.map_collect_vec(0..16, |x| x);

        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(policy_len(&other), 0);
    }

    /// A spawn awaited from a thread inside the pool must complete even when no other
    /// worker can run the job: the pool below registers this thread as a member and never
    /// starts its remaining worker, so only the spawn future's yield loop can execute the
    /// job (a single poll must suffice; there is no executor to re-poll a pending future).
    #[test]
    fn spawn_driven_inline_on_member_thread() {
        let pool = ThreadPoolBuilder::new()
            .num_threads(2)
            .use_current_thread()
            .spawn_handler(|_| Ok(()))
            .build()
            .unwrap();
        let strategy = Rayon::with_pool(Arc::new(pool));

        let result = strategy
            .spawn(2, |strategy| strategy.map_collect_vec(0..2, |i| i + 1))
            .now_or_never()
            .expect("spawn should complete on first poll via the yield loop");
        assert_eq!(result, vec![1, 2]);
    }

    #[test]
    fn with_parallelism_overrides_planning_parallelism() {
        let strategy = Rayon::new(NonZeroUsize::new(1).unwrap())
            .unwrap()
            .with_parallelism(NonZeroUsize::new(4).unwrap());
        let strategy = strategy.manual();
        assert_eq!(strategy.parallelism(), 4);
        assert_eq!(strategy.run(2, || "serial", || "parallel"), "parallel");
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
    fn adaptive_policy_records_all_adaptive_operations() {
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
        let _: Vec<_> = strategy.map_init_collect_vec_with_multiplier(
            0..16,
            2,
            || AtomicUsize::new(0),
            |counter, x| {
                counter.fetch_add(1, Ordering::Relaxed);
                x
            },
        );
        let _: usize = strategy.run(16, || 1, || 2);
        let _: (Vec<_>, Vec<_>) = strategy.map_partition_collect_vec(0..16, |x| {
            if x % 2 == 0 { (x, Some(x)) } else { (x, None) }
        });
        let _: (i32, i32) = strategy.join(|| 1, || 2);
        let mut sortable = vec![3, 2, 1];
        strategy.sort_by(&mut sortable, |a, b| a.cmp(b));

        assert_eq!(sortable, vec![1, 2, 3]);
        assert_eq!(policy_len(&strategy), 10);
    }

    #[test]
    fn adaptive_policy_buckets_by_input_size() {
        let strategy = parallel_strategy();

        map_from_same_callsite(&strategy, 1);
        map_from_same_callsite(&strategy, 2);
        map_from_same_callsite(&strategy, 3);

        assert_eq!(policy_len(&strategy), 2);
    }

    #[test]
    fn adaptive_policy_buckets_by_work_multiplier() {
        let strategy = parallel_strategy();

        map_init_with_multiplier_from_same_callsite(&strategy, 16, 1);
        map_init_with_multiplier_from_same_callsite(&strategy, 16, 2);
        map_init_with_multiplier_from_same_callsite(&strategy, 16, 3);

        assert_eq!(policy_len(&strategy), 2);
    }

    #[test]
    fn adaptive_run_buckets_by_input_size() {
        let strategy = parallel_strategy();

        run_from_same_callsite(&strategy, 1);
        run_from_same_callsite(&strategy, 2);
        run_from_same_callsite(&strategy, 3);

        assert_eq!(policy_len(&strategy), 2);
    }

    /// `manual()` forces the hand-off on a multi-worker pool: the job runs on the pool no matter
    /// what the adaptive policy would have decided for this call site.
    #[test]
    fn manual_spawn_always_hands_off() {
        let strategy = parallel_strategy();
        let manual = strategy.manual();

        for _ in 0..10 {
            let on_pool = futures::executor::block_on(
                manual.spawn(1, |_| rayon::current_thread_index().is_some()),
            );
            assert!(on_pool, "manual spawn ran on the calling task");
        }
    }

    #[test]
    fn manual_strategy_does_not_use_adaptive_policy() {
        let strategy = parallel_strategy();
        let manual = strategy.manual();

        let _: usize = manual.fold(0..4, || 0, |acc, x| acc + x, |a, b| a + b);
        assert_eq!(manual.run(4, || 1, || 2), 2);

        assert_eq!(policy_len(&strategy), 0);
        assert_eq!(policy_len(&manual.strategy), 0);
    }

    #[test]
    fn sequential_run_uses_serial_body() {
        assert_eq!(Sequential.run(4, || 1, || 2), 1);
    }

    #[test]
    fn adaptive_policy_keys_default_methods_by_external_callsite() {
        let strategy = parallel_strategy();

        // Default methods must attribute policy keys to their external callers.
        let _: i32 = strategy.fold(0..16, || 0, |acc, x| acc + x, |a, b| a + b);
        let _: i32 = strategy.fold(0..16, || 0, |acc, x| acc + x, |a, b| a + b);
        strategy.run_batches(16, NonZeroUsize::MIN, 1, |_| ());
        strategy.run_batches(16, NonZeroUsize::MIN, 1, |_| ());

        assert_eq!(policy_len(&strategy), 4);
    }

    #[test]
    fn adaptive_policy_keys_partition_map_by_external_callsite() {
        let strategy = parallel_strategy();

        map_partition_from_same_callsite(&strategy, 16);
        let _: (Vec<_>, Vec<_>) = strategy.map_partition_collect_vec(0..16, |x| {
            if x % 2 == 0 { (x, Some(x)) } else { (x, None) }
        });

        assert_eq!(policy_len(&strategy), 2);
    }

    #[test]
    fn join_does_not_use_adaptive_policy() {
        let strategy = parallel_strategy();

        let result = strategy.join(|| 1, || 2);

        assert_eq!(result, (1, 2));
        assert_eq!(policy_len(&strategy), 0);
    }

    #[test]
    fn sequential_spawn_runs_job() {
        let result = futures::executor::block_on(Sequential.spawn(1, |_| 7));

        assert_eq!(result, 7);
    }

    #[test]
    fn rayon_spawn_runs_job_on_pool() {
        let strategy = parallel_strategy();

        let result = futures::executor::block_on(strategy.spawn(1, |_| {
            assert!(rayon::current_thread_index().is_some());
            7
        }));

        assert_eq!(result, 7);

        // Spawn trains only the spawn-side policy: no run entries are created.
        assert_eq!(policy_len(&strategy), 0);
    }

    #[test]
    fn rayon_spawn_runs_inline_on_current_thread_single_worker_pool() {
        let pool = ThreadPoolBuilder::new()
            .num_threads(1)
            .use_current_thread()
            .build()
            .unwrap();
        let strategy =
            Rayon::with_pool(Arc::new(pool)).with_parallelism(NonZeroUsize::new(4).unwrap());

        assert_eq!(strategy.manual().parallelism(), 4);

        let result = strategy.spawn(1, |_| 7).now_or_never();

        assert_eq!(result, Some(7));
        assert_eq!(policy_len(&strategy), 0);
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn rayon_spawn_propagates_job_panic() {
        // A panic on a pool worker must surface at the await point, not abort the process.
        let strategy = parallel_strategy();

        let _: () = futures::executor::block_on(strategy.spawn(1, |_| panic!("boom")));
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn sequential_spawn_propagates_job_panic() {
        let _: () = futures::executor::block_on(Sequential.spawn(1, |_| panic!("boom")));
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
            if i == 3 { Err(i) } else { Ok(i) }
        });

        assert_eq!(result, Err(3));
        assert_eq!(calls.load(Ordering::Relaxed), 4);
    }

    fn manual_strategy(parallelism: usize) -> crate::Manual<Rayon> {
        Rayon::new(NonZeroUsize::new(4).unwrap())
            .unwrap()
            .with_parallelism(NonZeroUsize::new(parallelism).unwrap())
            .manual()
    }

    /// The tiles a strategy supplies, each as its row and the pieces `fill` received.
    fn tiles_of(
        strategy: &impl Strategy,
        rows: usize,
        len: usize,
        tile_cost: usize,
    ) -> Vec<(usize, Vec<Range<usize>>)> {
        strategy.run_tiles(
            rows,
            len,
            NonZeroUsize::new(tile_cost).unwrap(),
            1,
            |tiles| {
                // Record each piece with its row. Finishing a tile takes every recorded piece,
                // which must belong to that row, and leaves the state empty for the next tile.
                tiles.fill_collect_vec(
                    Vec::new,
                    |pieces: &mut Vec<(usize, Range<usize>)>, row, columns| {
                        pieces.push((row, columns))
                    },
                    |pieces, row| {
                        let pieces = core::mem::take(pieces);
                        assert!(pieces.iter().all(|(piece_row, _)| *piece_row == row));
                        (
                            row,
                            pieces.into_iter().map(|(_, columns)| columns).collect(),
                        )
                    },
                )
            },
        )
    }

    /// Asserts that `tiles` cover a `rows` by `len` grid exactly once, each tile with
    /// contiguous pieces in column order.
    fn assert_covers(tiles: &[(usize, Vec<Range<usize>>)], rows: usize, len: usize) {
        // Validate piece geometry and mark each cell once; the final scan detects missing cells.
        let mut seen = vec![false; rows * len];
        for (row, pieces) in tiles {
            assert!(*row < rows && !pieces.is_empty());
            assert!(pieces.windows(2).all(|pair| pair[0].end == pair[1].start));
            for columns in pieces {
                assert!(!columns.is_empty() && columns.end <= len);
                for column in columns.clone() {
                    assert!(!core::mem::replace(&mut seen[row * len + column], true));
                }
            }
        }
        assert!(seen.into_iter().all(|cell| cell));
    }

    #[test]
    fn run_tiles_cover_every_cell_once() {
        // Empty grids, one cell, rows too short to cut (30 x 63 and 30 x 100 at tile cost 64),
        // and longer rows, the last two with more than `MAX_UNITS` cells and multi-cell units.
        let grids = [
            (0, 5, 1),
            (3, 0, 1),
            (1, 1, 1),
            (3, 10, 1),
            (5, 7, 1),
            (5, 7, 3),
            (30, 63, 64),
            (30, 100, 64),
            (30, 32_769, 2_304),
            (44, 2_001, 288),
        ];

        // Each grid runs serially, adaptively, and manually at 1 to 64 planned workers.
        for (rows, len, tile_cost) in grids {
            assert_covers(&tiles_of(&Sequential, rows, len, tile_cost), rows, len);
            assert_covers(
                &tiles_of(&parallel_strategy(), rows, len, tile_cost),
                rows,
                len,
            );
            for parallelism in [1, 2, 8, 16, 32, 64] {
                let strategy = manual_strategy(parallelism);
                assert_covers(&tiles_of(&strategy, rows, len, tile_cost), rows, len);
            }
        }

        // More workers than pool threads, with tiles cheap enough to cut finely, keep claims and
        // steals racing.
        let strategy = manual_strategy(16);
        for _ in 0..200 {
            assert_covers(&tiles_of(&strategy, 7, 300, 2), 7, 300);
        }
    }

    #[test]
    fn run_tiles_serial_runs_make_every_row_one_tile() {
        // A single-worker manual run is serial too, and a grid without columns has no tiles.
        let whole: Vec<_> = (0..3)
            .map(|row| (row, core::iter::once(0..10).collect()))
            .collect();
        assert_eq!(tiles_of(&Sequential, 3, 10, 1), whole);
        assert_eq!(tiles_of(&manual_strategy(1), 3, 10, 1), whole);
        assert!(tiles_of(&Sequential, 3, 0, 1).is_empty());
    }

    #[test]
    fn run_tiles_bound_workers_by_the_grid() {
        // A planning parallelism far beyond the grid allocates and dispatches only the workers the
        // grid can occupy.
        let strategy = Rayon::new(NonZeroUsize::new(4).unwrap())
            .unwrap()
            .with_parallelism(NonZeroUsize::MAX)
            .manual();
        for (rows, len, tile_cost) in [(1, 1, 1), (3, 10, 1), (32, 1, 100), (30, 100, 64)] {
            assert_covers(&tiles_of(&strategy, rows, len, tile_cost), rows, len);
        }
    }

    #[test]
    fn run_tiles_spread_short_rows_across_workers() {
        // Every row is shorter than a tile's cost, so no row is cut, but rows still go to separate
        // workers: the worker filling the first row waits until another has filled a row.
        let rows = 32;
        let others = AtomicUsize::new(0);
        let tiles =
            manual_strategy(4).run_tiles(rows, 1, NonZeroUsize::new(100).unwrap(), 1, |tiles| {
                tiles.fill_collect_vec(
                    Vec::new,
                    |pieces: &mut Vec<Range<usize>>, row, columns| {
                        if row == 0 {
                            let deadline = Instant::now() + Duration::from_secs(30);
                            while others.load(Ordering::Acquire) == 0 {
                                assert!(Instant::now() < deadline, "no other worker filled a row");
                                std::thread::yield_now();
                            }
                        } else {
                            others.fetch_add(1, Ordering::Release);
                        }
                        pieces.push(columns);
                    },
                    |pieces, row| (row, core::mem::take(pieces)),
                )
            });
        assert_covers(&tiles, rows, 1);
        assert_eq!(tiles.len(), rows);
    }

    #[test]
    fn run_tiles_cut_the_share_of_a_stalled_worker() {
        // Four equal shares of one row. The worker holding the first share stalls in its first
        // piece until the others have filled every cell except those it may keep for itself: that
        // piece, plus at most two tile costs that are not worth taking.
        let (len, tile_cost) = (4_000, 10);
        let filled = AtomicUsize::new(0);
        let tiles = manual_strategy(4).run_tiles(
            1,
            len,
            NonZeroUsize::new(tile_cost).unwrap(),
            1,
            |tiles| {
                tiles.fill_collect_vec(
                    Vec::new,
                    |pieces: &mut Vec<Range<usize>>, _, columns| {
                        if columns.start == 0 {
                            let deadline = Instant::now() + Duration::from_secs(30);
                            while filled.load(Ordering::Acquire) < len - 3 * tile_cost {
                                assert!(Instant::now() < deadline, "the stalled share was not cut");
                                std::thread::yield_now();
                            }
                        }
                        filled.fetch_add(columns.len(), Ordering::Release);
                        pieces.push(columns);
                    },
                    |pieces, row| (row, core::mem::take(pieces)),
                )
            },
        );
        assert_covers(&tiles, 1, len);

        // The tile holding the stalled piece kept at most those three tile costs.
        let first: usize = tiles
            .iter()
            .find(|(_, pieces)| pieces[0].start == 0)
            .map(|(_, pieces)| pieces.iter().map(|columns| columns.len()).sum())
            .unwrap();
        assert!(first <= 3 * tile_cost, "first tile kept {first} cells");
    }

    /// Fills one row of `len` cells as four shares and asserts that no worker steals.
    /// Workers on the last three shares pause at the claims starting at `wait_for` until
    /// the first share's tile finishes. The first worker pauses at the claim starting at
    /// `drain` until all three have paused, then empties its share. The tails left pending
    /// must be too small to pay for a split, so the run ends with one tile per share.
    fn assert_no_cheap_steal(len: usize, tile_cost: usize, wait_for: [usize; 3], drain: usize) {
        let ready = AtomicUsize::new(0);
        let release = AtomicUsize::new(0);
        let tiles = manual_strategy(4).run_tiles(
            1,
            len,
            NonZeroUsize::new(tile_cost).unwrap(),
            1,
            |tiles| {
                tiles.fill_collect_vec(
                    Vec::new,
                    |pieces: &mut Vec<Range<usize>>, _, columns| {
                        // Three workers leave their pending tails available until the first
                        // worker finishes its original share and checks whether to steal.
                        let deadline = Instant::now() + Duration::from_secs(30);
                        if wait_for.contains(&columns.start) {
                            ready.fetch_add(1, Ordering::Release);
                            while release.load(Ordering::Acquire) == 0 {
                                assert!(Instant::now() < deadline, "first share did not finish");
                                std::thread::yield_now();
                            }
                        } else if columns.start == drain {
                            while ready.load(Ordering::Acquire) != wait_for.len() {
                                assert!(Instant::now() < deadline, "other shares did not wait");
                                std::thread::yield_now();
                            }
                        }
                        pieces.push(columns);
                    },
                    |pieces, row| {
                        if pieces[0].start == 0 {
                            release.store(1, Ordering::Release);
                        }
                        (row, core::mem::take(pieces))
                    },
                )
            },
        );
        assert_covers(&tiles, 1, len);
        assert_eq!(tiles.len(), 4, "len={len} tile_cost={tile_cost}");
    }

    /// Shares of three claims each: a paused share's pending back half is exactly one tile cost.
    #[test]
    fn run_tiles_do_not_steal_equal_cost_tails() {
        assert_no_cheap_steal(120, 10, [30, 60, 90], 0);
    }

    /// Two-cell units at a tile cost of three cells: the last share's pending back half
    /// spans two units but only three cells before the grid ends.
    #[test]
    fn run_tiles_do_not_steal_clipped_tails_at_cost() {
        assert_no_cheap_steal(65_537, 3, [32_762, 49_146, 65_526], 16_384);
    }

    #[test]
    fn run_tiles_serial_runs_reuse_worker_state() {
        // A serial run creates its state once and reuses it for every tile.
        let inits = AtomicUsize::new(0);
        let tiles = Sequential.run_tiles(7, 1_000, NonZeroUsize::new(16).unwrap(), 1, |tiles| {
            tiles.fill_collect_vec(
                || {
                    inits.fetch_add(1, Ordering::Relaxed);
                },
                |_, _, _| {},
                |_, row| row,
            )
        });
        assert_eq!(inits.load(Ordering::Relaxed), 1);
        assert_eq!(tiles.len(), 7);
    }

    #[test]
    fn try_map_collect_vec_parallel_returns_an_error() {
        let result: Result<Vec<usize>, usize> = parallel_strategy()
            .try_map_collect_vec(0..128, |i| if i == 17 || i == 42 { Err(i) } else { Ok(i) });

        assert!(matches!(result, Err(17 | 42)));
    }
}
