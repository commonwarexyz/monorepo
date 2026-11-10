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
//! - [`sort_unstable_by`](Strategy::sort_unstable_by): Like `sort_by`, but without preserving the
//!   order of equal elements
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
//! - [`Rayon`]: Adaptively executes collection operations serially or on a work-stealing thread
//!   pool (requires `std`)
//!
//! # Features
//!
//! - `std` (default): Enables the [`Rayon`] strategy and its thread pool
//! - `test-utils`: Enables `mocks`, strategies that pin or explore a test's execution shapes
//! - `loom`: Enables Loom models of the wake protocol when compiling tests (implies `std`)
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
                FutureExt as _,
            };
            use self::rayon::{ThreadPoolBuildError, ThreadPoolBuilder};
            use std::{
                panic::{self, AssertUnwindSafe, Location},
                pin::Pin,
                sync::{
                    Arc,
                    atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
                },
                task::Poll,
                time::Instant,
            };

            mod policy;
            pub mod rayon;
            mod topology;
        } else {
            extern crate alloc;
            use alloc::vec::Vec;
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

        /// Splits `0..len` into `count` ordered batches whose lengths differ by at most one.
        #[cfg(any(feature = "std", test))]
        fn balanced(strategy: &'scope S, len: usize, count: usize) -> Self {
            let per_batch = len / count;
            let extra = len % count;
            let ranges = (0..count)
                .map(|batch| {
                    let start = batch * per_batch + batch.min(extra);
                    start..start + per_batch + usize::from(batch < extra)
                })
                .collect();
            Self { strategy, ranges }
        }

        /// Returns whether the strategy supplied the whole input as one batch, which executes on
        /// the calling thread.
        ///
        /// Such a run can process the input directly rather than preparing its single batch.
        pub const fn is_whole(&self) -> bool {
            self.ranges.len() == 1
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
            if self.is_whole() {
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
            if self.is_whole() {
                prepare(self.ranges).into_iter().map(map_op).collect()
            } else {
                self.strategy.try_map_collect_vec(prepare(self.ranges), map_op)
            }
        }
    }

    /// A grid that [`Strategy::run_tiles`] can cut, made of `rows` passes over the run's columns.
    /// Finishing a tile costs a fixed `tile_cost` cells.
    ///
    /// A tile is one row over a contiguous range of columns, and a run pays `tile_cost` once per
    /// tile, so every cut of a row adds a finish. Three rows over eight columns, as a serial run
    /// and as two workers `A` and `B` might cut them (`[ ]` marks a tile):
    ///
    /// ```text
    ///              serial              whole rows           shares of cells
    /// row 0   [A A A A A A A A]     [A A A A A A A A]     [A A A A A A A A]
    /// row 1   [A A A A A A A A]     [B B B B B B B B]     [A A A A][B B B B]
    /// row 2   [A A A A A A A A]     [A A A A A A A A]     [B B B B B B B B]
    ///
    ///         3 tiles on the        3 tiles: A claimed    4 tiles: 12 cells and
    ///         calling thread        row 2 after row 0     2 finishes per worker
    /// ```
    ///
    /// Here whole rows leave `A` 16 cells and two finishes against `B`'s eight and one, while
    /// shares balance the cells at the price of a cut in row 1. Which cut finishes first depends on
    /// `tile_cost`, and [`Tiles`] describes how a run chooses and how workers claim.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Grid {
        /// Passes over the columns.
        pub rows: usize,
        /// The cost of finishing a tile, in cells.
        pub tile_cost: NonZeroUsize,
    }

    impl Grid {
        /// Estimates the cells on the critical path when `workers` share this grid over `len`
        /// columns, and whether the workers take whole rows.
        ///
        /// Workers taking whole rows run `ceil(rows / workers)` rows each, and a row costs its
        /// cells plus a tile's finish. Shares that cut rows balance the cells, but each finishes
        /// about two extra tiles, one at a share boundary and one from a steal. Each also ends with
        /// up to a tile's cost of cells that no steal evens out. The estimate considers cutting
        /// only when half a row is at least the tile cost, and a tie goes to whole rows.
        const fn critical_path(&self, len: usize, workers: usize) -> (usize, bool) {
            let tile_cost = self.tile_cost.get();
            let row = len.saturating_add(tile_cost);
            let whole = self.rows.div_ceil(workers).saturating_mul(row);
            if len < tile_cost.saturating_mul(2) {
                return (whole, true);
            }
            let cut = (self.rows.saturating_mul(row) / workers)
                .saturating_add(tile_cost.saturating_mul(3));
            if cut < whole { (cut, false) } else { (whole, true) }
        }

        /// The grid among `grids` with the shortest estimated critical path when `workers`
        /// share it over `len` columns, as its index, that estimate in cells, and whether the
        /// workers take whole rows. Ties go to the earliest grid.
        fn choose(grids: &[Self], len: usize, workers: usize) -> (usize, usize, bool) {
            grids
                .iter()
                .enumerate()
                .map(|(index, grid)| {
                    let (cells, whole) = grid.critical_path(len, workers);
                    (index, cells, whole)
                })
                .min_by_key(|&(_, cells, _)| cells)
                .expect("run_tiles must receive at least one grid")
        }
    }

    /// How a [`Tiles`] run cuts the grid.
    #[derive(Debug)]
    enum Plan {
        /// Every row is one tile, processed on the calling thread.
        Serial,
        /// Workers claim whole rows from one queue when `whole` is set, and otherwise start on
        /// equal shares of the cells and take halves of pending shares when they run out.
        #[cfg(any(feature = "std", test))]
        Shared {
            tile_cost: usize,
            workers: usize,
            whole: bool,
        },
    }

    /// Tiles supplied for one invocation of [`Strategy::run_tiles`].
    ///
    /// Each tile is one row over a contiguous range of columns, and the tiles cover every cell
    /// exactly once. A serial run makes every row one tile on the calling thread.
    ///
    /// A parallel run estimates each grid's critical path over its workers both as whole rows
    /// and as equal shares of cells, and cuts the grid in the way with the shortest estimate.
    /// Workers claim whole rows from one queue, one row at a time unless the grid has more than
    /// 65,535 rows, and whole rows may leave some workers a row short. Shares of cells cut rows
    /// and cost each worker about two extra tiles and a tile's cost of unevenness.
    ///
    /// A worker that runs out of its share of cells takes the back half of the largest other
    /// pending share. Taking it can cut a row, so it happens only while the half is longer than
    /// `tile_cost`, where the extra tile pays for itself.
    ///
    /// When an operation does its work in `fill`, a worker that runs slowly or starts late holds
    /// up the run by at most one claim of rows, or by one claim of cells and the halves of its
    /// share too short to take. Those cells come to a few tile costs, or proportionally more in a
    /// grid of more than 65,535 tile costs. Work an operation defers to `finish` stays with the
    /// worker that holds the tile.
    #[derive(Debug)]
    pub struct Tiles<'scope, S: Strategy> {
        #[cfg_attr(
            not(any(feature = "std", test)),
            expect(dead_code, reason = "only shared plans, which need std, dispatch work")
        )]
        strategy: &'scope S,
        grid: usize,
        rows: usize,
        len: usize,
        plan: Plan,
    }

    impl<'scope, S: Strategy> Tiles<'scope, S> {
        /// Makes every row of the cheapest serial grid one tile, processed on the calling thread.
        fn serial(strategy: &'scope S, grids: &[Grid], len: usize) -> Self {
            let (grid, _, _) = Grid::choose(grids, len, 1);
            Self {
                strategy,
                grid,
                rows: grids[grid].rows,
                len,
                plan: Plan::Serial,
            }
        }

        /// Shares the grid that `workers` workers finish soonest among them.
        #[cfg(any(feature = "std", test))]
        fn parallel(strategy: &'scope S, grids: &[Grid], len: usize, workers: usize) -> Self {
            let (grid, _, whole) = Grid::choose(grids, len, workers);
            let rows = grids[grid].rows;
            assert!(rows.checked_mul(len).is_some(), "rows * len must fit in usize");
            Self {
                strategy,
                grid,
                rows,
                len,
                plan: Plan::Shared {
                    tile_cost: grids[grid].tile_cost.get(),
                    workers,
                    whole,
                },
            }
        }

        /// The index, among the grids supplied to the run, of the grid it cuts.
        pub const fn grid(&self) -> usize {
            self.grid
        }

        /// Fills every tile piece by piece with per-worker state, collecting one result per tile.
        ///
        /// `fill` receives a tile's row and the columns of each of its pieces in column order, and
        /// no piece is empty. `finish` then ends the tile and returns its result. `init` creates
        /// state that a worker reuses across its tiles, so `finish` must leave the state ready for
        /// another tile.
        ///
        /// Results come back in no particular order. Where a parallel run cuts a row depends on
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

                // Each worker is one task that claims rows from the queue or cells from its share,
                // and an idle task can take the back half of another share. `Shares` bounds how
                // long a late-starting task or a costlier share can hold up the run.
                #[cfg(any(feature = "std", test))]
                Plan::Shared {
                    tile_cost,
                    workers,
                    whole,
                } => {
                    let shares = Shares::new(self.rows, self.len, tile_cost, workers, whole);
                    self.strategy
                        .map_init_collect_vec(0..shares.workers, init, |state, worker| {
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

    /// The unclaimed cells of a shared [`Tiles`] run.
    ///
    /// Whole rows queue in one share that every worker claims from, one unit of rows at a time, so
    /// a worker that runs slowly or starts late holds up the run by at most one claim.
    ///
    /// Cells are divided into one share per worker. Each worker claims from the front of its own
    /// share, one claim at a time, so its consecutive claims extend one tile within a row and the
    /// rest stays available. A worker whose share is empty takes the back half of the largest
    /// other share whose back half pays for a split, and stops once no share qualifies. A slow or
    /// late worker therefore keeps at most a claim and the halves too short to take. A split can
    /// cut a row and add a tile, so it happens only while the half is longer than a tile's cost.
    #[cfg(any(feature = "std", test))]
    struct Shares {
        /// The unclaimed units of the one queue of whole rows, or of each worker's share of
        /// cells, packed with [`pack`] so that claiming from the front and splitting off the back
        /// are each one atomic update.
        pending: Vec<Pending>,
        /// Workers claiming from `pending`.
        workers: usize,
        /// Cells per unit, enough that every unit index fits in [`HALF_BITS`].
        unit: usize,
        /// Cells in the grid.
        cells: usize,
        /// Units in one claim.
        claim: usize,
        /// Cells a stolen half must exceed, or zero for the queue of whole rows.
        split_cost: usize,
        /// Whether any initial share of cells has a payable split. Claims only shrink shares, and
        /// only a taken half refills one, so a run with no initial payable split never makes one.
        /// The queue of whole rows is never split.
        splittable: bool,
    }

    /// One worker's packed range of units, alone on its cache line so that neighboring workers'
    /// claims do not contend.
    #[cfg(any(feature = "std", test))]
    #[repr(align(128))]
    struct Pending(AtomicUsize);

    #[cfg(any(feature = "std", test))]
    impl Shares {
        /// Queues the grid's whole rows when `whole` is set, and otherwise splits its cells into
        /// equal shares, none smaller than a claim. Either way, at most `workers` workers take
        /// part.
        ///
        /// Each unit of the queue holds whole rows, so a claim never cuts a row. Shares of cells
        /// use units small enough to cut anywhere, claimed one tile's cost at a time.
        fn new(rows: usize, len: usize, tile_cost: usize, workers: usize, whole: bool) -> Self {
            // At most `MAX_UNITS` units cover the grid, so a unit may hold several whole rows.
            let cells = rows * len;
            let (unit, claim, split_cost) = if whole {
                (len * rows.div_ceil(MAX_UNITS), 1, 0)
            } else {
                let unit = cells.div_ceil(MAX_UNITS);
                (unit, tile_cost.div_ceil(unit), tile_cost)
            };
            let units = cells.div_ceil(unit);

            // A nonempty grid holds at least one whole claim, since `Grid::critical_path` shares
            // cells only when a row holds two tile costs. This keeps at least one worker and at
            // most one per whole claim. Shares of cells differ by at most one unit, and the first
            // `extra` take the larger size.
            let workers = workers.min(units / claim);
            let pending = if whole {
                vec![Pending(AtomicUsize::new(pack(0, units)))]
            } else {
                let (per_share, extra) = (units / workers, units % workers);
                (0..workers)
                    .map(|worker| {
                        let start = worker * per_share + worker.min(extra);
                        let end = start + per_share + usize::from(worker < extra);
                        Pending(AtomicUsize::new(pack(start, end)))
                    })
                    .collect()
            };
            let mut shares = Self {
                pending,
                workers,
                unit,
                cells,
                claim,
                split_cost,
                splittable: false,
            };
            shares.splittable = !whole
                && shares
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
            // Whole rows queue in the one share.
            let pending = &self.pending[worker.min(self.pending.len() - 1)].0;
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
        /// Submit one CPU-bound job to this strategy, running it inline on the calling task when
        /// it is measured cheaper than the round trip of offloading it to the pool.
        ///
        /// `len` groups calls at a call site into size classes for those measurements, so similar
        /// `len` must mean comparable cost. An inline job runs to completion before `spawn`
        /// returns, and jobs whose measured cost exceeds a small time budget offload.
        ///
        /// The returned future resolves when the job completes. Blocking on external
        /// synchronization or I/O inside the job can occupy execution capacity until it returns.
        /// When the polling thread itself belongs to the strategy's execution resources (e.g. a
        /// runtime whose executor thread is registered as a pool worker), the job (and other
        /// pending work) may be executed inline on that thread rather than waited on. Synchronous
        /// code waits for the result with [`Self::block_on`].
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

        /// Blocks on `future` and returns its output. A run that waits for a spawned job this
        /// way is charged the job's work, not the wait. The default busy-waits, which suits jobs
        /// that complete before [`Self::spawn`] returns.
        fn block_on<F: core::future::Future>(&self, future: F) -> F::Output {
            let mut future = core::pin::pin!(future);
            let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
            loop {
                if let core::task::Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                    return output;
                }
                core::hint::spin_loop();
            }
        }

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

        /// Run an operation on strategy-provided tiles over `len` columns.
        ///
        /// `grids` are the ways the operation can cut its input. Each [`Grid`] has some number of
        /// rows that pass over the columns and a fixed cost of finishing a tile. The strategy cuts
        /// the grid it estimates its workers will finish first, and [`Tiles::grid`] names that
        /// grid. `run` is called once with tiles that cover every `(row, column)` cell of that grid
        /// exactly once, so a grid without cells has no tiles. Each tile is one row over a
        /// contiguous range of columns, supplied in pieces and then finished once.
        ///
        /// This suits several independent passes over the same input where finishing a tile has a
        /// fixed cost, such as reducing per-tile state, so cutting a pass is costly. Several grids
        /// let an operation trade passes against that cost, as when a wider digit window makes
        /// fewer passes with more buckets to reduce.
        ///
        /// A serial run cuts the grid with the fewest cells, counting each row's finish, and makes
        /// every row one tile. A parallel run shares a grid among the strategy's workers as whole
        /// rows or as shares of cells that cut rows, and [`Tiles`] describes how it chooses and how
        /// workers claim.
        ///
        /// When rows differ in cost, order them so that consecutive rows mix cheap and expensive
        /// ones. `rows * len` must not overflow `usize` for any grid, and `grids` must not be
        /// empty.
        ///
        /// `multiplier` estimates work per cell. Complete the operation, including result assembly,
        /// inside `run`. Both execution shapes must produce equivalent results. The default
        /// implementation makes every row of the cheapest serial grid one tile on the calling
        /// thread.
        ///
        /// # Panics
        ///
        /// Panics if `grids` is empty, or if a parallel run cuts a grid whose `rows * len`
        /// overflows `usize`.
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_parallel::{Grid, Sequential, Strategy};
        /// use core::num::NonZeroUsize;
        ///
        /// let rows = [[1u64, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
        /// let grid = Grid {
        ///     rows: rows.len(),
        ///     tile_cost: NonZeroUsize::MIN,
        /// };
        /// let sums = Sequential.run_tiles(4, &[grid], 1, |tiles| {
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
            len: usize,
            grids: &[Grid],
            _multiplier: usize,
            run: F,
        ) -> R
        where
            R: Send,
            F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
        {
            run(Tiles::serial(self, grids, len))
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
        /// The strategy may run the closures on the calling thread or on pool workers.
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

        /// Sorts a slice with a comparator, without preserving the order of equal elements.
        ///
        /// Prefer it to [`sort_by`](Self::sort_by) when equal elements are indistinguishable or
        /// absent. Leaving their order unspecified lets a strategy choose a faster algorithm.
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_parallel::{Strategy, Sequential};
        ///
        /// let strategy = Sequential;
        /// let mut data = vec![3, 1, 2];
        /// strategy.sort_unstable_by(&mut data, |a, b| a.cmp(b));
        /// assert_eq!(data, vec![1, 2, 3]);
        /// ```
        #[track_caller]
        fn sort_unstable_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            self.sort_by(items, compare);
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

        fn sort_unstable_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            items.sort_unstable_by(compare);
        }
    }
});
commonware_macros::stability_scope!(BETA, cfg(any(feature = "std", test)) {
    /// A shared [`rayon::ThreadPool`].
    pub type ThreadPool = Arc<rayon::ThreadPool>;

    /// A parallel execution strategy backed by a work-stealing [`rayon::ThreadPool`].
    ///
    /// This strategy adaptively executes collection operations serially or through its backing
    /// pool. It keeps wall-clock and busy-time estimates for each callsite, input-size bucket,
    /// work-size bucket, and planning parallelism, so small inputs can avoid thread-pool scheduling
    /// overhead without disabling parallel execution for larger inputs.
    ///
    /// Nested calls at the same callsite share estimates across parent paths, so use distinct
    /// callsites (propagating `#[track_caller]` through helpers as needed) to tune them separately.
    ///
    /// # Cache Affinity
    ///
    /// A strategy built with [`Rayon::new`] splits its pool's workers into groups sized to the
    /// host's last-level cache domains. A strategy built with [`Rayon::with_pool`] is one group
    /// that is never homed.
    ///
    /// A group's home is the domain it requests its workers to run in. An unhomed group can take a
    /// permanent home in the domain of a caller that finds it idle, when that domain allows a CPU
    /// for each of its workers.
    ///
    /// Parallel work submitted from outside the pool runs on one group or across the whole pool, as
    /// the policy learns per call site. Work on one group prefers the group homed in the caller's
    /// domain and otherwise takes the least loaded full-width group. Joins make the same choice or
    /// run serially on the caller, and parallel sorts use one group.
    ///
    /// When the chosen group's home is another domain, the calling thread may be moved there for
    /// the call, within its own affinity mask. The caller's own code in that call, such as a
    /// [`Strategy::run_batches`] body, runs under that mask, and threads it creates inherit it.
    ///
    /// A pool keeps the CPUs of the thread that creates it. To give several pools their own CPUs,
    /// create each from a thread pinned to its share. A pool created from inside a job or a
    /// strategy call gets only the CPUs that thread was kept to, so it can end up in one domain.
    ///
    /// A worker's nested calls, joins, and spawned jobs inherit its placement. A job that
    /// [`Strategy::spawn`] hands to the pool from outside it can start on any idle worker and
    /// prefers waking its submitter's home group.
    ///
    /// With several groups, the group a job prefers waking admits up to one unfinished job per
    /// worker. For admitted jobs, the policy learns whether descendants stay on the starting
    /// worker's group or use the whole pool. It times the job itself, not its consumer's later
    /// work. Other jobs use the whole pool.
    ///
    /// Requested masks stay within the workers' inherited masks, and the operating system may
    /// reject a request. Other threads can still run on a group's CPUs.
    ///
    /// # Thread Pool Ownership
    ///
    /// `Rayon` shares its [`rayon::ThreadPool`] through an [`Arc`], so it can be cheaply cloned and
    /// shared across threads. Multiple strategies can share the same pool.
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
    /// use commonware_parallel::{Rayon, Strategy, rayon::ThreadPoolBuilder};
    /// use std::num::NonZeroUsize;
    ///
    /// let strategy = Rayon::new(ThreadPoolBuilder::new(NonZeroUsize::new(2).unwrap())).unwrap();
    ///
    /// let data: Vec<i64> = (0..1000).collect();
    /// let sum = strategy.fold(&data, || 0i64, |acc, &n| acc + n, |a, b| a + b);
    /// assert_eq!(sum, 499500);
    /// ```
    #[derive(Debug, Clone)]
    pub struct Rayon {
        // The parallelism assumed for policy decisions and for planning batches and tiles.
        // Defaults to the pool's thread count.
        parallelism: usize,

        // `Some` enables adaptive serial-vs-parallel decisions. `None` runs the parallel body
        // whenever the parallelism exceeds one and allocates no policy state.
        policy: Option<policy::Policy>,

        // The pool that runs this strategy's parallel work, and the groups its workers are split
        // into, with their homes and their load.
        groups: Arc<topology::Groups>,

        // The placement a copy made by `placed` runs its parallel bodies under when the caller is
        // not a worker of the strategy's pool, or `None` outside such a copy.
        placement: Option<rayon::Placement>,

        // The clock that measured runs and spawned jobs read their busy time from.
        clock: rayon::Clock,
    }

    /// Where a run's parallel body may run. It decides the body's placement when the caller is not
    /// a worker of the strategy's pool.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Body {
        /// The caller's own code. It runs on the calling thread, so there is nothing to place.
        Caller,
        /// Work that runs on one group, such as a sort.
        Group,
        /// Work the strategy places on a group or on the whole pool.
        Placed,
    }

    impl Rayon {
        /// Builds the pool from `builder` and groups its workers by last-level cache domain as
        /// described on [`Rayon`]. Workers the builder does not name are named `group<g>-<w>`,
        /// and the builder's start handler runs before the strategy's own. With
        /// `use_current_thread`, the calling thread is worker 0: it is never moved to a home, and
        /// the other workers stop only once it has run the jobs queued for it.
        ///
        /// A group is as wide as the most CPUs the calling thread may use in any one domain, less
        /// one when that number is at least six to leave room for the caller and other threads.
        /// With fewer than two domains, or no domain allowing two CPUs, all workers form one
        /// unhomed group.
        ///
        /// When the pool fills all allowed CPUs across two or more equally sized domains of at
        /// least two CPUs each, groups use the full domain width and get fixed homes at startup. A
        /// worker count of at most the group width gives one group, and workers past a multiple of
        /// it form a narrower last group that takes only whole-pool work.
        pub fn new(builder: ThreadPoolBuilder) -> Result<Self, ThreadPoolBuildError> {
            let groups = topology::Groups::build(builder)?;
            Ok(Self::with_groups(Arc::new(groups)))
        }

        /// Creates a [`Rayon`] strategy that treats the given [`ThreadPool`] as one group.
        /// The strategy does not change the pool's worker affinity.
        pub fn with_pool(thread_pool: ThreadPool) -> Self {
            Self::with_groups(Arc::new(topology::Groups::new(thread_pool)))
        }

        /// Creates a strategy over `groups` that plans with the pool's thread count, decides
        /// serial or parallel execution adaptively, and places each parallel body as described
        /// on [`Rayon`].
        fn with_groups(groups: Arc<topology::Groups>) -> Self {
            Self {
                parallelism: groups.pool().current_num_threads(),
                policy: Some(policy::Policy::default()),
                groups,
                placement: None,
                clock: rayon::Clock::Wall,
            }
        }

        /// Overrides the parallelism assumed for planning decisions.
        ///
        /// This does not resize the backing pool. By default a strategy plans with the pool's
        /// thread count. Override it when the strategy should expose a different parallelism
        /// (e.g. a runtime that executes strategy work inline on a single thread). Work placed on
        /// one group of a strategy with several groups plans for at most that group's width.
        pub const fn with_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
            self.parallelism = parallelism.get();
            self
        }

        /// Returns the current job's placement if the caller is a worker of this strategy's pool.
        /// Nested strategy work inherits that placement, allowing a waiting worker to run the
        /// jobs it submitted. A nested install can temporarily change the worker's placement.
        fn current_placement(&self) -> Option<rayon::Placement> {
            self.groups.pool().current_placement()
        }

        /// The parallelism a body placed on `group` plans with. The groups of a grouped strategy
        /// share its parallelism, so each plans for no more tasks than it has workers. A strategy
        /// with one group plans for its whole parallelism, including an override.
        fn group_parallelism(&self, group: usize) -> usize {
            let groups = self.groups.groups();
            if groups.len() > 1 {
                self.parallelism.min(groups[group].width())
            } else {
                self.parallelism
            }
        }

        /// Copies this strategy to run its parallel bodies under `placement`. A group plans with
        /// [`Self::group_parallelism`], and the whole pool with the strategy's parallelism. The
        /// copy has no policy because its caller has already decided how the work should run.
        fn placed(&self, placement: rayon::Placement) -> Self {
            let parallelism = match placement {
                rayon::Placement::Local(group) => self.group_parallelism(group),
                rayon::Placement::Wide { .. } => self.parallelism,
            };
            Self {
                parallelism,
                policy: None,
                groups: Arc::clone(&self.groups),
                placement: Some(placement),
                clock: self.clock.clone(),
            }
        }

        /// Resolves placement when the policy does not choose it. A worker of this strategy's
        /// pool uses its current job's placement. Other callers use the strategy's explicit
        /// placement, falling back to the whole pool.
        fn resolve_placement(&self) -> rayon::Placement {
            self.current_placement()
                .or(self.placement)
                .unwrap_or(rayon::Placement::Wide { near: 0 })
        }

        /// Runs `op` under `placement` on the backing pool and returns its result. A thread
        /// outside the pool blocks until then, so this first calls the calling thread's block
        /// hook (see [`set_block_hook`]). Every synchronous parallel body of the strategy runs
        /// through here, except a join on a worker of the pool, which joins in place and calls
        /// the hook itself.
        fn install_in<OP, R>(&self, placement: rayon::Placement, op: OP) -> R
        where
            OP: FnOnce() -> R + Send,
            R: Send,
        {
            Self::call_block_hook();
            self.groups.pool().install_in(placement, op)
        }

        /// Calls the calling thread's block hook, if it has one (see [`set_block_hook`]).
        fn call_block_hook() {
            if let Some(hook) = BLOCK_HOOK.try_with(core::cell::Cell::get).ok().flatten() {
                hook();
            }
        }

        /// Runs [`Self::try_execute`] with an infallible `run`.
        #[track_caller]
        fn execute<R>(
            &self,
            len: usize,
            work: usize,
            body: Body,
            run: impl FnOnce(policy::RunExecution, rayon::Placement) -> R,
        ) -> R {
            match self.try_execute(len, work, body, |execution, placement| {
                Ok::<_, Infallible>(run(execution, placement))
            }) {
                Ok(result) => result,
                Err(e) => match e {},
            }
        }

        /// Runs `run` on the execution path the policy prefers for this call site's `len` items and
        /// estimated `work`, passing the placement a parallel run uses.
        ///
        /// A worker of the strategy's pool decides every body against the placement of the job it
        /// runs, since the body's work runs there. A [`Body::Caller`] body, a serial run, and every
        /// run without a policy use [`Self::resolve_placement`].
        ///
        /// A thread outside the pool decides a [`Body::Group`] body against one group, and a
        /// [`Body::Placed`] body also against the whole pool when the strategy has several groups.
        /// That one group is the group homed in the caller's domain, homing one if it can, or else
        /// the least loaded full-width group.
        #[track_caller]
        fn try_execute<R, E>(
            &self,
            len: usize,
            work: usize,
            body: Body,
            run: impl FnOnce(policy::RunExecution, rayon::Placement) -> Result<R, E>,
        ) -> Result<R, E> {
            let Some(policy) = &self.policy else {
                let execution = if self.parallelism <= 1 {
                    policy::RunExecution::Serial
                } else {
                    policy::RunExecution::Parallel
                };
                return run(execution, self.resolve_placement());
            };

            let caller = Location::caller();
            let own = self.current_placement();
            let pools = match (own, body) {
                (Some(rayon::Placement::Local(_)), _) => {
                    policy::Pools::Fixed(policy::Placement::Local)
                }
                (Some(rayon::Placement::Wide { .. }), _) | (None, Body::Caller) => {
                    policy::Pools::Fixed(policy::Placement::Wide)
                }
                (None, Body::Placed) if self.groups.groups().len() > 1 => {
                    policy::Pools::Either
                }
                (None, Body::Group | Body::Placed) => {
                    policy::Pools::Fixed(policy::Placement::Local)
                }
            };
            let plan = policy.choose_run(caller, len, work, self.parallelism, pools);

            // Resolve where the body runs, holding a lease on the groups it uses until the body
            // returns.
            let mut lease = None;
            let mut nudge = None;
            let placement = match own {
                Some(placement) => placement,
                None if body == Body::Caller || plan.execution == policy::RunExecution::Serial => {
                    self.resolve_placement()
                }
                None => {
                    // A Local body first tries to use or establish a home in the caller's domain,
                    // then falls back to the least loaded full-width group. Only a strategy with
                    // several groups places a body on the whole pool.
                    if plan.placement == policy::Placement::Local {
                        let local = self
                            .groups
                            .local()
                            .unwrap_or_else(|| self.groups.least_loaded());
                        nudge = self.groups.nudge(local.group());
                        let placement = rayon::Placement::Local(local.group());
                        lease = Some(local);
                        placement
                    } else {
                        let wide = self.groups.wide();
                        let placement = rayon::Placement::Wide { near: wide.group() };
                        lease = Some(wide);
                        placement
                    }
                }
            };

            // A measured parallel run also meters its busy time. A serial run's busy time is its
            // wall time.
            let start = plan.measure.then(Instant::now);
            let (result, busy) = {
                // The guard requests the caller's original mask when the body returns or unwinds.
                let _nudge = nudge;
                match plan.execution {
                    policy::RunExecution::Parallel if plan.measure => {
                        let (result, busy) =
                            rayon::measure_with(self.clock.clone(), || run(plan.execution, placement));
                        (result, Some(busy))
                    }
                    policy::RunExecution::Parallel | policy::RunExecution::Serial => {
                        (run(plan.execution, placement), None)
                    }
                }
            };
            drop(lease);

            // Record only successful runs. An error can skip work and bias the estimates down.
            if let (Some(start), Ok(_)) = (start, &result) {
                let wall = start.elapsed();
                let busy = busy.unwrap_or(wall);
                let sample = policy::RunSample { wall, busy };
                policy.record_run(caller, len, work, self.parallelism, plan, sample);
            }
            result
        }

        /// Sorts `items` by `compare` with `serial`, or with `parallel` on the workers of the
        /// placement, as the policy decides.
        #[track_caller]
        fn sort_with<T, C>(
            &self,
            items: &mut [T],
            compare: C,
            serial: impl FnOnce(&mut [T], C),
            parallel: impl FnOnce(&mut [T], C) + Send,
        ) where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            self.execute(
                items.len(),
                items.len(),
                Body::Group,
                |execution, placement| match execution {
                    policy::RunExecution::Serial => serial(items, compare),
                    policy::RunExecution::Parallel => {
                        self.install_in(placement, || parallel(items, compare))
                    }
                },
            );
        }

        /// Blocks on `future` like [`Strategy::block_on`], calling `park` to park the calling
        /// thread between polls when it is not a worker of the pool.
        fn block_on_with<F: Future>(&self, future: F, park: impl FnMut()) -> F::Output {
            let _waiting = rayon::Waiting::new();
            let mut future = core::pin::pin!(future);
            if let Some(output) = self.groups.pool().block_on_worker(future.as_mut()) {
                return output;
            }
            let _parked = rayon::Parked::new();
            park_on(future, park)
        }
    }

    /// Drives `future` to completion on the calling thread, calling `park` between polls. Each poll
    /// runs with the thread's context charging, so a parked context is charged for the future's
    /// own work and not for the parks. Each call tracks its own wakes, since the thread's park
    /// token is shared with a `park_on` nested inside a poll, whose park would otherwise consume a
    /// wake meant for this loop.
    fn park_on<F: Future>(future: F, mut park: impl FnMut()) -> F::Output {
        struct Unpark {
            thread: std::thread::Thread,
            woken: AtomicBool,
        }
        impl std::task::Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.woken.store(true, AtomicOrdering::Release);
                self.thread.unpark();
            }
        }

        let unpark = Arc::new(Unpark {
            thread: std::thread::current(),
            woken: AtomicBool::new(false),
        });
        let waker = std::task::Waker::from(Arc::clone(&unpark));
        let mut cx = std::task::Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        loop {
            if let Poll::Ready(output) = rayon::unparked(|| future.as_mut().poll(&mut cx)) {
                return output;
            }
            while !unpark.woken.swap(false, AtomicOrdering::Acquire) {
                park();
            }
        }
    }

    impl Strategy for Rayon {
        /// A worker of the strategy's pool that awaits the result runs queued jobs on its own stack
        /// while it waits, so blocking waits inside jobs must allow nesting. For example,
        /// `futures::executor::block_on` panics if a nested job calls it on a thread that is
        /// already inside it.
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
            let threads = self.groups.pool().current_num_threads();
            let caller = Location::caller();

            // A worker of the strategy's pool submits under its current placement and can run
            // the job itself while waiting for the result.
            let own = self.current_placement();

            // A pool with one worker always runs the job inline without measurement. With more
            // workers, a strategy without a policy always offloads. An adaptive strategy compares
            // the job's estimated cost with the overhead of offloading it.
            let (mut plan, policy) = if threads <= 1 {
                (policy::SpawnPlan::fixed(policy::SpawnExecution::Inline), None)
            } else {
                self.policy.as_ref().map_or(
                    (policy::SpawnPlan::fixed(policy::SpawnExecution::Offload), None),
                    |policy| {
                        let spawner = if own.is_some() {
                            policy::Spawner::Worker
                        } else {
                            policy::Spawner::Outside
                        };
                        let plan = policy.choose_spawn(caller, len, threads, spawner);
                        (plan, Some(policy))
                    },
                )
            };

            match plan.execution {
                policy::SpawnExecution::Inline => {
                    // Inline: run on the calling task and hand back a ready future.
                    let start = plan.measure.then(Instant::now);
                    let result = f(self.clone());
                    if let (Some(start), Some(policy)) = (start, policy) {
                        policy.record_spawn_inline(caller, len, threads, start.elapsed());
                    }
                    Either::Left(future::ready(result))
                }
                policy::SpawnExecution::Offload => {
                    // The worker records the job's elapsed time so its estimate survives a dropped
                    // future. The awaiting future records the round trip when it observes the
                    // result.
                    //
                    // A job submitted by a worker of the pool inherits that worker's placement. A
                    // job submitted by any other thread is an external root. It can start on any
                    // worker, and its wakeup prefers its submitter's home group.
                    //
                    // Admissions limit how many roots learn descendant placement, and excess roots
                    // execute Wide. Every tracked external root leases all groups, so no group
                    // gains a new home until it finishes. Leases belong to the job, even after its
                    // future or parent is gone.
                    //
                    // external root -> shared Wide queue -> worker in group H
                    //                                       |
                    //           admitted, Local, full width +--> Local(H)
                    //                             otherwise +--> Wide
                    let (queued, placement, lease) = match own {
                        Some(placement @ rayon::Placement::Local(group)) => {
                            (placement, placement, self.groups.lease(group))
                        }
                        Some(placement @ rayon::Placement::Wide { .. }) => {
                            (placement, placement, self.groups.wide())
                        }
                        None => {
                            let (lease, admitted) = self.groups.root();
                            let group = lease.group();
                            let wide = rayon::Placement::Wide { near: group };
                            if admitted
                                && self.groups.groups().len() > 1
                                && let Some(policy) = policy
                            {
                                plan = policy.choose_spawn_placement(caller, len, threads, plan);
                            }
                            let placement = if admitted && plan.placement != Some(policy::Placement::Wide) {
                                rayon::Placement::Local(group)
                            } else {
                                wide
                            };
                            (wide, placement, lease.into_wide())
                        }
                    };
                    let spawn_start = plan.measure.then(Instant::now);
                    let (tx, mut rx) = oneshot::channel();
                    let s = self.clone();
                    let pool = self.groups.pool().clone();
                    let worker_pool = self.groups.pool().clone();
                    let clock = self.clock.clone();
                    let recorder = if plan.measure {
                        policy.cloned().map(|policy| (policy, caller, len, threads))
                    } else {
                        None
                    };
                    let worker_recorder = recorder.clone();
                    let job = move || {
                        let job_start = worker_recorder.is_some().then(Instant::now);

                        // Local descendants stay in the group of the worker that claimed the root.
                        // A root that starts on a group not preferred for Local work, such as a
                        // narrower one that cannot supply the learned width, executes Wide without
                        // training the descendant-placement estimate.
                        let mut plan = plan;
                        let placement = if own.is_none()
                            && matches!(placement, rayon::Placement::Local(_))
                        {
                            let current = worker_pool
                                .current_placement()
                                .expect("external root must run on a worker of its pool");
                            let (rayon::Placement::Local(group) | rayon::Placement::Wide { near: group }) = current;
                            if s.groups.groups()[group].placeable() {
                                rayon::Placement::Local(group)
                            } else {
                                plan.placement = None;
                                rayon::Placement::Wide { near: group }
                            }
                        } else {
                            placement
                        };

                        // The pool aborts on an uncaught panic in a spawned job, so catch the
                        // panic and propagate it to the awaiting task. The job measures its own
                        // busy time for the run that awaits it.
                        let (result, busy) = rayon::measure_with(clock, || {
                            panic::catch_unwind(AssertUnwindSafe(|| {
                                worker_pool.install_in(placement, || f(s))
                            }))
                        });
                        let job = job_start.map(|start| start.elapsed());
                        let ok = result.is_ok();
                        let _ = tx.send((result, job, busy));

                        // A panic can skip work and bias the estimate down, so record only
                        // successful jobs. Sending the result first lets the caller resume
                        // without waiting for this bookkeeping.
                        if ok
                            && let (Some((policy, caller, len, threads)), Some(job)) =
                                (worker_recorder, job)
                        {
                            policy.record_spawn_job(caller, len, threads, plan, job);
                        }
                    };
                    self.groups.pool().spawn_in(queued, move || {
                        let _lease = lease;
                        job();
                    });
                    Either::Right(async move {
                        // Each poll checks membership because the future can move between threads.
                        let payload = future::poll_fn(|cx| {
                            if let Poll::Ready(payload) = rx.poll_unpin(cx) {
                                return Poll::Ready(payload);
                            }
                            pool.block_on_worker(Pin::new(&mut rx))
                                .map_or(Poll::Pending, Poll::Ready)
                        })
                        .await;
                        let (result, job, busy) = payload.unwrap_or_else(|_| {
                            panic!("strategy job must not be dropped before completion")
                        });

                        // A worker awaits with its context suspended, and a thread in `block_on`
                        // with its park uncharged, so either charges its run the job's busy time
                        // on receipt. A thread blocking any other way is charged for its park,
                        // which covers the part of the job that overlaps it.
                        if pool.current_placement().is_some() || rayon::is_waiting() {
                            rayon::charge(busy);
                        }
                        match result {
                            Ok(value) => {
                                // The round trip starts after placement and lease acquisition. It
                                // includes channel setup, queueing, the job, and receiving the
                                // result.
                                //
                                // A late poll adds the delay after job completion to the sample.
                                // That biases the choice toward inline, within the policy's budget.
                                if let (
                                    Some((policy, caller, len, threads)),
                                    Some(job),
                                    Some(start),
                                ) = (recorder, job, spawn_start)
                                {
                                    policy.record_spawn_round_trip(
                                        caller,
                                        len,
                                        threads,
                                        plan,
                                        start.elapsed(),
                                        job,
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

        /// A worker of the strategy's pool runs queued jobs while it waits. Any other thread parks
        /// between polls with its context parked, so a measured run is charged the future's own
        /// work and the spawned jobs it receives, and not the wait. A wait nested inside the future
        /// should go through `block_on` as well: a foreign executor's park there is charged.
        fn block_on<F: Future>(&self, future: F) -> F::Output {
            self.block_on_with(future, std::thread::park)
        }

        #[track_caller]
        fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
        where
            R: Send,
            SEQ: FnOnce() -> R + Send,
            PAR: FnOnce() -> R + Send,
        {
            self.execute(len, len, Body::Caller, |execution, _| match execution {
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
            self.try_execute(len, len, Body::Caller, |execution, _| match execution {
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
            self.try_execute(
                len,
                len.saturating_mul(multiplier),
                Body::Placed,
                |execution, placement| match execution {
                    policy::RunExecution::Serial => run(Batches::whole(self, len)),
                    policy::RunExecution::Parallel => {
                        // Plan the batches with the parallelism of the placement, so a group of a
                        // grouped strategy gets no more batches than it has workers.
                        let placed = self.placed(placement);
                        let count = placed.parallelism.min(len / minimum_batch_len.get());
                        run(Batches::balanced(&placed, len, count))
                    }
                },
            )
        }

        #[track_caller]
        fn run_tiles<R, F>(
            &self,
            len: usize,
            grids: &[Grid],
            multiplier: usize,
            run: F,
        ) -> R
        where
            R: Send,
            F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
        {
            // The policy picks the shape from the cheapest serial grid's cells. A parallel run
            // dispatches its shares through a placed copy without a policy, since a policy would
            // see only one item per share and could run them serially.
            let (_, cells, _) = Grid::choose(grids, len, 1);
            let work = cells.saturating_mul(multiplier);
            self.execute(len, work, Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => run(Tiles::serial(self, grids, len)),
                policy::RunExecution::Parallel => {
                    let placed = self.placed(placement);
                    run(Tiles::parallel(&placed, grids, len, placed.parallelism))
                }
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
            let items: Vec<I::Item> = iter.into_iter().collect();
            self.execute(items.len(), items.len(), Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => {
                    Sequential.fold_init(items, init, identity, fold_op, reduce_op)
                }
                policy::RunExecution::Parallel => self.install_in(placement, || {
                    rayon::fold_init(items, &init, &identity, &fold_op, &reduce_op)
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
            self.execute(items.len(), items.len(), Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => Sequential.map_collect_vec(items, map_op),
                policy::RunExecution::Parallel => self.install_in(placement, || {
                    rayon::map_collect_vec(items, &map_op)
                }),
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
            self.try_execute(items.len(), items.len(), Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => Sequential.try_map_collect_vec(items, map_op),
                policy::RunExecution::Parallel => self.install_in(placement, || {
                    rayon::try_map_collect_vec(items, &map_op)
                }),
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
            self.execute(items.len(), items.len(), Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
                policy::RunExecution::Parallel => self.install_in(placement, || {
                    rayon::map_init_collect_vec(items, &init, &map_op)
                }),
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
            self.execute(items.len(), items.len().saturating_mul(multiplier), Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
                policy::RunExecution::Parallel => self.install_in(placement, || {
                    rayon::map_init_collect_vec(items, &init, &map_op)
                }),
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
            self.try_execute(items.len(), items.len(), Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => {
                    Sequential.try_fold(items, identity, fold_op, reduce_op)
                }
                policy::RunExecution::Parallel => self.install_in(placement, || {
                    rayon::try_fold(items, &identity, &fold_op, &reduce_op)
                }),
            })
        }

        #[track_caller]
        fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send,
        {
            // A worker of the strategy's pool joins in place under its current placement.
            // Other threads share one size class per call site. The policy chooses between
            // serial execution on the caller, one group, and the whole pool.
            if self.current_placement().is_some() {
                // Joining in place can still hold this thread until the other side returns, so it
                // calls the thread's block hook as an install does.
                Self::call_block_hook();
                return rayon::join(a, b);
            }

            // A strategy without a policy always joins on its pool under its own placement.
            if self.policy.is_none() {
                return self.install_in(self.resolve_placement(), || rayon::join(a, b));
            }
            self.execute(1, 1, Body::Placed, |execution, placement| match execution {
                policy::RunExecution::Serial => (a(), b()),
                policy::RunExecution::Parallel => self.install_in(placement, || rayon::join(a, b)),
            })
        }

        #[track_caller]
        fn sort_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            self.sort_with(
                items,
                compare,
                |items, compare| Sequential.sort_by(items, compare),
                |items, compare| {
                    rayon::par_mergesort(items, |a, b| compare(a, b) == Ordering::Less)
                },
            );
        }

        #[track_caller]
        fn sort_unstable_by<T, C>(&self, items: &mut [T], compare: C)
        where
            T: Send,
            C: Fn(&T, &T) -> Ordering + Send + Sync,
        {
            self.sort_with(
                items,
                compare,
                |items, compare| Sequential.sort_unstable_by(items, compare),
                |items, compare| {
                    rayon::par_quicksort(items, |a, b| compare(a, b) == Ordering::Less)
                },
            );
        }
    }
});
#[cfg(any(feature = "std", test))]
std::thread_local! {
    /// The function [`Rayon`] calls on this thread before blocking it in its pool.
    static BLOCK_HOOK: core::cell::Cell<Option<fn()>> = const { core::cell::Cell::new(None) };
}
commonware_macros::stability_scope!(ALPHA, cfg(any(feature = "std", test)) {
    /// Sets the function that [`Rayon`] calls on the current thread before it blocks the thread
    /// in its pool, or clears it with `None`, and returns the function it replaces. A runtime
    /// worker installs one to hand off its queued work before a parallel call blocks it, and
    /// restores the replaced one when it stops. The hook runs inside the call, so its time counts
    /// toward the call's measured run, and a hook must not itself make a parallel call.
    pub fn set_block_hook(hook: Option<fn()>) -> Option<fn()> {
        BLOCK_HOOK
            .try_with(|current| current.replace(hook))
            .ok()
            .flatten()
    }
});
commonware_macros::stability_scope!(ALPHA, cfg(any(feature = "test-utils", test)) {
    pub mod mocks;
});

#[cfg(test)]
mod test {
    use crate::{
        Grid, MAX_UNITS, Rayon, Sequential, Strategy,
        mocks::Explorer,
        rayon::{self, Placement, ThreadPoolBuilder},
    };
    use commonware_utils::{
        NZUsize, Widen,
        sync::{Condvar, Mutex},
    };
    use core::{num::NonZeroUsize, ops::Range};
    use futures::FutureExt;
    use proptest::prelude::*;
    use std::{
        panic::{self, AssertUnwindSafe, Location},
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    fn parallel_strategy() -> Rayon {
        Rayon::new(ThreadPoolBuilder::new(NZUsize!(4))).unwrap()
    }

    /// Builds a strategy with group `widths` whose groups tests can home through fake domains.
    /// Worker `j` of group `i` is named `g{i}-{j}`. All groups must have the first group's width,
    /// except the last group may be narrower.
    fn synthetic(widths: &[usize]) -> Rayon {
        let width = widths[0];
        let pool = ThreadPoolBuilder::new(NZUsize!(widths.iter().sum()))
            .group_width(width)
            .thread_name(|worker| format!("g{}-{}", worker.group, worker.offset))
            .build()
            .unwrap();
        assert_eq!(pool.group_widths(), widths);
        let groups = crate::topology::Groups::new(Arc::new(pool));
        Rayon::with_groups(Arc::new(groups))
    }

    /// Blocks the calling thread until `future` completes, parking between polls. Jobs wait with
    /// this because a worker awaiting one job can run another waiting job on its own stack, and
    /// `futures::executor::block_on` panics when called inside itself.
    fn block_on_nested<F: core::future::Future>(future: F) -> F::Output {
        super::park_on(future, std::thread::park)
    }

    /// Spins until `bit` is set in `release`. Returns `false` if that takes more than 60 seconds.
    fn wait_for_release(release: &AtomicUsize, bit: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(60);
        while release.load(Ordering::Acquire) & bit == 0 {
            if Instant::now() >= deadline {
                return false;
            }
            core::hint::spin_loop();
        }
        true
    }

    /// Waits up to ten seconds until every worker of `pool` is registered as asleep. A worker
    /// finishes a job, including the samples it records for the job, before it sleeps, so a quiet
    /// pool has no bookkeeping in flight.
    fn wait_until_asleep(pool: &rayon::ThreadPool) {
        wait_until_sleeping(pool, pool.current_num_threads());
    }

    /// Waits up to ten seconds until at least `count` workers of `pool` are registered as asleep. A
    /// sleeping worker waits with its context suspended, so virtual time that passes afterwards is
    /// not charged to it.
    fn wait_until_sleeping(pool: &rayon::ThreadPool, count: usize) {
        let start = Instant::now();
        while pool.sleeping_workers() < count {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "{count} workers of the pool must go to sleep within 10 seconds"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Forced parallel work can use an idle group while another group's workers are occupied.
    #[test]
    fn forced_parallel_uses_idle_group() {
        // Release blocked workers during unwinding as well as normal cleanup.
        struct Release(Arc<(Mutex<bool>, Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0.0.lock() = true;
                self.0.1.notify_all();
            }
        }

        // Occupy the first group so only the second can start the forced operation.
        let strategy = synthetic(&[2, 2]);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let release_guard = Release(release.clone());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        strategy.groups.pool().spawn_broadcast(move |context| {
            if context.index() < 2 {
                let mut released = release.0.lock();
                ready_tx.send(context.index()).unwrap();
                while !*released {
                    release.1.wait(&mut released);
                }
            }
        });
        for _ in 0..2 {
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }

        // Record progress before releasing the first group, then let all work finish.
        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        let operation = std::thread::spawn(move || {
            Explorer::parallel(&strategy).map_collect_vec(0..64, |i| {
                progress_tx
                    .send(strategy.groups.pool().current_thread_index().unwrap())
                    .unwrap();
                i * i
            })
        });
        let first = progress_rx.recv_timeout(Duration::from_secs(5));
        drop(release_guard);
        let actual = operation.join().unwrap();

        // The idle group must have started useful work while the first was blocked.
        assert_eq!(actual, (0..64).map(|i| i * i).collect::<Vec<_>>());
        assert!(
            matches!(first, Ok(2 | 3)),
            "the idle group must start useful work: {first:?}"
        );
    }

    /// Local calls from a domain home a group there, and the strategy reports it.
    #[test]
    fn local_calls_home_group() {
        // Repeated placed calls from domain 1 home a group there.
        let strategy = synthetic(&[2, 2]);
        crate::topology::Groups::fake_domain(Some(1));
        for _ in 0..8 {
            let out = strategy.map_collect_vec(0..64u64, |x| {
                std::thread::sleep(Duration::from_micros(200));
                x + 1
            });
            assert_eq!(out, (1..=64).collect::<Vec<_>>());
        }
        crate::topology::Groups::fake_domain(None);

        // The report shows the home, with no call left in flight.
        let report = strategy.groups.describe();
        assert!(report.contains("home Some(1)"), "{report}");
        assert!(report.contains("in_flight 0"), "{report}");
    }

    /// Runs one placed map from a thread outside the pool and returns its call site with the
    /// placement each item ran under. Each calling line is its own policy entry.
    #[track_caller]
    fn map_placements(
        strategy: &Rayon,
    ) -> (
        &'static std::panic::Location<'static>,
        Vec<Option<crate::rayon::Placement>>,
    ) {
        let placements = commonware_utils::sync::Mutex::new(Vec::new());
        let out = strategy.map_collect_vec(0..64u64, |x| {
            placements.lock().push(strategy.current_placement());
            x + 1
        });
        assert_eq!(out, (1..=64).collect::<Vec<_>>());
        (std::panic::Location::caller(), placements.into_inner())
    }

    /// A worker's nested placed call records its sample under the placement it runs under, so
    /// a worker confined to one group trains that group's estimate rather than the whole pool's.
    #[test]
    fn nested_calls_record_current_placement() {
        for (placement, local) in [
            (crate::rayon::Placement::Local(1), true),
            (crate::rayon::Placement::Wide { near: 1 }, false),
        ] {
            // A map nested under `placement` trains only the estimate of that placement.
            let strategy = synthetic(&[2, 2]);
            let (site, _) = strategy
                .groups
                .pool()
                .install_in(placement, || map_placements(&strategy));
            let (wide_ns, local_ns) = strategy
                .policy
                .as_ref()
                .unwrap()
                .run_placement_estimates(site, 64, 64, strategy.parallelism)
                .unwrap();
            assert_eq!(
                (wide_ns.is_some(), local_ns.is_some()),
                (!local, local),
                "{placement:?}: {wide_ns:?} {local_ns:?}"
            );
        }
    }

    /// A placed call from a thread whose domain has no home, or is unknown, still compares one
    /// group with the whole pool. Its Local runs take the least loaded full-width group, even
    /// while every full-width group is busy, never the narrower final group, and record Local
    /// samples. No group moves or gains a home.
    #[test]
    fn unhomed_calls_compare_remote_group() {
        for caller in [Some(2), None] {
            // Two full groups homed in domains 0 and 1 and held busy, plus a narrower third group.
            let strategy = synthetic(&[2, 2, 1]);
            crate::topology::Groups::fake_domain(Some(0));
            let first = strategy.groups.local().unwrap();
            crate::topology::Groups::fake_domain(Some(1));
            let second = strategy.groups.local().unwrap();

            // Two placed calls from a domain without a home, or from an unknown one.
            crate::topology::Groups::fake_domain(caller);
            let runs: Vec<_> = (0..2).map(|_| map_placements(&strategy)).collect();
            crate::topology::Groups::fake_domain(None);
            drop((first, second));

            // The calls tried one group, and only a full-width one.
            let local: Vec<_> = runs
                .iter()
                .flat_map(|(_, placements)| placements)
                .filter(|placement| matches!(placement, Some(crate::rayon::Placement::Local(_))))
                .collect();
            assert!(
                !local.is_empty(),
                "{caller:?}: a caller without a home must try one group"
            );
            assert!(
                local.iter().all(|placement| matches!(
                    placement,
                    Some(crate::rayon::Placement::Local(0 | 1))
                )),
                "{caller:?}: local runs must use a full-width group: {local:?}"
            );

            // The Local run was recorded.
            let (_, local_ns) = strategy
                .policy
                .as_ref()
                .unwrap()
                .run_placement_estimates(runs[0].0, 64, 64, strategy.parallelism)
                .unwrap();
            assert!(
                local_ns.is_some(),
                "{caller:?}: the local run must be recorded"
            );

            // No home moved, and the narrow group gained none.
            let report = strategy.groups.describe();
            for line in [
                "group 0: width 2 home Some(0)",
                "group 1: width 2 home Some(1)",
                "group 2: width 1 home None",
            ] {
                assert!(report.contains(line), "{caller:?}: {report}");
            }
        }
    }

    /// A strategy with one group places a call from outside the pool on that group, so the
    /// first call homes it in the caller's domain. A caller from another domain then runs on the
    /// same group, which keeps its home.
    #[test]
    fn single_group_places_outside_calls() {
        // Call from domain 1, then from domain 0.
        let strategy = synthetic(&[2]);
        crate::topology::Groups::fake_domain(Some(1));
        let (_, first) = map_placements(&strategy);
        let homed = strategy.groups.describe();
        crate::topology::Groups::fake_domain(Some(0));
        let (_, second) = map_placements(&strategy);
        crate::topology::Groups::fake_domain(None);

        // Both calls ran on the only group, and it kept the first call's home.
        assert!(homed.contains("home Some(1)"), "{homed}");
        for placements in [first, second] {
            assert!(
                placements
                    .iter()
                    .all(|placement| *placement == Some(crate::rayon::Placement::Local(0))),
                "{placements:?}"
            );
        }
        let report = strategy.groups.describe();
        assert!(report.contains("home Some(1)"), "{report}");
    }

    /// A fold reduces its partial results in input order when it seeds the whole pool.
    #[test]
    fn fold_init_wide_seed_preserves_order() {
        let strategy = synthetic(&[2, 2]);
        crate::topology::Groups::fake_domain(Some(0));
        let data: Vec<u64> = (0..1000).collect();
        let parallel: Vec<u64> = strategy.fold_init(
            &data,
            || (),
            Vec::new,
            |mut acc, _, &x| {
                std::thread::sleep(Duration::from_micros(20));
                acc.push(x * 2);
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );
        crate::topology::Groups::fake_domain(None);
        assert_eq!(parallel, data.iter().map(|x| x * 2).collect::<Vec<_>>());
    }

    /// A worker running a job placed on its group keeps a nested placed call in that group.
    #[test]
    fn local_nested_calls_stay_on_group() {
        let strategy = synthetic(&[2, 2]);
        let local = crate::rayon::Placement::Local(0);
        let groups = strategy.groups.pool().install_in(local, || {
            let seen = commonware_utils::sync::Mutex::new(Vec::new());
            for _ in 0..4 {
                let _: Vec<_> = strategy.map_collect_vec(0..32u64, |x| {
                    std::thread::sleep(Duration::from_micros(200));
                    seen.lock().push(
                        strategy
                            .groups
                            .pool()
                            .current_worker()
                            .map(|worker| worker.group),
                    );
                    x
                });
            }
            seen.into_inner()
        });
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|group| *group == Some(0)), "{groups:?}");
    }

    /// A worker running a job placed on the whole pool spreads a nested placed call over every
    /// group.
    #[test]
    fn wide_nested_calls_span_groups() {
        let strategy = synthetic(&[2, 2]).without_policy();
        let wide = crate::rayon::Placement::Wide { near: 0 };
        let groups = strategy.groups.pool().install_in(wide, || {
            let seen = commonware_utils::sync::Mutex::new(std::collections::HashSet::new());
            let _: Vec<_> = strategy.map_collect_vec(0..64u64, |x| {
                std::thread::sleep(Duration::from_millis(1));
                seen.lock().insert(
                    strategy
                        .groups
                        .pool()
                        .current_worker()
                        .map(|worker| worker.group),
                );
                x
            });
            seen.into_inner()
        });
        assert_eq!(groups, [Some(0), Some(1)].into_iter().collect());
    }

    /// A worker's sort, stable or unstable, with or without a policy, compares under the placement
    /// of the job the worker runs, whether that placement is Local or Wide.
    #[test]
    fn sort_inherits_worker_placement() {
        let grouped = synthetic(&[2, 2]);

        // Both sorts, on a strategy with and without a policy.
        let strategies = [false, true].into_iter().flat_map(|unstable| {
            [
                (grouped.without_policy(), unstable),
                (grouped.clone(), unstable),
            ]
        });
        for (strategy, unstable) in strategies {
            // Sort a reversed input and record the placement seen by every comparison.
            let sort = || {
                let placements = commonware_utils::sync::Mutex::new(Vec::new());
                let mut items: Vec<u64> = (0..1024).rev().collect();
                let compare = |a: &u64, b: &u64| {
                    placements.lock().push(strategy.current_placement());
                    a.cmp(b)
                };
                if unstable {
                    strategy.sort_unstable_by(&mut items, compare);
                } else {
                    strategy.sort_by(&mut items, compare);
                }
                assert_eq!(items, (0..1024).collect::<Vec<_>>());
                placements.into_inner()
            };

            // Under a Local job, every comparison runs under that placement.
            let local = crate::rayon::Placement::Local(1);
            let placements = strategy.groups.pool().install_in(local, sort);
            assert!(!placements.is_empty());
            assert!(
                placements.iter().all(|&p| p == Some(local)),
                "{placements:?}"
            );

            // Under a Wide job, every comparison runs under the worker's Wide placement.
            let wide = crate::rayon::Placement::Wide { near: 0 };
            let (placements, own) = strategy
                .groups
                .pool()
                .install_in(wide, || (sort(), strategy.current_placement()));
            assert!(matches!(own, Some(crate::rayon::Placement::Wide { .. })));
            assert!(placements.iter().all(|&p| p == own), "{placements:?}");
        }
    }

    /// A collection operation placed on a group from a thread outside the pool runs every item
    /// on that group's workers and none on the calling thread.
    #[test]
    fn local_calls_use_only_group_workers() {
        let strategy = synthetic(&[2, 2]);
        let placed = strategy.placed(crate::rayon::Placement::Local(1));
        let me = std::thread::current().id();
        let seen = commonware_utils::sync::Mutex::new(Vec::new());
        let out = placed.map_collect_vec(0..64u64, |x| {
            std::thread::sleep(Duration::from_millis(1));
            seen.lock().push((
                std::thread::current().id() == me,
                strategy
                    .groups
                    .pool()
                    .current_worker()
                    .map(|worker| worker.group),
            ));
            x
        });
        assert_eq!(out, (0..64).collect::<Vec<_>>());
        let seen = seen.into_inner();
        assert!(seen.iter().all(|&(on_caller, _)| !on_caller));
        assert!(seen.iter().all(|&(_, group)| group == Some(1)), "{seen:?}");
    }

    /// Callers in several domains spawn jobs and place runs at once, and jobs from a worker's
    /// own nested work are awaited on the worker. Everything completes, every result is right,
    /// and the groups end idle with no submitter left registered.
    #[test]
    fn grouped_jobs_and_runs_complete() {
        // Callers in three domains each spawn jobs and run placed maps, checking every result.
        let strategy = synthetic(&[2, 2]);
        std::thread::scope(|scope| {
            for domain in 0..3u16 {
                let strategy = &strategy;
                scope.spawn(move || {
                    crate::topology::Groups::fake_domain(Some(domain));
                    for round in 0..20u64 {
                        let jobs: Vec<_> = (0..4)
                            .map(|j| {
                                strategy.spawn(64, move |strategy| {
                                    // Nested calls and jobs inherit the root's placement.
                                    // The worker waits for its child before returning.
                                    let doubled: Vec<u64> =
                                        strategy.map_collect_vec(0..16u64, |x| x * 2);
                                    let child =
                                        block_on_nested(strategy.spawn(1, move |_| j + round));
                                    doubled.iter().sum::<u64>() + child
                                })
                            })
                            .collect();
                        let summed = strategy.map_collect_vec(0..64u64, |x| x + round);
                        assert_eq!(summed.iter().sum::<u64>(), 2016 + 64 * round);
                        for (j, job) in jobs.into_iter().enumerate() {
                            let got = futures::executor::block_on(job);
                            assert_eq!(got, 240 + Widen::widen(j) + round);
                        }
                    }
                });
            }
        });

        // A job releases its group after it sends its result, so the groups settle shortly
        // after the last result arrives.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let report = strategy.groups.describe();
            let idle = report.lines().all(|line| line.contains("in_flight 0"));
            let unregistered = strategy
                .groups
                .groups()
                .iter()
                .all(|group| !group.has_leases());
            if idle && unregistered {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the groups must end idle with no submitter registered:\n{report}"
            );
            std::thread::yield_now();
        }
    }

    /// A job that runs inline runs on the caller and neither claims nor homes a group.
    #[test]
    fn spawn_inline_leaves_groups_untouched() {
        // A one-thread strategy runs every job inline.
        let strategy = synthetic(&[1]);
        crate::topology::Groups::fake_domain(Some(0));
        let value = strategy.spawn(1, |_| 7).now_or_never();
        crate::topology::Groups::fake_domain(None);
        assert_eq!(value, Some(7));
        let report = strategy.groups.describe();
        assert!(report.contains("home None"), "{report}");
        assert!(report.contains("in_flight 0"), "{report}");
    }

    /// A sort from a thread outside the pool, stable or unstable, runs on the group homed in the
    /// caller's domain and holds only that group's lease. The policy decides it against that group
    /// alone, so it never times the sort on the whole pool, and a serial sort runs on the caller.
    #[test]
    fn sort_leases_only_its_group() {
        /// Sorts at the caller's policy entry. Returns the call site, the maximum number of
        /// groups in use during a comparison, and the placements of the comparisons.
        #[track_caller]
        fn sort(
            strategy: &Rayon,
            unstable: bool,
        ) -> (
            &'static std::panic::Location<'static>,
            usize,
            Vec<Option<crate::rayon::Placement>>,
        ) {
            let mut items: Vec<u64> = (0..1024).rev().collect();
            let busy = AtomicUsize::new(0);
            let placements = commonware_utils::sync::Mutex::new(Vec::new());
            let compare = |a: &u64, b: &u64| {
                let report = strategy.groups.describe();
                let in_use = report
                    .lines()
                    .filter(|line| !line.contains("in_flight 0"))
                    .count();
                busy.fetch_max(in_use, Ordering::Relaxed);
                placements.lock().push(strategy.current_placement());
                a.cmp(b)
            };
            if unstable {
                strategy.sort_unstable_by(&mut items, compare);
            } else {
                strategy.sort_by(&mut items, compare);
            }
            assert_eq!(items, (0..1024).collect::<Vec<_>>());
            (
                std::panic::Location::caller(),
                busy.into_inner(),
                placements.into_inner(),
            )
        }

        for unstable in [false, true] {
            // Six sorts from domain 0 share one call site.
            let strategy = synthetic(&[2, 2]);
            let policy = strategy.policy.as_ref().unwrap();
            let local = Some(crate::rayon::Placement::Local(0));
            crate::topology::Groups::fake_domain(Some(0));
            let mut sorts = Vec::new();
            for _ in 0..6 {
                sorts.push(sort(&strategy, unstable));
            }
            crate::topology::Groups::fake_domain(None);

            // A site's first sort runs in parallel to seed its estimate.
            let (site, busy, placements) = &sorts[0];
            assert_eq!(
                *busy, 1,
                "a sort must hold only the lease of the group it sorts on"
            );
            assert!(placements.iter().all(|p| *p == local), "{placements:?}");
            for (_, busy, placements) in &sorts {
                assert!(*busy <= 1);
                assert!(
                    placements.iter().all(|p| *p == local || p.is_none()),
                    "{placements:?}"
                );
            }

            // The policy timed the sorts only on the group, and it kept its home in domain 0.
            let (wide, local) = policy
                .run_placement_estimates(site, 1024, 1024, strategy.parallelism)
                .unwrap();
            assert_eq!(
                wide, None,
                "a sort from outside the pool must not be timed on the whole pool"
            );
            assert!(local.is_some());
            let report = strategy.groups.describe();
            assert!(report.contains("group 0: width 2 home Some(0)"), "{report}");
        }
    }

    /// A join from a thread outside the pool is placed like the other operations. A site's first
    /// join seeds the whole pool, and its second seeds the group homed in the caller's domain,
    /// runs both closures on that group's workers, and counts against that group while it runs.
    #[test]
    fn join_seeds_wide_then_home_group() {
        /// Runs a join at a single policy entry. Returns each closure's placement and the
        /// groups' state during the first closure.
        fn join(
            strategy: &Rayon,
        ) -> (
            (Option<crate::rayon::Placement>, String),
            Option<crate::rayon::Placement>,
        ) {
            strategy.join(
                || (strategy.current_placement(), strategy.groups.describe()),
                || strategy.current_placement(),
            )
        }

        let strategy = synthetic(&[2, 2]);

        // A lease from domain 0 homes the first group and holds it, so a Local join from domain 1
        // homes the second.
        crate::topology::Groups::fake_domain(Some(0));
        let held = strategy.groups.local().unwrap();
        crate::topology::Groups::fake_domain(Some(1));
        let ((wide_first, _), wide_second) = join(&strategy);
        let ((first, report), second) = join(&strategy);
        crate::topology::Groups::fake_domain(None);
        drop(held);

        // The first join ran on the whole pool. The second ran on group 1 and held it until
        // it returned.
        let is_wide = |p: Option<crate::rayon::Placement>| {
            matches!(p, Some(crate::rayon::Placement::Wide { .. }))
        };
        assert!(
            is_wide(wide_first) && is_wide(wide_second),
            "a site's first join must seed the whole pool"
        );
        assert_eq!(first, Some(crate::rayon::Placement::Local(1)));
        assert_eq!(second, Some(crate::rayon::Placement::Local(1)));
        assert!(
            report.contains("group 1: width 2 home Some(1) in_flight 1"),
            "{report}"
        );
        let report = strategy.groups.describe();
        assert!(
            report.contains("group 1: width 2 home Some(1) in_flight 0"),
            "{report}"
        );
    }

    /// Job A waits on job B in the other group, and B waits for job C, queued on A's group. A's
    /// group-mate is held, so the chain completes only if A's worker runs C while it waits.
    #[test]
    fn waiting_worker_runs_queued_dependencies() {
        // Job B, on group 0, waits for a value.
        let strategy = synthetic(&[2, 2]).without_policy();
        let (value_tx, value_rx) = futures::channel::oneshot::channel();
        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let b = strategy.groups.pool().install_in(Placement::Local(0), || {
            strategy.spawn(1, move |_| block_on_nested(value_rx).unwrap())
        });

        // Hold A's group-mate, then start job A on group 1 waiting for B.
        let release = Arc::new(AtomicUsize::new(0));
        let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let busy_release = Arc::clone(&release);
        strategy
            .groups
            .pool()
            .spawn_in(Placement::Local(1), move || {
                let _ = occupied_tx.send(());
                let released = wait_for_release(&busy_release, 1);
                let _ = released_tx.send(released);
            });
        let occupied = occupied_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        let a = strategy.groups.pool().install_in(Placement::Local(1), || {
            strategy.spawn(1, move |_| {
                let _ = waiting_tx.send(());
                let _ = done_tx.send(block_on_nested(b));
            })
        });
        let waiting = waiting_rx.recv_timeout(Duration::from_secs(10)).is_ok();

        // Job C, queued on A's group, sends the value B waits for.
        strategy
            .groups
            .pool()
            .spawn_in(Placement::Local(1), move || {
                let _ = value_tx.send(42);
            });
        let result = done_rx.recv_timeout(Duration::from_secs(10)).ok();

        // Releasing the group-mate lets C finish even if A stopped helping its queue.
        release.store(1, Ordering::Release);
        let released = released_rx.recv_timeout(Duration::from_secs(10)).ok();
        futures::executor::block_on(a);
        assert!(occupied && waiting);
        assert_eq!(released, Some(true));
        assert_eq!(
            result,
            Some(42),
            "A's worker must run C while it waits for B"
        );
    }

    /// On a strategy with one group, a collection operation from a thread outside the pool runs
    /// every item on the pool's workers and none on the calling thread, since its Local and Wide
    /// placements name the same workers.
    #[test]
    fn single_group_calls_use_pool_workers() {
        let strategy = parallel_strategy();
        let me = std::thread::current().id();
        let on_caller = AtomicUsize::new(0);

        // A site's first call runs in parallel to seed its estimate.
        let out = strategy.map_collect_vec(0..64u64, |x| {
            std::thread::sleep(Duration::from_micros(200));
            if std::thread::current().id() == me {
                on_caller.fetch_add(1, Ordering::Relaxed);
            }
            x
        });
        assert_eq!(out, (0..64).collect::<Vec<_>>());
        assert_eq!(on_caller.into_inner(), 0);
    }

    /// An external root whose preferred group is busy with Wide work starts on a worker of the
    /// other group and runs Local there, as does its nested job. Dropping its result future
    /// leaves its claim on that group in place until the root finishes.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn root_keeps_claim_on_execution_group() {
        // Home group 0 in domain 0 and keep its lease, and home group 1 in domain 1.
        let strategy = synthetic(&[2, 2]).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let preferred = strategy.groups.local().unwrap();
        assert_eq!(preferred.group(), 0);
        crate::topology::Groups::fake_domain(Some(1));
        let other = strategy.groups.local().unwrap();
        assert_eq!(other.group(), 1);
        drop(other);
        crate::topology::Groups::fake_domain(Some(0));

        // Wide work occupies both preferred workers without spending root admissions.
        let wide = strategy.groups.wide();
        let release = Arc::new(AtomicUsize::new(0));
        let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
        let (busy_done_tx, busy_done_rx) = std::sync::mpsc::channel();
        let busy_pool = strategy.groups.pool().clone();
        let busy_release = Arc::clone(&release);
        strategy.groups.pool().spawn_broadcast_in(0, move || {
            let released = busy_pool.install_in(Placement::Wide { near: 0 }, || {
                let _ = occupied_tx.send(busy_pool.current_worker().unwrap());
                wait_for_release(&busy_release, 1)
            });
            let _ = busy_done_tx.send(released);
        });
        let occupied: Vec<_> = (0..2)
            .map(|_| occupied_rx.recv_timeout(Duration::from_secs(10)))
            .collect();

        // A root from domain 0 records its worker around a nested job, then blocks.
        let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
        let (root_done_tx, root_done_rx) = std::sync::mpsc::channel();
        let root_release = Arc::clone(&release);
        let root = strategy.spawn(1, move |strategy| {
            let before = strategy.groups.pool().current_worker().unwrap();
            let child = block_on_nested(strategy.spawn(1, |strategy| {
                strategy.groups.pool().current_worker().unwrap()
            }));
            let after = strategy.groups.pool().current_worker().unwrap();
            let _ = arrived_tx.send((before, child, after));
            let released = wait_for_release(&root_release, 2);
            let _ = root_done_tx.send(released);
        });

        // Arrival must precede either preferred worker becoming free.
        let arrived = arrived_rx.recv_timeout(Duration::from_secs(10)).ok();
        drop(root);
        release.fetch_or(1, Ordering::Release);
        let busy_done: Vec<_> = (0..2)
            .map(|_| busy_done_rx.recv_timeout(Duration::from_secs(10)).ok())
            .collect();
        drop(wide);

        // The held root cannot service this sentinel. Its group-mate must finish any child
        // wrapper before taking it, leaving only the root's claim on the actual group.
        let (drained_tx, drained_rx) = std::sync::mpsc::channel();
        strategy
            .groups
            .pool()
            .spawn_in(Placement::Local(1), move || {
                let _ = drained_tx.send(());
            });
        let child_drained = drained_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        let root_holds_actual = strategy.groups.groups()[1].has_leases();
        let report = strategy.groups.describe();

        // Release all work, including a root that was still queued at the arrival deadline.
        release.fetch_or(2, Ordering::Release);
        let root_done = root_done_rx.recv_timeout(Duration::from_secs(10)).ok();
        drop(preferred);
        crate::topology::Groups::fake_domain(None);
        let deadline = Instant::now() + Duration::from_secs(10);
        while strategy
            .groups
            .groups()
            .iter()
            .any(|group| group.has_leases())
            && Instant::now() < deadline
        {
            std::thread::yield_now();
        }

        assert!(
            occupied.iter().all(|worker| matches!(
                worker,
                Ok(worker)
                    if worker.group == 0
                        && matches!(worker.placement, Placement::Wide { .. })
            )),
            "both preferred workers must have entered Wide work"
        );
        assert_eq!(busy_done, vec![Some(true), Some(true)]);
        assert!(child_drained, "the nested job's wrapper must have finished");
        assert_eq!(root_done, Some(true));
        let (before, child, after) =
            arrived.expect("the root must start while both preferred workers are occupied");
        assert_eq!(before, after);
        for worker in [before, child] {
            assert_eq!(worker.group, 1);
            assert_eq!(worker.placement, Placement::Local(1));
            assert_eq!(worker.width, 2);
        }
        assert!(
            root_holds_actual,
            "dropping the result future must retain the executing group's lease: {report}"
        );
        assert!(
            strategy
                .groups
                .groups()
                .iter()
                .all(|group| !group.has_leases()),
            "completed jobs must release their claims"
        );
    }

    /// An admitted external root runs under the descendant placement its call site has learned.
    /// Under Local, its join stays on its group at the group's width. Under Wide, with its
    /// group-mate held, the join's second closure runs on the other group at the pool's width.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn root_uses_learned_descendant_width() {
        #[track_caller]
        fn check(wide: bool) {
            // Train the call site to prefer Wide descendants when `wide`, and Local otherwise.
            let strategy = synthetic(&[2, 2]);
            let caller = std::panic::Location::caller();
            for placement in [
                crate::policy::Placement::Wide,
                crate::policy::Placement::Local,
            ] {
                let preferred = (placement == crate::policy::Placement::Wide) == wide;
                strategy.policy.as_ref().unwrap().record_spawn_job(
                    caller,
                    64,
                    4,
                    crate::policy::SpawnPlan {
                        execution: crate::policy::SpawnExecution::Offload,
                        spawner: crate::policy::Spawner::Outside,
                        placement: Some(placement),
                        measure: true,
                    },
                    Duration::from_millis(if preferred { 2 } else { 8 }),
                );
            }

            // A root reports its group, then joins once the test signals it.
            let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
            let (join_tx, join_rx) = std::sync::mpsc::channel();
            let job = strategy.spawn(64, move |strategy| {
                let before = strategy.groups.pool().current_worker().unwrap();
                let _ = arrived_tx.send(before.group);
                join_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let pool = strategy.groups.pool();
                let children = strategy.join(
                    move || {
                        if wide {
                            started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                        }
                        pool.current_worker().unwrap()
                    },
                    move || {
                        if wide {
                            let _ = started_tx.send(());
                        }
                        pool.current_worker().unwrap()
                    },
                );
                (
                    before,
                    children,
                    strategy.groups.pool().current_worker().unwrap(),
                )
            });
            let group = arrived_rx.recv_timeout(Duration::from_secs(10)).unwrap();

            // Hold the root's group-mate. Only Wide descendants can use the other group.
            let release = Arc::new(AtomicUsize::new(0));
            let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
            let (released_tx, released_rx) = std::sync::mpsc::channel();
            let busy_release = Arc::clone(&release);
            strategy
                .groups
                .pool()
                .spawn_in(Placement::Local(group), move || {
                    let _ = occupied_tx.send(());
                    let released = wait_for_release(&busy_release, 1);
                    let _ = released_tx.send(released);
                });
            let occupied = occupied_rx.recv_timeout(Duration::from_secs(10)).is_ok();
            let _ = join_tx.send(());
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                futures::executor::block_on(job)
            }));
            release.store(1, Ordering::Release);
            let released = released_rx.recv_timeout(Duration::from_secs(10)).ok();
            assert!(occupied);
            assert_eq!(released, Some(true));
            let (before, (left, right), after) = outcome.unwrap();
            assert_eq!(before, after);
            assert_eq!(left.group, group);
            if wide {
                assert!(matches!(before.placement, Placement::Wide { .. }));
                assert!(matches!(right.placement, Placement::Wide { .. }));
                assert_ne!(right.group, group);
                assert_eq!((before.width, right.width), (4, 4));
            } else {
                assert_eq!(before.placement, Placement::Local(group));
                assert_eq!(right.placement, Placement::Local(group));
                assert_eq!(right.group, group);
                assert_eq!((before.width, right.width), (2, 2));
            }
        }

        for wide in [false, true] {
            check(wide);
        }
    }

    /// A root planned Local that starts on the narrower final group runs Wide, as does its nested
    /// job, and records no Local sample, so the call site's Local seed stays due.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn narrow_root_runs_wide_unrecorded() {
        #[track_caller]
        fn check() {
            // Home group 0, hold every group, and give the call site only a Wide job sample.
            let strategy = synthetic(&[2, 1]);
            crate::topology::Groups::fake_domain(Some(0));
            let home = strategy.groups.local().unwrap();
            let wide = strategy.groups.wide();
            let caller = std::panic::Location::caller();
            let policy = strategy.policy.as_ref().unwrap();
            policy.record_spawn_job(
                caller,
                64,
                3,
                crate::policy::SpawnPlan {
                    execution: crate::policy::SpawnExecution::Offload,
                    spawner: crate::policy::Spawner::Outside,
                    placement: Some(crate::policy::Placement::Wide),
                    measure: true,
                },
                Duration::from_millis(8),
            );

            // Occupy the preferred group without consuming external-root admissions.
            let release = Arc::new(AtomicUsize::new(0));
            let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
            let (released_tx, released_rx) = std::sync::mpsc::channel();
            let busy_release = Arc::clone(&release);
            let pool = strategy.groups.pool().clone();
            strategy.groups.pool().spawn_broadcast_in(0, move || {
                let released = pool.install_in(Placement::Wide { near: 0 }, || {
                    let _ = occupied_tx.send(());
                    wait_for_release(&busy_release, 1)
                });
                let _ = released_tx.send(released);
            });
            let occupied: Vec<_> = (0..2)
                .map(|_| occupied_rx.recv_timeout(Duration::from_secs(10)).is_ok())
                .collect();

            // A root, able to start only on the narrow group, records its worker and its child's.
            let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
            let job = strategy.spawn(64, move |strategy| {
                let root = strategy.groups.pool().current_worker().unwrap();
                let child = block_on_nested(strategy.without_policy().spawn(1, |strategy| {
                    strategy.groups.pool().current_worker().unwrap()
                }));
                let _ = arrived_tx.send(());
                (root, child)
            });
            let arrived = arrived_rx.recv_timeout(Duration::from_secs(10)).is_ok();
            release.store(1, Ordering::Release);
            let released: Vec<_> = (0..2)
                .map(|_| released_rx.recv_timeout(Duration::from_secs(10)).ok())
                .collect();
            let (root, child) = futures::executor::block_on(job);

            // The only remainder worker must finish the root's recording before this callback.
            let (drained_tx, drained_rx) = std::sync::mpsc::channel();
            strategy.groups.pool().spawn_broadcast_in(1, move || {
                let _ = drained_tx.send(());
            });
            let drained = drained_rx.recv_timeout(Duration::from_secs(10)).is_ok();
            drop((home, wide));
            crate::topology::Groups::fake_domain(None);

            assert!(occupied.into_iter().all(|occupied| occupied) && arrived && drained);
            assert_eq!(released, vec![Some(true), Some(true)]);
            assert_eq!(root.group, 1);
            for worker in [root, child] {
                assert!(matches!(worker.placement, Placement::Wide { .. }));
                assert_eq!(worker.width, 3);
            }

            // An unmeasured Local seed stays due. A recorded seed would instead start probing
            // or sampling the two placements, even if its timing made Local the slower one.
            for _ in 0..2 {
                let plan = policy.choose_spawn_placement(
                    caller,
                    64,
                    3,
                    crate::policy::SpawnPlan::fixed(crate::policy::SpawnExecution::Offload),
                );
                assert_eq!(plan.placement, Some(crate::policy::Placement::Local));
                assert!(plan.measure);
            }
        }

        check();
    }

    /// A job a worker spawns runs under the placement of the job the worker runs: on the worker's
    /// group under a Local placement, and anywhere in the pool under a Wide one.
    #[test]
    fn spawn_inherits_worker_placement() {
        // Without a policy, every job is handed off to the pool rather than run inline.
        let strategy = synthetic(&[2, 2]).without_policy();
        let spawn_under = |placement| {
            strategy.groups.pool().install_in(placement, || {
                futures::executor::block_on(
                    strategy.spawn(1, |strategy| strategy.current_placement()),
                )
            })
        };

        // A job spawned under a Local placement stays on the worker's group.
        let local = Placement::Local(1);
        assert_eq!(spawn_under(local), Some(local));

        // A job spawned under a Wide placement stays on the whole pool.
        assert!(matches!(
            spawn_under(Placement::Wide { near: 0 }),
            Some(Placement::Wide { .. })
        ));
    }

    /// Dropping a result future leaves its queued and running job's claims intact.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn spawn_dropped_future_keeps_claims() {
        // Hold every worker at a barrier so the submitted root must remain queued.
        let strategy = synthetic(&[2, 2]).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let barrier = Arc::new(std::sync::Barrier::new(5));
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        for group in 0..2 {
            let (barrier, held_tx) = (Arc::clone(&barrier), held_tx.clone());
            strategy.groups.pool().spawn_broadcast_in(group, move || {
                held_tx.send(()).unwrap();
                barrier.wait();
            });
        }
        for _ in 0..4 {
            held_rx.recv().unwrap();
        }

        // Drop the result future before any worker can begin the root. Once started,
        // the root waits for a second release so its running claims can be sampled.
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel::<()>();
        let runs = Arc::new(AtomicUsize::new(0));
        let ran = Arc::clone(&runs);
        let future = strategy.spawn(1, move |_| {
            ran.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
        });
        drop(future);

        // Snapshot the claims while the root is still queued and owns no worker.
        let busy = || {
            strategy
                .groups
                .groups()
                .iter()
                .map(crate::topology::Group::has_leases)
                .collect::<Vec<_>>()
        };
        let queued = busy();
        let queued_runs = runs.load(Ordering::SeqCst);

        // Let the root start, then sample its claims while its body remains blocked.
        barrier.wait();
        started_rx.recv().unwrap();
        let running = busy();

        // Every worker must reach the broadcast, including the one finishing the root.
        // This waits for the root's wrapper to release its claims before the final check.
        finish_tx.send(()).unwrap();
        strategy.groups.pool().broadcast(|_| ());
        crate::topology::Groups::fake_domain(None);

        // Assert after releasing all workers so a failed snapshot cannot strand them.
        assert_eq!(queued_runs, 0);
        assert_eq!(
            queued,
            vec![true, true],
            "the queued root must retain its claims"
        );
        assert_eq!(
            running,
            vec![true, true],
            "the running root must retain its claims"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(busy(), vec![false, false]);
    }

    /// Detaches a job from a worker running under a Local placement or, when `wide`, a Wide one.
    /// After the parent's install returns, the job's claims alone must keep its group busy, or
    /// every group under Wide, until it finishes.
    fn check_detached_claims(wide: bool) {
        // A worker under `placement` detaches a child job, and the test then drops its own leases.
        let strategy = synthetic(&[2, 2]).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let home = strategy.groups.local().unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let child = || {
            drop(strategy.spawn(1, move |strategy| {
                let _ = started_tx.send(strategy.current_placement());
                let _ = release_rx.recv_timeout(Duration::from_secs(60));
                let _ = done_tx.send(());
            }));
        };
        let placement = if wide {
            Placement::Wide { near: 0 }
        } else {
            Placement::Local(0)
        };
        let wide_lease = wide.then(|| strategy.groups.wide());
        strategy.groups.pool().install_in(placement, child);
        drop((home, wide_lease));
        let placement = started_rx.recv_timeout(Duration::from_secs(10)).ok();

        // The parent's install has returned. Only the detached child can keep its group busy.
        let busy: Vec<_> = strategy
            .groups
            .groups()
            .iter()
            .map(crate::topology::Group::has_leases)
            .collect();
        let report = strategy.groups.describe();
        drop(release_tx);
        let done = done_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        crate::topology::Groups::fake_domain(None);

        let deadline = Instant::now() + Duration::from_secs(10);
        while strategy
            .groups
            .groups()
            .iter()
            .any(|group| group.has_leases())
            && Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        assert!(matches!(
            (wide, placement),
            (true, Some(Some(Placement::Wide { .. }))) | (false, Some(Some(Placement::Local(0))))
        ));
        assert!(done);
        assert_eq!(
            busy,
            vec![true, wide],
            "the detached job must retain each placement claim: {report}"
        );
        assert!(
            strategy
                .groups
                .groups()
                .iter()
                .all(|group| !group.has_leases())
        );
    }

    /// A job detached from a worker under a Local placement keeps its claim on that group until it
    /// finishes.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn spawn_detached_local_keeps_group_busy() {
        check_detached_claims(false);
    }

    /// A job detached from a worker under a Wide placement keeps its claims on every group until it
    /// finishes.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn spawn_detached_wide_keeps_groups_busy() {
        check_detached_claims(true);
    }

    /// A Wide collection wakes every group and runs its parallel callbacks on pool workers.
    #[test]
    fn wide_calls_wake_all_groups() {
        let strategy = synthetic(&[2, 2]);
        let placed = strategy.placed(crate::rayon::Placement::Wide { near: 0 });
        let pool = strategy.groups.pool();

        // Wait for every worker to sleep, so each wakeup below is the call's.
        wait_until_asleep(pool);
        let before = pool.wakeups();
        let me = std::thread::current().id();
        let on_caller = AtomicUsize::new(0);

        // Run a Wide map and note whether any item ran on the caller.
        let out = placed.map_collect_vec(0..64u64, |x| {
            std::thread::sleep(Duration::from_millis(1));
            if std::thread::current().id() == me {
                on_caller.fetch_add(1, Ordering::Relaxed);
            }
            x
        });
        assert_eq!(out, (0..64).collect::<Vec<_>>());

        // Both groups woke, and no item ran on the caller.
        let after = pool.wakeups();
        for group in 0..2 {
            let workers = group * 2..group * 2 + 2;
            let woke = after[workers.clone()].iter().sum::<usize>()
                > before[workers].iter().sum::<usize>();
            assert!(woke, "group {group} must wake for the call");
        }
        assert_eq!(on_caller.load(Ordering::Relaxed), 0);
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
        let parallelism = strategy.parallelism;
        strategy
            .policy
            .as_ref()
            .is_some_and(|policy| policy.spawn_recorded(loc, 64, parallelism))
    }

    /// Only a successful run records its wall time. An error aborts early, so it creates the
    /// entry without estimates and never overwrites an established one.
    #[test]
    fn try_run_records_success_not_errors() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();

        /// Every call below goes through `run`, a single call site, so they share one policy
        /// entry.
        #[track_caller]
        fn attempt(
            strategy: &Rayon,
            fail: bool,
        ) -> (&'static std::panic::Location<'static>, Result<(), ()>) {
            let outcome = move || if fail { Err(()) } else { Ok(()) };
            (
                std::panic::Location::caller(),
                strategy.try_run(10, outcome, outcome),
            )
        }
        let run = |fail| attempt(&strategy, fail);

        let (loc, result) = run(true);
        assert_eq!(result, Err(()));
        assert_eq!(policy.run_estimates(loc, 10, 10, 4), Some((None, None)));

        let (loc, result) = run(false);
        assert_eq!(result, Ok(()));
        let established = policy.run_estimates(loc, 10, 10, 4).unwrap();
        assert!(established.1.is_some());

        for _ in 0..20 {
            let (loc, _) = run(true);
            assert_eq!(policy.run_estimates(loc, 10, 10, 4), Some(established));
        }
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

        // The worker sends the result before it records the job, so wait for the job to finish.
        wait_until_asleep(strategy.groups.pool());
        assert!(!spawn_recorded(&strategy, loc));

        let (loc, job) = spawn_flagged(&strategy, false);
        assert_eq!(futures::executor::block_on(job), 7);
        assert!(spawn_recorded(&strategy, loc));
    }

    /// A job that a pool worker keeps in its own pool records its round trip as the overhead kept
    /// for workers, not as a hand-off. The awaiting side records the round trip before the future
    /// resolves, and the worker's job sample may land later, so the assertion holds on the round
    /// trip alone.
    #[test]
    fn spawn_worker_records_separate_overhead() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();
        let parallelism = strategy.parallelism;
        let (loc, value) = strategy
            .groups
            .pool()
            .install_in(Placement::Wide { near: 0 }, || {
                let (loc, job) = spawn_flagged(&strategy, false);
                (loc, futures::executor::block_on(job))
            });
        assert_eq!(value, 7);
        let (hand_off, own) = policy
            .spawn_overhead_estimates(loc, 64, parallelism)
            .unwrap();
        assert!(
            own.is_some(),
            "a worker must record its own-pool round trip"
        );
        assert_eq!(
            hand_off, None,
            "a job kept in a worker's own pool must record no hand-off overhead"
        );
    }

    /// A pool worker records the wall time of the job it ran after sending the result, so the
    /// sample may land after the awaiting side has observed the result.
    #[test]
    fn spawn_worker_records_job_wall() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();
        let parallelism = strategy.parallelism;
        let (loc, job) = spawn_flagged(&strategy, false);
        assert_eq!(futures::executor::block_on(job), 7);
        let deadline = Instant::now() + Duration::from_secs(10);
        while policy.spawn_job_estimate(loc, 64, parallelism).is_none() {
            assert!(
                Instant::now() < deadline,
                "the worker must record the job wall after sending the result"
            );
            std::thread::yield_now();
        }
    }

    /// A root that finds its group's admissions full runs Wide without consulting or training the
    /// call site's descendant placement.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn spawn_overflow_leaves_placement_untouched() {
        // Two roots from domain 0 fill the admissions of the group homed there.
        let strategy = synthetic(&[2, 2]);
        crate::topology::Groups::fake_domain(Some(0));
        let roots: Vec<_> = (0..2).map(|_| strategy.groups.root()).collect();
        assert!(roots.iter().all(|(_, admitted)| *admitted));

        // A third root records its job without consulting or training descendant placement.
        let (loc, job) = spawn_flagged(&strategy, false);
        assert_eq!(futures::executor::block_on(job), 7);
        let policy = strategy.policy.as_ref().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while policy.spawn_job_estimate(loc, 64, 4).is_none() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(!policy.spawn_placement_used(loc, 64, 4));
        drop(roots);
        crate::topology::Groups::fake_domain(None);
    }

    /// Spawn honors an inline decision after cheap job and hand-off samples are recorded.
    /// Caller tracking keys the recorded samples and spawn to the same policy entry.
    #[test]
    #[track_caller]
    fn spawn_inlines_a_sub_overhead_job() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();
        let caller = std::panic::Location::caller();
        let threads = strategy.groups.pool().current_num_threads();

        for _ in 0..2 {
            let plan = policy.choose_spawn(caller, 64, threads, crate::policy::Spawner::Outside);
            assert_eq!(
                plan,
                crate::policy::SpawnPlan {
                    execution: crate::policy::SpawnExecution::Offload,
                    spawner: crate::policy::Spawner::Outside,
                    placement: None,
                    measure: true,
                }
            );
            policy.record_spawn_job(
                caller,
                64,
                threads,
                plan,
                std::time::Duration::from_micros(2),
            );
            policy.record_spawn_round_trip(
                caller,
                64,
                threads,
                plan,
                std::time::Duration::from_micros(52),
                std::time::Duration::from_micros(2),
            );
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
                crate::rayon::current_thread_index().is_some()
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

    /// A strategy over four workers whose measured runs read the returned virtual clock.
    fn virtual_strategy() -> (Rayon, rayon::TestClock) {
        let clock = rayon::TestClock::default();
        let mut strategy = parallel_strategy();
        strategy.clock = rayon::Clock::Virtual(clock.clone());
        (strategy, clock)
    }

    /// The busy-time estimate `strategy` recorded at `caller` for `len` items. Panics unless a
    /// parallel run at `caller` has been measured.
    fn recorded(strategy: &Rayon, caller: &'static Location<'static>, len: usize) -> Duration {
        let policy = strategy.policy.as_ref().unwrap();
        let (wide, local) = policy
            .run_busy_estimates(caller, len, len, strategy.parallelism)
            .unwrap();
        Duration::from_nanos(wide.or(local).unwrap())
    }

    /// Maps `len` items that each spin for `each` on `clock`, and returns the run's call site.
    #[track_caller]
    fn spin_map(
        strategy: &Rayon,
        clock: &rayon::TestClock,
        len: usize,
        each: Duration,
    ) -> &'static Location<'static> {
        strategy.map_collect_vec(0..len, |_| clock.spin(each));
        Location::caller()
    }

    /// A run of 32 items that each spin for 1ms records 32ms of busy time, since each spin charges
    /// the run on whichever thread executes the item.
    #[test]
    fn measured_run_records_busy_time_of_all_items() {
        let (strategy, clock) = virtual_strategy();
        let caller = spin_map(&strategy, &clock, 32, Duration::from_millis(1));
        assert_eq!(recorded(&strategy, caller, 32), Duration::from_millis(32));
    }

    /// A join is charged its 5ms side and the 40ms that pass on the thief of its other side. The
    /// joining worker sleeps before the 40ms pass, so its wait is not charged.
    #[test]
    fn measured_join_excludes_idle_waits() {
        #[track_caller]
        fn spin_join(strategy: &Rayon, clock: &rayon::TestClock) -> &'static Location<'static> {
            let stolen = AtomicBool::new(false);
            strategy.join(
                // The first side returns once the second is stolen, so the joiner has to wait.
                || {
                    clock.spin(Duration::from_millis(5));
                    let start = Instant::now();
                    while !stolen.load(Ordering::Acquire) {
                        assert!(
                            start.elapsed() < Duration::from_secs(10),
                            "the second side must be stolen within 10s"
                        );
                        std::hint::spin_loop();
                    }
                },
                || {
                    stolen.store(true, Ordering::Release);
                    wait_until_sleeping(strategy.groups.pool(), 3);
                    clock.elapse(Duration::from_millis(40));
                },
            );
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = spin_join(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(45));
    }

    /// A run that queues behind busy workers is charged its four 1ms items but not the 200ms that
    /// the four occupied workers let pass while it waits in the queue.
    #[test]
    fn measured_run_excludes_queueing() {
        let (strategy, clock) = virtual_strategy();

        // Occupy every worker until the measured run queues behind them, and have each let 50ms
        // pass. No worker is released before all four have done so, so the run's items start only
        // after the 200ms.
        let started = Arc::new(std::sync::Barrier::new(5));
        let released = Arc::new(std::sync::Barrier::new(4));
        let missed = Arc::new(AtomicBool::new(false));
        let queued = Arc::new(AtomicBool::new(false));
        {
            let pool = Arc::clone(strategy.groups.pool());
            let started = Arc::clone(&started);
            let released = Arc::clone(&released);
            let missed = Arc::clone(&missed);
            let queued = Arc::clone(&queued);
            let clock = clock.clone();
            strategy.groups.pool().spawn_broadcast(move |_| {
                started.wait();

                // One worker seeing the queued run releases them all, so a worker descheduled past
                // the dequeue still stops. A miss after 10s fails the test.
                let deadline = Instant::now() + Duration::from_secs(10);
                while !queued.load(Ordering::Relaxed) {
                    if pool.has_injected_job() {
                        queued.store(true, Ordering::Relaxed);
                        break;
                    }
                    if Instant::now() >= deadline {
                        missed.store(true, Ordering::Relaxed);
                        break;
                    }
                    core::hint::spin_loop();
                }
                if !missed.load(Ordering::Relaxed) {
                    clock.elapse(Duration::from_millis(50));
                }
                released.wait();
            });
        }
        started.wait();

        // The run waits through the queue but executes only its own four 1ms items.
        let caller = spin_map(&strategy, &clock, 4, Duration::from_millis(1));

        // Wait for every blocker to finish before checking that the run queued.
        strategy.groups.pool().broadcast(|_| ());
        assert!(
            !missed.load(Ordering::Relaxed),
            "the measured run must queue behind the occupied workers within 10s"
        );
        assert_eq!(recorded(&strategy, caller, 4), Duration::from_millis(4));
    }

    /// A spawn awaited by a run outside the pool is charged once, for the 20ms that pass while the
    /// run parks on it.
    #[test]
    fn spawns_awaited_outside_the_pool_are_charged_once() {
        #[track_caller]
        fn spawn_and_block(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let clock = clock.clone();
                block_on_nested(strategy.spawn(1, move |_| clock.elapse(Duration::from_millis(20))))
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = spawn_and_block(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(20));
    }

    /// A spawn awaited by a run on a worker is charged once, on receipt, for the 20ms that pass on
    /// the job's worker while the awaiting worker sleeps.
    #[test]
    fn spawns_awaited_on_a_worker_are_charged_once() {
        #[track_caller]
        fn await_on_a_worker(
            strategy: &Rayon,
            future: impl core::future::Future<Output = ()> + Send,
            start: std::sync::mpsc::Sender<()>,
        ) -> &'static Location<'static> {
            let future = Mutex::new(Some(future));
            let body = || {
                start.send(()).unwrap();
                block_on_nested(future.lock().take().unwrap());
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        // Spawn a job from outside the pool. It holds a worker until the run starts and the
        // awaiting worker sleeps, and then lets 20ms pass.
        let (strategy, clock) = virtual_strategy();
        let (held, on_worker) = std::sync::mpsc::channel();
        let (start, started) = std::sync::mpsc::channel();
        let future = strategy.spawn(1, move |strategy| {
            held.send(()).unwrap();
            started.recv().unwrap();
            wait_until_sleeping(strategy.groups.pool(), 3);
            clock.elapse(Duration::from_millis(20));
        });
        on_worker.recv().unwrap();

        // Await the job inside a measured run on another worker.
        let caller = strategy
            .groups
            .pool()
            .install(|| await_on_a_worker(&strategy, future, start));
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(20));
    }

    /// A spawn issued by a worker inside a run and awaited by the run's caller outside the pool is
    /// charged once, for the 20ms that pass while the caller parks on it, and never on receipt.
    #[test]
    fn worker_spawns_awaited_outside_the_pool_are_charged_at_most_once() {
        #[track_caller]
        fn spawn_on_a_worker_and_block(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let (start, started) = std::sync::mpsc::channel();
                let clock = clock.clone();
                let future = strategy.groups.pool().install(|| {
                    strategy.spawn(1, move |_| {
                        started.recv().unwrap();
                        clock.elapse(Duration::from_millis(20));
                    })
                });
                start.send(()).unwrap();
                block_on_nested(future)
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = spawn_on_a_worker_and_block(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(20));
    }

    /// Spawns issued inside a nested measured run and awaited by the enclosing run on a worker are
    /// charged on receipt to the enclosing run, so the two 20ms jobs charge it 40ms.
    #[test]
    fn enclosing_runs_are_charged_for_spawns_of_nested_runs() {
        #[track_caller]
        fn spawn_in_a_nested_run_and_block(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let futures = strategy.map_collect_vec(0..2, |_| {
                    let clock = clock.clone();
                    strategy.spawn(1, move |_| clock.spin(Duration::from_millis(20)))
                });
                for future in futures {
                    block_on_nested(future);
                }
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = strategy
            .groups
            .pool()
            .install(|| spawn_in_a_nested_run_and_block(&strategy, &clock));
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(40));
    }

    /// A measured run outside the pool can await a spawn under the standard futures executor, and
    /// the job can depend on input the caller supplies after polling, since a pending spawn
    /// returns control to the caller.
    #[test]
    fn runs_outside_the_pool_poll_spawns_without_blocking() {
        let strategy = parallel_strategy();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let job = strategy.spawn(1, move |_| {
            release_receiver
                .recv_timeout(Duration::from_secs(5))
                .is_ok()
        });
        let mut job = std::pin::pin!(job);

        // Poll the spawn once, then release its input, all inside a measured run driven by the
        // futures executor.
        let polled_pending = AtomicBool::new(false);
        let released = strategy.run(
            1,
            || unreachable!("the first run at a site is a measured parallel run"),
            || {
                futures::executor::block_on(std::future::poll_fn(|cx| {
                    let polled = job.as_mut().poll(cx);
                    polled_pending.fetch_or(polled.is_pending(), Ordering::Relaxed);
                    let _ = release_sender.send(());
                    polled
                }))
            },
        );

        // The first poll found the job waiting for its input, and the caller then supplied it.
        assert!(
            polled_pending.load(Ordering::Relaxed),
            "a pending spawn must return control to its caller"
        );
        assert!(
            released,
            "the job must receive the input supplied after the first poll"
        );
    }

    /// A run outside the pool that fans out four spawns and parks on each is charged for the 80ms
    /// its four jobs let pass while it parks, and never for the jobs again.
    #[test]
    fn fan_out_outside_the_pool_is_charged_for_its_parks() {
        #[track_caller]
        fn spawn_four_and_block(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let futures: Vec<_> = (0..4)
                    .map(|_| {
                        let clock = clock.clone();
                        strategy.spawn(1, move |_| clock.elapse(Duration::from_millis(20)))
                    })
                    .collect();
                for future in futures {
                    block_on_nested(future);
                }
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = spawn_four_and_block(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(80));
    }

    /// A spawned job that panics is still measured, so the run on a worker that awaits it is
    /// charged the job's 20ms spin before the panic reaches it.
    #[test]
    fn panicking_spawns_are_charged_before_they_propagate() {
        #[track_caller]
        fn spawn_and_catch(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let clock = clock.clone();
                let future = strategy.spawn(1, move |_| {
                    clock.spin(Duration::from_millis(20));
                    panic!("spawned job");
                });
                let result = panic::catch_unwind(AssertUnwindSafe(|| block_on_nested(future)));
                assert!(
                    result.is_err(),
                    "the job's panic must reach the awaiting run"
                );
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = strategy
            .groups
            .pool()
            .install(|| spawn_and_catch(&strategy, &clock));
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(20));
    }

    /// A `Strategy::run` body that spins for 2ms and then maps 16 items that each spin for 1ms is
    /// charged its own 2ms plus the nested run's 16ms once.
    #[test]
    fn measured_run_includes_nested_runs() {
        #[track_caller]
        fn run_body(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> (&'static Location<'static>, &'static Location<'static>) {
            let body = || {
                clock.spin(Duration::from_millis(2));
                spin_map(strategy, clock, 16, Duration::from_millis(1))
            };
            (Location::caller(), strategy.run(2, body, body))
        }

        let (strategy, clock) = virtual_strategy();
        let (outer, inner) = run_body(&strategy, &clock);
        assert_eq!(recorded(&strategy, inner, 16), Duration::from_millis(16));
        assert_eq!(recorded(&strategy, outer, 2), Duration::from_millis(18));
    }

    /// A run outside the pool that waits through `block_on` is charged a spawned job's spin on
    /// receipt and nothing for the parks, during which the thread's own time advances.
    #[test]
    fn block_on_outside_the_pool_charges_the_job_not_the_wait() {
        #[track_caller]
        fn wait_for_a_spawn(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let job_clock = clock.clone();
                let future = async {
                    assert!(rayon::is_waiting(), "the wait must be marked");
                    strategy
                        .spawn(1, move |_| job_clock.spin(Duration::from_millis(20)))
                        .await
                };
                strategy.block_on_with(future, || {
                    clock.spin(Duration::from_millis(50));
                    std::thread::park();
                });
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = wait_for_a_spawn(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(20));
    }

    /// A run outside the pool that waits through `block_on` is charged the work the future does
    /// itself between parks.
    #[test]
    fn block_on_outside_the_pool_charges_the_future_s_own_work() {
        #[track_caller]
        fn work_then_wait(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let job_clock = clock.clone();
                strategy.block_on(async {
                    clock.spin(Duration::from_millis(7));
                    strategy
                        .spawn(1, move |_| job_clock.spin(Duration::from_millis(20)))
                        .await
                });
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = work_then_wait(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(27));
    }

    /// A run outside the pool that waits for four spawns through `block_on` is charged the sum of
    /// their spins, and a nested run issued meanwhile is charged too.
    #[test]
    fn block_on_outside_the_pool_sums_jobs_and_nested_runs() {
        #[track_caller]
        fn wait_for_spawns(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                strategy.block_on(async {
                    strategy.map_collect_vec(0..16, |_| clock.spin(Duration::from_millis(1)));
                    for _ in 0..4 {
                        let clock = clock.clone();
                        strategy
                            .spawn(1, move |_| clock.spin(Duration::from_millis(20)))
                            .await;
                    }
                });
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = wait_for_spawns(&strategy, &clock);
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(96));
    }

    /// A single-worker strategy runs every spawn inline. Inline jobs on a thread waiting in
    /// `block_on`, including one that panics, are charged as the run's own work.
    #[test]
    fn inline_spawns_while_waiting_are_charged() {
        let clock = rayon::TestClock::default();
        let mut strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(1))).unwrap();
        strategy.clock = rayon::Clock::Virtual(clock.clone());
        let (_, busy) = rayon::measure_with(rayon::Clock::Virtual(clock.clone()), || {
            let spin = clock.clone();
            strategy.block_on(async {
                strategy
                    .spawn(1, move |_| spin.spin(Duration::from_millis(20)))
                    .await
            });
            let spin = clock.clone();
            let panicked = panic::catch_unwind(AssertUnwindSafe(|| {
                strategy.block_on(async {
                    strategy
                        .spawn(1, move |_| {
                            spin.spin(Duration::from_millis(5));
                            panic!("spawned job");
                        })
                        .await
                })
            }));
            assert!(panicked.is_err());
            clock.spin(Duration::from_millis(3));
        });
        assert_eq!(busy, Duration::from_millis(28));
    }

    /// A run on a worker that waits through `block_on` services the pool while it waits and is
    /// charged the job on receipt.
    #[test]
    fn block_on_on_a_worker_is_charged_the_job() {
        #[track_caller]
        fn wait_for_a_spawn(
            strategy: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let clock = clock.clone();
                strategy
                    .block_on(strategy.spawn(1, move |_| clock.spin(Duration::from_millis(20))));
            };
            strategy.run(1, body, body);
            Location::caller()
        }

        let (strategy, clock) = virtual_strategy();
        let caller = strategy
            .groups
            .pool()
            .install(|| wait_for_a_spawn(&strategy, &clock));
        assert_eq!(recorded(&strategy, caller, 1), Duration::from_millis(20));
    }

    /// A run on a worker of one strategy that waits through that strategy's `block_on` for another
    /// strategy's spawn is charged the job on receipt.
    #[test]
    fn block_on_on_a_worker_is_charged_another_strategy_s_job() {
        #[track_caller]
        fn wait_for_other(
            first: &Rayon,
            other: &Rayon,
            clock: &rayon::TestClock,
        ) -> &'static Location<'static> {
            let body = || {
                let clock = clock.clone();
                first.block_on(other.spawn(1, move |_| clock.spin(Duration::from_millis(20))));
            };
            first.run(1, body, body);
            Location::caller()
        }

        let (first, clock) = virtual_strategy();
        let mut other = parallel_strategy();
        other.clock = rayon::Clock::Virtual(clock.clone());
        let caller = first
            .groups
            .pool()
            .install(|| wait_for_other(&first, &other, &clock));
        assert_eq!(recorded(&first, caller, 1), Duration::from_millis(20));
    }

    /// The only worker of a pool that waits in `block_on` runs the queued job it waits for.
    #[test]
    fn block_on_on_a_worker_runs_queued_jobs() {
        let strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(1))).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let output = strategy.groups.pool().install(|| {
                let (tx, rx) = futures::channel::oneshot::channel();
                strategy.groups.pool().spawn(move || {
                    let _ = tx.send(7);
                });
                strategy.block_on(rx).unwrap()
            });
            done.send(output).unwrap();
        });
        assert_eq!(
            finished.recv_timeout(Duration::from_secs(10)),
            Ok(7),
            "the only worker must run the job it waits for"
        );
    }

    /// A `block_on` nested inside a future that `block_on` drives outside the pool keeps the outer
    /// loop's wake: a sibling that completes while the inner loop runs is polled again.
    #[test]
    fn nested_block_on_keeps_the_outer_wake() {
        let strategy = parallel_strategy();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let sibling_waker: Arc<Mutex<Option<std::task::Waker>>> = Arc::new(Mutex::new(None));
            let sibling_ready = Arc::new(AtomicBool::new(false));
            let sibling = {
                let (waker, ready) = (Arc::clone(&sibling_waker), Arc::clone(&sibling_ready));
                std::future::poll_fn(move |cx| {
                    if ready.load(Ordering::SeqCst) {
                        return std::task::Poll::Ready(());
                    }
                    *waker.lock() = Some(cx.waker().clone());
                    std::task::Poll::Pending
                })
            };
            let nested = async {
                strategy.block_on(async {
                    // The sibling completes and wakes the outer loop, then the inner loop parks
                    // once on the shared thread token before its future is ready.
                    sibling_ready.store(true, Ordering::SeqCst);
                    sibling_waker.lock().take().unwrap().wake();
                    let mut yielded = false;
                    std::future::poll_fn(move |cx| {
                        if yielded {
                            return std::task::Poll::Ready(());
                        }
                        yielded = true;
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    })
                    .await
                })
            };
            strategy.block_on(futures::future::join(sibling, nested));
            done.send(()).unwrap();
        });
        assert!(
            finished.recv_timeout(Duration::from_secs(10)).is_ok(),
            "the outer loop must keep the sibling's wake"
        );
    }

    /// The default `block_on` drives a ready future to completion on the calling thread.
    #[test]
    fn sequential_block_on_returns_the_output() {
        assert_eq!(Sequential.block_on(Sequential.spawn(1, |_| 7)), 7);
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
                assert!(batches.is_whole());
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

        let one_worker = Rayon::new(ThreadPoolBuilder::new(NZUsize!(1))).unwrap();
        let parallel = parallel_strategy();
        let minimum = NonZeroUsize::new(8).unwrap();
        for len in [0, 1, 7, 8, 15] {
            check(&Sequential, len, minimum);
            check(&one_worker, len, minimum);
            check(&parallel, len, minimum);
            check(&parallel.without_policy(), len, minimum);
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
        // A one-group pool places the run on its group, so it has one parallel placement to seed.
        let strategy = Rayon::with_pool(Arc::new(
            ThreadPoolBuilder::new(NZUsize!(4)).build().unwrap(),
        ));
        let policy = strategy.policy.as_ref().unwrap();
        let caller = std::panic::Location::caller();

        // Record samples that make serial the preferred path.
        policy.record_run(
            caller,
            16,
            16,
            4,
            crate::policy::RunPlan {
                execution: crate::policy::RunExecution::Parallel,
                placement: crate::policy::Placement::Local,
                measure: true,
            },
            crate::policy::RunSample {
                wall: std::time::Duration::from_micros(100),
                busy: std::time::Duration::from_micros(400),
            },
        );
        policy.record_execution(
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
            assert!(batches.is_whole());
            batches.map_collect_vec(
                |ranges| ranges,
                |range| (range, std::thread::current().id()),
            )
        });
        assert_eq!(items, [(0..16, thread)]);
    }

    #[test]
    fn run_batches_supplies_ordered_balanced_ranges() {
        let strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(1)))
            .unwrap()
            .with_parallelism(NonZeroUsize::new(8).unwrap())
            .without_policy();
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
                |batches| {
                    assert!(!batches.is_whole());
                    batches.map_collect_vec(|ranges| ranges, |range| range)
                },
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
        assert_eq!(policy_len(&strategy), 0);
    }

    #[test]
    fn run_batches_prepares_borrowed_outputs_once() {
        let strategy = parallel_strategy().without_policy();
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
                    assert!(crate::rayon::current_thread_index().is_some());
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
            policy.run_estimates(mapping_loc, 16, usize::MAX, 4),
            Some((None, None))
        );

        let (assembly_loc, assembly) = run_batches_flagged(&strategy, false, true);
        assert_eq!(assembly, Err(()));
        assert_eq!(
            policy.run_estimates(assembly_loc, 16, usize::MAX, 4),
            Some((None, None))
        );

        let (success_loc, result) = run_batches_flagged(&strategy, false, false);
        assert_eq!(result, Ok(16));
        let (wide, local) = policy
            .run_placement_estimates(success_loc, 16, usize::MAX, 4)
            .unwrap();
        assert!(wide.is_some() || local.is_some());
        assert_eq!(policy_len(&strategy), 3);
    }

    #[test]
    fn run_batches_keeps_one_policy_decision_and_fixed_execution() {
        let strategy = parallel_strategy();
        let run = |strategy: &Rayon| {
            strategy.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                batches.map_collect_vec(|ranges| ranges, |range| range.len())
            })
        };
        assert_eq!(run(&strategy).into_iter().sum::<usize>(), 16);
        assert_eq!(policy_len(&strategy), 1);

        let fixed = strategy.without_policy();
        for _ in 0..3 {
            let on_pool = fixed.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                batches.map_collect_vec(
                    |ranges| ranges,
                    |_| crate::rayon::current_thread_index().is_some(),
                )
            });
            assert!(on_pool.into_iter().all(|on_pool| on_pool));
        }
        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(policy_len(&fixed), 0);
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
        let pool = ThreadPoolBuilder::new(NZUsize!(2))
            .use_current_thread()
            .unstarted_workers()
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
    fn spawn_future_moved_from_outside_to_worker_keeps_helping() {
        check_moved_future(Rayon::new(ThreadPoolBuilder::new(NZUsize!(2))).unwrap(), 0);
    }

    /// A pending spawn future that moves from outside the pool onto a worker of a grouped
    /// strategy's pool runs pool work while it waits.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn spawn_moved_future_helps_grouped_workers() {
        let strategy = synthetic(&[2, 2]).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let first = strategy.groups.local().unwrap();
        crate::topology::Groups::fake_domain(Some(1));
        let second = strategy.groups.local().unwrap();
        assert_eq!(second.group(), 1);
        check_moved_future(strategy, 1);
        crate::topology::Groups::fake_domain(None);
        drop((first, second));
    }

    /// Spawns a job from outside the pool while every group but `group` is held, so the job
    /// starts on `group`, then polls its future outside the pool and moves it onto the group's
    /// other worker. The job blocks on a value sent by a later job on the same group, so the
    /// moved future must run that job while it waits.
    fn check_moved_future(strategy: Rayon, group: usize) {
        // Hold every worker outside `group`, so only `group` can start the job.
        let strategy = strategy.without_policy();
        let placement = Placement::Local(group);
        let release = Arc::new(AtomicUsize::new(0));
        let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let mut occupied_workers = 0;
        for (index, other) in strategy.groups.groups().iter().enumerate() {
            if index == group {
                continue;
            }
            occupied_workers += other.width();
            let (occupied_tx, released_tx) = (occupied_tx.clone(), released_tx.clone());
            let release = Arc::clone(&release);
            strategy.groups.pool().spawn_broadcast_in(index, move || {
                let _ = occupied_tx.send(());
                let released = wait_for_release(&release, 1);
                let _ = released_tx.send(released);
            });
        }
        let occupied: Vec<_> = (0..occupied_workers)
            .map(|_| occupied_rx.recv_timeout(Duration::from_secs(10)).is_ok())
            .collect();

        // Create the future outside the pool while only its intended group can start the job.
        let (value_tx, value_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiting = strategy.spawn(1, move |strategy| {
            let _ = started_tx.send(strategy.current_placement());
            value_rx.recv_timeout(Duration::from_secs(60)).unwrap()
        });
        let started = started_rx.recv_timeout(Duration::from_secs(10)).ok();
        release.store(1, Ordering::Release);
        let released: Vec<_> = (0..occupied_workers)
            .map(|_| released_rx.recv_timeout(Duration::from_secs(10)).ok())
            .collect();

        // Poll outside the pool, then transfer the pending future to the other eligible worker.
        let mut waiting = Box::pin(waiting);
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let pending = std::future::Future::poll(waiting.as_mut(), &mut cx).is_pending();
        let (polling_tx, polling_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        strategy.groups.pool().spawn_in(placement, move || {
            let _ = polling_tx.send(());
            let _ = done_tx.send(block_on_nested(waiting));
        });
        let polling = polling_rx.recv_timeout(Duration::from_secs(10)).is_ok();

        // The job's worker is blocked on this value, so only the worker waiting on the moved
        // future can run the job that sends it.
        let sender = value_tx.clone();
        let (supplied_tx, supplied_rx) = std::sync::mpsc::channel();
        strategy.groups.pool().spawn_in(placement, move || {
            let _ = sender.send(42);
            let _ = supplied_tx.send(());
        });
        let result = done_rx.recv_timeout(Duration::from_secs(10)).ok();

        // Release the blocked job even when the progress assertion fails.
        let _ = value_tx.send(0);
        let supplied = supplied_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        if result.is_none() {
            let _ = done_rx.recv_timeout(Duration::from_secs(10));
        }
        assert_eq!(started, Some(Some(placement)));
        assert!(occupied.into_iter().all(|started| started));
        assert!(released.into_iter().all(|released| released == Some(true)));
        assert!(pending && polling && supplied);
        assert_eq!(
            result,
            Some(42),
            "the moved future must run pool work while it waits"
        );
    }

    /// A run placed on one group of a grouped strategy plans no more batches than that group has
    /// workers, and a run placed on the whole pool plans the strategy's parallelism.
    #[test]
    fn placed_runs_plan_placement_width() {
        let strategy = synthetic(&[2, 2]);
        let batches = |placed: &Rayon| {
            placed.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                batches
                    .map_collect_vec(|ranges| ranges, |range| range)
                    .len()
            })
        };
        assert_eq!(strategy.group_parallelism(1), 2);
        let local = strategy.placed(Placement::Local(1));
        assert_eq!(local.parallelism, 2);
        assert_eq!(batches(&local), 2);
        let wide = strategy.placed(Placement::Wide { near: 0 });
        assert_eq!(wide.parallelism, 4);
        assert_eq!(batches(&wide), 4);
        let narrow = strategy
            .with_parallelism(NonZeroUsize::MIN)
            .placed(Placement::Local(0));
        assert_eq!(narrow.parallelism, 1);
    }

    #[test]
    fn with_parallelism_overrides_planning_parallelism() {
        let strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(1)))
            .unwrap()
            .with_parallelism(NonZeroUsize::new(4).unwrap())
            .without_policy();
        assert_eq!(strategy.parallelism, 4);
        assert_eq!(strategy.run(2, || "serial", || "parallel"), "parallel");
    }

    /// A worker's placed calls split over its own pool from inside it, nested ones included. On a
    /// one-thread pool the worker runs every item itself, and on a two-thread pool its peer takes
    /// part. Neither leaves a job behind.
    #[test]
    fn nested_calls_use_current_pool() {
        for threads in [1, 2] {
            let strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(threads)))
                .unwrap()
                .with_parallelism(NonZeroUsize::new(4).unwrap())
                .without_policy();
            let pool = strategy.groups.pool().clone();

            // From a worker, map over the input with a nested map per item, recording the workers
            // that ran items.
            let (sums, workers) = pool.install_in(Placement::Wide { near: 0 }, || {
                let workers = commonware_utils::sync::Mutex::new(std::collections::HashSet::new());
                let sums = strategy.map_collect_vec(0..16u64, |x| {
                    let products = strategy.map_collect_vec(0..16u64, |y| {
                        std::thread::sleep(Duration::from_micros(100));
                        workers
                            .lock()
                            .insert(pool.current_worker().map(|worker| worker.index));
                        x * y
                    });
                    products.into_iter().sum::<u64>()
                });
                (sums, workers.into_inner())
            });

            // Every item ran on a worker of the pool, every worker took part, and nothing was left
            // queued.
            assert_eq!(sums, (0..16u64).map(|x| x * 120).collect::<Vec<_>>());
            assert!(workers.iter().all(Option::is_some), "{workers:?}");
            assert_eq!(workers.len(), threads, "{workers:?}");
            assert_eq!(
                pool.install_in(Placement::Wide { near: 0 }, rayon::yield_now),
                Some(rayon::Yield::Idle)
            );
        }
    }

    #[test]
    fn with_pool_plans_the_pool_thread_count() {
        let strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(3))).unwrap();
        assert_eq!(strategy.parallelism, 3);
    }

    /// A strategy keeps the names its builder gives workers, names the rest by group, and runs
    /// the builder's start handler on every worker.
    #[test]
    fn new_keeps_builder_settings() {
        let started = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&started);
        let named = Rayon::new(
            ThreadPoolBuilder::new(NZUsize!(3))
                .thread_name(|worker| format!("mine-{}", worker.index))
                .start_handler(move |_| {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
        )
        .unwrap();
        let names = |strategy: &Rayon| {
            strategy
                .groups
                .pool()
                .broadcast(|_| std::thread::current().name().map(str::to_owned))
        };
        assert_eq!(
            names(&named),
            ["mine-0", "mine-1", "mine-2"].map(|name| Some(name.to_owned()))
        );
        assert_eq!(started.load(Ordering::SeqCst), 3);

        // The default names follow whatever groups the host gives three workers.
        let unnamed = Rayon::new(ThreadPoolBuilder::new(NZUsize!(3))).unwrap();
        let expected: Vec<_> = unnamed
            .groups
            .groups()
            .iter()
            .enumerate()
            .flat_map(|(group, g)| {
                (0..g.width()).map(move |offset| Some(format!("group{group}-{offset}")))
            })
            .collect();
        assert_eq!(names(&unnamed), expected);
    }

    /// A runtime that runs strategy work inline registers its executor thread as the sole
    /// worker of a pool, and that worker's runs still plan with the overridden parallelism.
    #[test]
    fn single_worker_respects_planning_override() {
        let pool = ThreadPoolBuilder::new(NZUsize!(1))
            .use_current_thread()
            .build()
            .unwrap();
        let strategy =
            Rayon::with_pool(Arc::new(pool)).with_parallelism(NonZeroUsize::new(4).unwrap());
        assert!(
            strategy.current_placement().is_some(),
            "the test thread must be the pool's worker"
        );

        // A site's first call runs in parallel to seed its estimate.
        let counts: Vec<usize> = (0..4)
            .map(|_| {
                strategy.run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                    batches
                        .map_collect_vec(|ranges| ranges, |range| range)
                        .len()
                })
            })
            .collect();
        assert!(
            counts.contains(&4),
            "a parallel run must plan four batches, got {counts:?}"
        );
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
        strategy.sort_unstable_by(&mut sortable, |a, b| b.cmp(a));
        assert_eq!(sortable, vec![3, 2, 1]);

        assert_eq!(policy_len(&strategy), 12);
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

    /// A strategy without a policy hands every job off on a multi-worker pool, so the job runs on
    /// the pool whatever an adaptive policy would decide for this call site.
    #[test]
    fn spawn_without_policy_always_hands_off() {
        let strategy = parallel_strategy().without_policy();

        for _ in 0..10 {
            let on_pool = futures::executor::block_on(
                strategy.spawn(1, |_| crate::rayon::current_thread_index().is_some()),
            );
            assert!(
                on_pool,
                "spawn without a policy must run off the calling task"
            );
        }
    }

    #[test]
    fn strategy_without_policy_records_nothing() {
        let strategy = parallel_strategy();
        let fixed = strategy.without_policy();

        let _: usize = fixed.fold(0..4, || 0, |acc, x| acc + x, |a, b| a + b);
        assert_eq!(fixed.run(4, || 1, || 2), 2);

        assert_eq!(policy_len(&strategy), 0);
        assert_eq!(policy_len(&fixed), 0);
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

    /// Joins submitted from outside the pool share one policy entry per call site. Joins from
    /// the pool's workers run in place without consulting the policy.
    #[test]
    fn join_shares_policy_entry_per_callsite() {
        let strategy = parallel_strategy();
        for _ in 0..3 {
            assert_eq!(strategy.join(|| 1, || 2), (1, 2));
        }
        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(strategy.join(|| 3, || 4), (3, 4));
        assert_eq!(policy_len(&strategy), 2);

        let nested = strategy
            .groups
            .pool()
            .install_in(Placement::Wide { near: 0 }, || strategy.join(|| 5, || 6));
        assert_eq!(nested, (5, 6));
        assert_eq!(policy_len(&strategy), 2);
    }

    /// A thread registered as a pool's only worker must complete its collection operations
    /// without leaving queued jobs. This thread has no worker loop to drain them later.
    #[test]
    fn taken_over_thread_leaves_no_jobs() {
        let pool = Arc::new(
            ThreadPoolBuilder::new(NZUsize!(1))
                .use_current_thread()
                .build()
                .unwrap(),
        );
        let strategy = Rayon::with_pool(pool).with_parallelism(NonZeroUsize::new(4).unwrap());
        for _ in 0..4 {
            let out = strategy.map_collect_vec(0..64u64, |x| x + 1);
            assert_eq!(out, (1..=64).collect::<Vec<_>>());
            let sum = strategy.fold(0..64u64, || 0, |acc, x| acc + x, |a, b| a + b);
            assert_eq!(sum, 2016);
        }
        assert_eq!(rayon::yield_now(), Some(rayon::Yield::Idle));
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
            assert!(crate::rayon::current_thread_index().is_some());
            7
        }));

        assert_eq!(result, 7);

        // Spawn trains only the spawn-side policy: no run entries are created.
        assert_eq!(policy_len(&strategy), 0);
    }

    #[test]
    fn rayon_spawn_runs_inline_on_current_thread_single_worker_pool() {
        let pool = ThreadPoolBuilder::new(NZUsize!(1))
            .use_current_thread()
            .build()
            .unwrap();
        let strategy =
            Rayon::with_pool(Arc::new(pool)).with_parallelism(NonZeroUsize::new(4).unwrap());

        assert_eq!(strategy.parallelism, 4);

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

    fn fixed_strategy(parallelism: usize) -> Rayon {
        Rayon::with_pool(Arc::new(
            ThreadPoolBuilder::new(NZUsize!(4)).build().unwrap(),
        ))
        .with_parallelism(NonZeroUsize::new(parallelism).unwrap())
        .without_policy()
    }

    /// A tile as its row and the pieces `fill` received.
    type Tile = (usize, Vec<Range<usize>>);

    /// The tiles a strategy supplies for the one grid.
    fn tiles_of(strategy: &impl Strategy, rows: usize, len: usize, tile_cost: usize) -> Vec<Tile> {
        let (grid, tiles) = tiles_of_grids(strategy, len, &[grid(rows, tile_cost)]);
        assert_eq!(grid, 0);
        tiles
    }

    fn grid(rows: usize, tile_cost: usize) -> Grid {
        Grid {
            rows,
            tile_cost: NonZeroUsize::new(tile_cost).unwrap(),
        }
    }

    /// The grid a strategy cuts among `grids` and its tiles.
    #[track_caller]
    fn tiles_of_grids(strategy: &impl Strategy, len: usize, grids: &[Grid]) -> (usize, Vec<Tile>) {
        strategy.run_tiles(len, grids, 1, |tiles| {
            let grid = tiles.grid();

            // Record each piece with its row. Finishing a tile takes every recorded piece,
            // which must belong to that row, and leaves the state empty for the next tile.
            let tiles = tiles.fill_collect_vec(
                Vec::new,
                |pieces: &mut Vec<(usize, Range<usize>)>, row, columns| pieces.push((row, columns)),
                |pieces, row| {
                    let pieces = core::mem::take(pieces);
                    assert!(pieces.iter().all(|(piece_row, _)| *piece_row == row));
                    (
                        row,
                        pieces.into_iter().map(|(_, columns)| columns).collect(),
                    )
                },
            );
            (grid, tiles)
        })
    }

    /// Asserts that `tiles` cover a `rows` by `len` grid exactly once, each tile with
    /// contiguous pieces in column order.
    fn assert_covers(tiles: &[Tile], rows: usize, len: usize) {
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

        // Each grid runs serially, adaptively, without a policy at 1 to 64 planned workers, and
        // under seeded explorers. Seeded explorers can also run the shares one after another on
        // the calling thread.
        for (rows, len, tile_cost) in grids {
            assert_covers(&tiles_of(&Sequential, rows, len, tile_cost), rows, len);
            assert_covers(
                &tiles_of(&parallel_strategy(), rows, len, tile_cost),
                rows,
                len,
            );
            for parallelism in [1, 2, 8, 16, 32, 64] {
                let strategy = fixed_strategy(parallelism);
                assert_covers(&tiles_of(&strategy, rows, len, tile_cost), rows, len);
            }
            for seed in 0..16 {
                let strategy = Explorer::seeded(&fixed_strategy(16), seed);
                assert_covers(&tiles_of(&strategy, rows, len, tile_cost), rows, len);
            }
        }

        // More workers than pool threads, with tiles cheap enough to cut finely, keep claims and
        // steals racing.
        let strategy = fixed_strategy(16);
        for _ in 0..200 {
            assert_covers(&tiles_of(&strategy, 7, 300, 2), 7, 300);
        }
    }

    /// A queue of more than `MAX_UNITS` rows holds several rows per unit, so every unit index
    /// still fits the packed range and every row is still one tile.
    #[test]
    fn run_tiles_group_rows_beyond_the_unit_limit() {
        // Three columns at tile cost four keep every grid on whole rows.
        let strategy = fixed_strategy(4);
        for rows in [MAX_UNITS, MAX_UNITS + 1, 2 * MAX_UNITS + 1] {
            let tiles = tiles_of(&strategy, rows, 3, 4);
            assert_eq!(tiles.len(), rows);
            assert!(
                tiles.iter().all(
                    |(_, pieces)| matches!(pieces.as_slice(), [columns] if *columns == (0..3))
                )
            );
            assert_covers(&tiles, rows, 3);
        }
    }

    #[test]
    fn run_tiles_serial_runs_make_every_row_one_tile() {
        // A single-worker run without a policy is serial too, and a grid without columns has no
        // tiles.
        let whole: Vec<_> = (0..3)
            .map(|row| (row, core::iter::once(0..10).collect()))
            .collect();
        assert_eq!(tiles_of(&Sequential, 3, 10, 1), whole);
        assert_eq!(tiles_of(&fixed_strategy(1), 3, 10, 1), whole);
        assert!(tiles_of(&Sequential, 3, 0, 1).is_empty());
    }

    #[test]
    fn run_tiles_bound_workers_by_the_grid() {
        // A planning parallelism far beyond the grid allocates and dispatches only the workers the
        // grid can occupy.
        let strategy = Rayon::new(ThreadPoolBuilder::new(NZUsize!(4)))
            .unwrap()
            .with_parallelism(NonZeroUsize::MAX)
            .without_policy();
        for (rows, len, tile_cost) in [(1, 1, 1), (3, 10, 1), (32, 1, 100), (30, 100, 64)] {
            assert_covers(&tiles_of(&strategy, rows, len, tile_cost), rows, len);
        }
    }

    /// A run cuts the grid it estimates finishes first for its workers. A serial run cuts the one
    /// with the fewest cells, counting each row's finish. A shared run cuts the one whose shares
    /// finish soonest, so it may prefer rows that divide evenly among the workers to fewer cells.
    #[test]
    fn run_tiles_cut_the_grid_that_finishes_first() {
        // Twenty-six rows finishing at 1024 cells cost fewer cells than twenty-four finishing at
        // 2048 (156,624 against 169,152), so a serial run cuts the first grid. Eight workers get
        // three whole rows each of the second (21,144 cells) but would cut rows of the first
        // (19,578 plus three tile costs each, 22,650), so a shared run cuts the second as whole
        // rows.
        let len = 5_000;
        let grids = [grid(26, 1024), grid(24, 2048)];
        let (chosen, tiles) = tiles_of_grids(&Sequential, len, &grids);
        assert_eq!(chosen, 0);
        assert_covers(&tiles, 26, len);
        assert_eq!(tiles.len(), 26);

        let (chosen, tiles) = tiles_of_grids(&fixed_strategy(8), len, &grids);
        assert_eq!(chosen, 1);
        assert_covers(&tiles, 24, len);
        assert_eq!(tiles.len(), 24, "whole rows must never be cut");
        assert!(
            tiles
                .iter()
                .all(|(_, pieces)| matches!(pieces[..], [ref whole] if *whole == (0..len)))
        );

        // The order of equally cheap grids breaks the tie.
        let (chosen, _) = tiles_of_grids(&Sequential, len, &[grid(24, 2048), grid(24, 2048)]);
        assert_eq!(chosen, 0);
    }

    /// Long rows that divide evenly among the workers are shared whole, since cutting them
    /// would only add tiles. With one row more, the shares cut rows to balance the cells.
    #[test]
    fn run_tiles_share_whole_rows_when_cutting_only_adds_tiles() {
        let strategy = fixed_strategy(4);
        let (_, tiles) = tiles_of_grids(&strategy, 1_000, &[grid(8, 10)]);
        assert_covers(&tiles, 8, 1_000);
        assert_eq!(tiles.len(), 8);

        // Nine rows over four workers put three share boundaries inside rows, and each cuts one.
        let (_, tiles) = tiles_of_grids(&strategy, 1_000, &[grid(9, 10)]);
        assert_covers(&tiles, 9, 1_000);
        assert!(tiles.len() >= 12, "{} tiles", tiles.len());

        // With three rows of fifty cells over two workers, cutting at 90 cells plus three tile
        // costs ties with two whole rows at 120 cells, and the tie keeps the rows whole.
        let (_, tiles) = tiles_of_grids(&fixed_strategy(2), 50, &[grid(3, 10)]);
        assert_covers(&tiles, 3, 50);
        assert_eq!(tiles.len(), 3);
    }

    #[test]
    fn run_tiles_spread_short_rows_across_workers() {
        // Every row is shorter than a tile's cost, so no row is cut, but rows still go to separate
        // workers: the worker filling the first row waits until another has filled a row.
        let rows = 32;
        let others = AtomicUsize::new(0);
        let tiles = fixed_strategy(4).run_tiles(1, &[grid(rows, 100)], 1, |tiles| {
            tiles.fill_collect_vec(
                Vec::new,
                |pieces: &mut Vec<Range<usize>>, row, columns| {
                    if row == 0 {
                        let deadline = Instant::now() + Duration::from_secs(30);
                        while others.load(Ordering::Acquire) == 0 {
                            assert!(Instant::now() < deadline, "another worker must fill a row");
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
        let tiles = fixed_strategy(4).run_tiles(len, &[grid(1, tile_cost)], 1, |tiles| {
            tiles.fill_collect_vec(
                Vec::new,
                |pieces: &mut Vec<Range<usize>>, _, columns| {
                    if columns.start == 0 {
                        let deadline = Instant::now() + Duration::from_secs(30);
                        while filled.load(Ordering::Acquire) < len - 3 * tile_cost {
                            assert!(Instant::now() < deadline, "the stalled share must be cut");
                            std::thread::yield_now();
                        }
                    }
                    filled.fetch_add(columns.len(), Ordering::Release);
                    pieces.push(columns);
                },
                |pieces, row| (row, core::mem::take(pieces)),
            )
        });
        assert_covers(&tiles, 1, len);

        // The tile holding the stalled piece kept at most those three tile costs.
        let first: usize = tiles
            .iter()
            .find(|(_, pieces)| pieces[0].start == 0)
            .map(|(_, pieces)| pieces.iter().map(|columns| columns.len()).sum())
            .unwrap();
        assert!(first <= 3 * tile_cost, "first tile kept {first} cells");
    }

    #[test]
    fn run_tiles_take_a_stalled_workers_last_row() {
        // Two workers over eight whole rows. The worker filling the first row stalls until every
        // other row is filled. Only the other worker can fill them, by claiming the rest of the
        // queue through the last row.
        let rows = 8;
        let others = AtomicUsize::new(0);
        let tiles = fixed_strategy(2).run_tiles(1, &[grid(rows, 100)], 1, |tiles| {
            tiles.fill_collect_vec(
                Vec::new,
                |pieces: &mut Vec<Range<usize>>, row, columns| {
                    if row == 0 {
                        let deadline = Instant::now() + Duration::from_secs(30);
                        while others.load(Ordering::Acquire) < rows - 1 {
                            assert!(
                                Instant::now() < deadline,
                                "another worker must fill every other row"
                            );
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

    /// Fills one row of `len` cells as four shares and asserts that no worker steals.
    /// Workers on the last three shares pause at the claims starting at `wait_for` until
    /// the first share's tile finishes. The first worker pauses at the claim starting at
    /// `drain` until all three have paused, then empties its share. The tails left pending
    /// must be too small to pay for a split, so the run ends with one tile per share.
    fn assert_no_cheap_steal(len: usize, tile_cost: usize, wait_for: [usize; 3], drain: usize) {
        let ready = AtomicUsize::new(0);
        let release = AtomicUsize::new(0);
        let tiles = fixed_strategy(4).run_tiles(len, &[grid(1, tile_cost)], 1, |tiles| {
            tiles.fill_collect_vec(
                Vec::new,
                |pieces: &mut Vec<Range<usize>>, _, columns| {
                    // Three workers leave their pending tails available until the first
                    // worker finishes its original share and checks whether to steal.
                    let deadline = Instant::now() + Duration::from_secs(30);
                    if wait_for.contains(&columns.start) {
                        ready.fetch_add(1, Ordering::Release);
                        while release.load(Ordering::Acquire) == 0 {
                            assert!(Instant::now() < deadline, "the first share must finish");
                            std::thread::yield_now();
                        }
                    } else if columns.start == drain {
                        while ready.load(Ordering::Acquire) != wait_for.len() {
                            assert!(Instant::now() < deadline, "the other shares must pause");
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
        });
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
        let tiles = Sequential.run_tiles(1_000, &[grid(7, 16)], 1, |tiles| {
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

    std::thread_local! {
        /// Calls of [`count_block_hook`] on this thread.
        static BLOCK_HOOK_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    /// Whether [`count_block_hook`] ran since a test last cleared it, read on the pool's threads.
    static BLOCK_HOOK_RAN: AtomicBool = AtomicBool::new(false);

    /// A block hook that counts its calls on the calling thread.
    fn count_block_hook() {
        BLOCK_HOOK_CALLS.with(|calls| calls.set(calls.get() + 1));
        BLOCK_HOOK_RAN.store(true, Ordering::Release);
    }

    /// Every synchronous parallel body calls the calling thread's block hook exactly once
    /// before the pool runs it, with or without a policy. A serial run and a cleared hook call
    /// nothing, and setting a hook returns the one it replaces.
    #[test]
    fn parallel_bodies_call_the_block_hook() {
        /// A named strategy call.
        type Body = (&'static str, fn(&Rayon));
        /// The items every body maps, folds or sorts.
        fn items() -> Vec<u64> {
            (0..64).collect()
        }
        let calls = || BLOCK_HOOK_CALLS.with(core::cell::Cell::get);
        let parallel = parallel_strategy().without_policy();
        let bodies: [Body; 9] = [
            ("fold_init", |s| {
                let sum = s.fold_init(items(), || (), || 0, |sum, _, x| sum + x, |a, b| a + b);
                assert_eq!(sum, 2016);
            }),
            ("map_collect_vec", |s| {
                // The hook runs before the pool runs any of the body.
                let out = s.map_collect_vec(items(), |x| {
                    assert!(BLOCK_HOOK_RAN.load(Ordering::Acquire));
                    x
                });
                assert_eq!(out, items());
            }),
            ("try_map_collect_vec", |s| {
                let out: Result<Vec<u64>, ()> = s.try_map_collect_vec(items(), Ok);
                assert_eq!(out, Ok(items()));
            }),
            ("map_init_collect_vec", |s| {
                assert_eq!(s.map_init_collect_vec(items(), || (), |_, x| x), items());
            }),
            ("map_init_collect_vec_with_multiplier", |s| {
                let out = s.map_init_collect_vec_with_multiplier(items(), 2, || (), |_, x| x);
                assert_eq!(out, items());
            }),
            ("try_fold", |s| {
                let sum: Result<u64, ()> =
                    s.try_fold(items(), || 0, |sum, x| Ok(sum + x), |a, b| a + b);
                assert_eq!(sum, Ok(2016));
            }),
            ("join", |s| assert_eq!(s.join(|| 1, || 2), (1, 2))),
            ("sort_by", |s| {
                let mut values: Vec<u64> = items().into_iter().rev().collect();
                s.sort_by(&mut values, |a, b| a.cmp(b));
                assert_eq!(values, items());
            }),
            ("sort_unstable_by", |s| {
                let mut values: Vec<u64> = items().into_iter().rev().collect();
                s.sort_unstable_by(&mut values, |a, b| a.cmp(b));
                assert_eq!(values, items());
            }),
        ];

        assert!(crate::set_block_hook(Some(count_block_hook)).is_none());
        for (name, body) in bodies {
            BLOCK_HOOK_RAN.store(false, Ordering::Release);
            let before = calls();
            body(&parallel);
            assert_eq!(calls(), before + 1, "{name} must call the hook once");
        }

        // An adaptive join that runs on the pool calls the hook too. The first join at a call
        // site is a measured parallel run.
        let adaptive = parallel_strategy();
        let before = calls();
        let (pooled, ()) = adaptive.join(|| rayon::current_thread_index().is_some(), || ());
        assert!(pooled, "the first join at a call site must run on the pool");
        assert_eq!(
            calls(),
            before + 1,
            "an adaptive join must call the hook once"
        );

        // A serial run blocks nothing, so it calls no hook.
        let serial = parallel.clone().with_parallelism(NZUsize!(1));
        let before = calls();
        assert_eq!(serial.map_collect_vec(items(), |x| x), items());
        assert_eq!(calls(), before);

        // A cleared hook is not called.
        assert!(crate::set_block_hook(None).is_some());
        let before = calls();
        assert_eq!(parallel.map_collect_vec(items(), |x| x), items());
        assert_eq!(calls(), before);
    }

    /// A join from a worker of the strategy's own pool joins in place, and still calls the
    /// thread's block hook, since the join can hold the thread until its other side returns. A
    /// thread that a pool took over as its worker, as a runtime thread can be, runs it.
    #[test]
    fn same_pool_join_calls_the_block_hook() {
        std::thread::spawn(|| {
            /// A block hook that only counts its calls.
            fn count() {
                BLOCK_HOOK_CALLS.with(|calls| calls.set(calls.get() + 1));
            }
            let pool = Arc::new(
                ThreadPoolBuilder::new(NZUsize!(1))
                    .use_current_thread()
                    .build()
                    .unwrap(),
            );
            let strategy = Rayon::with_pool(pool);
            assert!(strategy.current_placement().is_some());
            assert!(crate::set_block_hook(Some(count)).is_none());
            assert_eq!(strategy.join(|| 1, || 2), (1, 2));
            assert!(crate::set_block_hook(None).is_some());
            assert_eq!(BLOCK_HOOK_CALLS.with(core::cell::Cell::get), 1);
        })
        .join()
        .unwrap();
    }
}
