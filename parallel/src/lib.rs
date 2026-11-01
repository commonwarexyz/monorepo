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
//! - [`Rayon`]: Adaptively executes collection operations serially or with a Commonware thread pool
//!   (requires `std`)
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
            use self::rayon::ThreadPoolBuildError;
            use std::{
                panic::{self, AssertUnwindSafe, Location},
                pin::Pin,
                sync::{
                    Arc,
                    atomic::{AtomicUsize, Ordering as AtomicOrdering},
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
        /// For [`Sequential`], this executes `a` then `b` on the current thread. For [`Rayon`],
        /// this executes `a` and `b` one after the other on the calling thread or with a
        /// work-stealing join on its pool, as its policy learns per call site.
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

    /// A parallel execution strategy backed by a Commonware thread pool.
    ///
    /// This strategy adaptively executes collection operations serially or through its backing
    /// pool. It records wall-clock estimates by callsite, input-size and work-size buckets, and
    /// planning parallelism so small inputs can avoid thread-pool scheduling overhead without
    /// disabling parallel execution for larger inputs.
    ///
    /// Nested calls at the same callsite share estimates across parent paths, so use distinct
    /// callsites (propagating `#[track_caller]` through helpers as needed) to tune them separately.
    ///
    /// A strategy built with [`Rayon::new`] or [`Rayon::grouped`] splits its pool's workers into
    /// groups sized to the host's last-level cache domains. A strategy built on a caller's pool
    /// is one group that is never homed.
    ///
    /// Parallel collection work submitted from outside the pool runs on one group or across the
    /// whole pool, as the policy learns per call site. Local work first tries to use or establish
    /// a home in the caller's domain, then falls back to the least loaded full-width group. The
    /// caller waits for this work to finish. Joins use the same placement choices or run serially
    /// on the caller. Parallel sorts from outside the pool use one group to limit cross-domain
    /// access to the values.
    ///
    /// A caller whose local work runs on a group homed in another domain waits in that domain:
    /// its affinity mask is narrowed to the domain's CPUs within its own mask for the call, so it
    /// resumes beside the workers that hold the call's data. The call restores the caller's mask
    /// before returning.
    ///
    /// A worker's nested strategy calls, joins, and spawned jobs inherit its placement. They
    /// stay in its group under a local placement and spread over the pool under a wide one.
    ///
    /// A job handed off from outside the pool prefers waking its submitter's home group. When
    /// another caller occupies that group, it prefers waking the least loaded group instead. On a
    /// pool with multiple groups, each group admits one such job per worker for learning descendant
    /// placement. Any idle worker can start a job.
    ///
    /// For admitted jobs, the policy learns whether descendants stay on the starting worker's
    /// group or use the whole pool. Further jobs use the whole pool, as do jobs that start on a
    /// narrower group. This decision measures the job's elapsed time. Work performed by a later
    /// consumer of the result is outside that measurement.
    ///
    /// When the pool fills all allowed CPUs across multiple equal-sized domains with at least
    /// two allowed CPUs each, every group gets a fixed home and requests its mask before running
    /// jobs. Otherwise, an idle unhomed group can acquire a permanent home in a caller's domain
    /// when the pool's initial mask is known and allows enough CPUs there for every worker in the
    /// group. Its workers apply the request asynchronously.
    ///
    /// Homing targets the domain's allowed CPUs. In a pool with multiple groups, floating groups
    /// request the remaining CPUs when enough remain for all floating workers. Otherwise they
    /// request their original masks. Other threads can still run on those CPUs. Requested masks
    /// stay within the workers' inherited masks, and the operating system may reject a request.
    ///
    /// A group narrower than the first, left over when the parallelism is not a multiple of the
    /// group width, is never homed. Its workers take work placed on the whole pool so a call
    /// placed on one group always has the width the policy planned.
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
        // The strategy's pool, whose workers form its groups.
        thread_pool: ThreadPool,
        // The parallelism assumed for policy decisions and for planning batches and tiles.
        // Defaults to the groups' total thread count.
        parallelism: usize,
        // `Some` enables adaptive serial-vs-parallel decisions. `None` runs the parallel body
        // whenever the parallelism exceeds one and allocates no policy state.
        policy: Option<policy::Policy>,
        // The groups the pool's workers are split into, with their homes and their load.
        groups: Arc<topology::Groups>,
        // The placement a copy made by `placed` runs its parallel bodies under, or `None` outside
        // such a copy. `own_dispatch` resolves where the bodies of a strategy without a policy run.
        placement: Option<rayon::Placement>,
    }

    /// Where a placed parallel body runs, and the parallelism it plans for there.
    #[derive(Clone, Copy, Debug)]
    struct Dispatch {
        /// The workers that run the body.
        placement: rayon::Placement,
        /// The number of tasks the body plans for.
        parallelism: usize,
    }

    /// Where a run's parallel body may run, which decides how a caller outside the pool places
    /// it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Body {
        /// The caller's own code, which runs on the caller and leaves nothing to place.
        Caller,
        /// Work that runs on one group, such as a sort.
        Group,
        /// Work the strategy places on a group or on the whole pool.
        Placed,
    }

    impl Rayon {
        /// Creates a strategy with the given number of workers, grouped automatically by the
        /// host's last-level cache topology as described by [`Self::grouped`].
        pub fn new(num_threads: NonZeroUsize) -> Result<Self, ThreadPoolBuildError> {
            Self::grouped(num_threads, None)
        }

        /// Creates a new [`Rayon`] strategy on the given [`ThreadPool`], whose workers form one
        /// group. The group is never homed, so the pool's threads keep their affinity.
        pub fn with_pool(thread_pool: ThreadPool) -> Self {
            let parallelism = thread_pool.current_num_threads().max(1);
            Self::over(Arc::new(topology::Groups::single(thread_pool)), parallelism)
        }

        /// Creates a [`Rayon`] strategy on one pool of `parallelism` threads, with `stack_size` per
        /// worker when one is given. The workers are split into groups as wide as the CPUs the
        /// calling thread may use in the host's widest last-level cache domain, less one when at
        /// least six are allowed there. This leaves capacity for the caller and other threads.
        ///
        /// If the pool fills all allowed CPUs across multiple equally sized domains with at least
        /// two allowed CPUs each, groups use the full domain width and receive fixed homes at
        /// startup.
        ///
        /// A smaller `parallelism` gives one group of that many workers. A larger `parallelism`
        /// that is not a multiple of the group width leaves a narrower last group, which takes
        /// only work placed on the whole pool.
        ///
        /// Calls, joins, sorts, and spawned jobs are placed among the groups as described on
        /// [`Rayon`]. If fewer than two domains are detected, the widest allowed domain has fewer
        /// than two CPUs, or affinity control is unavailable, all workers form one unhomed group.
        pub fn grouped(
            parallelism: NonZeroUsize,
            stack_size: Option<usize>,
        ) -> Result<Self, ThreadPoolBuildError> {
            let groups = topology::Groups::build(parallelism.get(), stack_size)?;
            let parallelism = groups.threads().max(1);
            Ok(Self::over(Arc::new(groups), parallelism))
        }

        fn over(groups: Arc<topology::Groups>, parallelism: usize) -> Self {
            Self {
                thread_pool: groups.pool().clone(),
                parallelism,
                policy: Some(policy::Policy::default()),
                groups,
                placement: None,
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

        /// The placement of the job the calling thread runs as a worker of the strategy's pool, or
        /// `None` for a thread outside it. A worker keeps every placed call, join, and job it makes
        /// under that placement, so while it waits on its own job it can run the work it queued
        /// meanwhile. This is a snapshot, and a nested install can change the placement while it
        /// runs.
        fn own_placement(&self) -> Option<rayon::Placement> {
            self.thread_pool.current_placement()
        }

        /// The parallelism a body placed on `group` plans with. The groups of a grouped strategy
        /// share its parallelism, so each plans for no more tasks than it has workers. A strategy
        /// with one group plans for its whole parallelism, including an override.
        fn planned(&self, group: usize) -> usize {
            let groups = self.groups.groups();
            if groups.len() > 1 {
                self.parallelism.min(groups[group].width())
            } else {
                self.parallelism
            }
        }

        /// The dispatch of a body placed as `placement`. A group plans with [`Self::planned`], and
        /// the whole pool with the strategy's parallelism.
        fn dispatch(&self, placement: rayon::Placement) -> Dispatch {
            let parallelism = match placement {
                rayon::Placement::Local(group) => self.planned(group),
                rayon::Placement::Wide { .. } => self.parallelism,
            };
            Dispatch {
                placement,
                parallelism,
            }
        }

        /// A copy of this strategy that runs every parallel body on `dispatch`, plans with its
        /// parallelism, and has no policy. It dispatches work already placed, so it has nothing
        /// left to place.
        fn placed(&self, dispatch: &Dispatch) -> Self {
            Self {
                thread_pool: self.thread_pool.clone(),
                parallelism: dispatch.parallelism,
                policy: None,
                groups: Arc::clone(&self.groups),
                placement: Some(dispatch.placement),
            }
        }

        /// The dispatch of this strategy's own parallel bodies when the policy does not place
        /// them. A worker of the strategy's pool keeps them under the placement of the job it
        /// runs, like its placed calls. Elsewhere, a copy made by `placed` uses its placement, and
        /// any other strategy the first group.
        fn own_dispatch(&self) -> Dispatch {
            Dispatch {
                placement: self
                    .own_placement()
                    .or(self.placement)
                    .unwrap_or(rayon::Placement::Local(0)),
                parallelism: self.parallelism,
            }
        }

        /// Runs [`Self::try_execute`] with an infallible `run`.
        #[track_caller]
        fn execute<R>(
            &self,
            len: usize,
            work: usize,
            body: Body,
            run: impl FnOnce(policy::RunExecution, &Dispatch) -> R,
        ) -> R {
            match self.try_execute(len, work, body, |execution, dispatch| {
                Ok::<_, Infallible>(run(execution, dispatch))
            }) {
                Ok(result) => result,
                Err(e) => match e {},
            }
        }

        /// Runs `run` on the execution path the policy prefers for this call site's `len` items and
        /// estimated `work`, passing the dispatch a parallel run uses.
        ///
        /// `body` says where the parallel body may run. With a policy, a worker of the strategy's
        /// pool runs placed work under the placement of the job it runs. A thread outside the pool
        /// first tries to use or establish a home in its domain for a local body, then falls back
        /// to the least loaded full-width group.
        ///
        /// A [`Body::Group`] body is compared against that local placement alone. On a strategy
        /// with several groups, a [`Body::Placed`] body chooses between one group and the whole
        /// pool, offered first to its home group. A strategy with one group places such work on
        /// that group, whose workers are the whole pool, so a caller outside it waits as an
        /// install does. Every other run, and every run of a strategy without a policy, uses
        /// [`Self::own_dispatch`].
        ///
        /// A [`Body::Caller`] body is the caller's own code and runs on the caller, so the policy
        /// has nothing to place there. A worker still decides it against its own placement, since
        /// the body's joins and placed calls run there.
        #[track_caller]
        fn try_execute<R, E>(
            &self,
            len: usize,
            work: usize,
            body: Body,
            run: impl FnOnce(policy::RunExecution, &Dispatch) -> Result<R, E>,
        ) -> Result<R, E> {
            let Some(policy) = &self.policy else {
                let execution = if self.parallelism <= 1 {
                    policy::RunExecution::Serial
                } else {
                    policy::RunExecution::Parallel
                };
                return run(execution, &self.own_dispatch());
            };

            let caller = Location::caller();
            let own = self.own_placement();
            let plan = policy.choose_run(caller, len, work, self.parallelism, || {
                let wide = policy::Pools::Fixed(policy::Placement::Wide, self.parallelism);
                match (own, body) {
                    (Some(rayon::Placement::Local(group)), _) => {
                        policy::Pools::Fixed(policy::Placement::Local, self.planned(group))
                    }
                    (Some(rayon::Placement::Wide { .. }), _) | (None, Body::Caller) => wide,
                    (None, Body::Placed) if self.groups.groups().len() > 1 => {
                        policy::Pools::Either(self.planned(0))
                    }
                    (None, Body::Group | Body::Placed) => {
                        policy::Pools::Fixed(policy::Placement::Local, self.planned(0))
                    }
                }
            });

            // Resolve where the body runs, holding a lease on each group it uses until the body
            // returns.
            let mut leases: Vec<topology::Lease> = Vec::new();
            let mut nudge = None;
            let dispatch = match own {
                Some(placement) => self.dispatch(placement),
                None if body == Body::Caller || plan.execution == policy::RunExecution::Serial => {
                    self.own_dispatch()
                }
                None => {
                    // A local body first tries to use or establish a home in the caller's domain,
                    // then falls back to the least loaded full-width group, whose home the caller
                    // waits in. Only a strategy with several groups places a body on the whole
                    // pool.
                    if plan.placement == policy::Placement::Local {
                        let lease = self
                            .groups
                            .local()
                            .unwrap_or_else(|| self.groups.least_loaded());
                        nudge = self.groups.nudge(lease.group());
                        let dispatch = self.dispatch(rayon::Placement::Local(lease.group()));
                        leases.push(lease);
                        dispatch
                    } else {
                        leases = self.groups.wide();
                        Dispatch {
                            placement: rayon::Placement::Wide {
                                near: leases[0].group(),
                            },
                            parallelism: self.parallelism,
                        }
                    }
                }
            };

            // Only a successful run records its wall time. An error often aborts early, and its
            // short wall would poison the estimate.
            let start = plan.measure.then(Instant::now);
            let result = run(plan.execution, &dispatch);
            drop(nudge);
            drop(leases);
            if let (Some(start), Ok(_)) = (start, &result) {
                policy.record_run_placed(caller, len, work, self.parallelism, plan, start.elapsed());
            }
            result
        }

        /// Sorts `items` by `compare` with `serial`, or with `parallel` on the workers of the
        /// dispatch, as the policy decides.
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
                |execution, dispatch| match execution {
                    policy::RunExecution::Serial => serial(items, compare),
                    policy::RunExecution::Parallel => self
                        .thread_pool
                        .install_in(dispatch.placement, || parallel(items, compare)),
                },
            );
        }
    }

    impl Strategy for Rayon {
        /// A pool worker that awaits the result runs queued jobs on its own stack while it waits,
        /// so blocking waits inside jobs must allow nesting. For example,
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
            let threads = self.groups.threads();
            let caller = Location::caller();

            // A worker of the strategy's pool submits under its current placement and can run
            // the job itself while waiting for the result.
            let own = self.own_placement();

            // A single-worker pool cannot overlap a hand-off, so the job always runs inline,
            // untimed. A strategy without a policy always hands the job off. Otherwise the policy
            // weighs the measured job cost against the offload round trip.
            let (mut plan, policy) = if threads <= 1 {
                (policy::SpawnPlan::fixed(policy::SpawnExecution::Inline), None)
            } else {
                self.policy.as_ref().map_or(
                    (policy::SpawnPlan::fixed(policy::SpawnExecution::Offload), None),
                    |policy| {
                        let plan = policy.choose_spawn(caller, len, threads, own.is_some());
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
                    // Offload: hand the job to the pool. The worker records the job wall, so job
                    // estimates survive a dropped future, and the awaiting future records the round
                    // trip when it observes the result.
                    //
                    // A worker's job inherits its placement. External roots can start on any
                    // worker, preferring their submitter's group. Admissions limit how many
                    // roots learn descendant placement. Excess roots execute Wide. Every
                    // external root leases all groups, preventing new homes until it finishes.
                    // Leases belong to the job, even after its future or parent is gone.
                    //
                    // external root -> shared Wide queue -> worker in group H
                    //                                       |
                    //           admitted, Local, full width +--> Local(H)
                    //                             otherwise +--> Wide
                    let (queued, placement, leases) = match own {
                        Some(placement @ rayon::Placement::Local(group)) => {
                            (placement, placement, Either::Left(self.groups.lease(group)))
                        }
                        Some(placement @ rayon::Placement::Wide { .. }) => {
                            (placement, placement, Either::Right(self.groups.wide()))
                        }
                        None => {
                            let (lease, admitted) = self.groups.for_job();
                            let group = lease.group();
                            let wide = rayon::Placement::Wide { near: group };
                            if admitted {
                                if self.groups.groups().len() > 1
                                    && let Some(policy) = policy
                                {
                                    plan = policy.choose_spawn_placement(caller, len, threads, plan);
                                }
                                let local = rayon::Placement::Local(group);
                                if plan.placement == Some(policy::Placement::Wide) {
                                    (wide, wide, Either::Right(lease.into_wide()))
                                } else {
                                    (wide, local, Either::Right(lease.into_wide()))
                                }
                            } else {
                                (wide, wide, Either::Right(lease.into_wide()))
                            }
                        }
                    };
                    let spawn_start = plan.measure.then(Instant::now);
                    let (tx, mut rx) = oneshot::channel();
                    let s = self.clone();
                    let pool = self.thread_pool.clone();
                    let worker_pool = self.thread_pool.clone();
                    let recorder = if plan.measure {
                        policy.cloned().map(|policy| (policy, caller, len, threads))
                    } else {
                        None
                    };
                    let worker_recorder = recorder.clone();
                    let job = move || {
                        // Local descendants use the worker that claimed the root. A narrower
                        // group cannot supply the learned width, so that root executes Wide
                        // without training the descendant-placement estimate.
                        let job_start = worker_recorder.is_some().then(Instant::now);
                        let mut plan = plan;
                        let placement = if own.is_none()
                            && matches!(placement, rayon::Placement::Local(_))
                        {
                            let current = worker_pool
                                .current_placement()
                                .expect("external root must run on a worker of its pool");
                            let (rayon::Placement::Local(group) | rayon::Placement::Wide { near: group }) = current;
                            let groups = s.groups.groups();
                            if groups[group].width() == groups[0].width() {
                                rayon::Placement::Local(group)
                            } else {
                                plan.placement = None;
                                rayon::Placement::Wide { near: group }
                            }
                        } else {
                            placement
                        };

                        // The pool aborts on an uncaught panic in a spawned job, so catch the
                        // panic and propagate it to the awaiting task.
                        let result = panic::catch_unwind(AssertUnwindSafe(|| {
                            worker_pool.install_in(placement, || f(s))
                        }));
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
                            policy.record_spawn_job(caller, len, threads, plan, job);
                        }
                    };
                    self.thread_pool.spawn_in(queued, move || {
                        let _leases = leases;
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
                        let (result, job) = payload.unwrap_or_else(|_| {
                            panic!("strategy job must not be dropped before completion")
                        });
                        match result {
                            Ok(value) => {
                                // The round trip starts after placement and lease acquisition.
                                // It includes channel setup, queueing, the job, and receiving
                                // the result. A late poll adds overlap slack to the sample and
                                // biases the choice toward inline, within the policy's budget.
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
                |execution, dispatch| match execution {
                    policy::RunExecution::Serial => run(Batches::whole(self, len)),
                    policy::RunExecution::Parallel => {
                        // Plan the batches with the parallelism of the dispatch the run was placed
                        // on, so a group of a grouped strategy gets no more batches than it has
                        // workers.
                        let parallelism = dispatch.parallelism;
                        let count = parallelism.min(len / minimum_batch_len.get());
                        let placed = self.placed(dispatch);
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
            self.execute(len, work, Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => run(Tiles::serial(self, grids, len)),
                policy::RunExecution::Parallel => {
                    let parallelism = dispatch.parallelism;
                    let placed = self.placed(dispatch);
                    run(Tiles::parallel(&placed, grids, len, parallelism))
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
            self.execute(items.len(), items.len(), Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => {
                    Sequential.fold_init(items, init, identity, fold_op, reduce_op)
                }
                policy::RunExecution::Parallel => self.thread_pool.install_in(dispatch.placement, || {
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
            self.execute(items.len(), items.len(), Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => Sequential.map_collect_vec(items, map_op),
                policy::RunExecution::Parallel => self.thread_pool.install_in(dispatch.placement, || {
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
            self.try_execute(items.len(), items.len(), Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => Sequential.try_map_collect_vec(items, map_op),
                policy::RunExecution::Parallel => self.thread_pool.install_in(dispatch.placement, || {
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
            self.execute(items.len(), items.len(), Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
                policy::RunExecution::Parallel => self.thread_pool.install_in(dispatch.placement, || {
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
            self.execute(items.len(), items.len().saturating_mul(multiplier), Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => Sequential.map_init_collect_vec(items, init, map_op),
                policy::RunExecution::Parallel => self.thread_pool.install_in(dispatch.placement, || {
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
            self.try_execute(items.len(), items.len(), Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => {
                    Sequential.try_fold(items, identity, fold_op, reduce_op)
                }
                policy::RunExecution::Parallel => self.thread_pool.install_in(dispatch.placement, || {
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
            // A thread outside the pool joins as the policy learns for the call site, with one
            // size class: serially on the caller, on one group, or on the whole pool.
            //
            // A strategy without a policy, such as a copy made by `placed` for a run already
            // placed, always joins on its pool under its own placement.
            if self.own_placement().is_some() {
                return rayon::join(a, b);
            }
            if self.policy.is_none() {
                let placement = self.own_dispatch().placement;
                return self
                    .thread_pool
                    .install_in(placement, || rayon::join(a, b));
            }
            self.execute(1, 1, Body::Placed, |execution, dispatch| match execution {
                policy::RunExecution::Serial => (a(), b()),
                policy::RunExecution::Parallel => self
                    .thread_pool
                    .install_in(dispatch.placement, || rayon::join(a, b)),
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
    use commonware_utils::Widen;
    use core::{num::NonZeroUsize, ops::Range};
    use futures::FutureExt;
    use proptest::prelude::*;
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

    /// A strategy on one pool whose workers form groups of `widths`, homed among `domains` fake
    /// domains. Worker `j` of group `i` is named `g{i}-{j}`. Every width but the last must equal
    /// the first.
    fn synthetic_groups(widths: &[usize], domains: usize) -> Rayon {
        let width = widths[0];
        let pool = ThreadPoolBuilder::new()
            .num_threads(widths.iter().sum())
            .group_width(width)
            .thread_name(move |index| format!("g{}-{}", index / width, index % width))
            .build()
            .unwrap();
        assert_eq!(pool.group_widths(), widths);
        let groups = crate::topology::Groups::synthetic(Arc::new(pool), domains);
        let parallelism = groups.threads();
        Rayon::over(Arc::new(groups), parallelism)
    }

    /// Blocks the calling thread until `future` completes, parking between polls. A job waits
    /// with this rather than `futures::executor::block_on`, since a worker awaiting another
    /// job may run it nested inside that executor, which refuses to nest.
    fn block_on_nested<F: core::future::Future>(future: F) -> F::Output {
        struct Unpark(std::thread::Thread);
        impl std::task::Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }

        let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = std::task::Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
            std::thread::park();
        }
    }

    fn hold_until_released(release: &AtomicUsize, bit: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(60);
        while release.load(Ordering::Acquire) & bit == 0 {
            if Instant::now() >= deadline {
                return false;
            }
            core::hint::spin_loop();
        }
        true
    }

    /// Local calls from a domain home a group there, and the strategy reports it.
    #[test]
    fn grouped_strategy_homes_a_group_for_local_calls() {
        let strategy = synthetic_groups(&[2, 2], 2);
        crate::topology::Groups::fake_domain(Some(1));
        for _ in 0..8 {
            let out = strategy.map_collect_vec(0..64u64, |x| {
                std::thread::sleep(Duration::from_micros(200));
                x + 1
            });
            assert_eq!(out, (1..=64).collect::<Vec<_>>());
        }
        crate::topology::Groups::fake_domain(None);
        let report = strategy.groups_report();
        assert!(report.contains("home Some(1)"), "{report}");
        assert!(report.contains("in_flight 0"), "{report}");
    }

    /// Runs one placed map from a thread outside the pool and returns its call site with the
    /// placement each item ran under. Each calling line is its own policy entry.
    #[track_caller]
    fn placed_map(
        strategy: &Rayon,
    ) -> (
        &'static std::panic::Location<'static>,
        Vec<Option<crate::rayon::Placement>>,
    ) {
        let placements = commonware_utils::sync::Mutex::new(Vec::new());
        let out = strategy.map_collect_vec(0..64u64, |x| {
            placements.lock().push(strategy.own_placement());
            x + 1
        });
        assert_eq!(out, (1..=64).collect::<Vec<_>>());
        (std::panic::Location::caller(), placements.into_inner())
    }

    /// A placed call from a thread whose domain has no home, or is unknown, still compares one
    /// group with the whole pool. Its local runs take the least loaded full-width group, even
    /// while every full-width group is busy, never the narrower final group, and record local
    /// samples. No group moves or gains a home.
    #[test]
    fn placed_call_without_a_home_compares_a_remote_group() {
        for caller in [Some(2), None] {
            let strategy = synthetic_groups(&[2, 2, 1], 3);
            crate::topology::Groups::fake_domain(Some(0));
            let first = strategy.groups.local().unwrap();
            crate::topology::Groups::fake_domain(Some(1));
            let second = strategy.groups.local().unwrap();
            crate::topology::Groups::fake_domain(caller);
            let runs: Vec<_> = (0..2).map(|_| placed_map(&strategy)).collect();
            crate::topology::Groups::fake_domain(None);
            drop((first, second));

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
            let report = strategy.groups_report();
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
    fn single_group_places_outside_calls_on_its_group() {
        let strategy = synthetic_groups(&[2], 2);
        crate::topology::Groups::fake_domain(Some(1));
        let (_, first) = placed_map(&strategy);
        let homed = strategy.groups_report();
        crate::topology::Groups::fake_domain(Some(0));
        let (_, second) = placed_map(&strategy);
        crate::topology::Groups::fake_domain(None);

        assert!(homed.contains("home Some(1)"), "{homed}");
        for placements in [first, second] {
            assert!(
                placements
                    .iter()
                    .all(|placement| *placement == Some(crate::rayon::Placement::Local(0))),
                "{placements:?}"
            );
        }
        let report = strategy.groups_report();
        assert!(report.contains("home Some(1)"), "{report}");
    }

    /// A fold reduces its partial results in input order when it seeds the whole pool.
    #[test]
    fn grouped_fold_init_keeps_input_order_on_the_wide_seed() {
        let strategy = synthetic_groups(&[2, 2], 2);
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
    fn grouped_strategy_keeps_a_workers_nested_call_in_its_group() {
        let strategy = synthetic_groups(&[2, 2], 2);
        let local = crate::rayon::Placement::Local(0);
        let groups = strategy.thread_pool.install_in(local, || {
            let seen = commonware_utils::sync::Mutex::new(Vec::new());
            for _ in 0..4 {
                let _: Vec<_> = strategy.map_collect_vec(0..32u64, |x| {
                    std::thread::sleep(Duration::from_micros(200));
                    seen.lock().push(
                        strategy
                            .thread_pool
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
    fn grouped_strategy_spreads_a_wide_workers_nested_call() {
        let strategy = synthetic_groups(&[2, 2], 2).without_policy();
        let wide = crate::rayon::Placement::Wide { near: 0 };
        let groups = strategy.thread_pool.install_in(wide, || {
            let seen = commonware_utils::sync::Mutex::new(std::collections::HashSet::new());
            let _: Vec<_> = strategy.map_collect_vec(0..64u64, |x| {
                std::thread::sleep(Duration::from_millis(1));
                seen.lock().insert(
                    strategy
                        .thread_pool
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
    /// of the job the worker runs, whether that placement is local or wide.
    #[test]
    fn a_workers_sort_stays_under_its_placement() {
        let grouped = synthetic_groups(&[2, 2], 2);
        let strategies = [false, true].into_iter().flat_map(|unstable| {
            [
                (grouped.without_policy(), unstable),
                (grouped.clone(), unstable),
            ]
        });
        for (strategy, unstable) in strategies {
            let sort = || {
                let placements = commonware_utils::sync::Mutex::new(Vec::new());
                let mut items: Vec<u64> = (0..1024).rev().collect();
                let compare = |a: &u64, b: &u64| {
                    placements.lock().push(strategy.own_placement());
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
            let local = crate::rayon::Placement::Local(1);
            let placements = strategy.thread_pool.install_in(local, sort);
            assert!(!placements.is_empty());
            assert!(
                placements.iter().all(|&p| p == Some(local)),
                "{placements:?}"
            );
            let wide = crate::rayon::Placement::Wide { near: 0 };
            let (placements, own) = strategy
                .thread_pool
                .install_in(wide, || (sort(), strategy.own_placement()));
            assert!(matches!(own, Some(crate::rayon::Placement::Wide { .. })));
            assert!(placements.iter().all(|&p| p == own), "{placements:?}");
        }
    }

    /// A collection operation placed on a group from a thread outside the pool runs every item
    /// on that group's workers, and the calling thread waits, as an install does.
    #[test]
    fn placed_local_call_runs_on_its_group_only() {
        let strategy = synthetic_groups(&[2, 2], 2);
        let placed = strategy.placed(&crate::Dispatch {
            placement: crate::rayon::Placement::Local(1),
            parallelism: 2,
        });
        let me = std::thread::current().id();
        let seen = commonware_utils::sync::Mutex::new(Vec::new());
        let out = placed.map_collect_vec(0..64u64, |x| {
            std::thread::sleep(Duration::from_millis(1));
            seen.lock().push((
                std::thread::current().id() == me,
                strategy
                    .thread_pool
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
    fn grouped_strategy_runs_competing_jobs_and_runs() {
        let strategy = synthetic_groups(&[2, 2], 3);
        std::thread::scope(|scope| {
            for domain in 0..3u16 {
                let strategy = &strategy;
                scope.spawn(move || {
                    crate::topology::Groups::fake_domain(Some(domain));
                    for round in 0..20u64 {
                        let jobs: Vec<_> = (0..4)
                            .map(|j| {
                                strategy.spawn(64, move |strategy| {
                                    // A job's nested call and its own child job stay in the
                                    // worker's group and are awaited there.
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
                .all(|group| !group.busy_with_others_for_test());
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
    fn inline_spawn_leaves_the_groups_untouched() {
        // A one-thread strategy runs every job inline.
        let strategy = synthetic_groups(&[1], 1);
        crate::topology::Groups::fake_domain(Some(0));
        let value = strategy.spawn(1, |_| 7).now_or_never();
        crate::topology::Groups::fake_domain(None);
        assert_eq!(value, Some(7));
        let report = strategy.groups_report();
        assert!(report.contains("home None"), "{report}");
        assert!(report.contains("in_flight 0"), "{report}");
    }

    /// A sort from a thread outside the pool, stable or unstable, runs on the group homed in the
    /// caller's domain and holds only that group's lease. The policy decides it against that group
    /// alone, so it never times the sort on the whole pool, and a serial sort runs on the caller.
    #[test]
    fn placed_sort_leases_only_the_group_it_sorts_on() {
        /// Every sort below goes through this helper, which tracks its caller, so the sorts from
        /// one line share one policy entry. Returns that line, the most groups in use while the
        /// sort compared, and the placements it compared under.
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
                placements.lock().push(strategy.own_placement());
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
            let strategy = synthetic_groups(&[2, 2], 2);
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
            let (wide, local) = policy
                .run_placement_estimates(site, 1024, 1024, strategy.parallelism)
                .unwrap();
            assert_eq!(
                wide, None,
                "a sort from outside the pool must not be timed on the whole pool"
            );
            assert!(local.is_some());
            let report = strategy.groups_report();
            assert!(report.contains("group 0: width 2 home Some(0)"), "{report}");
        }
    }

    /// A join from a thread outside the pool is placed like the other operations. A site's first
    /// join seeds the whole pool, and its second seeds the group homed in the caller's domain,
    /// runs both closures on that group's workers, and counts against that group while it runs.
    #[test]
    fn grouped_strategy_runs_an_outside_join_on_its_home_group() {
        /// Every join below goes through this helper, a single call site, so they share one policy
        /// entry. Returns the placement each closure ran under, with the groups' state while the
        /// first ran.
        fn join(
            strategy: &Rayon,
        ) -> (
            (Option<crate::rayon::Placement>, String),
            Option<crate::rayon::Placement>,
        ) {
            strategy.join(
                || (strategy.own_placement(), strategy.groups.describe()),
                || strategy.own_placement(),
            )
        }

        let strategy = synthetic_groups(&[2, 2], 2);

        // A lease from domain 0 homes the first group and holds it, so a local join from domain 1
        // homes the second.
        crate::topology::Groups::fake_domain(Some(0));
        let held = strategy.groups.local().unwrap();
        crate::topology::Groups::fake_domain(Some(1));
        let ((wide_first, _), wide_second) = join(&strategy);
        let ((first, report), second) = join(&strategy);
        crate::topology::Groups::fake_domain(None);
        drop(held);

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
        let report = strategy.groups_report();
        assert!(
            report.contains("group 1: width 2 home Some(1) in_flight 0"),
            "{report}"
        );
    }

    /// A waits on B in the other group, and B waits for C in A's group. With A's
    /// group-mate held, only A's native wait can execute C and complete the chain.
    #[test]
    fn waiting_worker_runs_jobs_queued_behind_it() {
        let strategy = synthetic_groups(&[2, 2], 2).without_policy();
        let (value_tx, value_rx) = futures::channel::oneshot::channel();
        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let b = strategy.thread_pool.install_in(Placement::Local(0), || {
            strategy.spawn(1, move |_| block_on_nested(value_rx).unwrap())
        });

        let release = Arc::new(AtomicUsize::new(0));
        let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let busy_release = Arc::clone(&release);
        strategy.thread_pool.spawn_in(Placement::Local(1), move || {
            let _ = occupied_tx.send(());
            let released = hold_until_released(&busy_release, 1);
            let _ = released_tx.send(released);
        });
        let occupied = occupied_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        let a = strategy.thread_pool.install_in(Placement::Local(1), || {
            strategy.spawn(1, move |_| {
                let _ = waiting_tx.send(());
                let _ = done_tx.send(block_on_nested(b));
            })
        });
        let waiting = waiting_rx.recv_timeout(Duration::from_secs(10)).is_ok();

        strategy.thread_pool.spawn_in(Placement::Local(1), move || {
            let _ = value_tx.send(42);
        });
        let result = done_rx.recv_timeout(Duration::from_secs(10)).ok();

        // Releasing the group-mate lets C finish even if A stopped helping its queue.
        release.store(1, Ordering::Release);
        let released = released_rx.recv_timeout(Duration::from_secs(10)).ok();
        futures::executor::block_on(a);
        assert!(occupied && waiting);
        assert_eq!(released, Some(true));
        assert_eq!(result, Some(42), "the native wait must complete the chain");
    }

    /// A strategy of one group leaves a collection operation from a thread outside its pool to
    /// the pool, as an install does, since its local and wide placements name the same workers.
    #[test]
    fn a_one_group_strategy_leaves_its_items_to_the_pool() {
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

    #[commonware_macros::test_group("miri")]
    #[test]
    fn external_root_uses_idle_group_and_keeps_its_local_lease() {
        let strategy = synthetic_groups(&[2, 2], 3).without_policy();
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
        let busy_pool = strategy.thread_pool.clone();
        let busy_release = Arc::clone(&release);
        strategy.thread_pool.spawn_broadcast_in(0, move || {
            let released = busy_pool.install_in(Placement::Wide { near: 0 }, || {
                let _ = occupied_tx.send(busy_pool.current_worker().unwrap());
                hold_until_released(&busy_release, 1)
            });
            let _ = busy_done_tx.send(released);
        });
        let occupied: Vec<_> = (0..2)
            .map(|_| occupied_rx.recv_timeout(Duration::from_secs(10)))
            .collect();

        let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
        let (root_done_tx, root_done_rx) = std::sync::mpsc::channel();
        let root_release = Arc::clone(&release);
        let root = strategy.spawn(1, move |strategy| {
            let before = strategy.thread_pool.current_worker().unwrap();
            let child = block_on_nested(
                strategy.spawn(1, |strategy| strategy.thread_pool.current_worker().unwrap()),
            );
            let after = strategy.thread_pool.current_worker().unwrap();
            let _ = arrived_tx.send((before, child, after));
            let released = hold_until_released(&root_release, 2);
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
        strategy.thread_pool.spawn_in(Placement::Local(1), move || {
            let _ = drained_tx.send(());
        });
        let child_drained = drained_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        let root_holds_actual = strategy.groups.groups()[1].busy_with_others_for_test();
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
            .any(|group| group.busy_with_others_for_test())
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
                .all(|group| !group.busy_with_others_for_test()),
            "completed jobs must release their claims"
        );
    }

    #[commonware_macros::test_group("miri")]
    #[test]
    fn spawned_root_uses_the_learned_descendant_width() {
        #[track_caller]
        fn check(wide: bool) {
            let strategy = synthetic_groups(&[2, 2], 2);
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
                        pool: crate::policy::SpawnPool::Pool,
                        placement: Some(placement),
                        measure: true,
                    },
                    Duration::from_millis(if preferred { 2 } else { 8 }),
                );
            }

            let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
            let (join_tx, join_rx) = std::sync::mpsc::channel();
            let job = strategy.spawn(64, move |strategy| {
                let before = strategy.thread_pool.current_worker().unwrap();
                let _ = arrived_tx.send(before.group);
                join_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let pool = &strategy.thread_pool;
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
                    strategy.thread_pool.current_worker().unwrap(),
                )
            });
            let group = arrived_rx.recv_timeout(Duration::from_secs(10)).unwrap();

            // Hold the root's group-mate. Only Wide descendants can use the other group.
            let release = Arc::new(AtomicUsize::new(0));
            let (occupied_tx, occupied_rx) = std::sync::mpsc::channel();
            let (released_tx, released_rx) = std::sync::mpsc::channel();
            let busy_release = Arc::clone(&release);
            strategy
                .thread_pool
                .spawn_in(Placement::Local(group), move || {
                    let _ = occupied_tx.send(());
                    let released = hold_until_released(&busy_release, 1);
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

    #[commonware_macros::test_group("miri")]
    #[test]
    fn narrow_root_uses_wide_descendants_without_recording_a_local_sample() {
        #[track_caller]
        fn check() {
            let strategy = synthetic_groups(&[2, 1], 2);
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
                    pool: crate::policy::SpawnPool::Pool,
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
            let pool = strategy.thread_pool.clone();
            strategy.thread_pool.spawn_broadcast_in(0, move || {
                let released = pool.install_in(Placement::Wide { near: 0 }, || {
                    let _ = occupied_tx.send(());
                    hold_until_released(&busy_release, 1)
                });
                let _ = released_tx.send(released);
            });
            let occupied: Vec<_> = (0..2)
                .map(|_| occupied_rx.recv_timeout(Duration::from_secs(10)).is_ok())
                .collect();
            let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
            let job = strategy.spawn(64, move |strategy| {
                let root = strategy.thread_pool.current_worker().unwrap();
                let child = block_on_nested(
                    strategy
                        .without_policy()
                        .spawn(1, |strategy| strategy.thread_pool.current_worker().unwrap()),
                );
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
            strategy.thread_pool.spawn_broadcast_in(1, move || {
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
    /// group under a local placement, and anywhere in the pool under a wide one.
    #[test]
    fn a_workers_spawned_job_runs_under_its_placement() {
        // Without a policy, every job is handed off to the pool rather than run inline.
        let strategy = synthetic_groups(&[2, 2], 2).without_policy();
        let spawn_under = |placement| {
            strategy.thread_pool.install_in(placement, || {
                futures::executor::block_on(strategy.spawn(1, |strategy| strategy.own_placement()))
            })
        };

        // A job spawned under a local placement stays on the worker's group.
        let local = Placement::Local(1);
        assert_eq!(spawn_under(local), Some(local));

        // A job spawned under a wide placement stays on the whole pool.
        assert!(matches!(
            spawn_under(Placement::Wide { near: 0 }),
            Some(Placement::Wide { .. })
        ));
    }

    /// Dropping a result future leaves its queued and running job's claims intact.
    #[commonware_macros::test_group("miri")]
    #[test]
    fn dropped_future_keeps_queued_job_claims() {
        // Hold every worker at a barrier so the submitted root must remain queued.
        let strategy = synthetic_groups(&[2, 2], 2).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let barrier = Arc::new(std::sync::Barrier::new(5));
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        for group in 0..2 {
            let (barrier, held_tx) = (Arc::clone(&barrier), held_tx.clone());
            strategy.thread_pool.spawn_broadcast_in(group, move || {
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
                .map(crate::topology::Group::busy_with_others_for_test)
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
        strategy.thread_pool.broadcast(|_| ());
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

    fn check_detached_job_lease(wide: bool) {
        let strategy = synthetic_groups(&[2, 2], 3).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let home = strategy.groups.local().unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let child = || {
            drop(strategy.spawn(1, move |strategy| {
                let _ = started_tx.send(strategy.own_placement());
                let _ = release_rx.recv_timeout(Duration::from_secs(60));
                let _ = done_tx.send(());
            }));
        };
        let placement = if wide {
            Placement::Wide { near: 0 }
        } else {
            Placement::Local(0)
        };
        let wide_leases = wide.then(|| strategy.groups.wide());
        strategy.thread_pool.install_in(placement, child);
        drop((home, wide_leases));
        let placement = started_rx.recv_timeout(Duration::from_secs(10)).ok();

        // The parent's install has returned. Only the detached child can keep its group busy.
        let busy: Vec<_> = strategy
            .groups
            .groups()
            .iter()
            .map(crate::topology::Group::busy_with_others_for_test)
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
            .any(|group| group.busy_with_others_for_test())
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
                .all(|group| !group.busy_with_others_for_test())
        );
    }

    #[commonware_macros::test_group("miri")]
    #[test]
    fn detached_local_job_keeps_its_group_busy() {
        check_detached_job_lease(false);
    }

    #[commonware_macros::test_group("miri")]
    #[test]
    fn detached_wide_job_keeps_every_group_busy() {
        check_detached_job_lease(true);
    }

    /// A Wide collection wakes every group and runs its parallel callbacks on pool workers.
    #[test]
    fn placed_wide_call_wakes_every_group_and_stays_on_workers() {
        let strategy = synthetic_groups(&[2, 2], 2);
        let placed = strategy.placed(&crate::Dispatch {
            placement: crate::rayon::Placement::Wide { near: 0 },
            parallelism: 4,
        });
        let pool = &strategy.thread_pool;
        let start = Instant::now();
        while pool.sleeping_workers() < pool.current_num_threads() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "every worker of the pool must go to sleep within 10 seconds"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let before = pool.wakeups();
        let me = std::thread::current().id();
        let on_caller = AtomicUsize::new(0);
        let out = placed.map_collect_vec(0..64u64, |x| {
            std::thread::sleep(Duration::from_millis(1));
            if std::thread::current().id() == me {
                on_caller.fetch_add(1, Ordering::Relaxed);
            }
            x
        });
        assert_eq!(out, (0..64).collect::<Vec<_>>());
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
        assert_eq!(policy.get_entry(loc, 10, 10, 4), Some((None, None)));

        let (loc, result) = run(false);
        assert_eq!(result, Ok(()));
        let established = policy.get_entry(loc, 10, 10, 4).unwrap();
        assert!(established.1.is_some());

        for _ in 0..20 {
            let (loc, _) = run(true);
            assert_eq!(policy.get_entry(loc, 10, 10, 4), Some(established));
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
    fn spawn_kept_in_a_workers_own_pool_records_no_hand_off() {
        let strategy = parallel_strategy();
        let policy = strategy.policy.as_ref().unwrap();
        let parallelism = strategy.parallelism;
        let (loc, value) = strategy
            .thread_pool
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
    fn spawn_worker_records_the_job_wall() {
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

    #[commonware_macros::test_group("miri")]
    #[test]
    fn overflowing_spawn_does_not_consult_or_train_placement() {
        let strategy = synthetic_groups(&[2, 2], 2);
        crate::topology::Groups::fake_domain(Some(0));
        let roots: Vec<_> = (0..2).map(|_| strategy.groups.for_job()).collect();
        assert!(roots.iter().all(|(_, admitted)| *admitted));

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
        let threads = strategy.thread_pool.current_num_threads();

        for _ in 0..2 {
            let plan = policy.choose_spawn(caller, 64, threads, false);
            assert_eq!(
                plan,
                crate::policy::SpawnPlan {
                    execution: crate::policy::SpawnExecution::Offload,
                    pool: crate::policy::SpawnPool::Pool,
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

        let one_worker = Rayon::new(NonZeroUsize::MIN).unwrap();
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
            ThreadPoolBuilder::new().num_threads(4).build().unwrap(),
        ));
        let policy = strategy.policy.as_ref().unwrap();
        let caller = std::panic::Location::caller();

        // Record samples that make serial the preferred path.
        policy.record_run_placed(
            caller,
            16,
            16,
            4,
            crate::policy::RunPlan {
                execution: crate::policy::RunExecution::Parallel,
                placement: crate::policy::Placement::Local,
                measure: true,
            },
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
        let strategy = Rayon::new(NonZeroUsize::MIN)
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
        let pool = ThreadPoolBuilder::new()
            .num_threads(2)
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
        check_moved_spawn_future(Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap(), 0);
    }

    #[commonware_macros::test_group("miri")]
    #[test]
    fn grouped_spawn_future_moved_to_worker_keeps_helping() {
        let strategy = synthetic_groups(&[2, 2], 2).without_policy();
        crate::topology::Groups::fake_domain(Some(0));
        let first = strategy.groups.local().unwrap();
        crate::topology::Groups::fake_domain(Some(1));
        let second = strategy.groups.local().unwrap();
        assert_eq!(second.group(), 1);
        check_moved_spawn_future(strategy, 1);
        crate::topology::Groups::fake_domain(None);
        drop((first, second));
    }

    fn check_moved_spawn_future(strategy: Rayon, group: usize) {
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
            strategy.thread_pool.spawn_broadcast_in(index, move || {
                let _ = occupied_tx.send(());
                let released = hold_until_released(&release, 1);
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
            let _ = started_tx.send(strategy.own_placement());
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
        strategy.thread_pool.spawn_in(placement, move || {
            let _ = polling_tx.send(());
            let _ = done_tx.send(block_on_nested(waiting));
        });
        let polling = polling_rx.recv_timeout(Duration::from_secs(10)).is_ok();

        // The other worker is blocked on this value, so only the native wait can send it.
        let sender = value_tx.clone();
        let (supplied_tx, supplied_rx) = std::sync::mpsc::channel();
        strategy.thread_pool.spawn_in(placement, move || {
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

    #[test]
    fn with_parallelism_overrides_planning_parallelism() {
        let strategy = Rayon::new(NonZeroUsize::new(1).unwrap())
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
    fn nested_placed_calls_run_on_the_workers_own_pool() {
        for threads in [1, 2] {
            let strategy = Rayon::new(NonZeroUsize::new(threads).unwrap())
                .unwrap()
                .with_parallelism(NonZeroUsize::new(4).unwrap())
                .without_policy();
            let pool = strategy.thread_pool.clone();
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
        let strategy = Rayon::new(NonZeroUsize::new(3).unwrap()).unwrap();
        assert_eq!(strategy.parallelism, 3);
    }

    /// A runtime that runs strategy work inline registers its executor thread as the sole
    /// worker of a pool, and that worker's runs still plan with the overridden parallelism.
    #[test]
    fn member_of_a_single_pool_plans_with_the_overridden_parallelism() {
        let pool = ThreadPoolBuilder::new()
            .num_threads(1)
            .use_current_thread()
            .build()
            .unwrap();
        let strategy =
            Rayon::with_pool(Arc::new(pool)).with_parallelism(NonZeroUsize::new(4).unwrap());
        assert!(
            strategy.own_placement().is_some(),
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

    /// A join from a thread outside the pool is decided by the policy, with one entry per call
    /// site for all of its joins, and a join on a worker of the pool runs in place without one.
    #[test]
    fn join_uses_one_adaptive_policy_entry_per_call_site() {
        let strategy = parallel_strategy();
        for _ in 0..3 {
            assert_eq!(strategy.join(|| 1, || 2), (1, 2));
        }
        assert_eq!(policy_len(&strategy), 1);
        assert_eq!(strategy.join(|| 3, || 4), (3, 4));
        assert_eq!(policy_len(&strategy), 2);

        let nested = strategy
            .thread_pool
            .install_in(Placement::Wide { near: 0 }, || strategy.join(|| 5, || 6));
        assert_eq!(nested, (5, 6));
        assert_eq!(policy_len(&strategy), 2);
    }

    /// A thread taken over as a pool's only worker, as a deterministic runtime's executor is,
    /// runs its collection operations in place and leaves no job queued behind it, since it runs
    /// no main loop that would ever take one.
    #[test]
    fn a_taken_over_thread_leaves_no_job_behind() {
        let pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(1)
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
        let pool = ThreadPoolBuilder::new()
            .num_threads(1)
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
            ThreadPoolBuilder::new().num_threads(4).build().unwrap(),
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
        let strategy = Rayon::new(NonZeroUsize::new(4).unwrap())
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
}
