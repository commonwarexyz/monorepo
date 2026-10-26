//! Mock strategy configurations for testing.
//!
//! An adaptive [`Rayon`] chooses the execution shape of every call from measurements, so a test
//! cannot tell which shape it ran. An [`Explorer`] chooses each shape by a fixed rule, and
//! [`explore`] runs a closure under serial, fully parallel, and seeded mixtures of shapes.

use crate::{Batches, Grid, Rayon, Sequential, Strategy, ThreadPool, Tiles};
use core::{
    cmp::Ordering,
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    iter,
    num::NonZeroUsize,
    panic::Location,
};
use futures::future::{self, Either};
use rayon::ThreadPoolBuilder;
use std::{hash::DefaultHasher, sync::Arc, thread};

/// The number of seeded rules [`explore`] runs after the serial and parallel ones.
const SEEDS: u64 = 4;

/// Returns a strategy whose spawned jobs run inline at submission: a single-worker pool with the
/// planning parallelism overridden to `parallelism`.
pub fn inline(parallelism: NonZeroUsize) -> Rayon {
    Rayon::new(NonZeroUsize::MIN)
        .unwrap()
        .with_parallelism(parallelism)
}

/// Returns a strategy whose spawned jobs never run: `workers` workers are registered but never
/// started, so offloaded jobs queue forever.
///
/// # Panics
///
/// Panics if `workers` is 1: `spawn` runs jobs inline at submission on a single-worker pool,
/// which would violate this mock's contract.
pub fn pending(workers: NonZeroUsize) -> Rayon {
    assert!(
        workers.get() >= 2,
        "pending requires a multi-worker pool: spawn inlines jobs on a single-worker pool"
    );
    let pool: ThreadPool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(workers.get())
            .spawn_handler(|_| Ok(()))
            .build()
            .unwrap(),
    );
    Rayon::with_pool(pool)
}

impl Rayon {
    /// Returns a copy of the strategy without its policy. It keeps the pool and the planning
    /// parallelism.
    ///
    /// Without a policy, parallel bodies run whenever the planning parallelism exceeds one, and
    /// batches and tiles are planned at that parallelism. A spawned job is handed off whenever
    /// the pool has more than one worker.
    pub(crate) fn without_policy(&self) -> Self {
        Self {
            policy: None,
            ..self.clone()
        }
    }
}

/// How an [`Explorer`] chooses the shape of each call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// Every call takes its serial shape.
    Serial,
    /// Every call takes its most parallel shape.
    Parallel,
    /// Each call takes a shape picked by hashing the seed, the call site, and the call's length.
    Seeded(u64),
}

/// A strategy that chooses the execution shape of each call by a fixed rule.
///
/// An adaptive [`Rayon`] may run any call serially or in parallel and may cut batches and tiles
/// for fewer workers than it plans for, so code generic over [`Strategy`] must produce the same
/// result whatever it chooses. An explorer makes each of these choices by rule on a [`Rayon`]'s
/// pool:
///
/// - [`run`](Strategy::run) takes its serial or parallel body.
/// - A collection operation runs on the calling thread or on the pool.
/// - [`join`](Strategy::join) runs its closures on the calling thread or on the pool.
/// - [`run_batches`](Strategy::run_batches) supplies the whole input as one batch or splits it
///   into balanced batches, at most one per planned task.
/// - [`run_tiles`](Strategy::run_tiles) cuts serial tiles or shares them among at most one
///   worker per planned task.
/// - A spawned job runs inline or is handed to the pool.
///
/// [`explore`] runs a closure under serial, fully parallel, and seeded explorers, and
/// [`Explorer::parallel`] pins the most parallel shapes.
#[derive(Clone, Debug)]
pub struct Explorer {
    // The explored strategy without its policy. Its pool runs the parallel shapes, and its
    // planning parallelism bounds the batch and worker counts.
    strategy: Rayon,
    // How the explorer chooses the shape of each call.
    rule: Rule,
}

impl Explorer {
    /// Returns a strategy that takes the most parallel shape of `strategy` at every call.
    ///
    /// When the planning parallelism exceeds one, [`run`](Strategy::run) takes its parallel body
    /// and collection operations run on the pool. A run is cut into as many batches as the
    /// planning parallelism and minimum batch length allow, and tiles are cut for one worker per
    /// planned task.
    ///
    /// [`join`](Strategy::join) always runs on the pool, and a spawned job is handed to the pool
    /// unless the pool has a single worker. A worker of that pool that waits on the job may run it
    /// itself, as with any spawn on a [`Rayon`]. This pins a shape for tests that count batches or
    /// need a job to run on the pool.
    pub fn parallel(strategy: &Rayon) -> Self {
        Self::new(strategy, Rule::Parallel)
    }

    /// Returns a strategy that picks the shape of each call by hashing `seed`, the call site, and
    /// the call's length, so a seed repeats its choices on the same toolchain.
    pub fn seeded(strategy: &Rayon, seed: u64) -> Self {
        Self::new(strategy, Rule::Seeded(seed))
    }

    fn new(strategy: &Rayon, rule: Rule) -> Self {
        Self {
            strategy: strategy.without_policy(),
            rule,
        }
    }

    /// Picks one of `options` shapes, ordered from serial to most parallel, for a call at `caller`
    /// over `len` items.
    fn pick(&self, caller: &Location<'_>, len: usize, options: usize) -> usize {
        match self.rule {
            Rule::Serial => 0,
            Rule::Parallel => options - 1,
            Rule::Seeded(seed) => {
                let mut hasher = DefaultHasher::new();
                (seed, caller, len).hash(&mut hasher);
                let options = u64::try_from(options).expect("usize fits in u64");
                usize::try_from(hasher.finish() % options).expect("the pick is below options")
            }
        }
    }

    /// Whether a call at `caller` over `len` items takes its parallel shape. A strategy planning
    /// one task never does.
    fn parallel_at(&self, caller: &Location<'_>, len: usize) -> bool {
        self.strategy.parallelism > 1 && self.pick(caller, len, 2) == 1
    }
}

impl Strategy for Explorer {
    #[track_caller]
    fn spawn<F, T>(&self, len: usize, f: F) -> impl Future<Output = T> + Send + 'static
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        let strategy = self.clone();
        if self.pick(Location::caller(), len, 2) == 1 {
            Either::Left(self.strategy.spawn(len, move |_| f(strategy)))
        } else {
            Either::Right(future::ready(f(strategy)))
        }
    }

    #[track_caller]
    fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        if self.parallel_at(Location::caller(), len) {
            parallel()
        } else {
            serial()
        }
    }

    #[track_caller]
    fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        if self.parallel_at(Location::caller(), len) {
            parallel()
        } else {
            serial()
        }
    }

    #[track_caller]
    fn try_run_batches<R, E, F>(
        &self,
        len: usize,
        minimum_batch_len: NonZeroUsize,
        _multiplier: usize,
        run: F,
    ) -> Result<R, E>
    where
        R: Send,
        E: Send,
        F: for<'scope> FnOnce(Batches<'scope, Self>) -> Result<R, E> + Send,
    {
        // Batches dispatch through the explorer, so it also chooses whether split batches run on
        // the pool or one after another on the calling thread.
        let most = self
            .strategy
            .parallelism
            .min(len / minimum_batch_len.get())
            .max(1);
        match self.pick(Location::caller(), len, most) + 1 {
            1 => run(Batches::whole(self, len)),
            count => run(Batches::balanced(self, len, count)),
        }
    }

    #[track_caller]
    fn run_tiles<R, F>(&self, len: usize, grids: &[Grid], _multiplier: usize, run: F) -> R
    where
        R: Send,
        F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
    {
        // Shares dispatch through the explorer, so they may run on the pool or one after another
        // on the calling thread, as when the pool's workers start late.
        match self.pick(Location::caller(), len, self.strategy.parallelism) + 1 {
            1 => run(Tiles::serial(self, grids, len)),
            workers => run(Tiles::parallel(self, grids, len, workers)),
        }
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
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy
                .fold_init(items, init, identity, fold_op, reduce_op)
        } else {
            Sequential.fold_init(items, init, identity, fold_op, reduce_op)
        }
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
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy.try_fold(items, identity, fold_op, reduce_op)
        } else {
            Sequential.try_fold(items, identity, fold_op, reduce_op)
        }
    }

    #[track_caller]
    fn map_collect_vec<I, F, T>(&self, iter: I, map_op: F) -> Vec<T>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        F: Fn(I::Item) -> T + Send + Sync,
        T: Send,
    {
        let items: Vec<I::Item> = iter.into_iter().collect();
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy.map_collect_vec(items, map_op)
        } else {
            Sequential.map_collect_vec(items, map_op)
        }
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
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy.try_map_collect_vec(items, map_op)
        } else {
            Sequential.try_map_collect_vec(items, map_op)
        }
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
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy.map_init_collect_vec(items, init, map_op)
        } else {
            Sequential.map_init_collect_vec(items, init, map_op)
        }
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
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy
                .map_init_collect_vec_with_multiplier(items, multiplier, init, map_op)
        } else {
            Sequential.map_init_collect_vec_with_multiplier(items, multiplier, init, map_op)
        }
    }

    #[track_caller]
    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        // A Rayon joins on its pool whatever its planning parallelism.
        if self.pick(Location::caller(), 2, 2) == 1 {
            self.strategy.join(a, b)
        } else {
            Sequential.join(a, b)
        }
    }

    #[track_caller]
    fn sort_by<T, C>(&self, items: &mut [T], compare: C)
    where
        T: Send,
        C: Fn(&T, &T) -> Ordering + Send + Sync,
    {
        if self.parallel_at(Location::caller(), items.len()) {
            self.strategy.sort_by(items, compare);
        } else {
            Sequential.sort_by(items, compare);
        }
    }
}

/// Runs `f` under several execution shapes and returns the output of its serial run.
///
/// `f` runs serially, then with the most parallel shape at every call, then under four seeded
/// rules ([`Explorer::seeded`]), all on one strategy of four workers planning eight tasks. A
/// seeded run mixes serial and parallel calls and picks batch and worker counts up to the planning
/// parallelism. Code generic over [`Strategy`] must return the same output from every run, since
/// an adaptive [`Rayon`] may make any of these choices at any call.
///
/// Each call builds that strategy and drops its own handle before returning, so the pool goes
/// with the last [`Explorer`] that holds it.
///
/// # Panics
///
/// Panics, naming the run's rule, if a run returns a different output than the serial run. When `f`
/// panics, `explore` prints that run's rule on stderr and the panic propagates. To reproduce a
/// seeded run, use [`Explorer::seeded`] with its seed on a strategy planning eight tasks.
///
/// # Examples
///
/// ```
/// use commonware_parallel::{Strategy, mocks::explore};
///
/// let squares = explore(|strategy| strategy.map_collect_vec(0..4u64, |n| n * n));
/// assert_eq!(squares, [0, 1, 4, 9]);
/// ```
#[track_caller]
pub fn explore<R, F>(mut f: F) -> R
where
    R: PartialEq + fmt::Debug,
    F: FnMut(&Explorer) -> R,
{
    // Each call builds its own pool of four workers planning eight tasks, so the most parallel
    // shapes cut more batches and tiles than the pool has workers. CI runs the SIMD test suites
    // under Intel SDE, and a pool that outlives the test can keep the process from exiting there.
    let strategy = Rayon::new(NonZeroUsize::new(4).unwrap())
        .expect("the explored pool must build")
        .with_parallelism(NonZeroUsize::new(8).unwrap());
    let mut run = |rule| {
        let _report = Report(rule);
        f(&Explorer::new(&strategy, rule))
    };
    let serial = run(Rule::Serial);
    for rule in iter::once(Rule::Parallel).chain((0..SEEDS).map(Rule::Seeded)) {
        assert_eq!(
            run(rule),
            serial,
            "the {rule:?} run must return the serial run's output"
        );
    }
    serial
}

/// Reports the rule of an [`explore`] run on stderr when the run panics.
struct Report(Rule);

impl Drop for Report {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!("explore: the {:?} run panicked", self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Plan;
    use futures::{FutureExt, executor::block_on};
    use std::collections::BTreeSet;

    #[test]
    fn inline_runs_spawned_jobs_at_submission() {
        let strategy = inline(NonZeroUsize::new(4).unwrap());

        // The planning parallelism cuts a run into four batches on the single worker.
        let batches = strategy
            .without_policy()
            .run_batches(16, NonZeroUsize::MIN, 1, |batches| {
                batches
                    .map_collect_vec(|ranges| ranges, |range| range)
                    .len()
            });
        assert_eq!(batches, 4);
        assert_eq!(strategy.spawn(1, |_| 7).now_or_never(), Some(7));
    }

    /// Construction must return (rayon's `build` does not wait for workers to prime) and the
    /// spawned job must stay queued forever.
    #[test]
    fn pending_never_completes_spawned_jobs() {
        let strategy = pending(NonZeroUsize::new(2).unwrap());

        assert!(strategy.spawn(1, |_| 7).now_or_never().is_none());
    }

    #[test]
    #[should_panic(expected = "pending requires a multi-worker pool")]
    fn pending_rejects_single_worker() {
        pending(NonZeroUsize::MIN);
    }

    /// The shapes the calls of one [`probe`] took.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Shapes {
        /// Batches its run was cut into.
        batches: usize,
        /// Workers its tiles were planned for, one for serial tiles.
        tile_workers: usize,
        /// The body its `run` took.
        body: &'static str,
        /// Whether its spawned job left the calling thread.
        offloaded: bool,
        /// Whether its map ran on the pool.
        pooled: bool,
        /// Whether its join ran on the pool.
        joined: bool,
    }

    /// The shapes every call takes under a serial rule.
    const SERIAL_SHAPES: Shapes = Shapes {
        batches: 1,
        tile_workers: 1,
        body: "serial",
        offloaded: false,
        pooled: false,
        joined: false,
    };

    /// Makes one call of each kind through `strategy` and returns the shapes they took.
    fn probe(strategy: &impl Strategy) -> Shapes {
        let batches = strategy.run_batches(64, NonZeroUsize::MIN, 1, |batches| {
            batches
                .map_collect_vec(|ranges| ranges, |range| range)
                .len()
        });
        let grid = Grid {
            rows: 4,
            tile_cost: NonZeroUsize::MIN,
        };
        let tile_workers = strategy.run_tiles(64, &[grid], 1, |tiles| match tiles.plan {
            Plan::Serial => 1,
            Plan::Shared { workers, .. } => workers,
        });
        let body = strategy.run(64, || "serial", || "parallel");
        let caller = thread::current().id();
        let offloaded = block_on(strategy.spawn(1, move |_| thread::current().id() != caller));
        let pooled = strategy
            .map_collect_vec(0..64, |_| rayon::current_thread_index().is_some())
            .into_iter()
            .all(|pooled| pooled);
        let (joined, ()) = strategy.join(|| rayon::current_thread_index().is_some(), || ());
        Shapes {
            batches,
            tile_workers,
            body,
            offloaded,
            pooled,
            joined,
        }
    }

    /// The shapes every call takes under a parallel rule planning `parallelism` tasks on a
    /// multi-worker pool.
    const fn parallel_shapes(parallelism: usize) -> Shapes {
        Shapes {
            batches: parallelism,
            tile_workers: parallelism,
            body: "parallel",
            offloaded: true,
            pooled: true,
            joined: true,
        }
    }

    #[test]
    fn explore_runs_serial_parallel_and_seeded_shapes() {
        // Record the shapes of every run, and return a sum that no shape changes.
        let mut runs = Vec::new();
        let sum = explore(|strategy| {
            runs.push(probe(strategy));
            strategy.fold(0..100u64, || 0, |acc, n| acc + n, |a, b| a + b)
        });
        assert_eq!(sum, 4950);

        // The serial run takes every serial shape, the parallel run takes every parallel shape
        // with one batch per planned task, and a run per seed follows.
        assert_eq!(
            runs.len(),
            2 + usize::try_from(SEEDS).expect("SEEDS fits in usize")
        );
        assert_eq!(runs[0], SERIAL_SHAPES);
        assert_eq!(runs[1], parallel_shapes(8));
    }

    #[test]
    fn explore_runs_the_rules_in_order() {
        // The serial run comes first, so every other run is checked against its output.
        let mut rules = Vec::new();
        explore(|strategy| rules.push(strategy.rule));
        assert_eq!(
            rules,
            [
                Rule::Serial,
                Rule::Parallel,
                Rule::Seeded(0),
                Rule::Seeded(1),
                Rule::Seeded(2),
                Rule::Seeded(3),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "the Parallel run must return the serial run's output")]
    fn explore_rejects_an_output_that_depends_on_the_shape() {
        // The serial and parallel runs take different bodies of the same call.
        explore(|strategy| strategy.run(64, || "serial", || "parallel"));
    }

    #[test]
    fn explore_drops_its_pool_on_return() {
        // Every run shares one pool, and nothing holds it once `explore` returns.
        let mut pools = Vec::new();
        explore(|strategy| pools.push(Arc::downgrade(&strategy.strategy.thread_pool)));
        assert!(pools.iter().all(|pool| pool.ptr_eq(&pools[0])));
        assert!(
            pools[0].upgrade().is_none(),
            "explore must drop its pool before it returns"
        );
    }

    #[test]
    fn seeded_explorers_repeat_and_vary_their_shapes() {
        // Probe many seeds on a strategy planning eight tasks.
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap())
            .unwrap()
            .with_parallelism(NonZeroUsize::new(8).unwrap());
        let shapes: Vec<_> = (0..256)
            .map(|seed| probe(&Explorer::seeded(&strategy, seed)))
            .collect();

        // A seed repeats its shapes.
        for (seed, shape) in (0..).zip(&shapes) {
            assert_eq!(probe(&Explorer::seeded(&strategy, seed)), *shape);
        }

        // Across seeds, every call takes each of its shapes, including every batch count from the
        // whole input to the planning parallelism and every tile worker count.
        let counts: BTreeSet<_> = shapes.iter().map(|shape| shape.batches).collect();
        assert_eq!(counts, (1..=8).collect());
        let workers: BTreeSet<_> = shapes.iter().map(|shape| shape.tile_workers).collect();
        assert_eq!(workers, (1..=8).collect());
        let bodies: BTreeSet<_> = shapes.iter().map(|shape| shape.body).collect();
        assert_eq!(bodies, BTreeSet::from(["parallel", "serial"]));
        let flags: [fn(&Shapes) -> bool; 3] = [
            |shape| shape.offloaded,
            |shape| shape.pooled,
            |shape| shape.joined,
        ];
        for flag in flags {
            let seen: BTreeSet<_> = shapes.iter().map(flag).collect();
            assert_eq!(seen, BTreeSet::from([false, true]));
        }
    }

    #[test]
    fn seeded_choices_depend_on_the_call_site_and_the_length() {
        fn body(strategy: &Explorer, len: usize) -> &'static str {
            strategy.run(len, || "serial", || "parallel")
        }
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();
        let explorers: Vec<_> = (0..64)
            .map(|seed| Explorer::seeded(&strategy, seed))
            .collect();

        // Some seed takes different bodies at one call site for two lengths.
        assert!(
            explorers
                .iter()
                .any(|explorer| body(explorer, 10) != body(explorer, 11))
        );

        // Some seed takes different bodies at two call sites for one length.
        assert!(explorers.iter().any(|explorer| {
            let first = explorer.run(10, || "serial", || "parallel");
            let second = explorer.run(10, || "serial", || "parallel");
            first != second
        }));
    }

    #[test]
    fn explore_runs_every_map_operation() {
        // Each map, stateful ones included, keeps input order, and a fallible map reports its one
        // failure, whatever shape the run takes.
        let (squares, shifted, failed, doubled, weighted) = explore(|strategy| {
            let squares = strategy.map_collect_vec(0..100u64, |n| n * n);
            let shifted: Result<Vec<u64>, u64> =
                strategy.try_map_collect_vec(0..100u64, |n| Ok(n + 1));
            let failed: Result<Vec<u64>, u64> =
                strategy.try_map_collect_vec(0..100u64, |n| if n == 57 { Err(n) } else { Ok(n) });
            let doubled = strategy.map_init_collect_vec(0..100u64, Vec::new, |seen, n| {
                seen.push(n);
                n * 2
            });
            let weighted =
                strategy.map_init_collect_vec_with_multiplier(0..100u64, 4, || (), |_, n| n + 3);
            (squares, shifted, failed, doubled, weighted)
        });
        assert_eq!(squares, (0..100u64).map(|n| n * n).collect::<Vec<_>>());
        assert_eq!(shifted, Ok((1..=100u64).collect()));
        assert_eq!(failed, Err(57));
        assert_eq!(doubled, (0..100u64).map(|n| n * 2).collect::<Vec<_>>());
        assert_eq!(weighted, (3..103u64).collect::<Vec<_>>());
    }

    #[test]
    fn parallel_explorer_takes_the_most_parallel_shapes() {
        // Every call takes its parallel shape at the planning parallelism.
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap())
            .unwrap()
            .with_parallelism(NonZeroUsize::new(3).unwrap());
        assert_eq!(probe(&Explorer::parallel(&strategy)), parallel_shapes(3));

        // Planning one task keeps bodies and collection operations serial, while the pool still
        // takes spawned jobs and joins.
        let serial = strategy.with_parallelism(NonZeroUsize::MIN);
        assert_eq!(
            probe(&Explorer::parallel(&serial)),
            Shapes {
                offloaded: true,
                joined: true,
                ..SERIAL_SHAPES
            }
        );

        // A single-worker pool runs spawned jobs inline but still joins on its worker.
        let single = Rayon::new(NonZeroUsize::MIN).unwrap();
        assert_eq!(
            probe(&Explorer::parallel(&single)),
            Shapes {
                joined: true,
                ..SERIAL_SHAPES
            }
        );
    }
}
