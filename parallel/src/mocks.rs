//! Mock strategy configurations for testing.
//!
//! An adaptive [`Rayon`] chooses the execution shape of every call from measurements, so a test
//! cannot tell which shape it ran. An [`Explorer`] chooses each shape by rule instead, and
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
use std::{
    hash::DefaultHasher,
    sync::{Arc, LazyLock},
    thread,
};

/// The seeded rules [`explore`] runs after the serial and parallel ones.
const SEEDS: u64 = 4;

/// The strategy [`explore`] runs every rule on: four workers planning eight tasks, so the most
/// parallel shapes cut more batches and tiles than the pool has workers.
static EXPLORED: LazyLock<Rayon> = LazyLock::new(|| {
    Rayon::new(NonZeroUsize::new(4).unwrap())
        .expect("failed to build the explored pool")
        .with_parallelism(NonZeroUsize::new(8).unwrap())
});

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
    /// A copy of the strategy that runs every operation at the planning parallelism instead of
    /// adapting per call site: parallel bodies run whenever the parallelism exceeds one, batches
    /// and tiles are planned at that parallelism on the shared pool, and a spawned job always
    /// hands off to a multi-worker pool. An [`Explorer`] chooses its shapes on top of it.
    pub(crate) fn without_policy(&self) -> Self {
        Self {
            policy: None,
            ..self.clone()
        }
    }
}

/// How an [`Explorer`] chooses the shape of each call.
#[derive(Clone, Copy, Debug)]
enum Rule {
    /// Every call takes its serial shape.
    Serial,
    /// Every call takes its most parallel shape.
    Parallel,
    /// Each call takes a shape picked by hashing the seed, the call site, and the call's length.
    Seeded(u64),
}

/// A strategy that chooses the execution shape of each call by a fixed rule instead of from
/// measurements.
///
/// An adaptive [`Rayon`] may run any call serially or in parallel, and may cut batches and tiles
/// for fewer workers than it plans for, so code generic over [`Strategy`] must produce the same
/// result whatever it chooses at each call. An explorer makes each of those choices by rule on a
/// [`Rayon`]'s pool: the serial or parallel body of [`run`](Strategy::run), the calling thread
/// or the pool for a collection operation, the whole input or up to the planning parallelism of
/// balanced batches for [`run_batches`](Strategy::run_batches), one worker or up to that many for
/// [`run_tiles`](Strategy::run_tiles), and inline or on the pool for a spawned job.
///
/// [`explore`] runs a closure under serial, fully parallel, and seeded explorers, and
/// [`Explorer::parallel`] pins the most parallel shapes.
#[derive(Clone, Debug)]
pub struct Explorer {
    // The explored strategy without its policy: its pool runs the parallel shapes, and its planning
    // parallelism bounds the batch and worker counts.
    strategy: Rayon,
    rule: Rule,
}

impl Explorer {
    /// Returns a strategy that takes the most parallel shape of `strategy` at every call.
    ///
    /// Parallel bodies run whenever the planning parallelism exceeds one, batches and tiles are cut
    /// for the full planning parallelism, and a spawned job is handed to the pool, which runs it
    /// off the calling task unless the pool has a single worker. This pins a shape for tests that
    /// count batches or need a job to leave the calling task.
    pub fn parallel(strategy: &Rayon) -> Self {
        Self::new(strategy, Rule::Parallel)
    }

    /// Returns a strategy that picks the shape of each call by hashing `seed`, the call site, and
    /// the call's length, so a seed repeats its choices.
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
                (hasher.finish() % options as u64) as usize
            }
        }
    }

    /// Whether a call at `caller` over `len` items takes its parallel shape, which needs a
    /// planning parallelism above one.
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
        // Batches are dispatched through the explorer, which also chooses whether they run on the
        // calling thread or the pool.
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
        // Shares are dispatched through the explorer, so they may also run one after another on the
        // calling thread, as when workers start late.
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
    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        if self.parallel_at(Location::caller(), 2) {
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

/// Runs `f` under several execution shapes and returns its output, which every run must match.
///
/// `f` runs serially, then with the most parallel shape at every call, then under four seeded
/// rules (see [`Explorer::seeded`]), each of which mixes serial and parallel calls and cuts batch
/// and worker counts between one and the planning parallelism. Every run uses a shared strategy of
/// four workers planning eight tasks. Code generic over [`Strategy`] must return the same output
/// from each run, as it must from an adaptive [`Rayon`], which may make any of these choices at
/// any call.
///
/// # Panics
///
/// Panics if a run returns a different output than the serial run, naming the run's rule, or if
/// `f` panics, after reporting the rule on stderr. [`Explorer::seeded`] over a strategy planning
/// eight tasks repeats the choices of a seeded run.
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
    let mut run = |rule| {
        let _report = Report(rule);
        f(&Explorer::new(&EXPLORED, rule))
    };
    let serial = run(Rule::Serial);
    for rule in iter::once(Rule::Parallel).chain((0..SEEDS).map(Rule::Seeded)) {
        assert_eq!(
            run(rule),
            serial,
            "the {rule:?} run disagrees with the serial run"
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

    /// The shapes a [`probe`] took: its batch count, its `run` body, whether its spawned job left
    /// the calling thread, and whether its map ran on the pool.
    type Shapes = (usize, &'static str, bool, bool);

    /// Makes one call of each kind through `strategy` and returns the shapes they took.
    fn probe(strategy: &impl Strategy) -> Shapes {
        let batches = strategy.run_batches(64, NonZeroUsize::MIN, 1, |batches| {
            batches
                .map_collect_vec(|ranges| ranges, |range| range)
                .len()
        });
        let body = strategy.run(64, || "serial", || "parallel");
        let caller = thread::current().id();
        let offloaded = block_on(strategy.spawn(1, move |_| thread::current().id() != caller));
        let pooled = strategy
            .map_collect_vec(0..64, |_| rayon::current_thread_index().is_some())
            .into_iter()
            .all(|pooled| pooled);
        (batches, body, offloaded, pooled)
    }

    #[test]
    fn explore_runs_serial_parallel_and_seeded_shapes() {
        // Record the shapes of every run, returning an output that no shape changes.
        let mut runs = Vec::new();
        let sum = explore(|strategy| {
            runs.push(probe(strategy));
            strategy.fold(0..100u64, || 0, |acc, n| acc + n, |a, b| a + b)
        });
        assert_eq!(sum, 4950);

        // The serial run takes every serial shape, the parallel run cuts as many batches as the
        // explored strategy plans tasks, and the seeded runs follow.
        assert_eq!(runs.len(), 2 + SEEDS as usize);
        assert_eq!(runs[0], (1, "serial", false, false));
        assert_eq!(runs[1], (8, "parallel", true, true));
    }

    #[test]
    #[should_panic(expected = "the Parallel run disagrees with the serial run")]
    fn explore_rejects_an_output_that_depends_on_the_shape() {
        // The serial and parallel runs take different bodies of the same call.
        explore(|strategy| strategy.run(64, || "serial", || "parallel"));
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
        // whole input to the planning parallelism.
        let counts: BTreeSet<_> = shapes.iter().map(|shape| shape.0).collect();
        assert_eq!(counts, (1..=8).collect());
        let bodies: BTreeSet<_> = shapes.iter().map(|shape| shape.1).collect();
        assert_eq!(bodies, BTreeSet::from(["parallel", "serial"]));
        let offloads: BTreeSet<_> = shapes.iter().map(|shape| shape.2).collect();
        assert_eq!(offloads, BTreeSet::from([false, true]));
        let pools: BTreeSet<_> = shapes.iter().map(|shape| shape.3).collect();
        assert_eq!(pools, BTreeSet::from([false, true]));
    }

    #[test]
    fn parallel_explorer_takes_the_most_parallel_shapes() {
        // Every call takes its parallel shape at the planning parallelism.
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap())
            .unwrap()
            .with_parallelism(NonZeroUsize::new(3).unwrap());
        assert_eq!(
            probe(&Explorer::parallel(&strategy)),
            (3, "parallel", true, true)
        );

        // Planning one task keeps bodies and collection operations serial, while the pool still
        // takes spawned jobs.
        let serial = strategy.with_parallelism(NonZeroUsize::MIN);
        assert_eq!(
            probe(&Explorer::parallel(&serial)),
            (1, "serial", true, false)
        );

        // A single-worker pool runs spawned jobs inline.
        let single = Rayon::new(NonZeroUsize::MIN).unwrap();
        assert_eq!(
            probe(&Explorer::parallel(&single)),
            (1, "serial", false, false)
        );
    }
}
