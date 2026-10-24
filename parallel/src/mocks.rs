//! Mock strategy configurations for testing.

use crate::{Manual, Rayon, Sequential, Strategy, ThreadPool};
use core::num::NonZeroUsize;
use rayon::ThreadPoolBuilder;
use std::sync::{Arc, Mutex};

/// Returns a strategy whose spawned jobs run inline at submission: a single-worker pool with the
/// manual parallelism overridden to `parallelism`.
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

/// A sequential-executing strategy that reports a chosen planning parallelism and records the
/// work hints passed to multiplier-aware operations.
///
/// Every operation executes like [Sequential], so tests stay deterministic, while the reported
/// parallelism engages callers' parallel planning paths and [Recording::multiplier_calls]
/// exposes the hints they passed.
#[derive(Clone, Debug)]
pub struct Recording {
    parallelism: usize,
    multiplier_calls: Arc<Mutex<Vec<(usize, usize)>>>,
}

/// Returns a [Recording] strategy whose [Strategy::manual] reports `parallelism`.
pub fn recording(parallelism: NonZeroUsize) -> Recording {
    Recording {
        parallelism: parallelism.get(),
        multiplier_calls: Arc::new(Mutex::new(Vec::new())),
    }
}

impl Recording {
    /// The `(items, multiplier)` pairs passed to multiplier-aware operations, in call order.
    pub fn multiplier_calls(&self) -> Vec<(usize, usize)> {
        self.multiplier_calls.lock().expect("lock poisoned").clone()
    }
}

impl Strategy for Recording {
    fn manual(&self) -> Manual<Self> {
        Manual::new(self.clone(), self.parallelism)
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
        core::future::ready(f(self.clone()))
    }

    fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        Sequential.run(len, serial, parallel)
    }

    fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        Sequential.try_run(len, serial, parallel)
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
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        Sequential.fold_init(iter, init, identity, fold_op, reduce_op)
    }

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
        Sequential.try_fold(iter, identity, fold_op, reduce_op)
    }

    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        Sequential.join(a, b)
    }

    fn sort_by<T, C>(&self, items: &mut [T], compare: C)
    where
        T: Send,
        C: Fn(&T, &T) -> core::cmp::Ordering + Send + Sync,
    {
        Sequential.sort_by(items, compare)
    }

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
        self.multiplier_calls
            .lock()
            .expect("lock poisoned")
            .push((items.len(), multiplier));
        Sequential.map_init_collect_vec(items, init, map_op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Strategy;
    use futures::FutureExt;

    #[test]
    fn inline_runs_spawned_jobs_at_submission() {
        let strategy = inline(NonZeroUsize::new(4).unwrap());

        assert_eq!(strategy.manual().parallelism(), 4);
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

    /// The recording strategy reports the requested planning parallelism, executes
    /// sequentially, and records the hints passed through the multiplier-aware maps
    /// (including calls routed through the stateless convenience wrapper).
    #[test]
    fn recording_reports_parallelism_and_records_multiplier_calls() {
        let strategy = recording(NonZeroUsize::new(4).unwrap());
        assert_eq!(strategy.manual().parallelism(), 4);

        let doubled: Vec<usize> = strategy.map_collect_vec_with_multiplier(0..3, 7, |x| x * 2);
        assert_eq!(doubled, vec![0, 2, 4]);
        assert_eq!(strategy.multiplier_calls(), vec![(3, 7)]);

        let summed: Vec<usize> =
            strategy.map_init_collect_vec_with_multiplier(0..2, 9, || 1, |state, x| *state + x);
        assert_eq!(summed, vec![1, 2]);
        assert_eq!(strategy.multiplier_calls(), vec![(3, 7), (2, 9)]);
    }
}
