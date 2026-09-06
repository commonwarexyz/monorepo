//! Mock strategy configurations for testing.

use crate::{Manual, Rayon, Sequential, Strategy, ThreadPool};
use core::num::NonZeroUsize;
use rayon::ThreadPoolBuilder;
use std::{
    future::{self, Future},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

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

/// Counts job submissions and executes them when their returned futures are polled.
///
/// Independent instances distinguish execution pools without starting worker threads.
#[derive(Clone, Debug, Default)]
pub struct CountingStrategy {
    spawns: Arc<AtomicUsize>,
    stall_at: Option<usize>,
}

impl CountingStrategy {
    /// Leaves the zero-based submission `stall_at` pending forever.
    pub fn stalling(stall_at: usize) -> Self {
        Self {
            stall_at: Some(stall_at),
            ..Self::default()
        }
    }

    /// Returns how many jobs this pool has been handed.
    pub fn spawns(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }
}

impl Strategy for CountingStrategy {
    fn manual(&self) -> Manual<Self> {
        Manual {
            strategy: self.clone(),
            parallelism: 1,
        }
    }

    fn spawn<F, T>(&self, _: usize, operation: F) -> impl Future<Output = T> + Send + 'static
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        let call = self.spawns.fetch_add(1, Ordering::SeqCst);
        let strategy = self.clone();
        async move {
            if strategy.stall_at == Some(call) {
                future::pending::<()>().await;
            }
            operation(strategy)
        }
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
        C: Fn(&T, &T) -> std::cmp::Ordering + Send + Sync,
    {
        Sequential.sort_by(items, compare);
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
}
