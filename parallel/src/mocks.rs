//! Mock strategy configurations for testing.

use crate::{Rayon, ThreadPool};
use core::num::NonZeroUsize;
use rayon::ThreadPoolBuilder;
use std::sync::Arc;

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
