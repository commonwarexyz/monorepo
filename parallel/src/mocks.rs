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
pub fn pending(workers: NonZeroUsize) -> Rayon {
    let pool: ThreadPool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(workers.get())
            .spawn_handler(|_| Ok(()))
            .build()
            .unwrap(),
    );
    Rayon::with_pool(pool)
}
