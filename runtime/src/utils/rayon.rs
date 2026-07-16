//! Shared single-threaded Rayon pool for executors that run all work inline.

use commonware_parallel::ThreadPool;
use rayon::{ThreadPoolBuildError, ThreadPoolBuilder};
use std::sync::Arc;

// Rayon permits one permanent registry registration per OS thread. Cache the pool that
// registered the executor thread so later requests and runners (of any single-threaded
// runtime flavor) reuse it.
commonware_utils::thread_local_cache!(static THREAD_POOL: ThreadPool);

/// Returns the single-threaded pool the executor thread registered with, created on first use.
///
/// All pool work executes inline on the executor thread, so a larger pool would only
/// add permanently unstarted workers.
///
/// Rayon's current-thread registration is permanent and per-OS-thread, so only one pool
/// can ever execute work on the executor thread. Every request (including from a later
/// runner on the same thread) returns that pool.
pub(crate) fn shared_thread_pool() -> Result<ThreadPool, ThreadPoolBuildError> {
    let pool = commonware_utils::Cached::take(
        &THREAD_POOL,
        || {
            ThreadPoolBuilder::new()
                .num_threads(1)
                .use_current_thread()
                .build()
                .map(Arc::new)
        },
        |_| Ok(()),
    )?;
    Ok(Arc::clone(&pool))
}
