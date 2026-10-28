//! Running one job on every worker of a group. Each worker takes it from its own broadcast deque
//! once it has exhausted its local work, before it tries to steal from other workers, and runs
//! the broadcasts queued for it in the order they were queued.

use super::{job::ArcJob, registry::Registry};
#[cfg(test)]
use super::{job::StackJob, latch::CountLatch, registry::WorkerThread};
use std::sync::Arc;

#[cfg(test)]
mod test;

/// Executes `op` on every worker of `group` and returns once all of them have, with their
/// results in worker order. A panic in `op` propagates after every worker has run it.
///
/// Unsafe because `registry` must not yet have terminated.
#[cfg(test)]
pub(super) unsafe fn broadcast_in<OP, R>(op: OP, registry: &Arc<Registry>, group: usize) -> Vec<R>
where
    OP: Fn() -> R + Sync,
    R: Send,
{
    let f = move |injected: bool| {
        debug_assert!(injected);
        op()
    };

    let workers = registry.group_range(group);
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let current_thread = unsafe { WorkerThread::current().as_ref() };
    let jobs: Vec<_> = workers
        .clone()
        .map(|_| StackJob::new(&f, CountLatch::new(current_thread)))
        .collect();
    // SAFETY: the jobs stay on this stack frame until each one's latch is set, once it has
    // executed.
    let job_refs = jobs.iter().map(|job| unsafe { job.as_job_ref() });

    registry.inject_broadcast(workers, job_refs);

    // Wait for all jobs to complete, then collect the results, maybe propagating a panic.
    for job in &jobs {
        job.latch.wait(current_thread);
    }
    // SAFETY: every job has executed, so each holds its result.
    jobs.into_iter()
        .map(|job| unsafe { job.into_result() })
        .collect()
}

/// Queues `op` to run on every worker of `group` and returns at once.
///
/// Unsafe because `registry` must not yet have terminated.
pub(super) unsafe fn spawn_broadcast_in<OP>(op: OP, registry: &Arc<Registry>, group: usize)
where
    OP: Fn() + Send + Sync + 'static,
{
    let job = ArcJob::new({
        let registry = Arc::clone(registry);
        move || {
            registry.catch_unwind(&op);
            registry.terminate(); // (*) permit registry to terminate now
        }
    });

    let workers = registry.group_range(group);
    let job_refs = workers.clone().map(|_| {
        // Ensure that registry cannot terminate until this job has executed
        // on each thread. This ref is decremented at the (*) above.
        registry.increment_terminate_count();

        ArcJob::as_static_job_ref(&job)
    });

    registry.inject_broadcast(workers, job_refs);
}
