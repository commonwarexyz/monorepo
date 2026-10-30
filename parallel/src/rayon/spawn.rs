use super::{
    job::{HeapJob, JobRef},
    registry::Registry,
    unwind,
};
use std::{mem, sync::Arc};

#[cfg(test)]
mod test;

/// Spawns an asynchronous job in `registry.`
///
/// Unsafe because `registry` must not yet have terminated.
pub(super) unsafe fn spawn_in<F>(func: F, registry: &Arc<Registry>)
where
    F: FnOnce() + Send + 'static,
{
    // We assert that this does not hold any references (we know
    // this because of the `'static` bound in the interface);
    // moreover, we assert that the code below is not supposed to
    // be able to panic, and hence the data won't leak but will be
    // enqueued into some deque for later execution.
    let abort_guard = unwind::AbortIfPanic; // just in case we are wrong, and code CAN panic
    // SAFETY: the caller guarantees `registry` has not terminated.
    let job_ref = unsafe { spawn_job(func, registry) };
    registry.inject_or_push(job_ref);
    mem::forget(abort_guard);
}

unsafe fn spawn_job<F>(func: F, registry: &Arc<Registry>) -> JobRef
where
    F: FnOnce() + Send + 'static,
{
    // Ensure that registry cannot terminate until this job has
    // executed. This ref is decremented at the (*) below.
    registry.increment_terminate_count();

    HeapJob::new({
        let registry = Arc::clone(registry);
        move || {
            registry.catch_unwind(func);
            registry.terminate(); // (*) permit registry to terminate now
        }
    })
    .into_static_job_ref()
}
