use super::{
    job::{ArcJob, StackJob},
    latch::{CountLatch, LatchRef},
    registry::{Registry, WorkerThread},
};
use std::{fmt, marker::PhantomData, ops::Range, sync::Arc};

#[cfg(test)]
mod test;

/// Provides context to a closure called by `broadcast`.
pub struct BroadcastContext<'a> {
    worker: &'a WorkerThread,

    /// Make sure to prevent auto-traits like `Send` and `Sync`.
    _marker: PhantomData<&'a mut dyn Fn()>,
}

impl BroadcastContext<'_> {
    pub(super) fn with<R>(f: impl FnOnce(BroadcastContext<'_>) -> R) -> R {
        let worker_thread = WorkerThread::current();
        assert!(!worker_thread.is_null());
        f(BroadcastContext {
            // SAFETY: a broadcast runs on a worker, whose state outlives the call.
            worker: unsafe { &*worker_thread },
            _marker: PhantomData,
        })
    }

    /// Our index amongst the broadcast threads (ranges from `0..self.num_threads()`).
    #[inline]
    pub const fn index(&self) -> usize {
        self.worker.index()
    }

    /// The number of threads receiving the broadcast in the thread pool.
    #[inline]
    pub fn num_threads(&self) -> usize {
        self.worker.registry().num_threads()
    }
}

impl fmt::Debug for BroadcastContext<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("BroadcastContext")
            .field("index", &self.index())
            .field("num_threads", &self.num_threads())
            .field("pool_id", &self.worker.registry().id())
            .finish()
    }
}

/// Execute `op` on every thread in the pool. It will be executed on each
/// thread when they have nothing else to do locally, before they try to
/// steal work from other threads. This function will not return until all
/// threads have completed the `op`.
///
/// Unsafe because `registry` must not yet have terminated.
pub(super) unsafe fn broadcast_in<OP, R>(
    op: OP,
    registry: &Arc<Registry>,
    workers: Range<usize>,
) -> Vec<R>
where
    OP: Fn(BroadcastContext<'_>) -> R + Sync,
    R: Send,
{
    let f = move |injected: bool| {
        debug_assert!(injected);
        BroadcastContext::with(&op)
    };

    let n_threads = workers.len();
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let current_thread = unsafe { WorkerThread::current().as_ref() };
    let latch = CountLatch::with_count(n_threads, current_thread);
    let jobs: Vec<_> = (0..n_threads)
        .map(|_| StackJob::new(&f, LatchRef::new(&latch)))
        .collect();
    // SAFETY: the jobs stay on this stack frame until the latch counts every one of them as
    // executed.
    let job_refs = jobs.iter().map(|job| unsafe { job.as_job_ref() });

    registry.inject_broadcast(workers, job_refs);

    // Wait for all jobs to complete, then collect the results, maybe propagating a panic.
    latch.wait(current_thread);
    // SAFETY: every job has executed, so each holds its result.
    jobs.into_iter()
        .map(|job| unsafe { job.into_result() })
        .collect()
}

/// Execute `op` on every thread in the pool. It will be executed on each
/// thread when they have nothing else to do locally, before they try to
/// steal work from other threads. This function returns immediately after
/// injecting the jobs.
///
/// Unsafe because `registry` must not yet have terminated.
pub(super) unsafe fn spawn_broadcast_in<OP>(op: OP, registry: &Arc<Registry>, workers: Range<usize>)
where
    OP: Fn(BroadcastContext<'_>) + Send + Sync + 'static,
{
    let job = ArcJob::new({
        let registry = Arc::clone(registry);
        move || {
            registry.catch_unwind(|| BroadcastContext::with(&op));
            registry.terminate(); // (*) permit registry to terminate now
        }
    });

    let n_threads = workers.len();
    let job_refs = (0..n_threads).map(|_| {
        // Ensure that registry cannot terminate until this job has executed
        // on each thread. This ref is decremented at the (*) above.
        registry.increment_terminate_count();

        ArcJob::as_static_job_ref(&job)
    });

    registry.inject_broadcast(workers, job_refs);
}
