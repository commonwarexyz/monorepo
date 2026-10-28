use super::{
    job::StackJob,
    latch::SpinLatch,
    registry::{self, WorkerThread},
    unwind,
};
use std::{any::Any, marker::PhantomData};

#[cfg(test)]
mod test;

/// Provides the calling context to a closure called by `join_context`.
#[derive(Debug)]
pub(super) struct FnContext {
    migrated: bool,

    /// disable `Send` and `Sync`, just for a little future-proofing.
    _marker: PhantomData<*mut ()>,
}

impl FnContext {
    #[inline]
    const fn new(migrated: bool) -> Self {
        Self {
            migrated,
            _marker: PhantomData,
        }
    }

    /// Returns `true` if the closure was called from a different thread
    /// than it was provided from.
    #[inline]
    pub(super) const fn migrated(&self) -> bool {
        self.migrated
    }
}

/// Takes two closures and *potentially* runs them in parallel. It
/// returns a pair of the results from those closures.
///
/// Conceptually, calling `join()` is similar to spawning two threads,
/// one executing each of the two closures. However, the
/// implementation is quite different and incurs very low
/// overhead. The underlying technique is called "work stealing": the
/// scheduler uses a fixed pool of worker threads and attempts to
/// only execute code in parallel when there are idle CPUs to handle
/// it.
///
/// The calling thread must be a worker of a pool, and it actively
/// participates in the thread pool. It will begin by executing closure
/// A (on the current thread). While it is doing that, it will advertise
/// closure B as being available for other threads to execute. Once closure A
/// has completed, the current thread will try to execute closure B;
/// if however closure B has been stolen, then it will look for other work
/// while waiting for the thief to fully execute closure B. (This is the
/// typical work-stealing strategy).
///
/// # Warning about blocking I/O
///
/// The assumption is that the closures given to `join()` are
/// CPU-bound tasks that do not perform I/O or other blocking
/// operations. If you do perform I/O, and that I/O should block
/// (e.g., waiting for a network request), the overall performance may
/// be poor.  Moreover, if you cause one closure to be blocked waiting
/// on another (for example, using a channel), that could lead to a
/// deadlock.
///
/// # Panics
///
/// No matter what happens, both closures will always be executed.  If
/// a single closure panics, whether it be the first or second
/// closure, that panic will be propagated and hence `join()` will
/// panic with the same panic value. If both closures panic, `join()`
/// will panic with the panic value from the first closure.
///
/// Panics if the calling thread is not a worker of a thread pool.
pub(crate) fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    #[inline]
    fn call<R>(f: impl FnOnce() -> R) -> impl FnOnce(FnContext) -> R {
        move |_| f()
    }

    join_context(call(oper_a), call(oper_b))
}

/// Identical to `join`, except that the closures have a parameter
/// that provides context for the way the closure has been called,
/// especially indicating whether they're executing on a different
/// thread than where `join_context` was called.  This will occur if
/// the second job is stolen by a different thread.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool.
pub(super) fn join_context<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
where
    A: FnOnce(FnContext) -> RA + Send,
    B: FnOnce(FnContext) -> RB + Send,
    RA: Send,
    RB: Send,
{
    #[inline]
    fn call_a<R>(f: impl FnOnce(FnContext) -> R, injected: bool) -> impl FnOnce() -> R {
        move || f(FnContext::new(injected))
    }

    #[inline]
    fn call_b<R>(f: impl FnOnce(FnContext) -> R) -> impl FnOnce(bool) -> R {
        move |migrated| f(FnContext::new(migrated))
    }

    registry::in_worker(|worker_thread, injected| {
        // Create virtual wrapper for task b; this all has to be
        // done here so that the stack frame can keep it all live
        // long enough.
        let job_b = StackJob::new(call_b(oper_b), SpinLatch::new(worker_thread));
        // SAFETY: `job_b` stays on this stack frame until it has run inline or its latch is set,
        // and `worker_thread` is the calling thread's worker state.
        unsafe {
            let job_b_ref = job_b.as_job_ref();
            let job_b_id = job_b_ref.id();
            worker_thread.push(job_b_ref);

            // Execute task a; hopefully b gets stolen in the meantime.
            let status_a = unwind::halt_unwinding(call_a(oper_a, injected));
            let result_a = match status_a {
                Ok(v) => v,
                Err(err) => join_recover_from_panic(worker_thread, &job_b.latch, err),
            };

            // Now that task A has finished, try to pop job B from the
            // local stack.  It may already have been popped by job A; it
            // may also have been stolen. There may also be some tasks
            // pushed on top of it in the stack, and we will have to pop
            // those off to get to it.
            while !job_b.latch.probe() {
                let Some(job) = worker_thread.take_local_job() else {
                    // Local deque is empty. Time to steal from other
                    // threads.
                    worker_thread.wait_until(&job_b.latch);
                    debug_assert!(job_b.latch.probe());
                    break;
                };
                if job_b_id == job.id() {
                    // Found it! Let's run it.
                    //
                    // Note that this could panic, but it's ok if we unwind here.
                    let result_b = job_b.run_inline(injected);
                    return (result_a, result_b);
                }
                worker_thread.execute(job);
            }

            (result_a, job_b.into_result())
        }
    })
}

/// If job A panics, we still cannot return until we are sure that job
/// B is complete. This is because it may contain references into the
/// enclosing stack frame(s).
#[cold] // cold path
unsafe fn join_recover_from_panic(
    worker_thread: &WorkerThread,
    job_b_latch: &SpinLatch<'_>,
    err: Box<dyn Any + Send>,
) -> ! {
    // SAFETY: `worker_thread` is the calling thread's worker state.
    unsafe { worker_thread.wait_until(job_b_latch) };
    unwind::resume_unwinding(err)
}
