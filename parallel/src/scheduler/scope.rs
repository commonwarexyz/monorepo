//! Methods for custom fork-join scopes, created by the [`scope()`]
//! function. These are a more flexible alternative to [`join()`].
//!
//! [`join()`]: super::join()

use super::{
    job::{HeapJob, JobRef},
    latch::{CountLatch, Latch},
    registry::{Registry, WorkerThread, in_worker},
    unwind,
};
use std::{
    any::Any,
    fmt,
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicPtr, Ordering},
    },
};

#[cfg(test)]
mod test;

/// Represents a fork-join scope which can be used to spawn any number of tasks.
/// See [`scope()`] for more information.
pub(crate) struct Scope<'scope> {
    base: ScopeBase<'scope>,
}

struct ScopeBase<'scope> {
    /// thread registry where `scope()` was executed.
    registry: Arc<Registry>,

    /// if some job panicked, the error is stored here; it will be
    /// propagated to the one who created the scope
    panic: AtomicPtr<Box<dyn Any + Send + 'static>>,

    /// latch to track job counts
    job_completed_latch: CountLatch,

    /// You can think of a scope as containing a list of closures to execute,
    /// all of which outlive `'scope`.  They're not actually required to be
    /// `Sync`, but it's still safe to let the `Scope` implement `Sync` because
    /// the closures are only *moved* across threads to be executed.
    #[allow(clippy::type_complexity)]
    marker: PhantomData<Box<dyn FnOnce(&Scope<'scope>) + Send + Sync + 'scope>>,
}

/// Creates a "fork-join" scope `s` and invokes the closure with a
/// reference to `s`. This closure can then spawn asynchronous tasks
/// into `s`. Those tasks may run asynchronously with respect to the
/// closure; they may themselves spawn additional tasks into `s`. When
/// the closure returns, it will block until all tasks that have been
/// spawned into `s` complete.
///
/// `scope()` is a more flexible building block compared to `join()`,
/// since a loop can be used to spawn any number of tasks without
/// recursing. However, that flexibility comes at a performance price:
/// tasks spawned using `scope()` must be allocated onto the heap,
/// whereas `join()` can make exclusive use of the stack. **Prefer
/// `join()` where possible.**
///
/// # A note on threading
///
/// The closure given to `scope()` executes on the calling worker, and
/// those given to `spawn()` execute in its thread pool. This means that
/// you can't access thread-local variables (well, you can, but they may
/// have unexpected values).
///
/// # Task execution
///
/// Task execution potentially starts as soon as `spawn()` is called.
/// The task will end sometime before `scope()` returns. Note that the
/// *closure* given to scope may return much earlier. In general
/// the lifetime of a scope created like `scope(body)` goes something like this:
///
/// - Scope begins when `scope(body)` is called
/// - Scope body `body()` is invoked
///     - Scope tasks may be spawned
/// - Scope body returns
/// - Scope tasks execute, possibly spawning more tasks
/// - Once all tasks are done, scope ends and `scope()` returns
///
/// Everything spawned into a scope terminates (at latest) right before the
/// call to `scope` returns. This includes new subtasks created by other
/// subtasks. If a new scope is created inside a task, the things spawned
/// into that scope will be joined before that scope returns, which in turn
/// occurs before the creating task finishes.
///
/// There is no guaranteed order of execution for spawns in a scope,
/// given that other threads may steal tasks at any time. However, they
/// are generally prioritized in a LIFO order on the thread from which
/// they were spawned. Other threads always steal from the other end of
/// the deque, like FIFO order.  The idea is that "recent" tasks are most
/// likely to be fresh in the local CPU's cache, while other threads can
/// steal older "stale" tasks.
///
/// # Accessing stack data
///
/// In general, spawned tasks may access stack data in place that
/// outlives the scope itself. Other data must be fully owned by the
/// spawned task.
///
/// # Panics
///
/// If a panic occurs, either in the closure given to `scope()` or in
/// any of the spawned jobs, that panic will be propagated and the
/// call to `scope()` will panic. If multiple panics occurs, it is
/// non-deterministic which of their panic values will propagate.
/// Regardless, once a task is spawned using `scope.spawn()`, it will
/// execute, even if the spawning task should later panic. `scope()`
/// returns once all spawned jobs have completed, and any panics are
/// propagated at that point.
///
/// Panics if the calling thread is not a worker of a thread pool.
pub(crate) fn scope<'scope, OP, R>(op: OP) -> R
where
    OP: FnOnce(&Scope<'scope>) -> R + Send,
    R: Send,
{
    in_worker(|owner_thread, _| {
        let scope = Scope::<'scope>::new(owner_thread);
        scope.base.complete(owner_thread, || op(&scope))
    })
}

impl<'scope> Scope<'scope> {
    fn new(owner: &WorkerThread) -> Self {
        let base = ScopeBase::new(owner);
        Scope { base }
    }

    /// Spawns a job into the fork-join scope `self`. This job will
    /// execute sometime before the fork-join scope completes.  The
    /// job is specified as a closure, and this closure receives its
    /// own reference to the scope `self` as argument. This can be
    /// used to inject new jobs into `self`.
    ///
    /// # Returns
    ///
    /// Nothing. The spawned closures cannot pass back values to the
    /// caller directly, though they can write to local variables on
    /// the stack (if those variables outlive the scope) or
    /// communicate through shared channels.
    ///
    /// # See also
    ///
    /// The [`scope` function] has more extensive documentation about
    /// task spawning.
    ///
    /// [`scope` function]: scope()
    pub(crate) fn spawn<BODY>(&self, body: BODY)
    where
        BODY: FnOnce(&Self) + Send + 'scope,
    {
        let scope_ptr = ScopePtr(self);
        let job = HeapJob::new(move || {
            // SAFETY: this job will execute before the scope ends.
            unsafe {
                let scope = scope_ptr.as_ref();
                ScopeBase::execute_job(&scope.base, move || body(scope))
            }
        });
        let job_ref = self.base.heap_job_ref(job);

        // Since `Scope` implements `Sync`, we can't be sure that we're still in a
        // thread of this pool, so we can't just push to the local worker thread.
        self.base.registry.inject_or_push(job_ref);
    }
}

impl<'scope> ScopeBase<'scope> {
    /// Creates the base of a new scope for the registry of `owner`
    fn new(owner: &WorkerThread) -> Self {
        ScopeBase {
            registry: Arc::clone(owner.registry()),
            panic: AtomicPtr::new(ptr::null_mut()),
            job_completed_latch: CountLatch::new(Some(owner)),
            marker: PhantomData,
        }
    }

    fn heap_job_ref<FUNC>(&self, job: Box<HeapJob<FUNC>>) -> JobRef
    where
        FUNC: FnOnce() + Send + 'scope,
    {
        // SAFETY: the job is counted in the scope's latch, so the scope waits for it to execute
        // before the data it closes over can expire.
        unsafe {
            self.job_completed_latch.increment();
            job.into_job_ref()
        }
    }

    /// Executes `func` as a job, either aborting or executing as
    /// appropriate.
    fn complete<FUNC, R>(&self, owner: &WorkerThread, func: FUNC) -> R
    where
        FUNC: FnOnce() -> R,
    {
        // SAFETY: `self` is alive for the whole call.
        let result = unsafe { Self::execute_job_closure(self, func) };
        self.job_completed_latch.wait(Some(owner));
        self.maybe_propagate_panic();
        result.unwrap() // only None if `op` panicked, and that would have been propagated
    }

    /// Executes `func` as a job, either aborting or executing as
    /// appropriate.
    unsafe fn execute_job<FUNC>(this: *const Self, func: FUNC)
    where
        FUNC: FnOnce(),
    {
        // SAFETY: the caller guarantees `this` is valid on entry.
        let _: Option<()> = unsafe { Self::execute_job_closure(this, func) };
    }

    /// Executes `func` as a job in scope. Adjusts the "job completed"
    /// counters and also catches any panic and stores it into
    /// `scope`.
    unsafe fn execute_job_closure<FUNC, R>(this: *const Self, func: FUNC) -> Option<R>
    where
        FUNC: FnOnce() -> R,
    {
        // SAFETY: the caller guarantees `this` is valid on entry, and the scope stays alive until
        // the latch counts this job as complete, which is the last access.
        unsafe {
            let result = match unwind::halt_unwinding(func) {
                Ok(r) => Some(r),
                Err(err) => {
                    (*this).job_panicked(err);
                    None
                }
            };
            Latch::set(&(*this).job_completed_latch);
            result
        }
    }

    fn job_panicked(&self, err: Box<dyn Any + Send + 'static>) {
        // capture the first error we see, free the rest
        if self.panic.load(Ordering::Relaxed).is_null() {
            let nil = ptr::null_mut();
            let mut err = ManuallyDrop::new(Box::new(err)); // box up the fat ptr
            let err_ptr: *mut Box<dyn Any + Send + 'static> = &mut **err;
            if self
                .panic
                .compare_exchange(nil, err_ptr, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                // ownership now transferred into self.panic
            } else {
                // another panic raced in ahead of us, so drop ours
                let _: Box<Box<_>> = ManuallyDrop::into_inner(err);
            }
        }
    }

    fn maybe_propagate_panic(&self) {
        // propagate panic, if any occurred; at this point, all
        // outstanding jobs have completed, so we can use a relaxed
        // ordering:
        let panic = self.panic.swap(ptr::null_mut(), Ordering::Relaxed);
        if !panic.is_null() {
            // SAFETY: a non-null pointer is the box leaked by `job_panicked`, taken out of the
            // scope by the swap, so it is reclaimed once.
            let value = unsafe { Box::from_raw(panic) };
            unwind::resume_unwinding(*value);
        }
    }
}

impl fmt::Debug for Scope<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Scope")
            .field("pool_id", &self.base.registry.id())
            .field("panic", &self.base.panic)
            .field("job_completed_latch", &self.base.job_completed_latch)
            .finish()
    }
}

/// Used to capture a scope `&Self` pointer in jobs, without faking a lifetime.
///
/// Unsafe code is still required to dereference the pointer, but that's fine in
/// scope jobs that are guaranteed to execute before the scope ends.
struct ScopePtr<T>(*const T);

// SAFETY: !Send for raw pointers is not for safety, just as a lint
unsafe impl<T: Sync> Send for ScopePtr<T> {}

// SAFETY: !Sync for raw pointers is not for safety, just as a lint
unsafe impl<T: Sync> Sync for ScopePtr<T> {}

impl<T> ScopePtr<T> {
    // Helper to avoid disjoint captures of `scope_ptr.0`
    const unsafe fn as_ref(&self) -> &T {
        // SAFETY: the caller guarantees the scope is still alive.
        unsafe { &*self.0 }
    }
}
