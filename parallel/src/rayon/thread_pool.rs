//! Contains support for user-managed thread pools, represented by the
//! the [`ThreadPool`] type (see that struct for details).

#[cfg(any(test, all(target_os = "linux", not(miri))))]
use super::registry::WorkerThread;
use super::{
    ThreadPoolBuildError, ThreadPoolBuilder,
    broadcast::{self, BroadcastContext},
    latch::OnceLatch,
    registry::{Placement, Registry},
    spawn,
};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

#[cfg(test)]
mod test;

/// Represents a user-created [thread pool].
///
/// Use a [`ThreadPoolBuilder`] to specify the number and/or names of threads
/// in the pool. After calling [`ThreadPoolBuilder::build()`], you can then
/// execute functions explicitly within this [`ThreadPool`] using
/// [`ThreadPool::install()`].
///
/// [`install()`][`ThreadPool::install()`] executes a closure in one of the `ThreadPool`'s
/// threads. In addition, any other scheduler operations called inside of `install()` will also
/// execute in the context of the `ThreadPool`.
///
/// When the `ThreadPool` is dropped, that's a signal for the threads it manages to terminate,
/// they will complete executing any remaining work that you have spawned, and automatically
/// terminate.
///
///
/// [thread pool]: https://en.wikipedia.org/wiki/Thread_pool
/// [`ThreadPoolBuilder::build()`]: ThreadPoolBuilder::build()
/// [`ThreadPool::install()`]: Self::install()
pub struct ThreadPool {
    registry: Arc<Registry>,
}

struct WorkerWake {
    latch: OnceLatch,
    registry: Arc<Registry>,
    index: usize,
}

impl Wake for WorkerWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // SAFETY: this Arc keeps the latch and registry alive through the notification.
        // The worker that created this waker is the only thread that waits on its latch.
        unsafe { OnceLatch::set_and_tickle_one(&self.latch, &self.registry, self.index) };
    }
}

impl ThreadPool {
    pub(super) fn build(builder: ThreadPoolBuilder) -> Result<Self, ThreadPoolBuildError> {
        let registry = Registry::new(builder)?;
        Ok(Self { registry })
    }

    /// Executes `op` within the thread pool. Any attempts to use
    /// `join` will then operate within that thread pool.
    ///
    /// # Warning: thread-local data
    ///
    /// Because `op` is executing within the thread pool,
    /// thread-local data from the current thread will not be
    /// accessible.
    ///
    /// # Warning: execution order
    ///
    /// If the current thread is part of a different thread pool, it will try to
    /// keep busy while the `op` completes in its target pool, similar to
    /// calling [`ThreadPool::yield_now()`] in a loop. Therefore, it may
    /// potentially schedule other tasks to run on the current thread in the
    /// meantime.
    ///
    /// # Panics
    ///
    /// If `op` should panic, that panic will be propagated.
    pub fn install<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        self.install_in(
            self.current_placement()
                .unwrap_or(Placement::Wide { near: 0 }),
            op,
        )
    }

    /// Executes `op` within every thread in the thread pool. Any attempts to use
    /// `join` will then operate within that thread pool.
    ///
    /// Broadcasts are executed on each thread after they have exhausted their
    /// local work queue, before they attempt work-stealing from other threads.
    /// The goal of that strategy is to run everywhere in a timely manner
    /// *without* being too disruptive to current work.
    ///
    /// # Warning: thread-local data
    ///
    /// Because `op` is executing within the thread pool,
    /// thread-local data from the current thread will not be
    /// accessible.
    ///
    /// # Panics
    ///
    /// If `op` should panic on one or more threads, exactly one panic
    /// will be propagated, only after all threads have completed
    /// (or panicked) their own `op`.
    pub fn broadcast<OP, R>(&self, op: OP) -> Vec<R>
    where
        OP: Fn(BroadcastContext<'_>) -> R + Sync,
        R: Send,
    {
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe { broadcast::broadcast_in(op, &self.registry) }
    }

    /// Returns the number of threads in the thread pool.
    #[inline]
    pub fn current_num_threads(&self) -> usize {
        self.registry.num_threads()
    }

    /// If called from a worker thread in this thread pool,
    /// returns the index of that thread; if not called from a worker
    /// thread, or called from a worker that belongs to a
    /// different thread pool, returns `None`.
    ///
    /// The index for a given thread will not change over the thread's
    /// lifetime. However, multiple threads may share the same index if
    /// they are in distinct thread pools.
    #[inline]
    pub fn current_thread_index(&self) -> Option<usize> {
        let curr = self.registry.current_thread()?;
        Some(curr.index())
    }

    /// Polls `future` to completion while the calling worker services this pool's jobs.
    /// Returns `None` without polling if the caller does not belong to this pool.
    ///
    /// Jobs run on the caller's stack, so blocking waits within them must allow nesting.
    pub(crate) fn block_on_worker<F: Future + ?Sized>(
        &self,
        mut future: Pin<&mut F>,
    ) -> Option<F::Output> {
        let worker = self.registry.current_thread()?;
        loop {
            // A future may retain a waker after it is polled again or completes.
            // Each poll owns its latch so those wakers remain valid independently.
            let wake = Arc::new(WorkerWake {
                latch: OnceLatch::new(),
                registry: Arc::clone(worker.registry()),
                index: worker.index(),
            });
            let waker = Waker::from(Arc::clone(&wake));
            match future.as_mut().poll(&mut Context::from_waker(&waker)) {
                Poll::Ready(result) => return Some(result),
                Poll::Pending => {
                    // SAFETY: this is the calling worker, and the local Arc keeps its
                    // latch alive until the scheduler returns from the wait.
                    unsafe { worker.wait_until(&wake.latch) };
                }
            }
        }
    }

    /// Spawns an asynchronous task in this thread pool. This task may
    /// outlast the current stack frame, so it cannot capture any references
    /// onto the stack (you will likely need a `move` closure).
    ///
    /// # Panics
    ///
    /// If the task panics, the process aborts, since the panic has nowhere to propagate.
    pub fn spawn<OP>(&self, op: OP)
    where
        OP: FnOnce() + Send + 'static,
    {
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe {
            spawn::spawn_in(
                op,
                &self.registry,
                self.current_placement()
                    .unwrap_or(Placement::Wide { near: 0 }),
            )
        }
    }

    /// Spawns an asynchronous task on every thread in this thread pool. This task
    /// may outlast the current stack frame, so it cannot capture any references
    /// onto the stack (you will likely need a `move` closure).
    ///
    /// # Panics
    ///
    /// If the task panics on any thread, the process aborts, since the panic has nowhere to
    /// propagate.
    pub fn spawn_broadcast<OP>(&self, op: OP)
    where
        OP: Fn(BroadcastContext<'_>) + Send + Sync + 'static,
    {
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe { broadcast::spawn_broadcast_in(op, &self.registry) }
    }

    /// Cooperatively yields execution to the scheduler.
    ///
    /// Looks for and executes one unit of work if the current thread is part of this pool.
    ///
    /// Returns `Some(Yield::Executed)` if anything was executed, `Some(Yield::Idle)` if
    /// the search found no work, or `None` if the current thread is not part of this pool.
    pub fn yield_now(&self) -> Option<Yield> {
        let curr = self.registry.current_thread()?;
        Some(curr.yield_now())
    }

    /// The pool's registry, for tests that observe its workers.
    #[cfg(test)]
    pub(super) const fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// The number of the pool's workers registered as asleep, for tests that start from a
    /// quiet pool.
    #[cfg(test)]
    pub(crate) fn sleeping_workers(&self) -> usize {
        (0..self.registry.group_widths().len())
            .map(|group| self.registry.sleeping_workers(group))
            .sum()
    }

    /// Whether a submitted job waits in a group's or the Wide injector for a worker to take it.
    #[cfg(test)]
    pub(crate) fn has_injected_job(&self) -> bool {
        self.registry.has_any_injected_job()
    }

    /// The number of times each worker was woken from sleep, in worker order, for tests of who
    /// wakes.
    #[cfg(test)]
    pub(crate) fn wakeups(&self) -> Vec<usize> {
        (0..self.registry.num_threads())
            .map(|index| self.registry.wakeups(index))
            .collect()
    }

    /// Runs `op` under `placement` and returns its result. Jobs it submits without an explicit
    /// placement inherit this placement.
    ///
    /// An eligible worker of this pool runs `op` inline. Other callers queue it and wait.
    /// Waiting workers can run jobs in their own pool that their group may take, regardless of
    /// the waiting job's placement.
    ///
    /// # Panics
    ///
    /// Panics if `placement` names no group of the pool. If `op` should panic, that panic will
    /// be propagated.
    pub(crate) fn install_in<OP, R>(&self, placement: Placement, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        self.registry.check_placement(placement);
        self.registry.in_worker_placed(placement, |_, _| op())
    }

    /// Executes `op` once on every worker of `group` and returns the results in worker order.
    ///
    /// Each worker runs `op` after draining its own deques and before stealing other work.
    /// A worker runs broadcasts in the order they were queued. The other workers receive a
    /// broadcast that does nothing, and the call waits for them too.
    ///
    /// # Panics
    ///
    /// Panics if `group` is not a group of the pool. If `op` should panic on one or more threads,
    /// exactly one panic will be propagated, only after all threads have completed (or panicked)
    /// their own `op`.
    #[cfg(test)]
    pub(crate) fn broadcast_in<OP, R>(&self, group: usize, op: OP) -> Vec<R>
    where
        OP: Fn() -> R + Sync,
        R: Send,
    {
        self.registry.check_placement(Placement::Local(group));
        let workers = self.registry.group_range(group);
        self.broadcast(|context| workers.contains(&context.index()).then(&op))
            .into_iter()
            .flatten()
            .collect()
    }

    /// Returns the width of each group of the pool's workers, in group order.
    #[inline]
    pub(crate) fn group_widths(&self) -> &[usize] {
        self.registry.group_widths()
    }

    /// Returns the placement of the job the calling worker runs, or `None` if the calling thread
    /// is not a worker of this pool. A Wide placement names the calling worker's own group as
    /// `near`.
    ///
    /// The placement is a snapshot that holds until the thread runs another job or installs an
    /// operation under another placement.
    #[inline]
    pub(crate) fn current_placement(&self) -> Option<Placement> {
        Some(self.registry.current_thread()?.placement())
    }

    /// Returns the calling worker's view of itself, or `None` if the calling thread is not a
    /// worker of this pool.
    #[cfg(test)]
    #[inline]
    pub(crate) fn current_worker(&self) -> Option<Worker> {
        let curr = self.registry.current_thread()?;
        Some(Worker {
            index: curr.index(),
            group: curr.group(),
            placement: curr.placement(),
            width: curr.width(),
        })
    }

    /// Spawns `op` in this thread pool under `placement`. The task may outlive this call.
    ///
    /// An eligible worker of this pool pushes the task onto its own deque for the placement, and
    /// other callers use the placement's injector. A worker submitting [`Placement::Wide`] work
    /// offers it to its own group first, regardless of `near`. Passing [`Self::current_placement`]
    /// gives the task the same placement as a nested join.
    ///
    /// # Panics
    ///
    /// Panics if `placement` names no group of the pool. If the task panics, the process aborts,
    /// since the panic has nowhere to propagate.
    pub(crate) fn spawn_in<OP>(&self, placement: Placement, op: OP)
    where
        OP: FnOnce() + Send + 'static,
    {
        self.registry.check_placement(placement);
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe { spawn::spawn_in(op, &self.registry, placement) }
    }

    /// Spawns an asynchronous task on every worker of `group` and returns at once.
    ///
    /// Each worker runs it after draining its own deques and before stealing other work, in the
    /// order broadcasts were queued. The other workers receive a broadcast that does nothing. The
    /// task may outlast the current stack frame, so it cannot capture references to the stack.
    ///
    /// # Panics
    ///
    /// Panics if `group` is not a group of the pool. If the task panics on any thread, the
    /// process aborts, since the panic has nowhere to propagate.
    #[cfg(test)]
    pub(crate) fn spawn_broadcast_in<OP>(&self, group: usize, op: OP)
    where
        OP: Fn() + Send + Sync + 'static,
    {
        self.registry.check_placement(Placement::Local(group));
        let workers = self.registry.group_range(group);
        self.spawn_broadcast(move |context| {
            if workers.contains(&context.index()) {
                op();
            }
        });
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.registry.terminate();
    }
}

impl fmt::Debug for ThreadPool {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ThreadPool")
            .field("num_threads", &self.current_num_threads())
            .field("id", &self.registry.id())
            .finish()
    }
}

/// The calling thread's view of itself as a worker of a pool, from [`ThreadPool::current_worker`],
/// for tests that observe where work runs.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Worker {
    /// The worker's fixed index in its pool. Workers of distinct pools may share an index.
    pub(crate) index: usize,

    /// The group of the pool's workers that the worker belongs to.
    pub(crate) group: usize,

    /// The running job's placement. Jobs it submits without an explicit placement inherit it.
    pub(crate) placement: Placement,

    /// The number of workers eligible to run the job.
    pub(crate) width: usize,
}

/// If called from a worker thread, returns the index of that
/// thread within its current pool; if not called from a worker thread,
/// returns `None`.
///
/// The index for a given thread will not change over the thread's
/// lifetime. However, multiple threads may share the same index if
/// they are in distinct thread pools.
///
/// See also: [the `ThreadPool::current_thread_index()` method][m].
///
/// [m]: ThreadPool::current_thread_index()
#[cfg(any(test, all(target_os = "linux", not(miri))))]
#[inline]
pub(crate) fn current_thread_index() -> Option<usize> {
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let curr = unsafe { WorkerThread::current().as_ref()? };
    Some(curr.index())
}

/// Cooperatively yields execution to the scheduler.
///
/// If the current thread is part of a thread pool, this looks for a
/// single unit of pending work in the pool, then executes it. Completion of
/// that work might include nested work or further work stealing.
///
/// This is similar to [`std::thread::yield_now()`], but does not literally make
/// that call. If you are implementing a polling loop, you may want to also
/// yield to the OS scheduler yourself if no work was found.
///
/// Returns `Some(Yield::Executed)` if anything was executed, `Some(Yield::Idle)` if
/// the search found no work, or `None` if this thread is not part of any pool at all.
#[cfg(test)]
pub(crate) fn yield_now() -> Option<Yield> {
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let thread = unsafe { WorkerThread::current().as_ref()? };
    Some(thread.yield_now())
}

/// Result of a worker's cooperative yield to its thread pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Yield {
    /// Work was found and executed.
    Executed,
    /// No available work was found.
    Idle,
}
