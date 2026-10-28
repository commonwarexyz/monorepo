//! Contains support for user-managed thread pools, represented by the
//! the [`ThreadPool`] type (see that struct for details).

#[cfg(any(test, all(target_os = "linux", not(miri))))]
use super::broadcast;
use super::{
    ThreadPoolBuildError, ThreadPoolBuilder,
    registry::{Placement, Registry, WorkerThread},
    spawn,
};
use std::{fmt, sync::Arc};

#[cfg(test)]
mod test;

/// A pool of worker threads, built with a [`ThreadPoolBuilder`] and handed to a strategy such
/// as [`Rayon::with_pool`](crate::Rayon::with_pool), which runs its work on them.
///
/// Dropping the pool signals its threads to stop once they have finished the work already
/// queued on it.
pub struct ThreadPool {
    registry: Arc<Registry>,
}

impl ThreadPool {
    pub(super) fn build(builder: ThreadPoolBuilder) -> Result<Self, ThreadPoolBuildError> {
        let registry = Registry::new(builder)?;
        Ok(Self { registry })
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

    /// The number of times each worker was woken from sleep, in worker order, for tests of who
    /// wakes.
    #[cfg(test)]
    pub(crate) fn wakeups(&self) -> Vec<usize> {
        (0..self.registry.num_threads())
            .map(|index| self.registry.wakeups(index))
            .collect()
    }

    /// Executes `op` within the thread pool as `placement` says, with that placement for every
    /// job it submits that names none, then returns its result.
    ///
    /// A worker of this pool that the placement admits runs `op` itself under the placement.
    /// Any other thread, including a worker of another group of this pool, queues `op` for the
    /// placement and waits. A waiting worker keeps busy with the jobs of its own pool that its
    /// group may take, whatever placement it runs under.
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
        self.registry.check(placement);
        self.registry.in_worker_placed(placement, |_, _| op())
    }

    /// Executes `op` once on every worker of `group` and returns the results in worker order.
    ///
    /// Each worker runs `op` after it has exhausted its local work, before it attempts to steal
    /// from other workers, so a broadcast runs everywhere in a timely manner without being too
    /// disruptive to current work. A worker runs broadcasts in the order they were queued.
    ///
    /// # Panics
    ///
    /// Panics if `group` is not a group of the pool. If `op` should panic on one or more threads,
    /// exactly one panic will be propagated, only after all threads have completed (or
    /// panicked) their own `op`.
    #[cfg(test)]
    pub(crate) fn broadcast_in<OP, R>(&self, group: usize, op: OP) -> Vec<R>
    where
        OP: Fn() -> R + Sync,
        R: Send,
    {
        self.registry.check(Placement::Local(group));
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe { broadcast::broadcast_in(op, &self.registry, group) }
    }

    /// Returns the number of threads in the thread pool.
    #[inline]
    pub(crate) fn current_num_threads(&self) -> usize {
        self.registry.num_threads()
    }

    /// Returns the number of the pool's workers that are idle, either looking for work or
    /// asleep. A worker that waits inside a job for another worker looks for work meanwhile and
    /// counts as idle.
    ///
    /// The count is a momentary reading that may be stale by the time it is used, since workers
    /// take jobs and run out of them concurrently.
    #[inline]
    pub(crate) fn idle_workers(&self) -> usize {
        self.registry.idle_workers()
    }

    /// Returns the width of each group of the pool's workers, in group order.
    #[inline]
    pub(crate) fn group_widths(&self) -> &[usize] {
        self.registry.group_widths()
    }

    /// Returns the placement of the job the calling worker runs, or `None` if the calling thread
    /// is not a worker of this pool.
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

    /// Spawns an asynchronous task in this thread pool as `placement` says. The task may outlast
    /// the current stack frame, so it cannot capture any references onto the stack (you will
    /// likely need a `move` closure).
    ///
    /// A worker of this pool that the placement admits pushes the task onto its own deque for the
    /// placement, and any other thread queues it for the placement. A worker that names the
    /// placement of the job it runs, which [`Self::current_placement`] reports, pushes the task
    /// where it pushes the second closure of a join, so the task inherits that placement. A
    /// worker that names [`Placement::Wide`] pushes the task onto its own wide deque whatever
    /// `near` says, so the task is offered to the worker's own group first.
    ///
    /// # Panics
    ///
    /// Panics if `placement` names no group of the pool. If the task panics, the process aborts,
    /// since the panic has nowhere to propagate.
    pub(crate) fn spawn_in<OP>(&self, placement: Placement, op: OP)
    where
        OP: FnOnce() + Send + 'static,
    {
        self.registry.check(placement);
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe { spawn::spawn_in(op, &self.registry, placement) }
    }

    /// Spawns an asynchronous task on every worker of `group` and returns at once. Each worker
    /// runs it after it has exhausted its local work, before it attempts to steal from other
    /// workers, and runs broadcasts in the order they were queued. The task may outlast the
    /// current stack frame, so it cannot capture any references onto the stack.
    ///
    /// # Panics
    ///
    /// Panics if `group` is not a group of the pool. If the task panics on any thread, the
    /// process aborts, since the panic has nowhere to propagate.
    #[cfg(any(test, all(target_os = "linux", not(miri))))]
    pub(crate) fn spawn_broadcast_in<OP>(&self, group: usize, op: OP)
    where
        OP: Fn() + Send + Sync + 'static,
    {
        self.registry.check(Placement::Local(group));
        // SAFETY: `self` holds a reference that keeps the registry from terminating.
        unsafe { broadcast::spawn_broadcast_in(op, &self.registry, group) }
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
    /// The worker's index in its pool, which never changes. Workers of distinct pools may share
    /// an index.
    pub(crate) index: usize,
    /// The group of the pool's workers that the worker belongs to.
    pub(crate) group: usize,
    /// The placement of the job the worker runs, which the jobs it submits without naming one
    /// inherit.
    pub(crate) placement: Placement,
    /// The number of workers that can run the job: those of the worker's group under
    /// [`Placement::Local`] and those of the whole pool under [`Placement::Wide`].
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
/// See also: [the `ThreadPool::current_worker()` method][m].
///
/// [m]: ThreadPool::current_worker()
#[cfg(test)]
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
/// nothing was available, or `None` if this thread is not part of any pool at all.
pub(crate) fn yield_now() -> Option<Yield> {
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let thread = unsafe { WorkerThread::current().as_ref()? };
    Some(thread.yield_now())
}

/// Result of a worker's cooperative yield to its thread pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Yield {
    /// Work was found and executed.
    Executed,
    /// No available work was found.
    Idle,
}
