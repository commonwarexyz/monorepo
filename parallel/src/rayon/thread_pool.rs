//! Contains support for user-managed thread pools, represented by the
//! the [`ThreadPool`] type (see that struct for details).

#[cfg(test)]
use super::registry::WorkerThread;
use super::{
    ThreadPoolBuildError, ThreadPoolBuilder,
    broadcast::{self, BroadcastContext},
    registry::Registry,
    spawn,
};
use std::{fmt, sync::Arc};

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
        self.registry.in_worker(|_, _| op())
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

    /// Spawns an asynchronous task in this thread pool. This task will
    /// run in the implicit, global scope, which means that it may outlast
    /// the current stack frame -- therefore, it cannot capture any references
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
        unsafe { spawn::spawn_in(op, &self.registry) }
    }

    /// Spawns an asynchronous task on every thread in this thread pool. This task
    /// will run in the implicit, global scope, which means that it may outlast the
    /// current stack frame -- therefore, it cannot capture any references onto the
    /// stack (you will likely need a `move` closure).
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
    /// nothing was available, or `None` if the current thread is not part this pool.
    pub fn yield_now(&self) -> Option<Yield> {
        let curr = self.registry.current_thread()?;
        Some(curr.yield_now())
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
