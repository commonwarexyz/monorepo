//! A work-stealing pool of worker threads.
//!
//! A [`ThreadPool`] owns a fixed set of worker threads arranged in groups. Each worker has Local
//! and Wide deques. Local jobs stay within their group. Any worker may steal a Wide job. Groups
//! have separate Local injectors and share a Wide injector for submissions from outside the pool.
//! A worker with nothing to run searches for work and then sleeps. Publishing a job or setting a
//! latch wakes sleeping workers as needed. A worker waiting for a job's latch keeps running jobs
//! its group may take until the latch is set.
//!
//! Internal `join` calls run two closures potentially in parallel. [`ThreadPool::spawn`] runs a
//! detached task, and [`ThreadPool::broadcast`] and [`ThreadPool::spawn_broadcast`] run a task on
//! every worker. The bridge maps, folds, and collects vectors by splitting them adaptively.
//! Sorting uses `par_mergesort` for stable sorts and `par_quicksort` for unstable sorts.
//!
//! # Changes vs. Upstream
//!
//! This module vendors the scheduler of [rayon-core] 1.13.0 and the producer/consumer bridge and
//! slice sorts of [rayon] 1.12.0. The upstream `LICENSE-APACHE`, `LICENSE-MIT`, and sleep protocol
//! `README.md` accompany the code.
//!
//! - Moved rayon-core into this module and rewrote crate paths. Flattened the `broadcast`, `join`,
//!   `spawn`, and `thread_pool` modules beside their test directories.
//! - Exports `ThreadPool`, `ThreadPoolBuilder`, `ThreadPoolBuildError`, and `Yield` through
//!   `commonware_parallel::rayon`. Retained free functions are crate-private or test-only.
//! - Removed the global pool, `build_global`, `initialize`, `Registry::current`, the `primed`
//!   latch, and `GlobalPoolAlreadyInitialized`. Internal `join` and `placement_width` require a
//!   calling worker.
//! - Removed free `spawn`, `broadcast`, and `spawn_broadcast`.
//! - Removed scopes and their `CountLatch` operations, FIFO scheduling, `yield_local`,
//!   `current_thread_has_pending_tasks`, `max_num_threads`, and `ThreadPool::join`.
//! - Removed `Configuration`, `ThreadPool::new`, and the deprecated error description override.
//! - Removed builder options `spawn_handler`, `build_scoped`, `exit_handler`, `panic_handler`, and
//!   `breadth_first`. The registry starts threads directly. Uncaught detached-job and start-handler
//!   panics abort.
//! - Removed the fallback for targets without threads, `ThreadPoolBuildError::is_unsupported`,
//!   `web_spin_lock`, `wasm_sync`, the build script, and the `links` key.
//! - `bridge.rs` directly composes the producer and consumers. Removed iterator traits and
//!   wrappers, `ProducerCallback`, producer-side map adapters, unindexed plumbing, ranged draining,
//!   and `NoopConsumer`. Whole-vector draining uses inherent methods and `IntoIterator`. Fallible
//!   folds and reductions use `Result` in place of `Try` and `ControlFlow`.
//! - Merge-sort chunks run through recursive `join` calls in the same indexed split order as the
//!   upstream `par_chunks_mut` iterator.
//! - Failed collections drop partial outputs before returning the error, without assembling a final
//!   vector.
//! - Added `ThreadPool::block_on_worker` to poll futures while servicing pool jobs and waiting
//!   through the scheduler's latch and sleep protocol.
//! - Added `ThreadPoolBuilder::unstarted_workers` for test mocks and a test-only notification when
//!   a worker commits to sleeping.
//! - Tests use explicit pools and `commonware_utils::test_rng`. Removed compile-fail tests and
//!   tests of omitted APIs. Added worker, collection, sorting, and wakeup regressions.
//! - Adapted unsafe blocks, borrowing, and syntax to Rust 2024 and workspace lints. Added `SAFETY`
//!   comments and local lint allowances for upstream `std::sync` primitives. List collection uses
//!   `Vec::with_capacity` in place of `new` followed by `reserve`.
//! - Adapted docs to the retained API, clarified queued join execution, removed inaccessible
//!   doctests and section banners, and named the scheduler in its abort message.
//!
//! - Workers form fixed groups with separate Local and Wide deques. Local jobs stay within one
//!   group. Wide jobs can run on any worker. Jobs carry their placement through stealing,
//!   nested helping, and unwinding. The bridge splits according to that placement's width.
//! - Each group owns its Local injector and sleep states. All groups share a Wide injector.
//!   Wide publication and idle exits propagate wakeups between groups. Native worker waits
//!   wake the owning worker through its group and offset.
//! - Internal placement methods run, spawn, and broadcast work within groups. Public pool
//!   operations remain available. A ranged broadcast implementation also supports group homing.
//! - Added group eligibility, wake propagation, and placement-restoration tests, plus Loom
//!   models of the wake protocol.
//!
//! [rayon-core]: https://crates.io/crates/rayon-core/1.13.0
//! [rayon]: https://crates.io/crates/rayon/1.12.0

use std::{env, error::Error, fmt, io, str::FromStr, sync, thread};

mod bridge;
mod broadcast;
mod job;
mod join;
mod latch;
mod registry;
mod sleep;
mod sort;
mod spawn;
#[cfg(test)]
mod test;
mod thread_pool;
mod unwind;
#[cfg(all(test, feature = "loom"))]
mod wake_loom_tests;

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use self::thread_pool::in_worker;
pub use self::thread_pool::{ThreadPool, Yield};
#[cfg(test)]
pub(crate) use self::thread_pool::{current_thread_index, yield_now};
pub(crate) use self::{
    bridge::{fold_init, map_collect_vec, map_init_collect_vec, try_fold, try_map_collect_vec},
    join::join,
    registry::Placement,
    sort::{par_mergesort, par_quicksort},
};

/// Returns the number of workers eligible to run the calling worker's current job.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool.
fn placement_width() -> usize {
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let worker = unsafe { registry::WorkerThread::current().as_ref() };
    worker
        .expect("the calling thread must be a worker of a thread pool")
        .width()
}

/// We need to transmit raw pointers across threads. It is possible to do this
/// without any unsafe code by converting pointers to usize or to `AtomicPtr<T>`
/// then back to a raw pointer for use. We prefer this approach because code
/// that uses this type is more explicit.
///
/// Unsafe code is still required to dereference the pointer, so this type is
/// not unsound on its own, although it does partly lift the unconditional
/// !Send and !Sync on raw pointers. As always, dereference with care.
struct SendPtr<T>(*mut T);

// SAFETY: !Send for raw pointers is not for safety, just as a lint
unsafe impl<T: Send> Send for SendPtr<T> {}

// SAFETY: !Sync for raw pointers is not for safety, just as a lint
unsafe impl<T: Send> Sync for SendPtr<T> {}

impl<T> SendPtr<T> {
    // Helper to avoid disjoint captures of `send_ptr.0`
    const fn get(self) -> *mut T {
        self.0
    }
}

// Implement Clone without the T: Clone bound from the derive
impl<T> Clone for SendPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// Implement Copy without the T: Copy bound from the derive
impl<T> Copy for SendPtr<T> {}

/// Error when initializing a thread pool.
#[derive(Debug)]
pub struct ThreadPoolBuildError {
    kind: ErrorKind,
}

#[derive(Debug)]
enum ErrorKind {
    CurrentThreadAlreadyInPool,
    IOError(io::Error),
}

/// Used to create a new [`ThreadPool`].
///
/// # Examples
///
/// The following creates a thread pool with 4 threads.
///
/// ```
/// use commonware_parallel::rayon::ThreadPoolBuilder;
///
/// let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
/// assert_eq!(pool.current_num_threads(), 4);
/// assert_eq!(pool.install(|| 1 + 1), 2);
/// ```
pub struct ThreadPoolBuilder {
    /// The number of threads in the thread pool.
    /// If zero, use the environment or the number of logical CPUs.
    num_threads: usize,

    /// The width of each worker group, or zero for one group.
    group_width: usize,

    /// The thread we're building *from* will also be part of the pool.
    use_current_thread: bool,

    /// Closure to compute the name of a thread.
    get_thread_name: Option<Box<dyn FnMut(usize) -> String>>,

    /// The stack size for the created worker threads
    stack_size: Option<usize>,

    /// Closure invoked on worker-thread start.
    start_handler: Option<Box<StartHandler>>,

    /// Whether the pool starts a thread for each worker it does not take over.
    start_threads: bool,
}

/// The type for a closure that gets invoked when a thread starts. The
/// closure is passed the index of the thread on which it is invoked.
/// Note that this same closure may be invoked multiple times in parallel.
type StartHandler = dyn Fn(usize) + Send + Sync;

impl Default for ThreadPoolBuilder {
    fn default() -> Self {
        Self {
            num_threads: 0,
            group_width: 0,
            use_current_thread: false,
            get_thread_name: None,
            stack_size: None,
            start_handler: None,
            start_threads: true,
        }
    }
}

impl ThreadPoolBuilder {
    /// Creates and returns a valid thread pool builder, but does not initialize it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new `ThreadPool` initialized using this configuration.
    pub fn build(self) -> Result<ThreadPool, ThreadPoolBuildError> {
        ThreadPool::build(self)
    }

    /// Get the number of threads that will be used for the thread
    /// pool. See `num_threads()` for more information.
    fn get_num_threads(&self) -> usize {
        if self.num_threads > 0 {
            self.num_threads
        } else {
            let default = || {
                thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            };

            match env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|s| usize::from_str(&s).ok())
            {
                Some(x @ 1..) => return x,
                Some(0) => return default(),
                _ => {}
            }

            // Support for deprecated `RAYON_RS_NUM_CPUS`.
            match env::var("RAYON_RS_NUM_CPUS")
                .ok()
                .and_then(|s| usize::from_str(&s).ok())
            {
                Some(x @ 1..) => x,
                _ => default(),
            }
        }
    }

    /// Get the width of the groups a pool of `n_threads` threads is split into.
    /// See `group_width()` for more information.
    const fn get_group_width(&self, n_threads: usize) -> usize {
        if self.group_width == 0 || self.group_width > n_threads {
            n_threads
        } else {
            self.group_width
        }
    }

    /// Splits the workers into consecutive groups of `width` workers, the last one narrower when
    /// `width` does not divide the thread count. Worker `i` is in group `i / width`.
    ///
    /// A job placed [`Placement::Local`] on a group runs only on that group's workers, and a job
    /// placed [`Placement::Wide`] runs on any worker. If `width` is 0 or at least the thread
    /// count, or you do not call this function, all workers form one group.
    pub(crate) const fn group_width(mut self, width: usize) -> Self {
        self.group_width = width;
        self
    }

    /// Get the thread name for the thread with the given index.
    fn get_thread_name(&mut self, index: usize) -> Option<String> {
        let f = self.get_thread_name.as_mut()?;
        Some(f(index))
    }

    /// Sets a closure which takes a thread index and returns
    /// the thread's name.
    pub fn thread_name<F>(mut self, closure: F) -> Self
    where
        F: FnMut(usize) -> String + 'static,
    {
        self.get_thread_name = Some(Box::new(closure));
        self
    }

    /// Sets the number of threads to be used in the thread pool.
    ///
    /// If you specify a non-zero number of threads using this
    /// function, then the resulting thread pools are guaranteed to
    /// start at most this number of threads.
    ///
    /// If `num_threads` is 0, or you do not call this function, then
    /// the pool uses `RAYON_NUM_THREADS`, then the deprecated `RAYON_RS_NUM_CPUS`, and
    /// otherwise the number of logical CPUs reported by [`std::thread::available_parallelism`].
    /// A zero `RAYON_NUM_THREADS` selects the logical CPU count.
    pub const fn num_threads(mut self, num_threads: usize) -> Self {
        self.num_threads = num_threads;
        self
    }

    /// Use the current thread as one of the threads in the pool.
    ///
    /// The current thread is guaranteed to be at index 0, and since the thread is not managed by
    /// the pool, the start handler does not run for that thread.
    ///
    /// Note that the current thread won't run the main work-stealing loop, so jobs spawned into
    /// the thread pool will generally not be picked up automatically by this thread unless you
    /// yield to the pool in some way, like via the pool's `yield_now`.
    ///
    /// # Leaks
    ///
    /// The current thread keeps its worker state for the rest of its life, so the pool's registry
    /// is leaked.
    pub const fn use_current_thread(mut self) -> Self {
        self.use_current_thread = true;
        self
    }

    /// Get the stack size of the worker threads
    const fn get_stack_size(&self) -> Option<usize> {
        self.stack_size
    }

    /// Sets the stack size of the worker threads
    pub const fn stack_size(mut self, stack_size: usize) -> Self {
        self.stack_size = Some(stack_size);
        self
    }

    /// Takes the current thread start callback, leaving `None`.
    const fn take_start_handler(&mut self) -> Option<Box<StartHandler>> {
        self.start_handler.take()
    }

    /// Sets a callback to be invoked on thread start.
    ///
    /// The closure is passed the index of the thread on which it is invoked.
    /// Note that this same closure may be invoked multiple times in parallel.
    /// If this closure panics, the process aborts.
    pub fn start_handler<H>(mut self, start_handler: H) -> Self
    where
        H: Fn(usize) + Send + Sync + 'static,
    {
        self.start_handler = Some(Box::new(start_handler));
        self
    }

    /// Registers the pool's workers without starting their threads, so jobs queued on the pool
    /// run only on a thread taken over with [`Self::use_current_thread`], or never.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) const fn unstarted_workers(mut self) -> Self {
        self.start_threads = false;
        self
    }
}

impl ThreadPoolBuildError {
    const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

const CURRENT_THREAD_ALREADY_IN_POOL: &str =
    "The current thread is already part of another thread pool.";

impl Error for ThreadPoolBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            ErrorKind::CurrentThreadAlreadyInPool => None,
            ErrorKind::IOError(e) => Some(e),
        }
    }
}

impl fmt::Display for ThreadPoolBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::CurrentThreadAlreadyInPool => CURRENT_THREAD_ALREADY_IN_POOL.fmt(f),
            ErrorKind::IOError(e) => e.fmt(f),
        }
    }
}

impl fmt::Debug for ThreadPoolBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            ref num_threads,
            ref group_width,
            ref use_current_thread,
            ref get_thread_name,
            ref stack_size,
            ref start_handler,
            ref start_threads,
        } = *self;

        // Just print `Some(<closure>)` or `None` to the debug
        // output.
        struct ClosurePlaceholder;
        impl fmt::Debug for ClosurePlaceholder {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("<closure>")
            }
        }
        let get_thread_name = get_thread_name.as_ref().map(|_| ClosurePlaceholder);
        let start_handler = start_handler.as_ref().map(|_| ClosurePlaceholder);

        f.debug_struct("ThreadPoolBuilder")
            .field("num_threads", num_threads)
            .field("group_width", group_width)
            .field("use_current_thread", use_current_thread)
            .field("get_thread_name", &get_thread_name)
            .field("stack_size", &stack_size)
            .field("start_handler", &start_handler)
            .field("start_threads", start_threads)
            .finish()
    }
}
