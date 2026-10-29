//! A work-stealing pool of worker threads.
//!
//! A [`ThreadPool`] owns a fixed set of worker threads. Each worker keeps a deque of jobs that it
//! pushes and pops at one end while idle workers steal from the other, and a pool-wide injector
//! takes jobs submitted from threads outside the pool. A worker with nothing to run searches for
//! work for a while and then sleeps. Publishing a job or setting a latch wakes sleeping workers
//! as needed. A worker waiting for a job's latch keeps running its pool's jobs until it is set.
//!
//! [`join()`] runs two closures potentially in parallel, [`ThreadPool::spawn`] runs a detached
//! task, and [`ThreadPool::broadcast`] and [`ThreadPool::spawn_broadcast`] run a task on every
//! worker. The bridge maps, folds, and collects vectors by splitting them adaptively. Sorting
//! uses [`par_mergesort`] for stable sorts and [`par_quicksort`] for unstable sorts.
//!
//! # Changes vs. Upstream
//!
//! This module vendors the scheduler of [rayon-core] 1.13.0 and the producer/consumer bridge and
//! slice sorts of [rayon] 1.12.0. The upstream `LICENSE-APACHE`, `LICENSE-MIT`, and sleep protocol
//! `README.md` accompany the code.
//!
//! - Moved rayon-core's crate root into this module. Modules retain their upstream names, with
//!   `broadcast/mod.rs`, `join/mod.rs`, `spawn/mod.rs`, and `thread_pool/mod.rs` flattened into
//!   files beside their test directories. Rewrote crate-root paths for the private module.
//! - Exposes Commonware-owned `ThreadPool`, `ThreadPoolBuilder`, `ThreadPoolBuildError`, and
//!   `Yield` through the crate's API. The bridge, sorts, `join`, and `current_num_threads` are
//!   crate-visible. `join_context` and `FnContext` remain internal. Free `current_thread_index`
//!   and `yield_now` are compiled only for tests.
//! - Removed the global pool, `build_global`, `initialize`, `Configuration`, `Registry::current`,
//!   and the fallback for targets without threads. Internal `join` and `current_num_threads`
//!   require a calling worker. Pool methods retain external and cross-pool submission.
//! - Removed free `spawn`, `broadcast`, and `spawn_broadcast`; their pool methods remain.
//! - Removed scopes, FIFO jobs and queues, `in_place_scope`, `yield_local`,
//!   `current_thread_has_pending_tasks`, and `max_num_threads`, including their pool methods.
//!   Removed the `ThreadPool::join` wrapper and deprecated `ThreadPool::new` constructor.
//!   `CountLatch` retains the fixed-count construction and wait used by broadcast, without the
//!   scope-only constructor or increment operation.
//! - Removed builder options `spawn_handler`, `build_scoped`, `exit_handler`, `panic_handler`,
//!   and `breadth_first`, along with the custom thread-spawning types and `private.rs`. The
//!   registry starts threads directly. Uncaught detached-job and start-handler panics abort,
//!   and workers pop their own deque in LIFO order, as upstream does with its default settings.
//! - Added `ThreadPoolBuilder::unstarted_workers` for crate tests and the `test-utils` mocks.
//!   It registers workers without starting threads. Removed the global-pool-only `primed`
//!   latch and wait. Default thread counts retain upstream environment-variable handling.
//! - Removed `GlobalPoolAlreadyInitialized`, `ThreadPoolBuildError::is_unsupported`, and the
//!   deprecated error description. Removed the `web_spin_lock` feature, `wasm_sync`, build
//!   script, `links` key, and compile-fail tests. No separate fork package is required.
//! - Preserves upstream `std::sync` mutexes and condition variables, with local allowances for
//!   the workspace's disallowed-types lint.
//! - Added explicit unsafe blocks and `SAFETY` comments for Rust 2024, precise capturing in
//!   `JobRef::id`, and a named registry-clone binding in `SpinLatch::set` so its borrow outlives
//!   use within the block.
//! - `sort.rs` retains the stable merge sort and pattern-defeating quicksort with their helpers.
//!   Merge-sort chunks are scheduled with recursive `join` calls over the chunk list instead of
//!   a parallel iterator over `par_chunks_mut`, preserving its indexed split order. Shared
//!   `SendPtr` remains at this module's root, as it does at rayon's crate root.
//! - `bridge.rs` retains the vector drain producer and slice-drain iterator, indexed splitting,
//!   and the consumers, folders, and reducers used by map, map-init, while-some, fold, reduce,
//!   try-fold, try-reduce, vector collection, and list-vector collection. Its five entry points
//!   compose these parts as the corresponding rayon parallel-iterator expressions do.
//! - Removed parallel-iterator traits and adapter wrappers, `ProducerCallback`, producer-side
//!   map adapters, unindexed producer/consumer plumbing, ranged drain tail restoration, and
//!   `NoopConsumer`. Whole-vector draining uses inherent `DrainProducer` methods and
//!   `IntoIterator` in place of `Producer`, with the upstream default split bounds (minimum
//!   one item and no maximum). `try_fold` and `try_reduce` use `Result` in place of the private
//!   `Try` trait and `ControlFlow`.
//! - List collection uses `Vec::with_capacity` instead of `new` followed by `reserve`. The
//!   error-saving map uses a let chain and returns through `Option::map_or_else`. `FnContext`'s
//!   inherent impls are merged. Uses `Self`, `const fn`, and option combinators where required
//!   by workspace lints.
//! - Tests run in explicit pools and use `commonware_utils::test_rng` instead of upstream RNGs.
//!   Tests of removed APIs are omitted. Retained adaptation tests cover worker membership,
//!   unstarted workers, sorting, ordered collection, reduction trees, stolen splits, early
//!   termination, and panic/drop behavior. Pool-free bridge tests use the Miri test group.
//! - Describes the join context as queued execution, which also includes a job run by nested
//!   work on its submitting worker; the upstream context bit and splitting behavior are retained.
//! - Adapted comments to the private module and retained API, removed inaccessible doctest
//!   examples and section banners, and named the scheduler in its abort message.
//!
//! [rayon-core]: https://crates.io/crates/rayon-core/1.13.0
//! [rayon]: https://crates.io/crates/rayon/1.12.0

use std::{env, error::Error, fmt, io, str::FromStr, thread};

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

pub use self::thread_pool::{ThreadPool, Yield};
#[cfg(test)]
pub(crate) use self::thread_pool::{current_thread_index, yield_now};
pub(crate) use self::{
    bridge::{fold_init, map_collect_vec, map_init_collect_vec, try_fold, try_map_collect_vec},
    join::join,
    sort::{par_mergesort, par_quicksort},
};

/// Returns the number of threads in the pool of the calling worker.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool.
pub(crate) fn current_num_threads() -> usize {
    registry::Registry::current_num_threads()
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

/// Used to create a new [`ThreadPool`](crate::ThreadPool).
///
/// # Examples
///
/// The following creates a thread pool with 4 threads.
///
/// ```
/// use commonware_parallel::ThreadPoolBuilder;
///
/// let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
/// assert_eq!(pool.current_num_threads(), 4);
/// assert_eq!(pool.install(|| 1 + 1), 2);
/// ```
pub struct ThreadPoolBuilder {
    /// The number of threads in the thread pool.
    /// If zero, use the environment or the number of logical CPUs.
    num_threads: usize,

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
    /// # Local thread pools
    ///
    /// Using this in a local thread pool means the registry will be leaked. In future versions
    /// there might be a way of cleaning up the current-thread state.
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
            .field("use_current_thread", use_current_thread)
            .field("get_thread_name", &get_thread_name)
            .field("stack_size", &stack_size)
            .field("start_handler", &start_handler)
            .field("start_threads", start_threads)
            .finish()
    }
}
