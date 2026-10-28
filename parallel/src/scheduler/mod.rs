//! A work-stealing pool of worker threads.
//!
//! A [`ThreadPool`] owns a fixed set of worker threads. Each worker keeps a deque of jobs that it
//! pushes and pops at one end while idle workers steal from the other, and a pool-wide injector
//! takes jobs submitted from threads outside the pool. A worker with nothing to run searches for
//! work for a while and then sleeps, and publishing a job or setting a latch wakes sleeping
//! workers as needed. Latches signal the completion of jobs, and a worker waiting on one keeps
//! running its pool's jobs until it is set.
//!
//! On top of this, [`join()`] runs two closures potentially in parallel, [`scope()`] runs any
//! number of tasks that borrow from its caller before it returns, [`ThreadPool::spawn`] runs a
//! detached task, [`ThreadPool::broadcast`] and [`ThreadPool::spawn_broadcast`] run a task on
//! every worker, [`par_mergesort`] sorts a slice stably on the pool, and the bridge maps, folds,
//! and collects the items of a vector on the pool, splitting them adaptively.
//!
//! # Changes vs. Upstream
//!
//! This module vendors the scheduler of [rayon-core] 1.13.0 and the stable merge sort and the
//! producer/consumer bridge of [rayon] 1.12.0.
//!
//! - Moved rayon-core's crate root into this module and its modules into `broadcast.rs`,
//!   `job.rs`, `join.rs`, `latch.rs`, `registry.rs`, `scope.rs`, `sleep/`, `spawn.rs`,
//!   `thread_pool.rs`, and `unwind.rs`, keeping each module's tests in its `test.rs`. Rewrote
//!   `crate::` paths to `super::`.
//! - Upstream's crate-wide `pub(super)` items are visible within this module. The functions
//!   this crate calls ([`join()`], [`scope()`], `current_num_threads`, `yield_now`,
//!   [`par_mergesort`], and the bridge's `map_collect_vec`, `try_map_collect_vec`,
//!   `map_init_collect_vec`, `fold_init`, and `try_fold`) are crate-visible. `join_context` and
//!   `FnContext` are visible within this module, for the bridge. The free `current_thread_index`
//!   is compiled only for tests.
//! - Retained the `LICENSE-APACHE` and `LICENSE-MIT` files, which rayon-core and rayon share,
//!   and the sleep protocol's `README.md`.
//! - Removed the global thread pool: `ThreadPoolBuilder::build_global`, `initialize`,
//!   `Configuration`, `Registry::current`, the global registry, the single-threaded fallback for
//!   targets without threads, and every fallback to the global pool. [`join()`], [`scope()`],
//!   and `current_num_threads` panic when the calling thread is not a worker of a pool. Scopes
//!   are therefore created only on a worker, and `ScopeBase` takes that worker rather than an
//!   optional worker and registry.
//! - Removed the free `spawn`, `broadcast`, and `spawn_broadcast` functions, which ran on the
//!   current or global pool. The [`ThreadPool`] methods of those names remain.
//! - Removed `scope_fifo`, `spawn_fifo`, `ScopeFifo`, `JobFifo` and the per-worker FIFO,
//!   `in_place_scope`, `in_place_scope_fifo`, `Scope::spawn_broadcast`, `yield_local`,
//!   `current_thread_has_pending_tasks`, and `max_num_threads`, with the `ThreadPool` methods
//!   `new`, `join`, `scope`, `scope_fifo`, `in_place_scope`, `in_place_scope_fifo`,
//!   `spawn_fifo`, `yield_local`, and `current_thread_has_pending_tasks`.
//! - Removed the `ThreadPoolBuilder` options `spawn_handler`, `build_scoped`, `exit_handler`,
//!   `panic_handler`, and `breadth_first`, with `ThreadBuilder`'s public interface, the
//!   `ThreadSpawn`, `DefaultSpawn`, and `CustomSpawn` machinery, and `private.rs`. The registry
//!   starts each worker thread itself. A panic in a detached job or a start handler aborts the
//!   process, as upstream does without a panic handler. Workers always pop their own deque in
//!   LIFO order.
//! - Added the crate-internal test option `ThreadPoolBuilder::unstarted_workers`, which registers
//!   workers without starting their threads, in place of a spawn handler that starts none.
//! - Removed the `primed` latch and `wait_until_primed`, which only `build_global` used.
//! - A builder without a thread count sizes the pool by [`std::thread::available_parallelism`]
//!   and ignores the `RAYON_NUM_THREADS` and `RAYON_RS_NUM_CPUS` environment variables.
//! - Removed the `GlobalPoolAlreadyInitialized` error, `ThreadPoolBuildError::is_unsupported`,
//!   and the deprecated `Error::description`.
//! - Removed the `web_spin_lock` feature and its `wasm_sync` dependency, the build script and
//!   `links` key that kept one copy of rayon-core per binary, and the compile-fail tests.
//! - Keeps upstream's `std::sync` `Mutex` and `Condvar` for the latches and sleep states under an
//!   allow of the crate's disallowed-types lint, since `parking_lot` proved slower on those
//!   paths, which every job hand-off crosses.
//! - Uses explicit `unsafe` blocks with `SAFETY` comments inside `unsafe fn` bodies for the 2024
//!   edition, precise capturing in `JobRef::id`, and a named binding for the registry clone in
//!   `SpinLatch::set`, whose temporary no longer outlives its block.
//! - [`par_mergesort`] vendors `par_mergesort` of rayon's slice sort with only the helpers it
//!   uses. It merge sorts its chunks with a recursive [`join()`] over halves of the chunk list in
//!   place of rayon's parallel iterator over `par_chunks_mut`, which split the chunks the same
//!   way. Removed `par_quicksort` and its helpers.
//! - Rayon's `SendPtr`, which the merge sort and the bridge share, lives in this module's root,
//!   as it does in rayon's crate root.
//! - `bridge.rs` vendors the parts of rayon's parallel iterators that the collection operations
//!   of this crate use: `bridge_producer_consumer`, `Splitter`, `LengthSplitter`, and the
//!   `Consumer`, `Folder`, and `Reducer` traits of `iter/plumbing`, the vector drain producer
//!   `DrainProducer` and its `SliceDrain` iterator of `vec.rs`, `collect_with_consumer`,
//!   `CollectConsumer`, `CollectResult`, and `CollectReducer` of `iter/collect`,
//!   `ListVecConsumer` of `iter/extend.rs`, the error-saving map of `Result`'s
//!   `FromParallelIterator`, and the consumers and folders of `map`, `map_init`, `while_some`,
//!   `fold`, `reduce`, `try_fold`, and `try_reduce`. The crate-internal `map_collect_vec`,
//!   `try_map_collect_vec`, `map_init_collect_vec`, `fold_init`, and `try_fold` compose them as
//!   rayon does for the parallel iterator expression each one documents.
//! - Removed the parallel iterator traits and adaptor types, `ProducerCallback`, the
//!   producer-side adaptors (`MapProducer`, `MapInitProducer`, `MapWithIter`),
//!   `UnindexedConsumer`, `UnindexedProducer`, `bridge_unindexed`, the ranged vector `Drain` and
//!   its tail restoration, and `NoopConsumer`. The operations drive their consumers as
//!   `drive_unindexed` does on a vector, which only splits at indices.
//! - The vector drain is the only producer, so `DrainProducer` has inherent `split_at` and
//!   `fold_with` methods and implements `IntoIterator` in place of the `Producer` trait, and
//!   `bridge_producer_consumer` passes the trait's default bounds, one item and no maximum, to
//!   `LengthSplitter::new`. `with_producer` drains the whole vector, as `IntoIter::with_producer`
//!   does through `Drain::with_producer`.
//! - `try_fold` and `try_reduce` keep their state in `Result` in place of rayon's private `Try`
//!   trait and `ControlFlow`.
//! - The error-saving map uses `commonware_utils::sync::Mutex`, which does not poison, in place of
//!   `std::sync::Mutex`. No code panics while holding it, so the saved error is the same.
//! - The vector of a failed or collected list is allocated with `Vec::with_capacity` in place of
//!   `Vec::new` and `reserve`, the error-saving map uses a let chain, and `try_map_collect_vec`
//!   returns through `Option::map_or_else`, where clippy asks for them. `FnContext`'s two inherent
//!   impls are merged.
//! - Tests run inside pools they build, use [`commonware_utils::test_rng`] in place of
//!   `rand_xorshift` and entropy-seeded RNGs, and drop the cases of removed features. Added tests
//!   for the panics outside a pool, `use_current_thread` on a worker, unstarted workers, the
//!   merge sort, and the bridge's order, reduction tree, splits of a stolen half, early stops,
//!   and drops on panics. The bridge tests that need no pool are in the Miri group.
//! - Rewrote comments in Commonware style: removed section banners, named the scheduler rather
//!   than Rayon where comments describe its behavior, including the abort message, and removed
//!   doc examples, which cannot reach this private module. Uses `Self`, `const fn`, and
//!   `Option` combinators where clippy asks for them.
//!
//! [rayon-core]: https://crates.io/crates/rayon-core
//! [rayon]: https://crates.io/crates/rayon

use std::{error::Error, fmt, io, thread};

mod bridge;
mod broadcast;
mod job;
mod join;
mod latch;
mod registry;
mod scope;
mod sleep;
mod sort;
mod spawn;
#[cfg(test)]
mod test;
mod thread_pool;
mod unwind;

#[cfg(test)]
pub(crate) use self::thread_pool::current_thread_index;
pub use self::thread_pool::{ThreadPool, Yield};
pub(crate) use self::{
    bridge::{fold_init, map_collect_vec, map_init_collect_vec, try_fold, try_map_collect_vec},
    join::join,
    scope::scope,
    sort::par_mergesort,
    thread_pool::yield_now,
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
    /// If zero will use the number of logical CPUs.
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
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
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
    /// the pool starts one thread per logical CPU, as reported by
    /// [`std::thread::available_parallelism`].
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
    /// yield to the pool in some way, like via the pool's `yield_now` or a scope.
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
