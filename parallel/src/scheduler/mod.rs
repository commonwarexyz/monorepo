//! A work-stealing pool of worker threads.
//!
//! A [`ThreadPool`] owns a fixed set of worker threads, split into consecutive groups. A job
//! runs under a [`Placement`], on the workers of one group or on any worker, and the jobs it
//! submits inherit that placement. Each worker keeps two deques of jobs, which it pushes and pops
//! at one end while idle workers steal from the other. Only its group-mates steal from its local
//! deque, and any worker steals from its wide deque. Each group has an injector for the jobs placed
//! on it from outside, and a pool-wide injector takes the jobs placed on the whole pool. A worker
//! with nothing to run searches for work for a while and then sleeps, and publishing a job or
//! setting a latch wakes sleeping workers that may run it as needed. Latches signal the
//! completion of jobs, and a worker waiting on one keeps running its pool's jobs until it is set.
//!
//! On top of this, [`join()`] runs two closures potentially in parallel, [`ThreadPool::spawn_in`]
//! runs a detached task, a broadcast runs a task once on every worker of a group, [`par_mergesort`]
//! and [`par_quicksort`] sort a slice stably and unstably on the pool, and the bridge maps, folds,
//! and collects the items of a vector on the pool, splitting them adaptively.
//!
//! # Changes vs. Upstream
//!
//! This module vendors the scheduler of [rayon-core] 1.13.0 and the stable merge sort, the unstable
//! quicksort, and the producer/consumer bridge of [rayon] 1.12.0.
//!
//! - Moved rayon-core's crate root into this module and its modules into `broadcast.rs`,
//!   `job.rs`, `join.rs`, `latch.rs`, `registry.rs`, `sleep/`, `spawn.rs`, `thread_pool.rs`,
//!   and `unwind.rs`, keeping each module's tests in its `test.rs`. Rewrote `crate::` paths to
//!   `super::`.
//! - The public interface is the opaque [`ThreadPool`], [`ThreadPoolBuilder`] with `new`,
//!   `num_threads`, `stack_size`, `use_current_thread`, and `build`, and
//!   [`ThreadPoolBuildError`]. The `ThreadPool` methods this crate calls
//!   (`current_num_threads` and `idle_workers`), `ThreadPoolBuilder::thread_name` and
//!   `start_handler`, and `Yield` are crate-visible.
//! - Upstream's crate-wide `pub(super)` items are visible within this module. The functions
//!   this crate calls ([`join()`], `yield_now`, [`par_mergesort`], [`par_quicksort`], and the
//!   bridge's `map_collect_vec`, `try_map_collect_vec`, `map_init_collect_vec`, `fold_init`, and
//!   `try_fold`) and the items the fan-out machinery of this crate waits with (`CountLatch`,
//!   `Latch`, and `WorkerThread::current`) are crate-visible. `join_context` is visible within
//!   this module, for the bridge. The free `current_thread_index` and each worker's `stopped`
//!   latch with `Registry::wait_until_stopped`, which upstream keeps for tests, are compiled only
//!   for tests, since nothing else in this crate uses them. The broadcast module, `ArcJob`,
//!   `Registry::inject_broadcast`, and `ThreadPoolBuilder::start_handler` are compiled only for
//!   tests and for Linux outside Miri, where homing is their only other user, and the broadcast
//!   deques stay empty on other targets.
//! - Retained the `LICENSE-APACHE` and `LICENSE-MIT` files, which rayon-core and rayon share,
//!   and the sleep protocol's `README.md`.
//! - Removed the global thread pool: `ThreadPoolBuilder::build_global`, `initialize`,
//!   `Configuration`, `Registry::current`, the global registry, the single-threaded fallback for
//!   targets without threads, and every fallback to the global pool. [`join()`] and
//!   `placement_width` panic when the calling thread is not a worker of a pool.
//! - Removed the free `spawn`, `broadcast`, and `spawn_broadcast` functions, which ran on the
//!   current or global pool, the [`ThreadPool`] methods `broadcast` and `spawn_broadcast`, which
//!   ran on every worker, and `BroadcastContext`.
//! - Removed `ThreadPool::install` with `Registry::in_worker`. An install from outside the pool
//!   is `install_in` with `Placement::Wide { near: 0 }`, the placement `install` gave it.
//!   Removed `ThreadPool::yield_now`, since the free `yield_now` serves its callers.
//! - Removed `FnContext` with `join_context`'s `call_b`, which only wrapped the flag in it.
//!   `join_context` passes each closure that flag, whether the closure runs on a thread other
//!   than the one that called `join_context`, as a `bool`.
//! - Removed `scope`, `Scope` with `Scope::spawn` and `Scope::spawn_broadcast`, `ScopeBase`,
//!   `ScopePtr`, `scope_fifo`, `ScopeFifo`, `spawn_fifo`, `JobFifo` and the per-worker FIFO,
//!   `in_place_scope`, `in_place_scope_fifo`, `yield_local`, `current_thread_has_pending_tasks`,
//!   `max_num_threads`, and `CountLatch::increment`, which only scopes used, with the
//!   `ThreadPool` methods `new`, `join`, `scope`, `scope_fifo`, `in_place_scope`,
//!   `in_place_scope_fifo`, `spawn_fifo`, `yield_local`, and `current_thread_has_pending_tasks`.
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
//!   way.
//! - [`par_quicksort`] vendors `par_quicksort` of rayon's slice sort with the helpers only it
//!   uses (`insert_head`, `insertion_sort_shift_right`, `partial_insertion_sort`, `heapsort`,
//!   `partition_in_blocks`, `partition`, `partition_equal`, `break_patterns`, `choose_pivot`, and
//!   `recurse`), and shares `InsertionHole`, `insert_tail`, and `insertion_sort_shift_left` with
//!   the merge sort. `recurse` sorts the two sides of a large partition with [`join()`], as
//!   upstream does with `rayon_core::join`, and tests its predecessor with a let chain where
//!   clippy asks for one.
//! - `bridge.rs` vendors the parts of rayon's parallel iterators that the collection operations
//!   of this crate use: `bridge_producer_consumer`, `Splitter`, `LengthSplitter`, and the
//!   `Consumer`, `Folder`, and `Reducer` traits of `iter/plumbing`, the vector drain producer
//!   `DrainProducer` and its `SliceDrain` iterator of `vec.rs`, `collect_with_consumer`,
//!   `CollectConsumer`, `CollectResult`, and `CollectReducer` of `iter/collect`,
//!   `ListVecConsumer` of `iter/extend.rs`, the error-saving map of `Result`'s
//!   `FromParallelIterator`, and the consumers and folders of `map`, `map_init`, `while_some`,
//!   `fold`, `reduce`, `try_fold`, and `try_reduce`. The crate-internal `map_collect_vec`,
//!   `try_map_collect_vec`, `map_init_collect_vec`, `fold_init`, and `try_fold` compose them
//!   as rayon does for the parallel iterator expression each one documents.
//! - Removed the parallel iterator traits and adaptor types, `ProducerCallback`, the
//!   producer-side adaptors (`MapProducer`, `MapInitProducer`, `MapWithIter`),
//!   `UnindexedConsumer`, `UnindexedProducer`, `bridge_unindexed`, the ranged vector `Drain`
//!   and its tail restoration, and `NoopConsumer`. The operations drive their consumers as
//!   `drive_unindexed` does on a vector, which only splits at indices.
//! - The vector drain is the only producer, so `DrainProducer` has inherent `split_at` and
//!   `fold_with` methods and implements `IntoIterator` in place of the `Producer` trait, and
//!   `bridge_producer_consumer` passes the trait's default bounds, one item and no maximum, to
//!   `LengthSplitter::new`. `with_producer` drains the whole vector, as
//!   `IntoIter::with_producer` does through `Drain::with_producer`.
//! - `try_fold` and `try_reduce` keep their state in `Result` in place of rayon's private `Try`
//!   trait and `ControlFlow`.
//! - The error-saving map uses `commonware_utils::sync::Mutex`, which does not poison, in place
//!   of `std::sync::Mutex`. No code panics while holding it, so the saved error is the same.
//! - The vector of a failed or collected list is allocated with `Vec::with_capacity` in place of
//!   `Vec::new` and `reserve`, the error-saving map uses a let chain, and `try_map_collect_vec`
//!   returns through `Option::map_or_else`, where clippy asks for them.
//! - Rayon's `SendPtr`, which the merge sort and the bridge both use, is defined once in this
//!   module.
//! - Tests run inside pools they build, use [`commonware_utils::test_rng`] in place of
//!   `rand_xorshift` and entropy-seeded RNGs, and drop the cases of removed features. Added tests
//!   for the panics outside a pool, `use_current_thread` on a worker, unstarted workers, the
//!   merge sort and the quicksort, and the bridge's order, reduction tree, splits of a stolen half,
//!   early stops, and drops on panics. The bridge and quicksort tests that need no pool are in the
//!   Miri group.
//! - Rewrote comments in Commonware style: removed section banners, named the scheduler rather
//!   than Rayon where comments describe its behavior, including the abort message, and removed
//!   doc examples, which cannot reach this private module. Uses `Self`, `const fn`, and
//!   `Option` combinators where clippy asks for them.
//! - Added groups of workers. The crate-internal `ThreadPoolBuilder::group_width` splits the
//!   workers into consecutive groups of that many workers, the last one narrower, and a pool
//!   built without it is one group. `THREADS_MAX` still bounds the whole pool.
//! - Added `Placement`, which runs a job on the workers of one group (`Local`) or on any worker
//!   (`Wide { near }`, offered first to the idle workers of group `near`). A worker runs each job
//!   under a tag, `Local` for its own group or `Wide`, and every job it pushes inherits that tag,
//!   so a placement holds for the tree of jobs below it until a job names another placement.
//! - Each worker has a local deque, which only its group-mates steal from, and a wide deque,
//!   which any worker steals from, in place of upstream's one deque, and pushes to the deque its
//!   current tag selects. Each group has its own injector for jobs placed on it from outside, and
//!   the registry's injector takes the jobs placed on the whole pool.
//! - `JobRef` carries the tag, which the queue it waits in stamps (`Local` for local deques,
//!   group injectors, and broadcast deques, `Wide` for wide deques and the wide injector). A
//!   worker runs a job it takes under the job's tag through `WorkerThread::run_as`, which
//!   restores the previous tag with a guard, also when unwinding. A thread taken over with
//!   `use_current_thread` starts under `Wide`, and broadcast jobs run under `Local`.
//! - `take_local_job` pops the deque of the current tag, then the other deque, then the broadcast
//!   deque. `find_work` then steals from the local deques of the worker's group-mates, pops its
//!   group's injector, steals from wide deques, its group-mates' first and then the rest of the
//!   pool's, each from a random start, and pops the wide injector last. `steal` is split into
//!   `steal_local` and `steal_wide`.
//! - The sleep protocol runs per group. Each group has its own `Sleep`, whose counters and sleep
//!   states cover its workers, indexed by their offset in the group, and a worker sleeps and is
//!   woken in its group's `Sleep`. Latch and broadcast notifications map a worker's index to its
//!   group and offset.
//! - A job placed on a group notifies only that group's `Sleep`. A job placed on the whole pool
//!   notifies the groups in cyclic order from the pushing worker's group or the injection's
//!   `near` group, and stops at the first group that covers it with an idle worker or a woken
//!   sleeper. `Sleep::new_jobs`, `new_injected_jobs`, and `new_internal_jobs` return how many
//!   jobs the group leaves uncovered, and `wake_any_threads` returns how many workers it woke,
//!   while their decisions whom to wake are upstream's.
//! - A sleeper's final check before it blocks covers its broadcast deque, its group's injector,
//!   and the wide injector.
//! - Added the crate-internal `ThreadPool` methods `install_in`, `spawn_in`, and `group_widths`,
//!   `spawn_broadcast_in`, which is compiled only for tests and for Linux outside Miri, and
//!   `broadcast_in`, which is compiled only for tests, with `Registry::in_worker_placed`,
//!   `Registry::place`, and `Registry::check`. A worker of the pool that a placement admits
//!   runs or pushes the job itself under the placement, and an install on another group of the
//!   same pool injects into that group's injector and waits stealing, as an install from another
//!   pool does.
//! - Replaced `ThreadPool::current_thread_index` with `current_worker`, which returns the
//!   calling worker's index, group, and placement with the width of that placement as a
//!   `Worker`. Only tests read the index, the group, and the width, so only tests compile them.
//! - Added `ThreadPool::idle_workers`, which counts the workers looking for work or asleep by
//!   summing the inactive counts of the groups' sleep counters, through
//!   `Registry::idle_workers` and `Sleep::idle_threads`.
//! - Removed `ThreadPool::spawn` and `Registry::inject_or_push`. The free `spawn_in` takes the
//!   placement of its job, which it queues through `Registry::place`, and `ThreadPool::spawn_in`
//!   is the only spawn. A worker that names the placement of the job it runs pushes the new job
//!   under its current tag, as upstream's spawn pushes on the worker.
//! - `inject` takes the placement of a job injected from outside.
//! - `inject_broadcast` takes the range of workers it reaches, and the broadcast module's
//!   `broadcast_in` and `spawn_broadcast_in` take the group whose workers they reach in place of
//!   reaching every worker, and run closures that take no argument. The test-only
//!   `broadcast_in` waits on a `CountLatch` per job, so `CountLatch::with_count` is removed.
//! - Replaced the free `current_num_threads` and `Registry::current_num_threads` with
//!   `placement_width`, which returns the number of threads that can run the calling worker's
//!   current job, the threads of its group under `Local` and of the whole pool under `Wide`.
//!   `ThreadPool::current_num_threads` still returns the pool's thread count.
//! - Added the test hooks `ThreadPool::registry`, `ThreadPool::sleeping_workers` and
//!   `ThreadPool::wakeups` over `Registry::sleeping_workers` and `Registry::wakeups`,
//!   `Sleep::sleeping_threads` and `Sleep::wakeups` with a wake count per worker, and
//!   `CountLatch::count`, and tests of groups and placements in `registry/test.rs`.
//!
//! [rayon-core]: https://crates.io/crates/rayon-core
//! [rayon]: https://crates.io/crates/rayon

use std::{error::Error, fmt, io, thread};

mod bridge;
#[cfg(any(test, all(target_os = "linux", not(miri))))]
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

pub use self::thread_pool::ThreadPool;
#[cfg(test)]
pub(crate) use self::thread_pool::current_thread_index;
pub(crate) use self::{
    bridge::{fold_init, map_collect_vec, map_init_collect_vec, try_fold, try_map_collect_vec},
    join::join,
    latch::{CountLatch, Latch},
    registry::{Placement, WorkerThread},
    sort::{par_mergesort, par_quicksort},
    thread_pool::{Yield, yield_now},
};

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

/// Returns the number of threads that can run the calling worker's current job, which are the
/// threads of its group under [`Placement::Local`] and of the whole pool under
/// [`Placement::Wide`].
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool.
fn placement_width() -> usize {
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let worker_thread = unsafe { WorkerThread::current().as_ref() };
    worker_thread
        .expect("the calling thread must be a worker of a thread pool")
        .width()
}

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
/// The following creates a thread pool with 4 threads and runs a strategy on it.
///
/// ```
/// use commonware_parallel::{Rayon, Strategy, ThreadPoolBuilder};
/// use std::sync::Arc;
///
/// let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
/// let strategy = Rayon::with_pool(Arc::new(pool));
/// let data: Vec<u64> = (1..=100).collect();
/// assert_eq!(strategy.fold(&data, || 0, |acc, &n| acc + n, |a, b| a + b), 5050);
/// ```
pub struct ThreadPoolBuilder {
    /// The number of threads in the thread pool.
    /// If zero will use the number of logical CPUs.
    num_threads: usize,

    /// The width of the groups the workers are split into. If zero, all workers form one group.
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
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
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

    /// Get the thread name for the thread with the given index.
    fn get_thread_name(&mut self, index: usize) -> Option<String> {
        let f = self.get_thread_name.as_mut()?;
        Some(f(index))
    }

    /// Sets a closure which takes a thread index and returns
    /// the thread's name.
    pub(crate) fn thread_name<F>(mut self, closure: F) -> Self
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

    /// Use the current thread as one of the threads in the pool.
    ///
    /// The current thread is guaranteed to be at index 0, and since the thread is not managed by
    /// the pool, the start handler does not run for that thread.
    ///
    /// The current thread does not run the main work-stealing loop, so it runs the pool's queued
    /// jobs only while it waits on the pool, such as while it awaits a job spawned through a
    /// strategy on the pool.
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
    #[cfg(any(test, all(target_os = "linux", not(miri))))]
    pub(crate) fn start_handler<H>(mut self, start_handler: H) -> Self
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
