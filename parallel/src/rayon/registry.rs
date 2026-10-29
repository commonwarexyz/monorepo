#![allow(
    clippy::disallowed_types,
    reason = "Preserve upstream synchronization semantics."
)]
use super::{
    ErrorKind, StartHandler, ThreadPoolBuildError, ThreadPoolBuilder, Yield,
    job::{JobRef, StackJob},
    latch::{AsCoreLatch, CoreLatch, Latch, LatchRef, LockLatch, OnceLatch, SpinLatch},
    sleep::{Sleep, THREADS_MAX},
    unwind,
};
use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use std::{
    cell::Cell,
    hash::{DefaultHasher, Hasher},
    io, mem, ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

/// The state `Registry::new` hands to each worker thread it starts.
struct ThreadBuilder {
    name: Option<String>,
    stack_size: Option<usize>,
    worker: Worker<JobRef>,
    stealer: Stealer<JobRef>,
    registry: Arc<Registry>,
    index: usize,
}

impl ThreadBuilder {
    /// Executes the main loop for this thread. This will not return until the
    /// thread pool is dropped.
    fn run(self) {
        // SAFETY: this runs on the thread spawned for this worker, which belongs to no pool yet.
        unsafe { main_loop(self) }
    }

    /// Spawns a thread with the builder's name and stack size that runs the main loop.
    fn spawn(self) -> io::Result<()> {
        let mut b = thread::Builder::new();
        if let Some(name) = &self.name {
            b = b.name(name.to_owned());
        }
        if let Some(stack_size) = self.stack_size {
            b = b.stack_size(stack_size);
        }
        b.spawn(|| self.run())?;
        Ok(())
    }
}

pub(super) struct Registry {
    thread_infos: Vec<ThreadInfo>,
    sleep: Sleep,
    injected_jobs: Injector<JobRef>,
    broadcasts: Mutex<Vec<Worker<JobRef>>>,
    start_handler: Option<Box<StartHandler>>,

    // When this latch reaches 0, it means that all work on this
    // registry must be complete. This is ensured in the following ways:
    //
    // - so long as the thread pool exists, it holds a reference.
    // - when we inject a "blocking job" into the registry with `ThreadPool::install()`,
    //   no adjustment is needed; the `ThreadPool` holds the reference, and since we won't
    //   return until the blocking job is complete, that ref will continue to be held.
    // - when `join()` is invoked, similarly, no adjustments are needed.
    //   These are always owned by some other job (e.g., one injected by `ThreadPool::install()`)
    //   and that job will keep the pool alive.
    terminate_count: AtomicUsize,
}

struct Terminator<'a>(&'a Arc<Registry>);

impl Drop for Terminator<'_> {
    fn drop(&mut self) {
        self.0.terminate()
    }
}

impl Registry {
    pub(super) fn new(mut builder: ThreadPoolBuilder) -> Result<Arc<Self>, ThreadPoolBuildError> {
        // Soft-limit the number of threads that we can actually support.
        let n_threads = Ord::min(builder.get_num_threads(), THREADS_MAX);

        let (workers, stealers): (Vec<_>, Vec<_>) = (0..n_threads)
            .map(|_| {
                let worker = Worker::new_lifo();
                let stealer = worker.stealer();
                (worker, stealer)
            })
            .unzip();

        let (broadcasts, broadcast_stealers): (Vec<_>, Vec<_>) = (0..n_threads)
            .map(|_| {
                let worker = Worker::new_fifo();
                let stealer = worker.stealer();
                (worker, stealer)
            })
            .unzip();

        let registry = Arc::new(Self {
            thread_infos: stealers.into_iter().map(ThreadInfo::new).collect(),
            sleep: Sleep::new(n_threads),
            injected_jobs: Injector::new(),
            broadcasts: Mutex::new(broadcasts),
            terminate_count: AtomicUsize::new(1),
            start_handler: builder.take_start_handler(),
        });

        // If we return early or panic, make sure to terminate existing threads.
        let t1000 = Terminator(&registry);

        for (index, (worker, stealer)) in workers.into_iter().zip(broadcast_stealers).enumerate() {
            let thread = ThreadBuilder {
                name: builder.get_thread_name(index),
                stack_size: builder.get_stack_size(),
                registry: Arc::clone(&registry),
                worker,
                stealer,
                index,
            };

            if index == 0 && builder.use_current_thread {
                if !WorkerThread::current().is_null() {
                    return Err(ThreadPoolBuildError::new(
                        ErrorKind::CurrentThreadAlreadyInPool,
                    ));
                }
                // Rather than starting a new thread, we're just taking over the current thread
                // *without* running the main loop, so we can still return from here.
                // The WorkerThread is leaked, so the registry is never freed.
                let worker_thread = Box::into_raw(Box::new(WorkerThread::from(thread)));

                // SAFETY: the current thread belongs to no pool, and the leaked worker state
                // stays valid for the rest of the thread's life.
                unsafe { WorkerThread::set_current(worker_thread) };
                continue;
            }

            if !builder.start_threads {
                continue;
            }
            if let Err(e) = thread.spawn() {
                return Err(ThreadPoolBuildError::new(ErrorKind::IOError(e)));
            }
        }

        // Returning normally now, without termination.
        mem::forget(t1000);

        Ok(registry)
    }

    /// Returns the number of threads in the current registry.
    ///
    /// # Panics
    ///
    /// Panics if the calling thread is not a worker of a thread pool.
    pub(super) fn current_num_threads() -> usize {
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
        let worker_thread = unsafe { WorkerThread::current().as_ref() };
        worker_thread
            .expect("the calling thread must be a worker of a thread pool")
            .registry
            .num_threads()
    }

    /// Returns the current `WorkerThread` if it's part of this `Registry`.
    pub(super) fn current_thread(&self) -> Option<&WorkerThread> {
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the borrow.
        let worker = unsafe { WorkerThread::current().as_ref()? };
        if worker.registry().id() == self.id() {
            Some(worker)
        } else {
            None
        }
    }

    /// Returns an opaque identifier for this registry.
    pub(super) fn id(&self) -> RegistryId {
        // We can rely on `self` not to change since we only ever create
        // registries that are boxed up in an `Arc` (see `new()` above).
        RegistryId {
            addr: self as *const Self as usize,
        }
    }

    pub(super) const fn num_threads(&self) -> usize {
        self.thread_infos.len()
    }

    /// Runs `f`, aborting the process if it panics, since a panic in detached work has nowhere
    /// to propagate.
    pub(super) fn catch_unwind(&self, f: impl FnOnce()) {
        if let Err(_err) = unwind::halt_unwinding(f) {
            let _abort_guard = unwind::AbortIfPanic;
        }
    }

    /// Waits for the worker threads to stop. This is used for testing
    /// -- so we can check that termination actually works.
    #[cfg(test)]
    pub(super) fn wait_until_stopped(&self) {
        for info in &self.thread_infos {
            info.stopped.wait();
        }
    }

    /// Push a job into the given `registry`. If we are running on a
    /// worker thread for the registry, this will push onto the
    /// deque. Else, it will inject from the outside (which is slower).
    pub(super) fn inject_or_push(&self, job_ref: JobRef) {
        let worker_thread = WorkerThread::current();
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the call, and
        // the caller keeps the job valid until it executes.
        unsafe {
            if !worker_thread.is_null() && (*worker_thread).registry().id() == self.id() {
                (*worker_thread).push(job_ref);
            } else {
                self.inject(job_ref);
            }
        }
    }

    /// Push a job into the "external jobs" queue; it will be taken by
    /// whatever worker has nothing to do. Use this if you know that
    /// you are not on a worker of this registry.
    pub(super) fn inject(&self, injected_job: JobRef) {
        // It should not be possible for `state.terminate` to be true
        // here. It is only set to true when the user creates (and
        // drops) a `ThreadPool`; and, in that case, they cannot be
        // calling `inject()` later, since they dropped their
        // `ThreadPool`.
        debug_assert_ne!(
            self.terminate_count.load(Ordering::Acquire),
            0,
            "inject() sees state.terminate as true"
        );

        let queue_was_empty = self.injected_jobs.is_empty();

        self.injected_jobs.push(injected_job);
        self.sleep.new_injected_jobs(1, queue_was_empty);
    }

    fn has_injected_job(&self) -> bool {
        !self.injected_jobs.is_empty()
    }

    fn pop_injected_job(&self) -> Option<JobRef> {
        loop {
            match self.injected_jobs.steal() {
                Steal::Success(job) => return Some(job),
                Steal::Empty => return None,
                Steal::Retry => {}
            }
        }
    }

    /// Push a job into each thread's own "external jobs" queue; it will be
    /// executed only on that thread, when it has nothing else to do locally,
    /// before it tries to steal other work.
    ///
    /// **Panics** if not given exactly as many jobs as there are threads.
    pub(super) fn inject_broadcast(&self, injected_jobs: impl ExactSizeIterator<Item = JobRef>) {
        assert_eq!(self.num_threads(), injected_jobs.len());
        {
            let broadcasts = self.broadcasts.lock().unwrap();

            // It should not be possible for `state.terminate` to be true
            // here. It is only set to true when the user creates (and
            // drops) a `ThreadPool`; and, in that case, they cannot be
            // calling `inject_broadcast()` later, since they dropped their
            // `ThreadPool`.
            debug_assert_ne!(
                self.terminate_count.load(Ordering::Acquire),
                0,
                "inject_broadcast() sees state.terminate as true"
            );

            assert_eq!(broadcasts.len(), injected_jobs.len());
            for (worker, job_ref) in broadcasts.iter().zip(injected_jobs) {
                worker.push(job_ref);
            }
        }
        for i in 0..self.num_threads() {
            self.sleep.notify_worker_latch_is_set(i);
        }
    }

    /// If already in a worker-thread of this registry, just execute `op`.
    /// Otherwise, inject `op` in this thread pool. Either way, block until `op`
    /// completes and return its return value. If `op` panics, that panic will
    /// be propagated as well.  The second argument indicates `true` if injection
    /// was performed, `false` if executed directly.
    pub(super) fn in_worker<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce(&WorkerThread, bool) -> R + Send,
        R: Send,
    {
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
        unsafe {
            let worker_thread = WorkerThread::current();
            if worker_thread.is_null() {
                self.in_worker_cold(op)
            } else if (*worker_thread).registry().id() != self.id() {
                self.in_worker_cross(&*worker_thread, op)
            } else {
                // Perfectly valid to give them a `&T`: this is the
                // current thread, so we know the data structure won't be
                // invalidated until we return.
                op(&*worker_thread, false)
            }
        }
    }

    #[cold]
    unsafe fn in_worker_cold<OP, R>(&self, op: OP) -> R
    where
        OP: FnOnce(&WorkerThread, bool) -> R + Send,
        R: Send,
    {
        thread_local!(static LOCK_LATCH: LockLatch = const { LockLatch::new() });

        LOCK_LATCH.with(|l| {
            // This thread isn't a member of *any* thread pool, so just block.
            debug_assert!(WorkerThread::current().is_null());
            let job = StackJob::new(
                |injected| {
                    let worker_thread = WorkerThread::current();
                    assert!(injected && !worker_thread.is_null());
                    // SAFETY: the job runs on a worker, whose state outlives the job.
                    op(unsafe { &*worker_thread }, true)
                },
                LatchRef::new(l),
            );
            // SAFETY: the job stays on this stack frame until its latch is set, which happens
            // once it has executed.
            unsafe {
                self.inject(job.as_job_ref());
                job.latch.wait_and_reset(); // Make sure we can use the same latch again next time.

                job.into_result()
            }
        })
    }

    #[cold]
    unsafe fn in_worker_cross<OP, R>(&self, current_thread: &WorkerThread, op: OP) -> R
    where
        OP: FnOnce(&WorkerThread, bool) -> R + Send,
        R: Send,
    {
        // This thread is a member of a different pool, so let it process
        // other work while waiting for this `op` to complete.
        debug_assert!(current_thread.registry().id() != self.id());
        let latch = SpinLatch::cross(current_thread);
        let job = StackJob::new(
            |injected| {
                let worker_thread = WorkerThread::current();
                assert!(injected && !worker_thread.is_null());
                // SAFETY: the job runs on a worker, whose state outlives the job.
                op(unsafe { &*worker_thread }, true)
            },
            latch,
        );
        // SAFETY: the job stays on this stack frame until its latch is set, which happens once it
        // has executed, and `current_thread` is this thread's worker state.
        unsafe {
            self.inject(job.as_job_ref());
            current_thread.wait_until(&job.latch);
            job.into_result()
        }
    }

    /// Increments the terminate counter. This increment should be
    /// balanced by a call to `terminate`, which will decrement. This
    /// is used when spawning asynchronous work, which needs to
    /// prevent the registry from terminating so long as it is active.
    ///
    /// Note that blocking functions such as `join` do not
    /// need to concern themselves with this fn; their context is
    /// responsible for ensuring the current thread pool will not
    /// terminate until they return.
    ///
    /// A thread pool has one outstanding reference that is dropped
    /// when the `ThreadPool` is dropped: since installing the thread
    /// pool blocks until its joins complete, this ensures that
    /// joins are covered.
    ///
    /// The exception is `::spawn()`, which can create a job outside
    /// of any blocking scope. In that case, the job itself holds a
    /// terminate count and is responsible for invoking `terminate()`
    /// when finished.
    pub(super) fn increment_terminate_count(&self) {
        let previous = self.terminate_count.fetch_add(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "registry ref count incremented from zero");
        assert!(previous != usize::MAX, "overflow in registry ref count");
    }

    /// Signals that the thread pool which owns this registry has been
    /// dropped. The worker threads will gradually terminate, once any
    /// extant work is completed.
    pub(super) fn terminate(&self) {
        if self.terminate_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            for (i, thread_info) in self.thread_infos.iter().enumerate() {
                // SAFETY: the latch belongs to this registry, which outlives the call.
                unsafe { OnceLatch::set_and_tickle_one(&thread_info.terminate, self, i) };
            }
        }
    }

    /// Notify the worker that the latch they are sleeping on has been "set".
    pub(super) fn notify_worker_latch_is_set(&self, target_worker_index: usize) {
        self.sleep.notify_worker_latch_is_set(target_worker_index);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RegistryId {
    addr: usize,
}

struct ThreadInfo {
    /// Latch is set once worker thread has completed. Used to wait
    /// until workers have stopped; only used for tests.
    stopped: LockLatch,

    /// The latch used to signal that terminated has been requested.
    /// This latch is *set* by the `terminate` method on the
    /// `Registry`, once the registry's main "terminate" counter
    /// reaches zero.
    terminate: OnceLatch,

    /// the "stealer" half of the worker's deque
    stealer: Stealer<JobRef>,
}

impl ThreadInfo {
    const fn new(stealer: Stealer<JobRef>) -> Self {
        Self {
            stopped: LockLatch::new(),
            terminate: OnceLatch::new(),
            stealer,
        }
    }
}

pub(super) struct WorkerThread {
    /// the "worker" half of our local deque
    worker: Worker<JobRef>,

    /// the "stealer" half of the worker's broadcast deque
    stealer: Stealer<JobRef>,

    index: usize,

    /// A weak random number generator.
    rng: XorShift64Star,

    registry: Arc<Registry>,
}

// This is a bit sketchy, but basically: the WorkerThread is
// allocated on the stack of the worker on entry and stored into this
// thread-local variable. So it will remain valid at least until the
// worker is fully unwound. Using an unsafe pointer avoids the need
// for a RefCell<T> etc.
thread_local! {
    static WORKER_THREAD_STATE: Cell<*const WorkerThread> = const { Cell::new(ptr::null()) };
}

impl From<ThreadBuilder> for WorkerThread {
    fn from(thread: ThreadBuilder) -> Self {
        Self {
            worker: thread.worker,
            stealer: thread.stealer,
            index: thread.index,
            rng: XorShift64Star::new(),
            registry: thread.registry,
        }
    }
}

impl Drop for WorkerThread {
    fn drop(&mut self) {
        // Undo `set_current`
        WORKER_THREAD_STATE.with(|t| {
            assert!(t.get().eq(&(self as *const _)));
            t.set(ptr::null());
        });
    }
}

impl WorkerThread {
    /// Gets the `WorkerThread` index for the current thread; returns
    /// NULL if this is not a worker thread. This pointer is valid
    /// anywhere on the current thread.
    #[inline]
    pub(super) fn current() -> *const Self {
        WORKER_THREAD_STATE.get()
    }

    /// Sets `self` as the worker-thread index for the current thread.
    /// This is done during worker-thread startup.
    unsafe fn set_current(thread: *const Self) {
        WORKER_THREAD_STATE.with(|t| {
            assert!(t.get().is_null());
            t.set(thread);
        });
    }

    /// Returns the registry that owns this worker thread.
    #[inline]
    pub(super) const fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Our index amongst the worker threads (ranges from `0..self.num_threads()`).
    #[inline]
    pub(super) const fn index(&self) -> usize {
        self.index
    }

    #[inline]
    pub(super) unsafe fn push(&self, job: JobRef) {
        let queue_was_empty = self.worker.is_empty();
        self.worker.push(job);
        self.registry.sleep.new_internal_jobs(1, queue_was_empty);
    }

    #[inline]
    pub(super) fn local_deque_is_empty(&self) -> bool {
        self.worker.is_empty()
    }

    /// Attempts to obtain a "local" job -- typically this means
    /// popping from the top of the stack.
    #[inline]
    pub(super) fn take_local_job(&self) -> Option<JobRef> {
        let popped_job = self.worker.pop();

        if popped_job.is_some() {
            return popped_job;
        }

        loop {
            match self.stealer.steal() {
                Steal::Success(job) => return Some(job),
                Steal::Empty => return None,
                Steal::Retry => {}
            }
        }
    }

    fn has_injected_job(&self) -> bool {
        !self.stealer.is_empty() || self.registry.has_injected_job()
    }

    /// Wait until the latch is set. Try to keep busy by popping and
    /// stealing tasks as necessary.
    #[inline]
    pub(super) unsafe fn wait_until<L: AsCoreLatch + ?Sized>(&self, latch: &L) {
        let latch = latch.as_core_latch();
        if !latch.probe() {
            // SAFETY: the caller upholds `wait_until`'s contract.
            unsafe { self.wait_until_cold(latch) };
        }
    }

    #[cold]
    unsafe fn wait_until_cold(&self, latch: &CoreLatch) {
        // the code below should swallow all panics and hence never
        // unwind; but if something does wrong, we want to abort,
        // because otherwise other code in the scheduler may assume that the
        // latch has been signaled, and that can lead to random memory
        // accesses, which would be *very bad*
        let abort_guard = unwind::AbortIfPanic;

        'outer: while !latch.probe() {
            // Check for local work *before* we start marking ourself idle,
            // especially to avoid modifying shared sleep state.
            if let Some(job) = self.take_local_job() {
                // SAFETY: a job taken from a deque executes once, on a worker of its pool.
                unsafe { self.execute(job) };
                continue;
            }

            let mut idle_state = self.registry.sleep.start_looking(self.index);
            while !latch.probe() {
                if let Some(job) = self.find_work() {
                    self.registry.sleep.work_found();
                    // SAFETY: a job taken from a queue executes once, on a worker of its pool.
                    unsafe { self.execute(job) };
                    // The job might have injected local work, so go back to the outer loop.
                    continue 'outer;
                } else {
                    self.registry
                        .sleep
                        .no_work_found(&mut idle_state, latch, || self.has_injected_job())
                }
            }

            // If we were sleepy, we are not anymore. We "found work" --
            // whatever the surrounding thread was doing before it had to wait.
            self.registry.sleep.work_found();
            break;
        }

        mem::forget(abort_guard); // successful execution, do not abort
    }

    unsafe fn wait_until_out_of_work(&self) {
        debug_assert_eq!(self as *const _, Self::current());
        let registry = &*self.registry;
        let index = self.index;

        // SAFETY: this is the calling thread's worker state, and the latches belong to its
        // registry, which outlives the call.
        unsafe {
            self.wait_until(&registry.thread_infos[index].terminate);

            // Should not be any work left in our queue.
            debug_assert!(self.take_local_job().is_none());

            // Let registry know we are done
            Latch::set(&registry.thread_infos[index].stopped);
        }
    }

    fn find_work(&self) -> Option<JobRef> {
        // Try to find some work to do. We give preference first
        // to things in our local deque, then in other workers
        // deques, and finally to injected jobs from the
        // outside. The idea is to finish what we started before
        // we take on something new.
        self.take_local_job()
            .or_else(|| self.steal())
            .or_else(|| self.registry.pop_injected_job())
    }

    pub(super) fn yield_now(&self) -> Yield {
        self.find_work().map_or(Yield::Idle, |job| {
            // SAFETY: a job taken from a queue executes once, on a worker of its pool.
            unsafe { self.execute(job) };
            Yield::Executed
        })
    }

    #[inline]
    pub(super) unsafe fn execute(&self, job: JobRef) {
        // SAFETY: the caller took the job from a queue of this worker's pool, so it executes once.
        unsafe { job.execute() };
    }

    /// Try to steal a single job and return it.
    ///
    /// This should only be done as a last resort, when there is no
    /// local work to do.
    fn steal(&self) -> Option<JobRef> {
        // we only steal when we don't have any work to do locally
        debug_assert!(self.local_deque_is_empty());

        // otherwise, try to steal
        let thread_infos = &self.registry.thread_infos.as_slice();
        let num_threads = thread_infos.len();
        if num_threads <= 1 {
            return None;
        }

        loop {
            let mut retry = false;
            let start = self.rng.next_usize(num_threads);
            let job = (start..num_threads)
                .chain(0..start)
                .filter(move |&i| i != self.index)
                .find_map(|victim_index| {
                    let victim = &thread_infos[victim_index];
                    match victim.stealer.steal() {
                        Steal::Success(job) => Some(job),
                        Steal::Empty => None,
                        Steal::Retry => {
                            retry = true;
                            None
                        }
                    }
                });
            if job.is_some() || !retry {
                return job;
            }
        }
    }
}

unsafe fn main_loop(thread: ThreadBuilder) {
    let worker_thread = &WorkerThread::from(thread);
    // SAFETY: this thread belongs to no pool yet, and `worker_thread` lives on this frame until
    // the thread leaves the pool, when its drop clears the thread-local again.
    unsafe { WorkerThread::set_current(worker_thread) };
    let registry = &*worker_thread.registry;
    let index = worker_thread.index;

    // Worker threads should not panic. If they do, just abort, as the
    // internal state of the thread pool is corrupted. Note that if
    // **user code** panics, we should catch that and redirect.
    let abort_guard = unwind::AbortIfPanic;

    // Inform a user callback that we started a thread.
    if let Some(ref handler) = registry.start_handler {
        registry.catch_unwind(|| handler(index));
    }

    // SAFETY: `worker_thread` is this thread's worker state.
    unsafe { worker_thread.wait_until_out_of_work() };

    // Normal termination, do not abort.
    mem::forget(abort_guard);
}

/// If already in a worker-thread, just execute `op`. Either way, block until
/// `op` completes and return its return value. If `op` panics, that panic will
/// be propagated as well.  The second argument indicates `true` if injection
/// was performed, `false` if executed directly.
///
/// # Panics
///
/// Panics if the calling thread is not a worker of a thread pool.
pub(super) fn in_worker<OP, R>(op: OP) -> R
where
    OP: FnOnce(&WorkerThread, bool) -> R + Send,
    R: Send,
{
    // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
    let owner_thread = unsafe { WorkerThread::current().as_ref() };
    // Perfectly valid to give them a `&T`: this is the
    // current thread, so we know the data structure won't be
    // invalidated until we return.
    op(
        owner_thread.expect("the calling thread must be a worker of a thread pool"),
        false,
    )
}

/// [xorshift*] is a fast pseudorandom number generator which will
/// even tolerate weak seeding, as long as it's not zero.
///
/// [xorshift*]: https://en.wikipedia.org/wiki/Xorshift#xorshift*
struct XorShift64Star {
    state: Cell<u64>,
}

impl XorShift64Star {
    fn new() -> Self {
        // Any non-zero seed will do -- this uses the hash of a global counter.
        let mut seed = 0;
        while seed == 0 {
            let mut hasher = DefaultHasher::new();
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            hasher.write_usize(COUNTER.fetch_add(1, Ordering::Relaxed));
            seed = hasher.finish();
        }

        Self {
            state: Cell::new(seed),
        }
    }

    fn next(&self) -> u64 {
        let mut x = self.state.get();
        debug_assert_ne!(x, 0);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state.set(x);
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Return a value from `0..n`.
    fn next_usize(&self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
