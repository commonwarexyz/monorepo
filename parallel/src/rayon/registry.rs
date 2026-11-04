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
use crossbeam_deque::{Steal, Stealer, Worker};
use injector::Injector;
use std::{
    cell::Cell,
    hash::{DefaultHasher, Hasher},
    io, mem,
    ops::Range,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering, fence},
    },
    thread,
};

mod injector;
#[cfg(test)]
mod test;
mod wake;

#[cfg(test)]
use test::{WakePoint, at_wake_point};

/// Where a job runs among the groups of a pool's workers.
///
/// A pool's workers form consecutive groups of equal width, the last possibly narrower. A job
/// runs under the placement it was submitted with. Joins, installs, and spawns that name no
/// placement inherit the calling job's placement. Broadcast callbacks run as Local on each
/// receiving worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Run on the workers of this group only.
    Local(usize),
    /// Run on any worker. A job queued by a thread that is not a worker of the pool is offered to
    /// the idle workers of group `near` first, and a job a worker of the pool queues is offered to
    /// its own group first.
    Wide { near: usize },
}

/// The placement a worker runs its current job under, which selects the deque it pushes to.
/// `Local` always means the worker's own group.
///
/// Each queue stamps the jobs it receives with its tag, and a worker runs a job it takes under that
/// tag. Local deques, group injectors, and broadcast deques stamp `Local`. Wide deques and the wide
/// injector stamp `Wide`.
///
/// ```text
///               external submissions
///           Local(g)                Wide
///               |                     |
///        g's injector          shared injector
///               |                     |
///               v                     v
///         g's workers             any worker
///               ^                     ^
///               |                     |
///       g's Local deques    every worker's Wide deque
/// ```
///
/// A job placed [`Placement::Local`] on group `g` runs only on a worker of `g`, because every path
/// that moves it between threads keeps it there:
///
/// - Only workers of `g` pop `g`'s injector or steal from its workers' local deques, so jobs
///   injected into `g`, and the jobs their `Local` descendants push, run as `Local` in `g`. A
///   worker of `g` that installs or spawns such a job runs or pushes it itself.
/// - Join's inline pop runs job b on the worker that pushed it, under the tag b was pushed under,
///   since every later tag change is undone before the pop, also by unwinding.
/// - A broadcast job runs as `Local` on the worker whose broadcast deque holds it.
/// - Wide deques and the wide injector receive only jobs placed [`Placement::Wide`] and the jobs
///   that `Wide` jobs push.
/// - An install on `g` from a thread outside `g` injects into `g`'s injector. While it waits,
///   that thread helps only with jobs of its own pool that its own group may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tag {
    /// Pushes go to the worker's local deque, which only its group-mates steal from.
    Local,
    /// Pushes go to the worker's wide deque, which any worker steals from.
    Wide,
}

/// The state `Registry::new` builds for each of its workers.
struct ThreadBuilder {
    name: Option<String>,
    stack_size: Option<usize>,
    local: Worker<JobRef>,
    wide: Worker<JobRef>,
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

    /// The groups of workers, each `group_width` consecutive workers, the last possibly narrower.
    groups: Vec<Group>,

    /// The width of each full group. Only the last group may be narrower.
    group_width: usize,

    /// The width of each group, in group order.
    group_widths: Box<[usize]>,

    /// Jobs placed by threads that are not workers of their placement.
    injector: Injector,

    /// The pushing halves of the workers' broadcast deques, indexed by worker.
    broadcasts: Mutex<Vec<Worker<JobRef>>>,
    start_handler: Option<Box<StartHandler>>,

    // References keeping this registry running: one for the pool, plus one for each detached
    // job from before it is queued until its closure completes. Blocking installs borrow the
    // pool, and joins finish within their parent job, so neither needs a separate reference.
    // The workers may stop when this count reaches zero.
    terminate_count: AtomicUsize,
}

/// The sleep states of one group's workers.
///
/// A job placed [`Placement::Local`] on the group runs only on the group's workers, and its
/// notification reaches only the group's sleep protocol. That protocol runs upstream's code over
/// exactly those workers, so upstream's argument that no wakeup is lost holds for such a job.
///
/// Every worker of the group searches its group-mates' local deques and its group's incoming queue,
/// and a sleeper's final check reads that queue.
struct Group {
    /// Governs when the group's workers sleep and wake, indexed by their offset in the group.
    sleep: Sleep,
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
        let group_width = builder.get_group_width(n_threads);
        let group_widths: Box<[usize]> = (0..n_threads)
            .step_by(group_width)
            .map(|start| Ord::min(group_width, n_threads - start))
            .collect();

        let (locals, local_stealers): (Vec<_>, Vec<_>) = (0..n_threads)
            .map(|_| {
                let worker = Worker::new_lifo();
                let stealer = worker.stealer();
                (worker, stealer)
            })
            .unzip();

        let (wides, wide_stealers): (Vec<_>, Vec<_>) = (0..n_threads)
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
            thread_infos: local_stealers
                .into_iter()
                .zip(wide_stealers)
                .map(|(local, wide)| ThreadInfo::new(local, wide))
                .collect(),
            groups: group_widths
                .iter()
                .map(|&width| Group {
                    sleep: Sleep::new(width),
                })
                .collect(),
            injector: Injector::new(group_widths.len()),
            group_width,
            group_widths,
            broadcasts: Mutex::new(broadcasts),
            terminate_count: AtomicUsize::new(1),
            start_handler: builder.take_start_handler(),
        });

        // If we return early or panic, make sure to terminate existing threads.
        let t1000 = Terminator(&registry);

        let deques = locals.into_iter().zip(wides).zip(broadcast_stealers);
        for (index, ((local, wide), stealer)) in deques.enumerate() {
            let thread = ThreadBuilder {
                name: builder.get_thread_name(index),
                stack_size: builder.get_stack_size(),
                registry: Arc::clone(&registry),
                local,
                wide,
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

    /// The width of each group of workers, in group order.
    pub(super) fn group_widths(&self) -> &[usize] {
        &self.group_widths
    }

    /// The indices of the workers of `group`.
    pub(super) fn group_range(&self, group: usize) -> Range<usize> {
        let start = group * self.group_width;
        start..start + self.group_widths[group]
    }

    /// Asserts that `placement` names one of the registry's groups.
    pub(super) fn check_placement(&self, placement: Placement) {
        let (Placement::Local(group) | Placement::Wide { near: group }) = placement;
        assert!(
            group < self.groups.len(),
            "the placement must name a group of the pool"
        );
    }

    /// Runs `f`, aborting the process if it panics, since a panic in detached work has nowhere
    /// to propagate.
    pub(super) fn catch_unwind(&self, f: impl FnOnce()) {
        if let Err(_err) = unwind::halt_unwinding(f) {
            let _abort_guard = unwind::AbortIfPanic;
        }
    }

    /// Waits for the worker threads to stop, so tests can check that termination works.
    #[cfg(test)]
    pub(super) fn wait_until_stopped(&self) {
        for info in &self.thread_infos {
            info.stopped.wait();
        }
    }

    /// Queues a job under `placement`. An eligible worker of this registry pushes it onto its
    /// own deque for that placement. Other callers use the placement's injector.
    pub(super) fn place(&self, placement: Placement, job_ref: JobRef) {
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
        let worker_thread = unsafe { WorkerThread::current().as_ref() }
            .filter(|worker_thread| worker_thread.registry().id() == self.id());
        let eligible = worker_thread
            .and_then(|worker_thread| Some((worker_thread, worker_thread.tag_for(placement)?)));
        match eligible {
            // SAFETY: `worker_thread` is this thread's worker state, and the caller keeps the job
            // valid until it executes.
            Some((worker_thread, tag)) => unsafe { worker_thread.push_as(tag, job_ref) },
            None => self.inject(placement, job_ref),
        }
    }

    /// Pushes a job into the injector selected by `placement`, where an eligible idle worker
    /// can take it.
    pub(super) fn inject(&self, placement: Placement, injected_job: JobRef) {
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

        match placement {
            Placement::Local(group) => {
                let queue_was_empty = self.injector.push(group, injected_job.tagged(Tag::Local));
                self.groups[group]
                    .sleep
                    .new_injected_jobs(1, queue_was_empty);
            }
            Placement::Wide { near } => {
                let queue_was_empty = self
                    .injector
                    .push(self.injector.wide(), injected_job.tagged(Tag::Wide));
                self.new_injected_wide_job(near, queue_was_empty);
            }
        }
    }

    /// Pushes one job into each worker's broadcast queue. Only that worker can execute the job,
    /// after draining its own deques and before stealing other work.
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

            for (worker, job_ref) in broadcasts.iter().zip(injected_jobs) {
                worker.push(job_ref.tagged(Tag::Local));
            }
        }
        for i in 0..self.num_threads() {
            self.notify_worker_latch_is_set(i);
        }
    }

    /// Runs `op` under `placement` and returns its result or propagates its panic. An eligible
    /// worker of this registry runs `op` inline. Other callers inject it and wait. The second
    /// argument to `op` is `true` when the job was injected and `false` when it runs inline.
    pub(super) fn in_worker_placed<OP, R>(&self, placement: Placement, op: OP) -> R
    where
        OP: FnOnce(&WorkerThread, bool) -> R + Send,
        R: Send,
    {
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
        unsafe {
            let worker_thread = WorkerThread::current();
            if worker_thread.is_null() {
                return self.in_worker_cold(placement, op);
            }
            let worker_thread = &*worker_thread;
            if worker_thread.registry().id() != self.id() {
                return self.in_worker_cross(worker_thread, placement, op);
            }
            match worker_thread.tag_for(placement) {
                Some(tag) => worker_thread.run_as(tag, || op(worker_thread, false)),
                None => self.in_worker_cross(worker_thread, placement, op),
            }
        }
    }

    #[cold]
    unsafe fn in_worker_cold<OP, R>(&self, placement: Placement, op: OP) -> R
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
                self.inject(placement, job.as_job_ref());
                job.latch.wait_and_reset(); // Make sure we can use the same latch again next time.

                job.into_result()
            }
        })
    }

    #[cold]
    unsafe fn in_worker_cross<OP, R>(
        &self,
        current_thread: &WorkerThread,
        placement: Placement,
        op: OP,
    ) -> R
    where
        OP: FnOnce(&WorkerThread, bool) -> R + Send,
        R: Send,
    {
        // This thread is a member of a different pool, or of a group that the placement
        // excludes, so let it process other work while waiting for this `op` to complete.
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
            self.inject(placement, job.as_job_ref());
            current_thread.wait_until(&job.latch);
            job.into_result()
        }
    }

    /// Keeps the registry running for a detached job. The job must call `terminate` once its
    /// closure completes. Blocking calls rely on their caller to keep the pool alive.
    pub(super) fn increment_terminate_count(&self) {
        let previous = self.terminate_count.fetch_add(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "registry ref count incremented from zero");
        assert!(previous != usize::MAX, "overflow in registry ref count");
    }

    /// Releases the pool's reference or a completed detached job's reference. Releasing the
    /// last reference signals every worker to stop.
    pub(super) fn terminate(&self) {
        if self.terminate_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            for (i, thread_info) in self.thread_infos.iter().enumerate() {
                // SAFETY: the latch belongs to this registry, which outlives the call.
                unsafe { OnceLatch::set_and_tickle_one(&thread_info.terminate, self, i) };
            }
        }
    }

    /// Wakes the worker waiting on a latch that has been set. The worker's offset in its group
    /// identifies its sleep state.
    pub(super) fn notify_worker_latch_is_set(&self, target_worker_index: usize) {
        let group = target_worker_index / self.group_width;
        self.groups[group]
            .sleep
            .notify_worker_latch_is_set(target_worker_index % self.group_width);
    }

    /// The number of workers of `group` registered as asleep, for tests that wait for a quiet
    /// pool.
    #[cfg(test)]
    pub(super) fn sleeping_workers(&self, group: usize) -> usize {
        self.groups[group].sleep.sleeping_threads()
    }

    /// The number of times the worker at `index` was woken from sleep, for tests of who wakes.
    #[cfg(test)]
    pub(super) fn wakeups(&self, index: usize) -> usize {
        self.groups[index / self.group_width]
            .sleep
            .wakeups(index % self.group_width)
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

    /// The end of the worker's local deque that its group-mates steal from.
    local: Stealer<JobRef>,

    /// The end of the worker's wide deque that any worker can steal from.
    wide: Stealer<JobRef>,
}

impl ThreadInfo {
    const fn new(local: Stealer<JobRef>, wide: Stealer<JobRef>) -> Self {
        Self {
            stopped: LockLatch::new(),
            terminate: OnceLatch::new(),
            local,
            wide,
        }
    }
}

pub(super) struct WorkerThread {
    /// The local deque this worker pushes to, which only its group-mates steal from.
    local: Worker<JobRef>,

    /// The wide deque this worker pushes to, which any worker can steal from.
    wide: Worker<JobRef>,

    /// The end of this worker's broadcast deque that it takes jobs from.
    stealer: Stealer<JobRef>,

    index: usize,

    /// This worker's group.
    group: usize,

    /// This worker's offset in its group.
    offset: usize,

    /// The current job's tag. It selects the deque this worker pushes to.
    tag: Cell<Tag>,

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
        let group_width = thread.registry.group_width;
        Self {
            local: thread.local,
            wide: thread.wide,
            stealer: thread.stealer,
            index: thread.index,
            group: thread.index / group_width,
            offset: thread.index % group_width,
            // Code that runs on a worker outside any job, such as a thread taken over with
            // `use_current_thread`, places its jobs on the whole pool.
            tag: Cell::new(Tag::Wide),
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

/// Restores a worker's tag when dropped.
struct RestoreTag<'a> {
    tag: &'a Cell<Tag>,
    previous: Tag,
}

impl Drop for RestoreTag<'_> {
    fn drop(&mut self) {
        self.tag.set(self.previous);
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

    /// Our group.
    #[cfg(test)]
    #[inline]
    pub(super) const fn group(&self) -> usize {
        self.group
    }

    /// The tag under which we may run or push work placed under `placement`, or `None` when
    /// `placement` is local to another group.
    #[inline]
    const fn tag_for(&self, placement: Placement) -> Option<Tag> {
        match placement {
            Placement::Local(group) if group != self.group => None,
            Placement::Local(_) => Some(Tag::Local),
            Placement::Wide { .. } => Some(Tag::Wide),
        }
    }

    /// The placement of the job we run.
    #[inline]
    pub(super) const fn placement(&self) -> Placement {
        match self.tag.get() {
            Tag::Local => Placement::Local(self.group),
            Tag::Wide => Placement::Wide { near: self.group },
        }
    }

    /// The number of workers the placement of the job we run spans: our group's under
    /// [`Tag::Local`] and the whole pool's under [`Tag::Wide`].
    #[inline]
    pub(super) fn width(&self) -> usize {
        match self.tag.get() {
            Tag::Local => self.registry.group_widths[self.group],
            Tag::Wide => self.registry.num_threads(),
        }
    }

    /// Runs `op` under `tag` and restores the previous tag afterward, even when `op` unwinds.
    ///
    /// Nested jobs and installs restore the suspended job's tag before it resumes. This also
    /// keeps a join's inline second closure under the tag it was pushed with.
    #[inline]
    pub(super) fn run_as<R>(&self, tag: Tag, op: impl FnOnce() -> R) -> R {
        let _restore = RestoreTag {
            tag: &self.tag,
            previous: self.tag.replace(tag),
        };
        op()
    }

    /// Pushes a job onto the deque for the current tag.
    #[inline]
    pub(super) unsafe fn push(&self, job: JobRef) {
        // SAFETY: the caller keeps the job valid until it executes.
        unsafe { self.push_as(self.tag.get(), job) }
    }

    /// Pushes a job onto the deque of `tag` and notifies the workers that may steal it.
    #[inline]
    pub(super) unsafe fn push_as(&self, tag: Tag, job: JobRef) {
        match tag {
            Tag::Local => {
                let queue_was_empty = self.local.is_empty();
                self.local.push(job.tagged(Tag::Local));
                self.registry.groups[self.group]
                    .sleep
                    .new_internal_jobs(1, queue_was_empty);
            }
            Tag::Wide => {
                let queue_was_empty = self.wide.is_empty();
                self.wide.push(job.tagged(Tag::Wide));
                self.registry.new_wide_job(self.group, queue_was_empty);
            }
        }
    }

    /// Whether both of our deques are empty.
    #[inline]
    pub(super) fn deques_are_empty(&self) -> bool {
        self.local.is_empty() && self.wide.is_empty()
    }

    /// Tries this worker's current-placement deque, then its other deque, then its broadcasts.
    #[inline]
    pub(super) fn take_own_job(&self) -> Option<JobRef> {
        let (own, other) = match self.tag.get() {
            Tag::Local => (&self.local, &self.wide),
            Tag::Wide => (&self.wide, &self.local),
        };
        let popped_job = own.pop().or_else(|| other.pop());

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
        !self.stealer.is_empty() || self.registry.has_injected_job(self.group)
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
        let sleep = &self.registry.groups[self.group].sleep;

        'outer: while !latch.probe() {
            // Check for local work *before* we start marking ourself idle,
            // especially to avoid modifying shared sleep state.
            if let Some(job) = self.take_own_job() {
                // SAFETY: a job taken from a deque executes once, on a worker of its pool.
                unsafe { self.execute(job) };
                continue;
            }

            let mut idle_state = sleep.start_looking(self.offset);
            while !latch.probe() {
                #[cfg(test)]
                at_wake_point(WakePoint::BeforeSearch);
                if let Some(job) = self.find_work() {
                    #[cfg(test)]
                    at_wake_point(WakePoint::Found);
                    self.registry.work_found(self.group, job.tag());
                    // SAFETY: a job taken from a queue executes once, on a worker of its pool.
                    unsafe { self.execute(job) };
                    // The job might have injected local work, so go back to the outer loop.
                    continue 'outer;
                } else {
                    sleep.no_work_found(&mut idle_state, latch, || self.has_injected_job())
                }
            }

            // Resuming the waiting job ends the idle search.
            #[cfg(test)]
            at_wake_point(WakePoint::Resumed);
            self.registry.work_found(self.group, self.tag.get());
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
            debug_assert!(self.take_own_job().is_none());

            // Let tests that wait for the workers to stop know we are done.
            Latch::set(&registry.thread_infos[index].stopped);
        }
    }

    /// Finds a job to run.
    ///
    /// The search tries each source below in turn, so deque work keeps priority over incoming jobs.
    /// Arrival order governs only the admission of incoming jobs, without reserving a share for
    /// either placement.
    ///
    /// ```text
    /// our own deques and broadcasts
    ///   | empty
    ///   v
    /// our group-mates' Local deques
    ///   | empty
    ///   v
    /// every other worker's Wide deque, our group-mates' first
    ///   | empty
    ///   v
    /// the oldest job across our group's Local injector and the shared Wide injector
    /// ```
    ///
    /// Joins and installs wait only on descendants, so their waits follow the job tree and cannot
    /// form a cycle. Their liveness follows upstream's argument under its assumptions that jobs
    /// block only in scheduler waits and workers keep searching.
    ///
    /// A thread taken over with `use_current_thread` does not search while it runs its own code.
    /// The waiting worker's placement only orders its own two deques, and each descendant is queued
    /// where an eligible searching worker reaches it:
    ///
    /// - A `Local` descendant sits in a local deque or the injector of our group, where our group's
    ///   searches reach it.
    /// - A `Wide` descendant sits in a wide deque or the wide injector, where every search reaches
    ///   it.
    /// - A descendant placed on another group `h` sits where the searches of `h`'s workers reach
    ///   it, and each of them is running a job or searching. The waiting ancestor meanwhile helps
    ///   with any job its own group may take, including the `Wide` jobs a stolen child pushes.
    ///
    /// Native future waits use the same search. Their completion also depends on the future's
    /// producer, and the producer can depend on work outside the job tree.
    fn find_work(&self) -> Option<JobRef> {
        self.take_own_job()
            .or_else(|| self.steal_local())
            .or_else(|| self.steal_wide())
            .or_else(|| self.registry.injector.pop(self.group))
    }

    pub(super) fn yield_now(&self) -> Yield {
        self.find_work().map_or(Yield::Idle, |job| {
            // SAFETY: a job taken from a queue executes once, on a worker of its pool.
            unsafe { self.execute(job) };
            Yield::Executed
        })
    }

    /// Executes `job` under the tag its queue stamped it with.
    #[inline]
    pub(super) unsafe fn execute(&self, job: JobRef) {
        self.run_as(job.tag(), || {
            // SAFETY: the caller took the job from a queue of this worker's pool, so it executes
            // once.
            unsafe { job.execute() }
        });
    }

    /// Try to steal a single job from the local deque of one of our group-mates and return it.
    ///
    /// This should only be done as a last resort, when there is no
    /// local work to do.
    fn steal_local(&self) -> Option<JobRef> {
        // we only steal when we don't have any work to do locally
        debug_assert!(self.deques_are_empty());

        // otherwise, try to steal
        let thread_infos = &self.registry.thread_infos.as_slice();
        let group = self.registry.group_range(self.group);
        let width = group.len();
        if width <= 1 {
            return None;
        }

        loop {
            let mut retry = false;
            let start = self.rng.next_usize(width);
            let job = (start..width)
                .chain(0..start)
                .map(|offset| group.start + offset)
                .filter(move |&i| i != self.index)
                .find_map(|victim_index| {
                    let victim = &thread_infos[victim_index];
                    match victim.local.steal() {
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

    /// Try to steal a single job from the wide deque of another worker and return it, trying our
    /// group-mates first and then the rest of the pool.
    ///
    /// This should only be done as a last resort, when there is no
    /// local work to do.
    fn steal_wide(&self) -> Option<JobRef> {
        // we only steal when we don't have any work to do locally
        debug_assert!(self.deques_are_empty());

        // otherwise, try to steal
        let thread_infos = &self.registry.thread_infos.as_slice();
        let num_threads = thread_infos.len();
        if num_threads <= 1 {
            return None;
        }
        let group = self.registry.group_range(self.group);
        let width = group.len();

        loop {
            let mut retry = false;
            let mate = self.rng.next_usize(width);
            let mates = (mate..width)
                .chain(0..mate)
                .map(|offset| group.start + offset);
            let start = self.rng.next_usize(num_threads);
            let others = (start..num_threads)
                .chain(0..start)
                .filter(|i| !group.contains(i));
            let job = mates
                .chain(others)
                .filter(move |&i| i != self.index)
                .find_map(|victim_index| {
                    let victim = &thread_infos[victim_index];
                    match victim.wide.steal() {
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

/// Runs `op` on the calling worker and returns its result or propagates its panic. The second
/// argument to `op` is always `false` because `op` runs directly.
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
        // Any nonzero seed is sufficient for choosing steal victims.
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
