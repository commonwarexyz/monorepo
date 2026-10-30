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
    io, mem,
    ops::Range,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

#[cfg(test)]
mod test;

/// Where a job runs among the groups of a pool's workers.
///
/// A pool's workers form consecutive groups of equal width, the last possibly narrower. A job
/// runs under the placement it was submitted with, and the jobs it submits from its worker that
/// name no placement inherit it, so a placement holds for the tree of jobs below it until one of
/// them names another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Run on the workers of this group only.
    Local(usize),
    /// Run on any worker. A job queued from outside the pool is offered to the idle workers of
    /// group `near` first, and a job a worker of the pool queues is offered to its own group first.
    Wide { near: usize },
}

/// The placement of the job a worker runs, which selects the deque the worker pushes to. A
/// worker's local placement is always for its own group.
///
/// Each queue stamps the jobs it receives with its tag: local deques, group injectors, and
/// broadcast deques with `Local`, and wide deques and the wide injector with `Wide`. A worker
/// runs a job it takes under the job's tag.
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
/// A job placed [`Placement::Local`] on group `g` runs only on a worker of `g`. Every path that
/// moves a job between threads preserves this restriction:
///
/// - From a thread that is not a worker of `g`, the job waits in `g`'s injector, which only the
///   workers of `g` pop, and the worker that pops it runs it as `Local`. A worker of `g` that
///   installs or spawns it runs or pushes it itself as `Local`.
/// - A worker running a `Local` job pushes to its local deque. It pops that deque itself, and
///   only its group-mates steal from it, so the jobs it holds run as `Local` in `g`, and so do
///   the jobs they push in turn.
/// - Join's inline pop runs job b on the worker that pushed it, under the worker's current tag.
///   That is the tag b was pushed under, since every tag change made after the push is undone
///   before the pop, also by unwinding.
/// - A broadcast job runs on the worker whose broadcast deque holds it, as `Local`.
/// - Wide deques and the wide injector, which any worker takes from, receive only jobs placed
///   [`Placement::Wide`] and the jobs that `Wide` jobs push. A `Wide` job leaves its placement
///   only by installing or spawning on a group explicitly, which the first rule covers.
/// - An install on `g` from a worker of another group or pool injects the operation into `g`'s
///   injector and waits stealing. The waiting thread helps only with jobs of its own pool that
///   its own group may take, never with jobs local to `g`.
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
    group_width: usize,
    group_widths: Box<[usize]>,
    /// Jobs placed [`Placement::Wide`] by threads that are not workers of this registry, taken by
    /// any worker.
    wide_injected_jobs: Injector<JobRef>,
    /// The pushing halves of the workers' broadcast deques, indexed by worker.
    broadcasts: Mutex<Vec<Worker<JobRef>>>,
    start_handler: Option<Box<StartHandler>>,

    // When this latch reaches 0, it means that all work on this
    // registry must be complete. This is ensured in the following ways:
    //
    // - so long as the thread pool exists, it holds a reference.
    // - when we inject a "blocking job" into the registry with `ThreadPool::install_in()`,
    //   no adjustment is needed; the `ThreadPool` holds the reference, and since we won't
    //   return until the blocking job is complete, that ref will continue to be held.
    // - when `join()` is invoked, similarly, no adjustments are needed. It is always owned by
    //   some other job (e.g., one injected by `ThreadPool::install_in()`) and that job will
    //   keep the pool alive.
    //
    // A detached job, spawned or broadcast, holds a reference from before it is queued until it
    // has run, so no detached job is left queued when the workers stop.
    terminate_count: AtomicUsize,
}

/// The jobs placed on one group by threads outside it, and the sleep states of its workers.
///
/// A job placed [`Placement::Local`] on the group runs only on the group's workers, and its
/// notification reaches only the group's sleep protocol, which runs upstream's code over exactly
/// those workers. Upstream's argument that no wakeup is lost therefore holds for such a job with
/// the pool restricted to the group: every worker of the group searches its group-mates' local
/// deques and its group's injector, and a sleeper's final check reads that injector.
struct Group {
    /// Jobs placed [`Placement::Local`] on the group by a thread that is not one of its workers.
    /// Only the group's workers take them.
    injected_jobs: Injector<JobRef>,
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
                    injected_jobs: Injector::new(),
                    sleep: Sleep::new(width),
                })
                .collect(),
            group_width,
            group_widths,
            wide_injected_jobs: Injector::new(),
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

    /// Panics unless `placement` names one of the registry's groups.
    pub(super) fn check(&self, placement: Placement) {
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

    /// Waits for the worker threads to stop. This is used for testing
    /// -- so we can check that termination actually works.
    #[cfg(test)]
    pub(super) fn wait_until_stopped(&self) {
        for info in &self.thread_infos {
            info.stopped.wait();
        }
    }

    /// Queues a job placed as `placement` says. A worker of this registry that the placement
    /// admits pushes it onto its own deque for that placement, and any other thread injects it.
    pub(super) fn place(&self, placement: Placement, job_ref: JobRef) {
        // SAFETY: a non-null pointer is this thread's worker state, which outlives the call.
        let worker_thread = unsafe { WorkerThread::current().as_ref() }
            .filter(|worker_thread| worker_thread.registry().id() == self.id());
        let tag = match (worker_thread, placement) {
            (Some(worker_thread), Placement::Local(group)) if group == worker_thread.group => {
                Tag::Local
            }
            (Some(_), Placement::Wide { .. }) => Tag::Wide,
            _ => return self.inject(placement, job_ref),
        };
        if let Some(worker_thread) = worker_thread {
            // SAFETY: `worker_thread` is this thread's worker state, and the caller keeps the job
            // valid until it executes.
            unsafe { worker_thread.push_as(tag, job_ref) };
        }
    }

    /// Push a job into the "external jobs" queue that `placement` selects; it will be taken
    /// by whatever worker of the placement has nothing to do. Use this if you know that
    /// you are not on a worker of this registry that the placement admits.
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
                let group = &self.groups[group];
                let queue_was_empty = group.injected_jobs.is_empty();

                group.injected_jobs.push(injected_job.tagged(Tag::Local));
                group.sleep.new_injected_jobs(1, queue_was_empty);
            }
            Placement::Wide { near } => {
                let queue_was_empty = self.wide_injected_jobs.is_empty();

                self.wide_injected_jobs.push(injected_job.tagged(Tag::Wide));
                self.new_wide_jobs(near, queue_was_empty, true);
            }
        }
    }

    /// Signals that a job any worker may take was queued, offering it to the workers of group
    /// `near` first and then to the other groups in cyclic order. `injected` says whether the job
    /// went to the wide injector rather than to a worker's wide deque.
    ///
    /// Each group runs upstream's sleep protocol on its own counters. The walk marks each
    /// visited group's jobs event counter active and stops at the first group that covers the
    /// job. For an empty queue, an awake idle worker counts as coverage; otherwise the group must
    /// wake a sleeper. `Sleep::new_jobs` reports any uncovered work to continue the walk.
    ///
    /// Coverage reserves no worker. A covering worker may take local work or resume a job whose
    /// latch was set. On either exit from the idle loop, `work_found` wakes local sleepers first.
    /// If none wake, starting or resuming wide work continues the chain in other groups. Local
    /// work continues it only while wide work remains queued. A wide transition can wake another
    /// worker after the last queued job has been taken. A worker that stays idle searches every
    /// wide queue before sleeping.
    ///
    /// An injection fences between queuing the job and reading each group's counters. A sleeper
    /// fences between registering as asleep and checking its broadcast deque, its group's
    /// injector, and the wide injector. An idle exit similarly fences between decrementing the
    /// idle count and checking wide queues for a local transition. These paired fences keep a
    /// queued injection visible when its publisher counted the worker idle. Internal pushes retain
    /// upstream's lighter notification protocol, with the publishing worker able to pop its own jobs.
    fn new_wide_jobs(&self, near: usize, queue_was_empty: bool, injected: bool) {
        let n_groups = self.groups.len();
        let mut uncovered = 1;
        for group in (near..n_groups).chain(0..near) {
            let sleep = &self.groups[group].sleep;
            uncovered = if injected {
                sleep.new_injected_jobs(uncovered, queue_was_empty)
            } else {
                sleep.new_internal_jobs(uncovered, queue_was_empty)
            };
            if uncovered == 0 {
                return;
            }
        }
    }

    /// Leaves the idle state and continues the wake chain for wide work.
    #[inline]
    fn work_found(&self, group: usize, tag: Tag) {
        if self.groups[group].sleep.work_found() || self.groups.len() == 1 {
            return;
        }

        if tag == Tag::Local {
            // Pair with the injector's fence so an injection either sees this worker active
            // or appears in the queue check below.
            std::sync::atomic::fence(Ordering::SeqCst);
            if self.wide_injected_jobs.is_empty()
                && self
                    .thread_infos
                    .iter()
                    .all(|thread| thread.wide.is_empty())
            {
                return;
            }
        }

        self.new_wide_jobs((group + 1) % self.groups.len(), false, false);
    }

    /// Whether a job is waiting in `group`'s injector or in the wide injector.
    fn has_injected_job(&self, group: usize) -> bool {
        !self.groups[group].injected_jobs.is_empty() || !self.wide_injected_jobs.is_empty()
    }

    fn pop_injected_job(injected_jobs: &Injector<JobRef>) -> Option<JobRef> {
        loop {
            match injected_jobs.steal() {
                Steal::Success(job) => return Some(job),
                Steal::Empty => return None,
                Steal::Retry => {}
            }
        }
    }

    /// Push a job into each thread's own "external jobs" queue, for each thread in `workers`;
    /// it will be executed only on that thread, when it has nothing else to do locally,
    /// before it tries to steal other work.
    ///
    /// **Panics** if not given exactly as many jobs as there are threads in `workers`.
    pub(super) fn inject_broadcast(
        &self,
        workers: Range<usize>,
        injected_jobs: impl ExactSizeIterator<Item = JobRef>,
    ) {
        assert_eq!(workers.len(), injected_jobs.len());
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

            for (worker, job_ref) in broadcasts[workers.clone()].iter().zip(injected_jobs) {
                worker.push(job_ref.tagged(Tag::Local));
            }
        }
        for i in workers {
            self.notify_worker_latch_is_set(i);
        }
    }

    /// Runs `op` as `placement` says and returns its result, propagating its panic. A worker of
    /// this registry that the placement admits runs `op` itself under that placement. Any other
    /// thread, including a worker of another group, injects `op` and waits for it. The second
    /// argument to `op` indicates `true` if injection was performed, `false` if executed
    /// directly.
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
            let tag = match placement {
                Placement::Local(group) if group != worker_thread.group => {
                    return self.in_worker_cross(worker_thread, placement, op);
                }
                Placement::Local(_) => Tag::Local,
                Placement::Wide { .. } => Tag::Wide,
            };
            worker_thread.run_as(tag, || op(worker_thread, false))
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

    /// Increments the terminate counter. This increment should be
    /// balanced by a call to `terminate`, which will decrement. This
    /// is used when spawning asynchronous work, which needs to
    /// prevent the registry from terminating so long as it is active.
    ///
    /// Note that blocking functions such as `join` do not need to
    /// concern themselves with this fn; their context is responsible
    /// for ensuring the current thread pool will not terminate until
    /// they return.
    ///
    /// A thread pool has one outstanding reference that is dropped
    /// when the `ThreadPool` is dropped: since installing the thread
    /// pool blocks until any joins complete, this ensures that joins
    /// are covered.
    ///
    /// The exception is `spawn_in`, which can create a job outside
    /// of any blocking call. In that case, the job itself holds a
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

    /// Notify the worker that the latch they are sleeping on has been "set". The worker sleeps
    /// in its group's sleep states, at its offset in the group.
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

    /// the "stealer" half of the worker's local deque, which only its group-mates use
    local: Stealer<JobRef>,

    /// the "stealer" half of the worker's wide deque, which any worker uses
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
    /// the "worker" half of our local deque, which only our group-mates steal from
    local: Worker<JobRef>,

    /// the "worker" half of our wide deque, which any worker steals from
    wide: Worker<JobRef>,

    /// the "stealer" half of the worker's broadcast deque
    stealer: Stealer<JobRef>,

    index: usize,

    /// Our group, and our offset in it.
    group: usize,
    offset: usize,

    /// The placement of the job we run, which selects the deque we push to.
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

    /// Runs `op` under `tag` and restores the previous tag afterwards, also when `op` unwinds.
    ///
    /// Only the jobs a worker takes from a queue and the operations it installs and runs itself
    /// pass through here, so a worker's tag always names the placement of the innermost such job
    /// or install on its stack, and the code after a nested one runs under its own placement
    /// again. Join's inline run of its second closure keeps the tag in force, which is the tag the
    /// closure was pushed under.
    #[inline]
    pub(super) fn run_as<R>(&self, tag: Tag, op: impl FnOnce() -> R) -> R {
        let _restore = RestoreTag {
            tag: &self.tag,
            previous: self.tag.replace(tag),
        };
        op()
    }

    /// Pushes a job onto the deque of the job we run.
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
                self.registry
                    .new_wide_jobs(self.group, queue_was_empty, false);
            }
        }
    }

    /// Whether both of our deques are empty.
    #[inline]
    pub(super) fn local_deque_is_empty(&self) -> bool {
        self.local.is_empty() && self.wide.is_empty()
    }

    /// Attempts to obtain a "local" job -- typically this means
    /// popping from the top of the stack. The deque of our current
    /// placement comes first, then our other deque, then our broadcasts.
    #[inline]
    pub(super) fn take_local_job(&self) -> Option<JobRef> {
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
            if let Some(job) = self.take_local_job() {
                // SAFETY: a job taken from a deque executes once, on a worker of its pool.
                unsafe { self.execute(job) };
                continue;
            }

            let mut idle_state = sleep.start_looking(self.offset);
            while !latch.probe() {
                #[cfg(test)]
                test::at_wake_point(test::WakePoint::BeforeSearch);
                if let Some(job) = self.find_work() {
                    #[cfg(test)]
                    test::at_wake_point(test::WakePoint::Found);
                    self.registry.work_found(self.group, job.tag());
                    // SAFETY: a job taken from a queue executes once, on a worker of its pool.
                    unsafe { self.execute(job) };
                    // The job might have injected local work, so go back to the outer loop.
                    continue 'outer;
                } else {
                    sleep.no_work_found(&mut idle_state, latch, || self.has_injected_job())
                }
            }

            // If we were sleepy, we are not anymore. We "found work" --
            // whatever the surrounding thread was doing before it had to wait.
            #[cfg(test)]
            test::at_wake_point(test::WakePoint::Resumed);
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
            debug_assert!(self.take_local_job().is_none());

            // Let tests that wait for the workers to stop know we are done.
            Latch::set(&registry.thread_infos[index].stopped);
        }
    }

    /// Finds a job to run.
    ///
    /// The search covers our own deques and broadcasts, our group-mates' local deques, our
    /// group's injector, every other worker's wide deque (our group-mates' first), and the wide
    /// injector, in that order. Our own deques come first whatever their placement. Among other
    /// workers' jobs and injected ones, those placed on our group come before those any worker
    /// may take, so a group's queued work does not wait while its workers help elsewhere.
    ///
    /// Joins and installs wait on descendant work, so their waits follow the job tree and cannot
    /// form a cycle. Their liveness follows upstream's argument under its assumptions that jobs
    /// block only in scheduler waits and workers keep searching. A thread taken over with
    /// `use_current_thread` does not search while it runs its own code. The search reaches the same
    /// queues whatever placement the waiting worker runs under, which only orders its own two
    /// deques. Each descendant must be queued where an eligible searching worker can reach it:
    ///
    /// - A descendant pushed under `Local` sits in the local deque of a worker of our group or in
    ///   our group's injector. Our search and our group-mates' searches reach it, which is
    ///   upstream's single pool restricted to the group.
    /// - A descendant pushed under `Wide` sits in a wide deque or the wide injector, which every
    ///   search reaches, which is upstream's single pool.
    /// - A descendant placed explicitly on a group `h` sits in `h`'s injector or in the local deque
    ///   of a worker of `h`, which the searches of `h`'s workers reach. Each worker of `h` is
    ///   running a job or searching, so the descendant starts, and its own descendants fall under
    ///   these cases again. Its waiting ancestor keeps searching meanwhile and helps with any of
    ///   them that its group may take.
    /// - In particular, a worker running a `Wide` job that waits on a `Local` job of its group
    ///   reaches that job in its group-mates' local deques and its group's injector, and a worker
    ///   running a `Local` job that waits on a `Wide` child stolen by a worker of another group
    ///   reaches every `Wide` job the child pushes, so it helps rather than idles while the thief
    ///   runs the child.
    ///
    /// Native future waits use the same search. Their completion also depends on the future's
    /// producer making progress; its dependencies need not follow the job tree.
    fn find_work(&self) -> Option<JobRef> {
        // Try to find some work to do. We give preference first
        // to things in our local deque, then in other workers
        // deques, and finally to injected jobs from the
        // outside. The idea is to finish what we started before
        // we take on something new.
        self.take_local_job()
            .or_else(|| self.steal_local())
            .or_else(|| Registry::pop_injected_job(&self.registry.groups[self.group].injected_jobs))
            .or_else(|| self.steal_wide())
            .or_else(|| Registry::pop_injected_job(&self.registry.wide_injected_jobs))
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
        debug_assert!(self.local_deque_is_empty());

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
        debug_assert!(self.local_deque_is_empty());

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

/// Runs `op` on the calling worker and returns its result, propagating its panic. The second
/// argument to `op` is always `false`, which marks a direct run on the calling worker.
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
