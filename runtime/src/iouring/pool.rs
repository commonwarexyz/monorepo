//! The pool of workers that poll ordinary tasks.
//!
//! [`Pool`] is the state the workers share: every worker's mailbox, the
//! pool-wide global queue, the idle set, and the shutdown barrier. The runner
//! creates it before any worker starts, every worker reaches it through the
//! runner's shared services, and every task's header holds a weak reference to
//! it, so a wake from any thread can find the task's pool without keeping the
//! pool alive. [`Threads`] starts the workers after worker zero, each on a
//! thread of its own, and joins them at shutdown.
//!
//! # Placement
//!
//! A runnable woken on a worker of its own pool joins that worker's ready
//! queue, and a new task stays on a pool worker with nothing else queued or no
//! other worker. Every other push goes to the global queue: wakes and spawns
//! from outside the pool or on a closing worker, and spawns that leave a busy
//! worker. Workers take a share of the queue whenever their own runs dry and
//! once every [global queue interval] of takes, so a busy worker cannot keep a
//! burst waiting one interval per runnable.
//!
//! [global queue interval]: super::Config::with_global_queue_interval
//!
//! # Global queue
//!
//! The global queue is a [`VecDeque`] behind one pool-wide mutex, with its
//! length mirrored in an atomic. Workers read the mirror to decide whether
//! there is anything to take, so a worker that finds nothing, the common case,
//! never locks. A take moves a share of the queue into the taking worker's own
//! queue under one lock: one runnable more than an even split between the
//! workers, at most [`GLOBAL_BATCH`]. The mirror is stored only under the lock,
//! so its stores follow the queue's own order.
//!
//! ```text
//! push   lock, refuse if closed, append, store the length, unlock, wake
//! take   load the length (zero: done), lock, move a share, store the
//!        length, unlock
//! close  lock, refuse later pushes, store zero, take the rest, unlock,
//!        discard what was taken
//! ```
//!
//! # Waking a parked worker
//!
//! The idle set is one `u64` with a bit per worker, which is why a pool has
//! at most [`MAX_WORKERS`] workers. A worker sets its bit before its last look at
//! the global queue and clears it once it runs again. A push into the global
//! queue clears the lowest set bit to claim that worker and wakes it, so each
//! parked worker is woken by at most one push. Each side fences between its
//! store and its load, so at least one of them sees the other's store: either
//! the worker finds the push and runs it, or the pusher finds the worker's bit,
//! so the idle set is not empty and the pusher wakes one idle worker, not
//! necessarily that one. A push is therefore never left queued with every
//! worker asleep.
//!
//! ```text
//! push                              parking worker i
//!   queue the runnable                set idle bit i
//!   fence(SeqCst)                     fence(SeqCst)
//!   load the idle set                 load the global queue length
//!   any bit set: clear the lowest     nonzero: clear bit i and run
//!     and wake its worker             zero: arm the wake source and block
//! ```
//!
//! A wake that arrives before the worker arms its wait is latched by the
//! worker's wake source, so the wait returns at once. A woken worker that finds
//! the queue already emptied by another worker publishes itself and parks
//! again.
//!
//! # Lifecycle
//!
//! Worker zero runs on the runner's thread. It starts the others one at a
//! time, each creating its ring and joining the shutdown barrier before the
//! next starts, and builds the root only once all of them run. The root of
//! every other worker ends when worker zero stops the pool.
//!
//! ```text
//! worker zero                            worker i (1..n)
//!   Pool::new (every mailbox)
//!   enter, start worker i ------------->   enter, report ready
//!   build and drive the root               drive tasks
//!   root ends: close the task set,
//!     then the global queue
//!   abort the supervision tree
//!   stop the pool --------------------->   root ends
//!   drain the set from shard 0             drain the set from its shards
//!   finish <=========== barrier ==========> finish
//!   close mailbox, drop inbox, ring        close mailbox, drop inbox, ring
//!   join <------------------------------   exit
//!   take a failure reported late
//! ```
//!
//! Shutdown closes the task set before the global queue, so a runnable the
//! closed queue refuses belongs to a task that teardown clears or already has
//! cleared. On the runner's normal path the pool stops after the supervision
//! tree is aborted, so the other workers destroy only cancelled tasks, apart
//! from one that failed earlier, which drains the set as soon as the pool
//! closes. Worker zero stops the pool from its own cleanup, so an unwind that
//! skips the runner's shutdown still releases the barrier. No worker closes
//! its mailbox, drops the messages it took from it, or closes its ring until
//! every pool worker has drained the set and finished its last poll, since a
//! task polled on one worker can hold registrations on another, whose mailbox
//! forwards their results.
//!
//! The barrier's state is [`Closing`], under a lock of its own: `closed`
//! releases the workers waiting in [`Pool::wait_closed`], `stopped` ends the roots
//! of the workers after worker zero, and `active` counts the workers
//! [`Pool::finish`] waits for. One condition variable signals both the close
//! and the last finish.
//!
//! # Failures
//!
//! A pool worker that fails sends the failure to the runner's pool failure
//! channel, then wakes worker zero's root, which takes the failure before its
//! next poll and unwinds with it, whether or not task panics are caught. A
//! worker that fails while the pool runs reports before its cleanup, since
//! cleanup waits for the pool to close, which needs the root to end. The
//! channel outlives the root, so a failure after the root completes is taken
//! once the pool is joined. Only the first failure is delivered.
//!
//! # Testing
//!
//! The unit tests here check the queue, the idle set, and the barrier one call
//! at a time. The loom models in `task.rs` race pushes from outside the pool
//! against parking workers with real task state, and the runtime tests in
//! `tests.rs` hook each step of a worker's park, startup, and shutdown.

use super::{
    mailbox::{Mailbox, Message},
    runtime::{Panic, Role, Shared, Worker},
    task::{Ready, Runnable},
};
use crate::utils::{self, Panicker};
use crossbeam_utils::CachePadded;
use std::{
    collections::VecDeque,
    future::poll_fn,
    mem,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{Arc, mpsc},
    task::Poll,
    thread::JoinHandle,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Condvar, Mutex, MutexGuard,
            atomic::{AtomicU64, AtomicUsize, Ordering, fence},
        };
    } else {
        use commonware_utils::sync::{Condvar, Mutex, MutexGuard};
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
    }
}

/// Maximum number of runnables one take moves from the global queue into a
/// worker's queue, which bounds how long the take holds the pool-wide lock.
const GLOBAL_BATCH: usize = 128;

/// Maximum number of workers in one pool, since the idle set gives each worker
/// one bit of a `u64`.
pub const MAX_WORKERS: usize = 64;

/// The global queue's contents, guarded by the pool-wide lock.
struct GlobalQueue {
    /// Whether pushes are still accepted. Shutdown clears it, after which a
    /// push hands its runnable back to the caller.
    open: bool,
    /// Runnables waiting for any worker, oldest first.
    runnables: VecDeque<Runnable>,
}

/// Progress of the pool's shutdown, guarded by its own lock and signalled
/// through the pool's `progress` condition variable.
struct Closing {
    /// Whether worker zero has closed the task set and the global queue. Pool
    /// workers wait for it before they drain the set.
    closed: bool,
    /// Whether worker zero has stopped the pool, which ends the root of every
    /// other worker.
    stopped: bool,
    /// Workers that have entered the barrier and not yet finished, which may
    /// still poll a task or clear one from the set.
    active: usize,
}

/// State shared by a pool's workers, the wakers of its tasks, and its runner.
pub struct Pool {
    /// Every pool worker's mailbox, indexed by worker. All exist before any
    /// worker starts, so a push can wake any worker from the first spawn on.
    mailboxes: Box<[Arc<Mailbox>]>,
    /// Bit `i` is set while worker `i` is published as parked or about to
    /// park and no push has claimed it. A push clears the bit to claim the
    /// worker before waking it, and the worker clears it when it runs again.
    /// Padded, like the two fields after it, so parks, pushes, and takes do not
    /// contend for one cache line.
    idle: CachePadded<AtomicU64>,
    /// The global queue's length, stored under its lock and read without it.
    global_len: CachePadded<AtomicUsize>,
    /// The global queue.
    global: CachePadded<Mutex<GlobalQueue>>,
    /// Shutdown progress, which workers wait on through `progress`.
    closing: Mutex<Closing>,
    /// Signalled when the pool closes and when the last active worker
    /// finishes.
    progress: Condvar,
}

impl Pool {
    /// The state for a pool whose workers own `mailboxes`, in worker order.
    pub fn new(mailboxes: Vec<Arc<Mailbox>>) -> Self {
        // The idle set has one bit per worker.
        assert!(
            (1..=MAX_WORKERS).contains(&mailboxes.len()),
            "an io_uring pool has 1 to {MAX_WORKERS} workers"
        );
        Self {
            mailboxes: mailboxes.into(),
            idle: CachePadded::new(AtomicU64::new(0)),
            global_len: CachePadded::new(AtomicUsize::new(0)),
            global: CachePadded::new(Mutex::new(GlobalQueue {
                open: true,
                runnables: VecDeque::new(),
            })),
            closing: Mutex::new(Closing {
                closed: false,
                stopped: false,
                active: 0,
            }),
            progress: Condvar::new(),
        }
    }

    /// Number of workers in the pool, worker zero included.
    pub fn workers(&self) -> usize {
        self.mailboxes.len()
    }

    /// Mailbox of worker `index`.
    pub fn mailbox(&self, index: u32) -> &Arc<Mailbox> {
        &self.mailboxes[index as usize]
    }

    /// Lock the global queue.
    fn global(&self) -> MutexGuard<'_, GlobalQueue> {
        // Loom's mutex reports poisoning, the standard build's does not.
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let queue = self.global.lock().unwrap();
            } else {
                let queue = self.global.lock();
            }
        }
        queue
    }

    /// Lock the shutdown progress.
    fn closing(&self) -> MutexGuard<'_, Closing> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let closing = self.closing.lock().unwrap();
            } else {
                let closing = self.closing.lock();
            }
        }
        closing
    }

    /// Wait on `progress` with `closing` held, returning the guard once
    /// signalled or woken spuriously. Callers recheck their condition.
    fn wait<'a>(&self, closing: MutexGuard<'a, Closing>) -> MutexGuard<'a, Closing> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                self.progress.wait(closing).unwrap()
            } else {
                let mut closing = closing;
                self.progress.wait(&mut closing);
                closing
            }
        }
    }

    /// Queue `runnable` for any worker and wake a parked one. Once the queue
    /// has closed, returns the runnable for the caller to discard: the task
    /// set closed first, so teardown clears its task or already has.
    pub fn push(&self, runnable: Runnable) -> Result<(), Runnable> {
        {
            let mut queue = self.global();
            if !queue.open {
                return Err(runnable);
            }
            queue.runnables.push_back(runnable);

            // Under the lock, so the mirror's stores follow the queue's own
            // order.
            self.global_len
                .store(queue.runnables.len(), Ordering::Release);
        }

        // Pairs with the fence in `park_begin`: either the load in `notify`
        // sees the parking worker's bit, or that worker's recheck sees the
        // push.
        fence(Ordering::SeqCst);
        self.notify();
        Ok(())
    }

    /// Whether the global queue holds runnables, read without the lock. After
    /// a worker publishes itself idle, the fence pairing between [`Self::push`]
    /// and [`Self::park_begin`] ensures that a push it misses here wakes some
    /// idle worker, not necessarily this one.
    pub fn has_global(&self) -> bool {
        self.global_len.load(Ordering::Acquire) != 0
    }

    /// Take a share of the global queue: one runnable more than an even split
    /// between the workers, at most [`GLOBAL_BATCH`].
    /// Returns the oldest and queues the rest in `ready`.
    #[must_use]
    pub fn take(&self, ready: &mut Ready) -> Option<Runnable> {
        // The queue is usually empty, so the mirrored length answers that
        // without the lock.
        if !self.has_global() {
            return None;
        }
        let mut queue = self.global();

        // One more than an even split, so a lone runnable still moves and a
        // burst spreads over the workers that look. Another take may have
        // emptied the queue since the check above, so the share never exceeds
        // what is left.
        let len = queue.runnables.len();
        let count = (len / self.workers() + 1).min(GLOBAL_BATCH).min(len);

        // The caller polls the oldest next, and the rest join the tail of its
        // own queue, behind the work already there.
        let mut taken = queue.runnables.drain(..count);
        let first = taken.next();
        for runnable in taken {
            ready.push(runnable);
        }

        // Store the new length before unlocking, so the mirror's stores follow
        // the queue's own order and a stale length never overwrites a newer
        // one.
        self.global_len
            .store(queue.runnables.len(), Ordering::Release);
        first
    }

    /// Wake one parked worker, if any.
    fn notify(&self) {
        // Clearing a worker's idle bit claims it, so a push that loses the
        // exchange to another push retries with the bits that remain, and
        // each parked worker is woken by at most one push. The exchange can
        // also fail spuriously or because a worker published or withdrew its
        // bit, and the retry uses the set as it is now.
        let mut idle = self.idle.load(Ordering::SeqCst);
        while idle != 0 {
            let index = idle.trailing_zeros();
            match self.idle.compare_exchange_weak(
                idle,
                idle & !(1 << index),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    // The worker's wake source latches a wake that arrives
                    // before it blocks, so the claimed worker wakes either
                    // way.
                    self.mailboxes[index as usize].waker.wake();
                    return;
                }
                Err(actual) => idle = actual,
            }
        }

        // No worker was published as idle. By the fence pairing in `push`,
        // any worker that publishes itself from here on finds this push when
        // it looks at the queue again, and a running worker takes it at its
        // next look.
    }

    /// Publish that worker `index` is about to park. The caller then looks
    /// at the global queue once more before it blocks, and calls
    /// [`Self::park_end`] once it runs again.
    pub fn park_begin(&self, index: u32) {
        self.idle.fetch_or(1 << index, Ordering::SeqCst);

        // Pairs with the fence in `push`.
        fence(Ordering::SeqCst);
    }

    /// Withdraw worker `index` from the idle set once it runs again. A push
    /// that claimed the worker has already cleared its bit, which leaves the set
    /// unchanged here.
    pub fn park_end(&self, index: u32) {
        self.idle.fetch_and(!(1 << index), Ordering::SeqCst);
    }

    /// Count one more pool worker that shutdown waits for. Each worker enters
    /// before it reports itself ready, so [`Self::finish`] waits for every
    /// worker that started.
    pub fn enter(&self) {
        self.closing().active += 1;
    }

    /// Close the global queue, discarding its runnables, and release the
    /// workers waiting for the pool to close. The caller has closed the task
    /// set, which retains every discarded runnable's task.
    pub fn close(&self) {
        // Refuse later pushes and take what is queued under one lock, so every
        // runnable is either discarded here or handed back to its pusher.
        let runnables = {
            let mut queue = self.global();
            queue.open = false;
            self.global_len.store(0, Ordering::Release);
            mem::take(&mut queue.runnables)
        };

        // Releasing references runs no user code, since the set still holds a
        // reference to each task.
        for runnable in runnables {
            runnable.discard();
        }

        // Release every worker waiting in `wait_closed`.
        self.closing().closed = true;
        self.progress.notify_all();
    }

    /// End the root of every pool worker after worker zero, which starts its
    /// shutdown. Repeated calls do nothing.
    pub fn stop(&self) {
        // Set the flag before waking the roots: a root polled after its wake
        // sees it, and one not polled yet sees it on its first poll.
        {
            let mut closing = self.closing();
            if closing.stopped {
                return;
            }
            closing.stopped = true;
        }

        // Worker zero, which calls this, polls the runner's root rather than
        // a stop root, so it is skipped. The others close their mailboxes only
        // after the shutdown barrier, which worker zero has not reached yet,
        // so every send succeeds.
        for mailbox in self.mailboxes.iter().skip(1) {
            let _ = mailbox.send(Message::WakeRoot);
        }
    }

    /// Whether worker zero has stopped the pool. The root of every worker
    /// after worker zero polls this.
    fn is_stopped(&self) -> bool {
        self.closing().stopped
    }

    /// Block until the pool has closed. Every pool worker waits here before it
    /// drains the task set, which holds back one that stopped early after a
    /// failure.
    pub fn wait_closed(&self) {
        let mut closing = self.closing();

        // Recheck after every wakeup, since one can be spurious.
        while !closing.closed {
            closing = self.wait(closing);
        }
    }

    /// Record that the calling worker polls and clears no more tasks, then
    /// block until every other pool worker has done the same.
    pub fn finish(&self) {
        let mut closing = self.closing();
        closing.active -= 1;

        // The last worker to finish releases the others.
        if closing.active == 0 {
            self.progress.notify_all();
            return;
        }

        // The others wait for it, rechecking after every wakeup, since one can
        // be spurious.
        while closing.active != 0 {
            closing = self.wait(closing);
        }
    }
}

/// The threads of the pool workers after worker zero, which runs on the
/// runner's thread.
#[derive(Default)]
pub struct Threads {
    /// Join handles in worker order, starting at worker one, each joined once
    /// its worker has cleaned up.
    handles: Vec<JoinHandle<()>>,
}

impl Threads {
    /// Start every worker after worker zero, waiting for each to create its
    /// ring before starting the next. Every failure of a started worker is
    /// sent to `failures`, which interrupts the root while it runs. The runner
    /// collects a later one after joining the pool.
    ///
    /// Panics with the first startup failure, after which worker zero's
    /// cleanup stops the workers already started.
    pub fn start(&mut self, shared: &Arc<Shared>, failures: &Panicker) {
        let count = shared.pool.workers();
        self.handles.reserve(count - 1);

        for index in 1..count {
            #[cfg(test)]
            let _fault = super::runtime::tests::before_pool_worker(shared, index);
            let (ready, started) = mpsc::channel();
            let shared = shared.clone();
            let failures = failures.clone();
            let handle = utils::thread::spawn(shared.cfg.thread_stack_size(), move || {
                run(shared, index as u32, ready, failures)
            });

            // Keep the handle before waiting, so a worker that fails at startup
            // is still joined.
            self.handles.push(handle);

            // One worker at a time: each has entered the barrier and created
            // its ring before the next starts. A startup failure resumes here,
            // inside worker zero's root builder, so the runner's root is never
            // built.
            match started.recv().expect("pool worker exited during startup") {
                Ok(()) => {}
                Err(panic) => resume_unwind(panic),
            }
        }
    }

    /// Join every worker, resuming the first thread that panicked. A later
    /// payload is leaked rather than dropped, since its destructor may panic.
    pub fn join(&mut self) {
        let mut first: Option<Panic> = None;
        for thread in self.handles.drain(..) {
            if let Err(panic) = thread.join() {
                if first.is_none() {
                    first = Some(panic);
                } else {
                    mem::forget(panic);
                }
            }
        }
        if let Some(panic) = first {
            resume_unwind(panic);
        }
    }
}

impl Drop for Threads {
    fn drop(&mut self) {
        // Joins the workers when an unwind skips the runner's own join. Worker
        // zero's cleanup, which runs first, has stopped them.
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| self.join())) {
            mem::forget(panic);
        }
    }
}

/// Run pool worker `index` on its own thread until worker zero stops the
/// pool. Reports readiness, or the startup failure, through `ready`.
///
/// Once started, the worker sends every failure to `failures` and wakes worker
/// zero's root, which takes the failure before its next poll. A failure that
/// ends the worker early goes before cleanup, since cleanup waits for the
/// runner to close the pool, and only the interrupted root makes it do so.
fn run(
    shared: Arc<Shared>,
    index: u32,
    ready: mpsc::Sender<Result<(), Panic>>,
    failures: Panicker,
) {
    // Kept beyond the worker, so a failure reported after its cleanup can
    // still wake worker zero's root.
    let pool = shared.pool.clone();

    // Readiness is sent only once the worker exists with its ring and TLS.
    // The sender is kept until then so a startup failure can be returned.
    let mut ready = Some(ready);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (mut worker, _) = Worker::run(
            shared,
            Role::Pool(index),
            || {
                let _ = ready.take().unwrap().send(Ok(()));

                // The root only waits for worker zero to stop the pool, which
                // wakes it through this worker's mailbox.
                poll_fn(|_| {
                    if pool.is_stopped() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
            },
            None,
        )?;

        // A failure that ended the drive loop is reported before cleanup.
        if let Some(panic) = worker.take_panic() {
            failures.notify(panic);
            let _ = pool.mailbox(0).send(Message::WakeRoot);
        }
        worker.cleanup();
        Ok::<_, Panic>(worker.take_panic())
    }));
    let panic = match result {
        Ok(Ok(None)) => return,
        Ok(Ok(Some(panic))) | Ok(Err(panic)) | Err(panic) => panic,
    };

    match ready {
        // A worker that never started must keep the root from running. The
        // send fails only if the starter is gone, and then the payload is
        // leaked rather than dropped, since its destructor may panic.
        Some(ready) => {
            if let Err(error) = ready.send(Err(panic)) {
                mem::forget(error);
            }
        }

        // A failure during cleanup, or one that escaped the worker, reaches
        // the runner the same way as one that ended the drive loop.
        None => {
            failures.notify(panic);
            let _ = pool.mailbox(0).send(Message::WakeRoot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::{
        task::{
            Task,
            tests::{refs, task_of},
        },
        tasks::Tasks,
    };
    use std::{future::pending, sync::Weak, thread, time::Duration};

    /// Bound on a test's wait for another thread.
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// How long a test watches for a thread that must stay blocked.
    const BLOCKED: Duration = Duration::from_millis(20);

    impl Pool {
        /// Take the oldest runnable from the global queue.
        #[must_use]
        pub fn pop(&self) -> Option<Runnable> {
            if !self.has_global() {
                return None;
            }
            let mut queue = self.global();
            let runnable = queue.runnables.pop_front();
            self.global_len
                .store(queue.runnables.len(), Ordering::Release);
            runnable
        }

        /// Whether worker `index` is published in the idle set.
        pub fn is_idle(&self, index: u32) -> bool {
            self.idle.load(Ordering::SeqCst) & (1 << index) != 0
        }
    }

    /// A pool of `workers` workers with no runner.
    fn pool(workers: usize) -> Pool {
        Pool::new(
            (0..workers)
                .map(|_| Arc::new(Mailbox::new().unwrap()))
                .collect(),
        )
    }

    /// A task that no set retains, with its first runnable.
    fn task(set: &Tasks) -> (Task, Runnable) {
        Task::new(pending::<()>(), set, Weak::new())
    }

    /// Push a new task's first runnable into `pool`, returning the task.
    fn push(pool: &Pool, set: &Tasks) -> Task {
        let (task, runnable) = task(set);
        assert!(pool.push(runnable).is_ok());
        task
    }

    #[test]
    fn test_take_moves_a_bounded_share_of_the_global_queue() {
        for (workers, queued, taken) in [(4, 8, 3), (1, 129, 128)] {
            let pool = pool(workers);
            let set = Tasks::new(1);
            let tasks: Vec<Task> = (0..queued).map(|_| push(&pool, &set)).collect();

            let mut ready = Ready::default();
            let mut moved = vec![pool.take(&mut ready).unwrap()];
            while let Some(runnable) = ready.pop() {
                moved.push(runnable);
            }
            assert_eq!(moved.len(), taken);
            for (runnable, task) in moved.iter().zip(&tasks) {
                assert_eq!(task_of(runnable).as_ptr(), task.as_ptr());
            }

            for runnable in moved {
                runnable.discard();
            }
            pool.close();
            for task in tasks {
                task.clear();
            }
        }
    }

    #[test]
    fn test_closed_queue_refuses_pushes_and_discards_its_runnables() {
        let pool = pool(1);
        let set = Tasks::new(1);
        let queued = push(&pool, &set);
        assert_eq!(refs(&queued), 2);

        pool.close();
        assert!(!pool.has_global());
        assert_eq!(refs(&queued), 1);

        let (late, runnable) = task(&set);
        pool.push(runnable).unwrap_err().discard();
        assert_eq!(refs(&late), 1);
        queued.clear();
        late.clear();
    }

    #[test]
    fn test_push_wakes_one_idle_worker_lowest_first() {
        let pool = pool(3);
        let set = Tasks::new(1);
        let mut tasks = Vec::new();
        pool.park_begin(1);
        pool.park_begin(2);

        tasks.push(push(&pool, &set));
        assert!(!pool.is_idle(1) && pool.is_idle(2));
        assert!(pool.mailbox(1).waker.signalled());
        assert!(!pool.mailbox(2).waker.signalled());

        tasks.push(push(&pool, &set));
        assert!(!pool.is_idle(2));
        assert!(pool.mailbox(2).waker.signalled());

        // With no worker published, and one that withdrew, a push wakes nobody.
        pool.park_begin(0);
        pool.park_end(0);
        tasks.push(push(&pool, &set));
        assert!(!pool.mailbox(0).waker.signalled());

        while let Some(runnable) = pool.pop() {
            runnable.discard();
        }
        for task in tasks {
            task.clear();
        }
    }

    #[test]
    fn test_stop_wakes_every_other_root_once() {
        let pool = pool(3);
        assert!(!pool.is_stopped());
        pool.stop();
        pool.stop();
        assert!(pool.is_stopped());

        assert!(!pool.mailbox(0).waker.pending(0));
        for index in 1..3 {
            let mut messages = Vec::new();
            assert!(pool.mailbox(index).take(&mut messages));
            assert!(matches!(messages.as_slice(), [Message::WakeRoot]));
        }
    }

    #[test]
    fn test_workers_wait_for_the_close_and_for_every_finish() {
        let pool = Arc::new(pool(2));
        pool.enter();
        pool.enter();
        let (progress, observed) = mpsc::channel();
        let other = thread::spawn({
            let pool = pool.clone();
            move || {
                pool.wait_closed();
                progress.send("closed").unwrap();
                pool.finish();
                progress.send("finished").unwrap();
            }
        });

        assert!(observed.recv_timeout(BLOCKED).is_err());
        pool.close();
        assert_eq!(observed.recv_timeout(TEST_TIMEOUT).unwrap(), "closed");

        // The other worker waits until this one finishes too.
        assert!(observed.recv_timeout(BLOCKED).is_err());
        pool.finish();
        assert_eq!(observed.recv_timeout(TEST_TIMEOUT).unwrap(), "finished");
        other.join().unwrap();
    }
}
