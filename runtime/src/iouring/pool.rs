//! The pool of workers that poll ordinary tasks.
//!
//! [`Pool`] is the state the workers share: every worker's mailbox and the
//! shared end of its run queue, the pool-wide global queue, the pool's idle
//! state, and the shutdown barrier. The runner creates it before any worker
//! starts, every worker reaches it through the runner's shared services, and
//! every task's header holds a weak reference to it, so a wake from any thread
//! can find the task's pool without keeping the pool alive.
//! [`Threads`] starts the workers after worker zero, each on a thread of its
//! own, and joins them at shutdown.
//!
//! [`Idle`] tracks idle publications and search responsibility, and selects
//! pool workers to wake. Their mailbox wakers deliver the signals.
//! [`super::idle`] describes the parking sequence and wake policy.
//!
//! # Placement
//!
//! A runnable woken on a live worker of its own pool is offered to that
//! worker's run queue, and a new task first stays on a pool worker with
//! nothing else queued or no other worker. Every other push goes to the global
//! queue: wakes and spawns from outside the pool or on a closing worker, spawns
//! that leave a busy worker, and the newest half of a full run queue. A queued
//! runnable can still move before it runs: an overflow sends it to the global
//! queue, and another worker can steal it. Workers take a share of the global
//! queue whenever their own run queue runs dry and once every [global queue
//! interval] of takes, so the global queue makes progress however busy a
//! worker is. A take queues a batch only in a run queue under half full, so a
//! worker whose run queue stays at least half full takes one runnable per
//! interval. A worker with nothing ready searches the other run queues before
//! parking, after servicing its own I/O and messages.
//!
//! [global queue interval]: super::Config::with_global_queue_interval
//!
//! # Run queues
//!
//! Each pool worker queues its runnables in a run queue, a [`LocalQueue`] of
//! [`CAPACITY`] that only it pushes into and pops from. A push into a full run
//! queue moves its newest half and the new runnable into the global queue in
//! one batch, keeping the oldest half in the run queue. If a thief's claim
//! prevents that split, only the new runnable goes to the global queue. A
//! claim keeps its slots, and every slot the owner pops past it, out of use
//! until the thief has read the claimed values and released it, so a run
//! queue the owner has emptied can still have no room. A pool of one worker
//! has no thief, so its run queue is exclusive and pops without an atomic
//! exchange.
//!
//! A take from the global queue returns the runnable the caller polls next and
//! queues the rest of its share in the run queue, no more than it has room for
//! and no more than fill it to half. A runnable a take queues therefore lands
//! in the oldest half, which an overflow keeps, so it is polled before an
//! overflow could send it back. A run queue already half full gets none, and
//! the take moves only the runnable the caller polls next.
//!
//! # Global queue
//!
//! The global queue is a [`VecDeque`] behind one pool-wide mutex, with its
//! length mirrored in an atomic. Workers read the mirror to decide whether
//! there is anything to take, so observing zero, the common case, avoids the
//! lock. A nonzero observation can be stale by the time the lock is acquired.
//! A take moves a share into the taking worker's run queue under one lock:
//! one runnable more than an even split between the workers, within the cap
//! above, which also bounds a take's work under the lock to half a run queue
//! and one runnable more. The mirror is stored only under the lock, after the
//! take's pushes into the run queue, so its stores follow the queue's own
//! order, and a worker that reads the length a take left also sees the
//! runnables it moved.
//!
//! ```text
//! push   lock, refuse if closed, append, store the length, unlock, fence,
//!        wake
//! take   load the length (zero: done), lock, move a share into the run queue,
//!        store the length, unlock
//! close  lock, refuse later pushes, store zero, take the rest, unlock,
//!        discard what was taken
//! ```
//!
//! # Stealing
//!
//! A worker with nothing to run, before it parks, scans every other worker's
//! run queue once, starting at a random one, and takes half of the first
//! unclaimed backlog it finds, rounded down, so a runnable queued alone stays
//! with its worker. It queues what it took in its own run queue and runs again.
//! A thief claims the runnables it takes with one exchange on the victim's head
//! and releases the claim once it has copied them, and a second thief backs off
//! while a claim is held. [`super::idle`] describes how many workers search at
//! once and how a backlog wakes a parked worker to steal it.
//!
//! # Lifecycle
//!
//! Worker zero runs on the runner's thread. It starts the others one at a time,
//! each creating its io_uring ring and joining the shutdown barrier before the
//! next starts, and builds the root only once all of them run. The root of
//! every other worker ends when worker zero stops the pool.
//!
//! ```text
//! worker zero                            worker i (1..n)
//!   Pool::new (mailboxes, run queues)
//!   enter, start worker i ------------->   enter, report ready
//!   build and drive the root               drive tasks
//!   root ends: close the task set,
//!     then the global queue
//!   abort the supervision tree
//!   stop the pool --------------------->   root ends
//!   discard its run queue                  discard its run queue
//!   drain all shards, starting at 0        drain all shards, starting at its own
//!   finish <=========== barrier ==========> finish
//!   close mailbox, drop inbox,             close mailbox, drop inbox,
//!     destroy io_uring ring                  destroy io_uring ring
//!   join <------------------------------   exit
//!   take a failure reported late
//! ```
//!
//! Shutdown closes the task set before the global queue, so a runnable the
//! closed queue refuses belongs to a task that teardown clears or already has
//! cleared, and so does a runnable a worker discards from its own run queue. A
//! worker still driving may steal from the run queue of one that is cleaning
//! up: it polls what it took, or discards it in its own cleanup, before it
//! reaches the barrier. On the runner's normal path the pool stops after the
//! supervision tree is aborted, so the other workers destroy only cancelled
//! tasks and the runner's metrics task. A worker that failed earlier is the
//! exception: it drains the set as soon as the pool closes. Worker zero stops
//! the pool from its own cleanup, so an unwind that skips the runner's shutdown
//! still releases the barrier. No worker closes its mailbox, drops the messages
//! it took from it, or destroys its io_uring ring until every pool worker has
//! drained the set and finished its last poll, since a task polled on one
//! worker can hold registrations on another, whose mailbox forwards their
//! results.
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

use super::{
    idle::Idle,
    mailbox::{Mailbox, Message},
    queue::{self, CAPACITY, Overflow, Push, STEALABLE},
    runtime::{Panic, Role, Shared, Worker},
    task::{Ready, Runnable},
};
use crate::utils::Panicker;
use crossbeam_utils::CachePadded;
use std::{
    collections::VecDeque,
    future::poll_fn,
    iter, mem,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{Arc, mpsc},
    task::Poll,
    thread::{self, JoinHandle},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Condvar, Mutex, MutexGuard,
            atomic::{AtomicUsize, Ordering, fence},
        };
    } else {
        use commonware_utils::sync::{Condvar, Mutex, MutexGuard};
        use std::sync::atomic::{AtomicUsize, Ordering, fence};
    }
}

/// Half a run queue: what an overflow keeps and what a take may fill one to.
pub const HALF: usize = CAPACITY / 2;

/// Maximum number of workers in one pool, since the idle set gives each worker
/// one bit of a `u64`. Here rather than in [`super::idle`], since the pool
/// enforces it and the runner's configuration checks it.
pub const MAX_WORKERS: usize = 64;

/// A pool worker's run queue as the pool holds it: the shared end that the
/// other workers steal through. The worker takes its [`queue::Owner`] when it
/// starts.
pub type LocalQueue = queue::Queue<Runnable>;

/// The global queue's contents, guarded by the pool-wide lock.
struct GlobalQueue {
    /// Whether pushes are still accepted. Shutdown clears it, after which a
    /// push hands its runnables back to the caller.
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
    /// The idle set and the search count, whose drop checks that every worker
    /// withdrew from the set and returned its count. First, so that check runs
    /// before the other fields drop. Padded, like the global queue and its
    /// length, so parks, pushes, and takes do not contend for one cache line.
    idle: CachePadded<Idle>,
    /// Every pool worker's mailbox, indexed by worker. All exist before any
    /// worker starts, so a push can wake any worker from the first spawn on.
    mailboxes: Box<[Arc<Mailbox>]>,
    /// The shared end of every pool worker's run queue, indexed by worker.
    /// Each worker takes its owner when it starts.
    queues: Box<[LocalQueue]>,
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
    /// The state for a pool whose workers own `mailboxes`, in worker order,
    /// with an empty run queue for each. Panics unless there are between one
    /// and [`MAX_WORKERS`] mailboxes.
    pub fn new(mailboxes: Vec<Arc<Mailbox>>) -> Self {
        // The idle set has one bit per worker.
        let workers = mailboxes.len();
        assert!(
            (1..=MAX_WORKERS).contains(&workers),
            "an io_uring pool has 1 to {MAX_WORKERS} workers"
        );

        // A worker reads another's run queue only to steal from it, and a pool
        // of one worker has no other worker, so its run queue is exclusive.
        let queue = || {
            if workers == 1 {
                LocalQueue::exclusive()
            } else {
                LocalQueue::shared()
            }
        };

        Self {
            idle: CachePadded::new(Idle::new()),
            mailboxes: mailboxes.into(),
            queues: (0..workers).map(|_| queue()).collect(),
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

    /// The pool's idle state, through which its workers park and search and
    /// its pushes and kicks wake them.
    pub fn idle(&self) -> &Idle {
        &self.idle
    }

    /// Mailbox of worker `index`. Panics if the index is outside the pool.
    pub fn mailbox(&self, index: u32) -> &Arc<Mailbox> {
        &self.mailboxes[index as usize]
    }

    /// Shared end of worker `index`'s run queue, whose owner the worker takes
    /// when it starts. Panics if the index is outside the pool.
    pub fn queue(&self, index: u32) -> &LocalQueue {
        &self.queues[index as usize]
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
        self.push_batch(iter::once(runnable))
            .map_err(|mut refused| refused.next().unwrap())
    }

    /// Queue `runnables` for any worker under one lock and wake a parked
    /// worker. Once the queue has closed, returns them for the caller to
    /// discard, as [`Self::push`] does.
    fn push_batch<I: Iterator<Item = Runnable>>(&self, runnables: I) -> Result<(), I> {
        {
            let mut queue = self.global();
            if !queue.open {
                return Err(runnables);
            }
            queue.runnables.extend(runnables);

            // Under the lock, so the mirror's stores follow the queue's own
            // order.
            self.global_len
                .store(queue.runnables.len(), Ordering::Release);
        }

        // Pairs with the fence in `Searcher::prepare_park`, which a worker
        // puts between publishing its bit and its last look: either the loads
        // in `Idle::notify_global` see the bit, or that look sees the length
        // stored above. The pair alone forbids both sides missing the other's
        // store, so the loads that follow need no ordering of their own.
        fence(Ordering::SeqCst);
        self.idle.notify_global(&self.mailboxes);
        Ok(())
    }

    /// Whether the global queue holds runnables, read without the lock. After
    /// a worker publishes itself idle, the fence pairing with [`Self::push`]
    /// ensures that a push it misses here leaves some worker, not necessarily
    /// this one, woken or running to take it.
    pub fn has_global(&self) -> bool {
        self.global_len.load(Ordering::Acquire) != 0
    }

    /// Take a share of the global queue: one runnable more than an even split
    /// between the workers. Returns the oldest and queues the rest in `ready`,
    /// no more than it has room for and no more than fill it to half, so a
    /// take into a run queue already half full returns only the oldest.
    ///
    /// The caller owns `ready` for a worker in this pool and must poll or
    /// discard the returned runnable. Returns `None` if the mirrored length
    /// is zero or another take or the close has emptied the queue before it
    /// is locked.
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
        let share = (len / self.workers() + 1).min(len);

        // The caller polls the first runnable next, and the run queue takes the
        // rest. Filling at most its oldest half keeps every taken runnable out
        // of the half an overflow exports and bounds the work under the lock,
        // and the room measured here only grows before the pushes below.
        let admitted = ready.room().min(HALF.saturating_sub(ready.len()));
        let count = share.min(admitted + 1);

        // The rest join the tail of the run queue, behind the work already
        // there, published with one tail store before the length below, so a
        // worker that reads that length also sees them.
        let mut taken = queue.runnables.drain(..count);
        let first = taken.next();
        ready.push_batch(taken);

        // Store the new length before unlocking, so the mirror's stores follow
        // the queue's own order and a stale length never overwrites a newer
        // one.
        self.global_len
            .store(queue.runnables.len(), Ordering::Release);
        first
    }

    /// Queue `runnable` in a pool worker's run queue `ready`, offering a
    /// stealable backlog to a parked worker. A full run queue moves its newest
    /// half and the runnable into the global queue, or only the runnable while
    /// a thief holds a claim on it. The caller owns `ready` for a worker in this
    /// pool, and the runnable belongs to this pool's task set. Closing the
    /// global queue discards exports, leaving local cleanup to drain `ready`.
    ///
    /// May run with the worker's `Local` mutably borrowed. Queueing and
    /// discarding runnable references must not invoke user code.
    #[inline]
    pub fn enqueue(&self, ready: &mut Ready, runnable: Runnable) {
        match ready.push(runnable) {
            Push::Pushed(len) => {
                if len >= STEALABLE && self.workers() > 1 {
                    self.kick();
                }
            }
            Push::Overflow(batch, runnable) => self.overflow(batch, runnable),
            Push::Claimed(runnable) => {
                if let Err(runnable) = self.push(runnable) {
                    runnable.discard();
                }
            }
        }
    }

    /// Move a full run queue's newest half, then `runnable`, into the global
    /// queue in one batch. A closed queue hands them back, and they are
    /// discarded: the task set closed first, so teardown clears their tasks.
    #[inline(never)]
    fn overflow(&self, batch: Overflow<'_, Runnable>, runnable: Runnable) {
        #[cfg(test)]
        super::runtime::tests::before_overflow(self);
        if let Err(refused) = self.push_batch(batch.chain(iter::once(runnable))) {
            for runnable in refused {
                runnable.discard();
            }
        }
    }

    /// Scan every run queue but worker `index`'s once, from `start`, and steal
    /// half of the first backlog found into `ready`. Returns whether a steal
    /// moved any runnable. The caller holds a search count and supplies worker
    /// `index`'s empty run queue, with `start` inside the pool. A pending claim
    /// can leave insufficient room even in an empty destination.
    #[inline]
    pub fn steal(&self, index: u32, start: usize, ready: &mut Ready) -> bool {
        let workers = self.workers();
        (0..workers)
            .map(|offset| (start + offset) % workers)
            .filter(|&victim| victim != index as usize)
            .any(|victim| self.queues[victim].steal_into(ready) > 0)
    }

    /// Ask [`Idle::notify`] to wake a parked worker for a run queue's backlog
    /// or to carry on the last returned count's search. A held search count
    /// suppresses the request. See [`super::idle`] for the wake policy.
    #[inline]
    pub fn kick(&self) {
        // Pairs with the fence in `Searcher::prepare_park`: either the loads
        // in `Idle::notify` see the worker's bit, or its last look sees what
        // the caller published before this fence, the run queue's new tail or
        // the return of the last search count.
        fence(Ordering::SeqCst);
        self.idle.notify(&self.mailboxes);
    }

    /// Whether a run queue other than worker `index`'s holds an unclaimed
    /// backlog that a steal would take from. This is a snapshot: another
    /// worker can pop or claim the backlog before a subsequent steal.
    #[inline]
    pub fn has_stealable(&self, index: u32) -> bool {
        self.queues
            .iter()
            .enumerate()
            .any(|(other, queue)| other != index as usize && queue.is_stealable())
    }

    /// Count one more pool worker that shutdown waits for. Each worker enters
    /// before it reports itself ready, so [`Self::finish`] waits for every
    /// worker that started. Each worker calls this once and must later call
    /// `finish` once. Startup must end before any worker can finish.
    pub fn enter(&self) {
        self.closing().active += 1;
    }

    /// Close the global queue, discarding its runnables, and release the
    /// workers waiting for the pool to close. The caller has closed the task
    /// set, so teardown clears each discarded runnable's task or already has.
    pub fn close(&self) {
        // Refuse later pushes and take what is queued under one lock, so every
        // runnable is either discarded here or handed back to its pusher.
        let runnables = {
            let mut queue = self.global();
            queue.open = false;
            self.global_len.store(0, Ordering::Release);
            mem::take(&mut queue.runnables)
        };

        // Releasing references runs no user code: the task is still retained
        // for teardown, or its future is already gone.
        for runnable in runnables {
            runnable.discard();
        }

        // Release every worker waiting in `wait_closed`.
        self.closing().closed = true;
        self.progress.notify_all();
    }

    /// End the root of every pool worker other than worker zero. Called by
    /// worker zero before it reaches [`Self::finish`], while every pool
    /// mailbox is still open. Ending a worker's root starts its shutdown.
    /// Repeated calls do nothing.
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
    ///
    /// Each worker calls this exactly once after [`Self::enter`], after the
    /// pool has closed, its run queue is discarded, and its task-set drain has
    /// finished. Startup must have ended. Mailboxes and io_uring rings remain
    /// open until this returns.
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
///
/// Worker zero must finish its cleanup before these threads are joined or this
/// value is dropped, so the other workers can pass the shutdown barrier.
#[derive(Default)]
pub struct Threads {
    /// Join handles in worker order, starting at worker one, each joined once
    /// its worker has cleaned up.
    handles: Vec<JoinHandle<()>>,
}

impl Threads {
    /// Start every worker after worker zero, waiting for each to create its
    /// io_uring ring before starting the next. Every failure of a started
    /// worker is sent to `failures`, which interrupts the root while it runs.
    /// The runner collects a later one after joining the pool.
    ///
    /// Called once by worker zero after it enters the shutdown barrier.
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
            let handle = thread::Builder::new()
                .name(format!("iouring-pool-{index}"))
                .stack_size(shared.cfg.thread_stack_size())
                .spawn(move || run(shared, index as u32, ready, failures))
                .expect("failed to spawn pool worker");

            // Keep the handle before waiting, so a worker that fails at startup
            // is still joined.
            self.handles.push(handle);

            // One worker at a time: each has entered the barrier and created
            // its io_uring ring before the next starts. A startup failure
            // resumes here, inside worker zero's root builder, so the runner's
            // root is never built.
            match started.recv().expect("pool worker exited during startup") {
                Ok(()) => {}
                Err(panic) => resume_unwind(panic),
            }
        }
    }

    /// Join every worker, resuming the first panic returned by a join. A later
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
/// ends the worker early goes before cleanup, since cleanup waits for the pool
/// to close, which happens only once worker zero's root ends.
fn run(
    shared: Arc<Shared>,
    index: u32,
    ready: mpsc::Sender<Result<(), Panic>>,
    failures: Panicker,
) {
    // Kept beyond the worker, so a failure reported after its cleanup can
    // still wake worker zero's root.
    let pool = shared.pool.clone();

    // Readiness is sent only once the worker exists with its io_uring ring and
    // TLS. The sender is kept until then so a startup failure can be returned.
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

/// Pool fixtures and tests of queueing, stealing, and shutdown.
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::iouring::{
        idle::Searcher,
        task::{
            Task,
            tests::{queue, refs, task_of},
        },
        tasks::Tasks,
    };
    use std::{
        future::pending,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Weak,
        thread,
        time::Duration,
    };

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

        /// Whether the global queue has closed.
        pub fn is_closed(&self) -> bool {
            !self.global().open
        }

        /// Every pool worker's mailbox, indexed by worker.
        pub fn mailboxes(&self) -> &[Arc<Mailbox>] {
            &self.mailboxes
        }
    }

    /// A pool of `workers` workers with no runner.
    pub fn pool(workers: usize) -> Pool {
        Pool::new(
            (0..workers)
                .map(|_| Arc::new(Mailbox::new().unwrap()))
                .collect(),
        )
    }

    /// The owner's end of worker `index`'s run queue.
    pub fn ready(pool: &Pool, index: u32) -> Ready {
        pool.queue(index).owner()
    }

    /// A task that no set retains, with its first runnable.
    pub fn task(set: &Tasks) -> (Task, Runnable) {
        Task::new(pending::<()>(), set, Weak::new())
    }

    /// Push a new task's first runnable into `pool`, returning the task.
    pub fn push(pool: &Pool, set: &Tasks) -> Task {
        let (task, runnable) = task(set);
        assert!(pool.push(runnable).is_ok());
        task
    }

    /// A take preserves FIFO order and bounds its share, including the returned runnable.
    #[test]
    fn test_take_moves_a_bounded_share_of_the_global_queue() {
        for (workers, queued, taken) in [(4, 8, 3), (1, HALF + 2, HALF + 1)] {
            let pool = pool(workers);
            let set = Tasks::new(1);
            let tasks: Vec<Task> = (0..queued).map(|_| push(&pool, &set)).collect();

            let mut ready = ready(&pool, 0);
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

    /// A take queues runnables only in the run queue's oldest half, besides the
    /// one it returns, so an overflow cannot export what a take queued before
    /// it is polled. A run queue already half full gets none, and a take into
    /// it returns one runnable.
    #[test]
    fn test_take_fills_the_run_queue_at_most_to_half() {
        for held in [0, 100, HALF - 1, HALF, 200, CAPACITY - 1] {
            let pool = pool(1);
            let set = Tasks::new(1);
            let mut ready = ready(&pool, 0);
            let mut tasks = Vec::new();
            for _ in 0..held {
                let (task, runnable) = task(&set);
                queue(&mut ready, runnable);
                tasks.push(task);
            }
            tasks.extend((0..300).map(|_| push(&pool, &set)));

            let first = pool.take(&mut ready).unwrap();
            let moved = ready.len() - held + 1;
            assert_eq!(
                moved,
                HALF.saturating_sub(held) + 1,
                "run queue held {held}"
            );

            first.discard();
            ready.discard();
            while let Some(runnable) = pool.pop() {
                runnable.discard();
            }
            for task in tasks {
                task.clear();
            }
        }
    }

    /// A take counts the slots a thief's claim holds as full, since the thief
    /// reads them after the owner has popped past them: while a claim of half
    /// the run queue is held on an otherwise empty one, a take returns one
    /// runnable and queues none, and once the claim is released it queues its
    /// share again.
    #[test]
    fn test_take_leaves_the_slots_of_a_held_claim_alone() {
        let pool = pool(2);
        let set = Tasks::new(1);
        let mut ready = ready(&pool, 0);
        let mut tasks = Vec::new();
        for _ in 0..CAPACITY {
            let (task, runnable) = task(&set);
            queue(&mut ready, runnable);
            tasks.push(task);
        }
        let claim = pool.queue(0).hold_claim(HALF as u32);
        while let Some(runnable) = ready.pop() {
            runnable.discard();
        }
        assert_eq!(ready.room(), 0);
        tasks.extend((0..200).map(|_| push(&pool, &set)));

        pool.take(&mut ready).unwrap().discard();
        assert!(ready.is_empty());

        // Released, the claim's slots are free again, and a take queues the
        // rest of an even split of the 199 left.
        for runnable in pool.queue(0).finish_claim(claim) {
            runnable.discard();
        }
        pool.take(&mut ready).unwrap().discard();
        assert_eq!(ready.len() + 1, 199 / 2 + 1);

        ready.discard();
        while let Some(runnable) = pool.pop() {
            runnable.discard();
        }
        for task in tasks {
            task.clear();
        }
    }

    /// Closing releases queued references and refuses later pushes without consuming them.
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

    /// A push into a full run queue keeps its oldest half and moves the newest
    /// half, then the new runnable, into the global queue in that order. Once
    /// the queue has closed, that batch is discarded.
    #[test]
    fn test_full_run_queue_moves_its_newest_half_to_the_global_queue() {
        let pool = pool(1);
        let set = Tasks::new(1);
        let mut ready = ready(&pool, 0);
        let mut tasks = Vec::new();
        for _ in 0..=CAPACITY {
            let (task, runnable) = task(&set);
            pool.enqueue(&mut ready, runnable);
            tasks.push(task);
        }
        assert_eq!(ready.len(), HALF);
        for task in &tasks[..HALF] {
            let runnable = ready.pop().unwrap();
            assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
            runnable.discard();
        }
        for task in &tasks[HALF..] {
            let runnable = pool.pop().unwrap();
            assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
            runnable.discard();
        }
        assert!(pool.pop().is_none());

        // The closed queue refuses the batch, whose runnables are discarded.
        pool.close();
        for _ in 0..=CAPACITY {
            let (task, runnable) = task(&set);
            pool.enqueue(&mut ready, runnable);
            tasks.push(task);
        }
        assert_eq!(ready.len(), HALF);
        for task in &tasks[tasks.len() - HALF - 1..] {
            assert_eq!(refs(task), 1);
        }
        ready.discard();
        for task in tasks {
            task.clear();
        }
    }

    /// A push into a full run queue while a thief holds a claim on its oldest
    /// half moves only the new runnable into the global queue, and the run
    /// queue keeps the rest. Once the queue has closed, that runnable is
    /// discarded.
    #[test]
    fn test_full_run_queue_under_a_claim_moves_only_the_new_runnable() {
        for open in [true, false] {
            let pool = pool(2);
            let set = Tasks::new(1);
            let mut ready = ready(&pool, 0);
            let mut tasks = Vec::new();
            for _ in 0..CAPACITY {
                let (task, runnable) = task(&set);
                queue(&mut ready, runnable);
                tasks.push(task);
            }
            let claim = pool.queue(0).hold_claim(HALF as u32);
            if !open {
                pool.close();
            }

            let (pushed, runnable) = task(&set);
            pool.enqueue(&mut ready, runnable);
            assert_eq!(ready.len(), CAPACITY - HALF);
            if open {
                let runnable = pool.pop().unwrap();
                assert_eq!(task_of(&runnable).as_ptr(), pushed.as_ptr());
                runnable.discard();
            } else {
                assert_eq!(refs(&pushed), 1);
            }
            assert!(pool.pop().is_none());

            for runnable in pool.queue(0).finish_claim(claim) {
                runnable.discard();
            }
            ready.discard();
            tasks.push(pushed);
            for task in tasks {
                task.clear();
            }
        }
    }

    /// A search steals half of another worker's backlog, rounded down, and
    /// leaves a lone runnable with its worker.
    #[test]
    fn test_search_steals_half_of_another_run_queue() {
        let pool = pool(3);
        let set = Tasks::new(1);
        let (mut zero, mut one, mut two) = (ready(&pool, 0), ready(&pool, 1), ready(&pool, 2));
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let (task, runnable) = task(&set);
            queue(&mut two, runnable);
            tasks.push(task);
        }
        let mut searcher = Searcher::new(&pool, 0);
        assert!(searcher.search(&mut zero));
        for task in &tasks[..2] {
            let runnable = zero.pop().unwrap();
            assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
            runnable.discard();
        }
        assert!(zero.is_empty());
        assert_eq!(two.len(), 3);

        // Of the three left, a second search takes one, and a lone runnable
        // stays.
        let mut other = Searcher::new(&pool, 1);
        assert!(other.search(&mut one));
        let second = one.pop().unwrap();
        assert_eq!(task_of(&second).as_ptr(), tasks[2].as_ptr());
        second.discard();
        two.pop().unwrap().discard();
        assert!(!other.search(&mut one));
        assert_eq!(two.len(), 1);
        searcher.leave_search();
        other.leave_search();
        two.discard();
        for task in tasks {
            task.clear();
        }
    }

    /// A pool of one worker builds its run queue exclusive, which refuses
    /// thieves, and a larger pool builds shared ones.
    #[test]
    fn test_only_a_one_worker_pool_has_an_exclusive_run_queue() {
        for (workers, exclusive) in [(1, true), (2, false)] {
            let pool = pool(workers);
            let set = Tasks::new(1);
            let mut ready = ready(&pool, 0);
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (task, runnable) = task(&set);
                queue(&mut ready, runnable);
                tasks.push(task);
            }
            let thief = LocalQueue::shared();
            let mut into = thief.owner();
            let stolen = catch_unwind(AssertUnwindSafe(|| pool.queue(0).steal_into(&mut into)));
            assert_eq!(stolen.is_err(), exclusive);
            ready.discard();
            into.discard();
            for task in tasks {
                task.clear();
            }
        }
    }

    /// Stopping wakes each non-runner root once, including across repeated calls.
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

    /// Close releases the first wait, and only the last finish releases the barrier.
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
