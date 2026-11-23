//! The pool of workers that poll ordinary tasks.
//!
//! [`Pool`] is the state the workers share: each worker's mailbox, timers,
//! and the shared end of its run queue, plus the pool-wide global queue, the
//! pool's idle state, and the shutdown barrier. The runner creates it before
//! any worker starts, every worker reaches it through the runner's shared
//! services, and every task's header holds a weak reference to it, so a wake
//! from any thread can find the task's pool without keeping the pool alive.
//! [`Threads`] starts the workers after worker zero, each on a thread of its
//! own, and joins them at shutdown.
//!
//! [`Idle`] tracks idle publications and search responsibility, and selects
//! pool workers to wake. The unparkers in their mailboxes deliver the
//! notifications. [`super::idle`] describes the parking sequence and wake
//! policy.
//!
//! Each worker's [`Timers`] holds the sleeps registered on it. The pool
//! keeps them so that a busy worker can expire the overdue timers of a peer
//! stalled in a long poll (see [`super::sleep`]).
//!
//! # Placement
//!
//! A runnable woken on a live worker of its own pool is offered to that
//! worker's run queue, and a new task first stays on a pool worker with
//! nothing else queued or no other worker. Every other push goes to the global
//! queue: wakes and spawns from outside the pool or on a closing worker, spawns
//! that leave a busy worker, and the newest half of a full run queue. A queued
//! runnable can still move before it runs. An overflow can send it to the
//! global queue, and another worker can steal it.
//!
//! Workers take a share of the global queue whenever their own run queue runs
//! dry and once every [global queue interval] of takes, so the global queue
//! makes progress however busy a worker is. A take queues a batch only in a run
//! queue under half full, so a worker whose run queue stays at least half full
//! takes one runnable per interval. A worker with nothing ready searches the
//! other run queues before parking, after servicing its own I/O and messages.
//!
//! A push into the global queue that finds no idle worker to wake leaves an
//! unserved hint with the time it tried to wake a worker. A push only sets a
//! hint when none is set, and a worker only clears one when it acts on it,
//! so the cache line stays quiet through a burst of pushes. A busy worker
//! reads the hint before each pop from its own run queue. Once the hint is
//! [`GLOBAL_AGE`] old, the worker that clears it attempts one global take
//! ahead of its run queue. The take starts with the oldest global runnable
//! still queued. The hinted push may already have been taken, and the
//! runnables still queued may be younger than the hint.
//!
//! A worker that takes for a hint ahead of a nonempty run queue pops from
//! that run queue before it acts on another hint. Between two pops of a run
//! queue that stays nonempty, a worker polls at most two runnables straight
//! from the global queue when the global queue interval is three or more,
//! one for a hint and one for the interval, and at most three when it is
//! two. An interval of one takes from the global queue before every pop,
//! hint or not, so the run queue waits while the global queue holds runnables.
//!
//! A worker reads the clock when it first sees a hint, so it can act on one
//! left during its own long poll. On later checks it uses the time sample
//! of its current turn. A hint first seen younger waits for a later turn's
//! sample. The global queue interval can bring work in sooner.
//!
//! [global queue interval]: super::Config::with_global_queue_interval
//!
//! # Run queues
//!
//! Each pool worker queues its runnables in a run queue, a [`LocalQueue`] of
//! [`CAPACITY`] that only it pushes into and pops from. A push into a full run
//! queue moves its newest half and the new runnable into the global queue in
//! one batch, keeping the oldest half in the run queue. If a thief's claim
//! prevents that split, only the new runnable goes to the global queue.
//!
//! A claim keeps its slots, and every slot the owner pops past it, out of use
//! until the thief has read the claimed values and released it, so a run queue
//! the owner has emptied can still have no room. A pool of one worker has no
//! thief, so its run queue is exclusive and pops without an atomic exchange.
//!
//! A take from the global queue returns the runnable the caller polls next and
//! queues the rest of its share in the run queue, no more than it has room for
//! and no more than would fill it to half. A runnable a take queues therefore
//! lands in the oldest half, which an overflow keeps, so it is polled before
//! an overflow could send it back. A run queue already half full gets none,
//! and the take moves only the runnable the caller polls next.
//!
//! # Global queue
//!
//! The global queue is a [`VecDeque`] behind one pool-wide mutex, with its
//! length mirrored in an atomic. Workers read the mirror to decide whether
//! there is anything to take, so observing zero, the common case, avoids the
//! lock. A nonzero observation can be stale by the time the lock is acquired.
//!
//! A take moves a share into the taking worker's run queue under one lock. The
//! share is one runnable more than an even split between the workers, within
//! the cap above, and that cap also bounds a take's work under the lock to half
//! a run queue and one runnable more. The mirror is stored only under the lock,
//! so its stores follow the queue's own order. A take stores it after its
//! pushes into the run queue, so a worker that reads the length a take left
//! also sees the runnables it moved.
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
//! unclaimed backlog it finds, rounded up, so it can take even a runnable
//! queued alone behind a long poll. It queues what it took in its own run
//! queue and runs again. A push offers its run queue to a parked worker only
//! once [`KICK`] runnables are queued, so a lone runnable moves only to a
//! worker that is already looking for work.
//! [`super::queue`] describes how a thief claims and copies the runnables it
//! takes. [`super::idle`] describes how many workers search at once and how a
//! backlog wakes a parked worker to steal it.
//!
//! A lone runnable must also be ripe: it must have stayed alone at the same run
//! queue position for the pool's [steal age] since a worker first looked at
//! it. A woken runnable's owner usually polls it next, so taking it at once
//! mostly splits tasks that work together on one worker, while one that waits
//! that long sits behind a long poll, a long root poll or a long service turn.
//! The owner pays nothing for this: its pops already move the position, and
//! the first look's time is kept in a stamp per run queue that only lookers
//! write. A look that refuses a young lone runnable records when it ripens,
//! and a worker that stays idle waits no longer than that before it looks
//! again, even past the search cap, so the runnable is taken about the steal
//! age after it was first seen, unless its owner gets to it first or that
//! worker finds other work first. The runnable then waits for its owner or a
//! later look. A timed wait on a worker's futex can also end late (see
//! [`MIN_STEAL_AGE`]). A steal age of zero takes a lone runnable at once.
//!
//! A position is the run queue head's full 55-bit count, in the stamp as in
//! the head, so a stamp names a later runnable only once that count repeats,
//! which the run queue's own claims already assume does not happen while a
//! thief stalls. The stamp keeps the time in a word of its own, which a look
//! only ever raises and raises before it publishes the position it observes,
//! so a racing look can delay a steal but never make one early.
//!
//! A new task's first runnable, which a spawn keeps on its worker only while
//! nothing else is queued there, is ripe at once. A spawn asks for
//! concurrency, and its spawner, still in its poll, usually spawns more or
//! goes on running, so making its first child wait would hold it back and,
//! since a run queue holding it is not empty, send every later spawn of a
//! burst through the global queue. The spawn marks the runnable in the run
//! queue as it pushes it, which a look reads beside the tail it loads anyway.
//!
//! [steal age]: super::Config::with_steal_age
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
//!   Pool::new (mailboxes, run queues,
//!     timers, parkers)
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
//!     close timers,                          close timers,
//!     destroy io_uring ring                  destroy io_uring ring
//!   join <------------------------------   exit
//!   take a failure reported late
//! ```
//!
//! Shutdown closes the task set before the global queue, so a runnable the
//! closed queue refuses belongs to a task that teardown clears or already has
//! cleared, and so does a runnable a worker discards from its own run queue. A
//! worker still driving may steal from the run queue of one that is cleaning
//! up. It polls what it took, or discards it in its own cleanup, before it
//! reaches the barrier.
//!
//! On the runner's normal path the pool stops after the supervision tree is
//! aborted, so the other workers destroy only cancelled tasks and the runner's
//! metrics task. A worker that failed earlier is the exception. It drains the
//! set as soon as the pool closes. Worker zero stops the pool from its own
//! cleanup, so an unwind that skips the runner's shutdown still releases the
//! barrier.
//!
//! No worker closes its mailbox or its timers, drops the messages it took from
//! its mailbox, or destroys its io_uring ring until every pool worker has
//! drained the set and finished its last poll, since a task polled on one
//! worker can hold registrations on another, whose mailbox forwards their
//! results and whose timers its sleeps poll.
//!
//! The barrier's state is [`Closing`], under a lock of its own: `closed`
//! releases the workers waiting in [`Pool::wait_closed`], `stopped` ends the
//! roots of the workers after worker zero, and `active` counts the workers
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
    park::Parker,
    queue::{self, Backlog, CAPACITY, Overflow, Push},
    runtime::{Panic, Role, Shared, Worker},
    sleep::Timers,
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
    time::{Duration, Instant},
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

/// Half a run queue: what an overflow keeps and what a take may fill one to.
pub const HALF: usize = CAPACITY / 2;

/// Maximum number of workers in one pool, since the idle set gives each worker
/// one bit of a `u64`.
pub const MAX_WORKERS: usize = 64;

/// Run queue length at which a push offers the backlog to a parked worker. A
/// lone runnable, which a searching worker can still steal, wakes no one: its
/// owner usually polls it next, sooner than a woken peer could.
pub const KICK: usize = 2;

/// Smallest nonzero steal age the runner accepts. A worker whose look refused
/// a young lone runnable looks again once it ripens, and a wait that ends at
/// once follows a lone runnable that stayed queued almost that long, so an
/// idle worker looks again at most about once per steal age for each run
/// queue it watches, and more often when it watches several whose lone
/// runnables ripen at different times. Each look scans every other run queue,
/// and the minimum bounds how often one watched run queue makes a worker
/// look. A timed wait on a worker's futex, which a worker with no request in
/// flight uses, can end up to the thread's timer slack late, 50 microseconds
/// by default, so there a steal age below the slack is not met: the worker
/// looks again up to the slack after the runnable ripens.
pub const MIN_STEAL_AGE: Duration = Duration::from_micros(10);

/// Largest steal age the runner accepts.
pub const MAX_STEAL_AGE: Duration = Duration::from_secs(1);

/// How long, in microseconds, an unserved hint waits before a busy worker
/// takes from the global queue ahead of its own run queue.
pub const GLOBAL_AGE: u64 = 100;

/// The key of a stamp that no look has set yet. No 55-bit head count equals
/// it.
const UNSEEN: u64 = u64::MAX;

/// A pool worker's run queue as the pool holds it: the shared end that the
/// other workers steal through. The worker takes its [`queue::Owner`] when it
/// starts.
pub type LocalQueue = queue::Queue<Runnable>;

/// Where, and since when, a look last saw a run queue holding a lone runnable.
/// Only lookers write it, and the run queue's owner never reads it.
struct Stamp {
    /// The full 55-bit head count of the lone runnable the latest observation
    /// started at, or [`UNSEEN`].
    key: AtomicU64,
    /// Microseconds since the pool's epoch, no earlier than when a look first
    /// saw the runnable at `key` there. Only ever raised, and raised before a
    /// look publishes a new key with release, so a look that acquires a key
    /// reads at least its first sighting's time.
    since: AtomicU64,
}

impl Stamp {
    /// A stamp that names no runnable.
    // Loom's atomics have no const constructor.
    #[allow(clippy::missing_const_for_fn)]
    fn new() -> Self {
        Self {
            key: AtomicU64::new(UNSEEN),
            since: AtomicU64::new(0),
        }
    }

    /// The age, in microseconds, of the observation of the lone runnable at
    /// the 55-bit count `real`, starting one if the stamp names another
    /// count, with the sample of `clock` it is measured against. `clock`
    /// returns an instant and its microseconds since the epoch, and each
    /// sample is taken after the key it is compared with was loaded.
    ///
    /// The age never exceeds the time since some look, sampling after it saw
    /// `real` alone, started this observation, so a lone runnable never
    /// ripens early, whatever looks race. A look whose count is already stale
    /// can restart another count's observation, which delays that steal by at
    /// most one more steal age. A stamp names the same count again only once
    /// the head's count repeats.
    fn age<I>(&self, real: u64, mut clock: impl FnMut() -> (I, u64)) -> (I, u64) {
        // Acquire pairs with the release of the exchange that stored the key,
        // so a matching key shows the time raised before it, or a later one.
        let mut key = self.key.load(Ordering::Acquire);
        loop {
            let (now, micros) = clock();
            if key == real {
                // A time raised after the sample, by a racing look or across
                // cores, counts as no age.
                let since = self.since.load(Ordering::Relaxed);
                return (now, micros.saturating_sub(since));
            }

            // Raise the time first, so a look that sees the new key reads at
            // least this sample. Raising, rather than storing, keeps a look
            // that stalled after its sample from lowering a newer one.
            self.since.fetch_max(micros, Ordering::Relaxed);
            match self
                .key
                .compare_exchange_weak(key, real, Ordering::Release, Ordering::Acquire)
            {
                Ok(_) => return (now, 0),
                Err(actual) => key = actual,
            }
        }
    }
}

/// The global queue's contents, guarded by the pool-wide lock.
struct GlobalQueue {
    /// Whether pushes are still accepted. Shutdown clears it, after which a
    /// push hands its runnables back to the caller.
    open: bool,
    /// Runnables waiting for any worker, oldest first.
    runnables: VecDeque<Runnable>,
}

/// Progress of the pool's shutdown, guarded by its own lock and signaled
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
    /// Every pool worker's sleep timers, indexed by worker.
    timers: Box<[Arc<Timers>]>,
    /// The lone runnable each run queue was last seen holding, and since
    /// when, indexed by worker. Each sits on a cache line of its own.
    seen: Box<[CachePadded<Stamp>]>,
    /// How long, in microseconds, a lone runnable must stay at one position
    /// before another worker may steal it. Zero steals it at once, as does a
    /// pool of one worker, which has no thief.
    steal_age: u64,
    /// The origin of the stamps' clock.
    epoch: Instant,
    /// Loom only: the microseconds since `epoch` that the stamps' clock
    /// reads, which a model advances where real time would pass, so its
    /// executions stay deterministic.
    #[cfg(feature = "loom")]
    model_clock: std::sync::atomic::AtomicU32,
    /// Test only: whether each worker's latest wait ends by a re-look
    /// deadline, so tests can tell a worker parked only until a lone runnable
    /// ripens from one parked until a wake.
    #[cfg(test)]
    relooking: Box<[std::sync::atomic::AtomicBool]>,
    /// The global queue's length, stored under its lock and read without it.
    global_len: CachePadded<AtomicUsize>,
    /// The unserved hint, or zero, as the module docs describe it.
    /// Set only from zero and cleared only by a worker acting on it, so busy
    /// workers read it on every pop without contending.
    unserved: CachePadded<AtomicU64>,
    /// The global queue.
    global: CachePadded<Mutex<GlobalQueue>>,
    /// Shutdown progress, which workers wait on through `progress`.
    closing: Mutex<Closing>,
    /// Signaled when the pool closes and when the last active worker
    /// finishes.
    progress: Condvar,
}

impl Pool {
    /// The state for a pool of `workers` workers, with a mailbox and an empty
    /// run queue for each, and the parker of each worker's word, in worker
    /// order. Each worker must start with its parker. A lone runnable becomes
    /// stealable once `steal_age` has passed since a look first saw it. Panics
    /// unless there are between one and [`MAX_WORKERS`] workers and
    /// `steal_age` is zero or between [`MIN_STEAL_AGE`] and [`MAX_STEAL_AGE`].
    pub fn new(workers: usize, steal_age: Duration) -> (Self, Vec<Parker>) {
        // The idle set has one bit per worker.
        assert!(
            (1..=MAX_WORKERS).contains(&workers),
            "an io_uring pool must have 1 to {MAX_WORKERS} workers"
        );
        assert!(
            steal_age.is_zero() || (MIN_STEAL_AGE..=MAX_STEAL_AGE).contains(&steal_age),
            "steal age must be zero or between 10 microseconds and one second"
        );
        let parkers: Vec<Parker> = (0..workers).map(|_| Parker::new()).collect();
        let mailboxes = parkers
            .iter()
            .map(|parker| Arc::new(Mailbox::new(parker.unparker())))
            .collect();

        // A worker reads another's run queue only to steal from it, and a pool
        // of one worker has no other worker, so its run queue is exclusive.
        let queue = || {
            if workers == 1 {
                LocalQueue::exclusive()
            } else {
                LocalQueue::shared()
            }
        };

        // Every worker's timers count from one origin, so that a peer
        // converts its time once to check all of them.
        let origin = Instant::now();

        let pool = Self {
            idle: CachePadded::new(Idle::new()),
            mailboxes,
            queues: (0..workers).map(|_| queue()).collect(),
            timers: (0..workers)
                .map(|_| Arc::new(Timers::new(origin)))
                .collect(),
            seen: (0..workers)
                .map(|_| CachePadded::new(Stamp::new()))
                .collect(),
            // At most a second, so whole microseconds fit, rounded up so a
            // nonzero age never means an immediate steal.
            steal_age: if workers == 1 {
                0
            } else {
                u64::try_from(steal_age.as_nanos().div_ceil(1_000))
                    .expect("steal age must fit in microseconds")
            },
            epoch: Instant::now(),
            #[cfg(feature = "loom")]
            model_clock: std::sync::atomic::AtomicU32::new(0),
            #[cfg(test)]
            relooking: (0..workers)
                .map(|_| std::sync::atomic::AtomicBool::new(false))
                .collect(),
            global_len: CachePadded::new(AtomicUsize::new(0)),
            unserved: CachePadded::new(AtomicU64::new(0)),
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
        };
        (pool, parkers)
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

    /// Every pool worker's sleep timers, in worker order.
    pub fn timers(&self) -> &[Arc<Timers>] {
        &self.timers
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
    /// signaled or woken spuriously. Callers recheck their condition.
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

    /// Queue `runnable` for any worker and wake a parked one, as
    /// [`Self::push_batch`] does. Once the queue has closed, returns the
    /// runnable for the caller to discard. The task set closed first, so
    /// teardown clears its task or already has.
    pub fn push(&self, runnable: Runnable) -> Result<(), Runnable> {
        self.push_batch(iter::once(runnable))
            .map_err(|mut refused| refused.next().unwrap())
    }

    /// Queue `runnables` for any worker under one lock and wake a parked
    /// worker. A batch that brings runnables but wakes no worker leaves an
    /// unserved hint, unless one is already left. An empty batch wakes no
    /// worker and leaves no hint. Once the queue has closed, returns them for
    /// the caller to discard, as [`Self::push`] does.
    pub fn push_batch<I: Iterator<Item = Runnable>>(&self, runnables: I) -> Result<(), I> {
        {
            let mut queue = self.global();
            if !queue.open {
                return Err(runnables);
            }
            let before = queue.runnables.len();
            queue.runnables.extend(runnables);
            let len = queue.runnables.len();

            // A batch that brought nothing, as a spill whose run queue thieves
            // emptied first, wakes no worker.
            if len == before {
                return Ok(());
            }

            // Under the lock, so the mirror's stores follow the queue's own
            // order.
            self.global_len.store(len, Ordering::Release);
        }

        // Pairs with the fence in `Searcher::prepare_park`, which a worker
        // puts between publishing its bit and its last look. Either the loads
        // in `Idle::notify_global` see the bit, or that look sees the length
        // stored above. The pair alone forbids both sides missing the other's
        // store, so the loads that follow need no ordering of their own.
        fence(Ordering::SeqCst);
        if !self.idle.notify_global(&self.mailboxes) {
            self.mark_unserved();
        }
        Ok(())
    }

    /// Leave an unserved hint for a push that woke no worker, unless one is
    /// already left. Reads the clock only to set one.
    #[inline]
    fn mark_unserved(&self) {
        if self.unserved.load(Ordering::Relaxed) != 0 {
            return;
        }
        // Leave zero for the absent hint.
        let hint = self.clock().1.saturating_add(1);

        // Publish the push before a worker clears the hint and locks the
        // queue. The queue lock also orders a refill with that worker's take.
        let _ = self
            .unserved
            .compare_exchange(0, hint, Ordering::Release, Ordering::Relaxed);
    }

    /// The unserved hint, or zero, read without the lock.
    #[inline]
    pub fn unserved(&self) -> u64 {
        self.unserved.load(Ordering::Relaxed)
    }

    /// When the nonzero unserved hint `hint` reaches [`GLOBAL_AGE`].
    pub fn unserved_due(&self, hint: u64) -> Instant {
        self.epoch + Duration::from_micros((hint - 1).saturating_add(GLOBAL_AGE))
    }

    /// Clear the hint and take one share as [`Self::take`] does, if it still
    /// matches. Returns `None` if another worker cleared it or the queue is
    /// empty when locked.
    #[inline(never)]
    #[must_use]
    pub fn take_unserved(&self, hint: u64, ready: &mut Ready) -> Option<Runnable> {
        if self
            .unserved
            .compare_exchange(hint, 0, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }

        // A refill can leave this hint in place. Use the lock to see any
        // refill before this take. A refill after it sees the cleared hint
        // through the lock and can mark a new one.
        let mut queue = self.global();
        if queue.runnables.is_empty() {
            return None;
        }
        self.take_locked(&mut queue, ready)
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
    /// no more than it has room for and no more than would fill it to half, so
    /// a take into a run queue already half full returns only the oldest.
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
        self.take_locked(&mut queue, ready)
    }

    /// [`Self::take`] with the global queue locked as `queue`.
    fn take_locked(&self, queue: &mut GlobalQueue, ready: &mut Ready) -> Option<Runnable> {
        // One more than an even split, so a lone runnable still moves and a
        // burst spreads over the workers that look. Another take may have
        // emptied the queue since the check above, so the share never exceeds
        // what is left.
        let len = queue.runnables.len();
        let share = (len / self.workers() + 1).min(len);

        // The caller polls the first runnable next, and the run queue takes the
        // rest. Filling at most its oldest half keeps every taken runnable out
        // of the half an overflow exports and bounds the work under the lock.
        // The room read here only grows before the pushes below.
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
    /// backlog of [`KICK`] or more to a parked worker. A full run queue moves
    /// its newest half and the runnable into the global queue, or only the
    /// runnable while a thief holds a claim on it. The caller owns `ready` for
    /// a worker in this pool, and the runnable belongs to this pool's task
    /// set. Closing the global queue discards exports, leaving local cleanup
    /// to drain `ready`.
    ///
    /// May run with the worker's `Local` mutably borrowed. Queueing and
    /// discarding runnable references must not invoke user code.
    #[inline]
    pub fn enqueue(&self, ready: &mut Ready, runnable: Runnable) {
        let push = ready.push(runnable);
        self.queued(push);
    }

    /// Queue a new task's first runnable as [`Self::enqueue`] does, marked
    /// so that it is ripe at once while it is alone in the run queue (see
    /// [`Self::ripe`]). Without a steal age every lone runnable is, so the
    /// mark is skipped.
    #[inline]
    pub fn enqueue_spawned(&self, ready: &mut Ready, runnable: Runnable) {
        let push = if self.steal_age == 0 {
            ready.push(runnable)
        } else {
            ready.push_marked(runnable)
        };
        self.queued(push);
    }

    /// Finish a push into a pool worker's run queue as [`Self::enqueue`]
    /// describes: kick for a backlog, or move what a full run queue handed
    /// back into the global queue.
    #[inline]
    fn queued(&self, push: Push<'_, Runnable>) {
        match push {
            Push::Pushed(len) => {
                if len >= KICK && self.workers() > 1 {
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
    /// discarded. The task set closed first, so teardown clears their tasks.
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
    /// half of the first backlog found. Returns the oldest runnable stolen,
    /// for the caller to poll next, and moves the rest into `ready`. The
    /// returned runnable is never published in `ready`, so no other worker
    /// can steal it before that poll. The caller holds a search count and
    /// supplies worker `index`'s empty run queue, with `start` inside the
    /// pool. A pending claim can leave insufficient room even in an empty
    /// destination.
    ///
    /// A lone runnable is taken only once ripe (see [`Self::ripe`]). One still
    /// young brings `relook` forward to when it ripens.
    #[inline]
    pub fn steal(
        &self,
        index: u32,
        start: usize,
        ready: &mut Ready,
        relook: &mut Option<Instant>,
    ) -> Option<Runnable> {
        let workers = self.workers();
        (0..workers)
            .map(|offset| (start + offset) % workers)
            .filter(|&victim| victim != index as usize)
            .find_map(|victim| {
                self.queues[victim].steal_into_if(ready, |real, spawned| {
                    self.ripe(victim, real, spawned, relook)
                })
            })
    }

    /// Ask [`Idle::notify`] to wake a parked worker for a run queue's backlog
    /// or to carry on the last returned count's search. A held search count
    /// suppresses the request. See [`super::idle`] for the wake policy.
    #[inline]
    pub fn kick(&self) {
        // Pairs with the fence in `Searcher::prepare_park`. Either the loads
        // in `Idle::notify` see the worker's bit, or its last look sees what
        // the caller published before this fence: the run queue's new tail or
        // the return of the last search count.
        fence(Ordering::SeqCst);
        self.idle.notify(&self.mailboxes);
    }

    /// Whether a run queue other than worker `index`'s holds an unclaimed
    /// backlog that a steal would take from. The answer is a snapshot, and
    /// another worker can pop or claim the backlog before a later steal.
    ///
    /// A lone runnable counts only once ripe (see [`Self::ripe`]). One still
    /// young brings `relook` forward to when it ripens.
    #[inline]
    pub fn has_stealable(&self, index: u32, relook: &mut Option<Instant>) -> bool {
        self.queues
            .iter()
            .enumerate()
            .filter(|&(other, _)| other != index as usize)
            .any(|(other, queue)| match queue.backlog() {
                Backlog::None => false,
                Backlog::Lone(real, spawned) => self.ripe(other, real, spawned, relook),
                Backlog::More => true,
            })
    }

    /// Whether the lone runnable at the 55-bit head count `real` in worker
    /// `victim`'s run queue may be stolen: always with a zero steal age or
    /// when `spawned` reports a new task's first runnable that a spawn queued
    /// there, otherwise once it has stayed there for the steal age since a
    /// look first saw it. The first look at a count starts its observation. A
    /// runnable still young brings `relook` forward to when it ripens, which
    /// is in the future.
    ///
    /// The stamp and the mark are only hints for this decision: the claim's
    /// exchange alone decides which runnable a steal takes. A stale mark only
    /// moves the decision for the count it names, and [`Stamp::age`] says
    /// how racing looks can delay a steal but not hasten it.
    fn ripe(&self, victim: usize, real: u64, spawned: bool, relook: &mut Option<Instant>) -> bool {
        if self.steal_age == 0 || spawned {
            return true;
        }
        let (now, age) = self.seen[victim].age(real, || self.clock());
        if age >= self.steal_age {
            return true;
        }
        let ripens = now + Duration::from_micros(self.steal_age - age);
        *relook = Some(relook.map_or(ripens, |relook| relook.min(ripens)));
        false
    }

    /// Now, as the stamps' clock reads it, which loom models advance
    /// themselves.
    pub fn now(&self) -> Instant {
        self.clock().0
    }

    /// The stamps' clock: now, and the microseconds since `epoch`. Loom
    /// models read and advance their own clock instead.
    fn clock(&self) -> (Instant, u64) {
        #[cfg(feature = "loom")]
        {
            let micros = self.model_clock.load(std::sync::atomic::Ordering::Relaxed);
            (
                self.epoch + Duration::from_micros(micros.into()),
                micros.into(),
            )
        }
        #[cfg(not(feature = "loom"))]
        {
            let now = Instant::now();
            // Microseconds overflow a u64 only after half a million years.
            let micros = now.duration_since(self.epoch).as_micros() as u64;
            (now, micros)
        }
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

        // Releasing references runs no user code, since each task is still
        // retained for teardown or its future is already gone.
        for runnable in runnables {
            runnable.discard();
        }

        // Release every worker waiting in `wait_closed`.
        self.closing().closed = true;
        self.progress.notify_all();
    }

    /// End the root of every pool worker other than worker zero. Worker zero
    /// must call this before it reaches [`Self::finish`], while every pool
    /// mailbox is still open. Ending a worker's root starts its shutdown.
    /// Repeated calls do nothing.
    pub fn stop(&self) {
        // Set the flag before waking the roots, so a root polled after its wake
        // sees it and one not polled yet sees it on its first poll.
        {
            let mut closing = self.closing();
            if closing.stopped {
                return;
            }
            closing.stopped = true;
        }

        // Worker zero polls the runner's root rather than a stop root, so it
        // is skipped. The others close their mailboxes only after the shutdown
        // barrier, which worker zero has not reached yet, so every send
        // succeeds.
        for mailbox in self.mailboxes.iter().skip(1) {
            let _ = mailbox.send(Message::WakeRoot);
        }
    }

    /// Whether worker zero has stopped the pool.
    fn is_stopped(&self) -> bool {
        self.closing().stopped
    }

    /// Block until the pool has closed. A pool worker must wait here before it
    /// drains the task set, so one that stopped early after a failure drains
    /// only a closed set.
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
    /// Start pool worker `index` with `parker`, the parker [`Pool::new`]
    /// returned for it, and wait until it has created its io_uring ring. Every
    /// failure of a started worker is sent to `failures`, which interrupts the
    /// root while it runs. The runner collects a later one after joining the
    /// pool.
    ///
    /// Worker zero starts every other worker this way, in index order, after
    /// it enters the shutdown barrier. Panics with a startup failure, after
    /// which worker zero's cleanup stops the workers already started.
    pub fn start(
        &mut self,
        shared: &Arc<Shared>,
        failures: &Panicker,
        index: usize,
        parker: Parker,
    ) {
        #[cfg(test)]
        let _fault = super::runtime::tests::before_pool_worker(shared, index);
        let (ready, started) = mpsc::channel();
        let shared = shared.clone();
        let failures = failures.clone();
        let handle = thread::Builder::new()
            .name(format!("iouring-pool-{index}"))
            .stack_size(shared.cfg.thread_stack_size())
            .spawn(move || run(shared, index as u32, parker, ready, failures))
            .expect("pool worker thread must spawn");

        // Keep the handle before waiting, so a worker that fails at startup
        // is still joined.
        self.handles.push(handle);

        // One worker at a time: each has entered the barrier and created its
        // io_uring ring before the next starts. A startup failure resumes
        // here, inside worker zero's root builder, so the runner's root is
        // never built.
        match started
            .recv()
            .expect("pool worker must report its startup before exiting")
        {
            Ok(()) => {}
            Err(panic) => resume_unwind(panic),
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
    parker: Parker,
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
            parker,
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
        idle::{Park, Searcher, tests::Keep},
        park::tests::notifications,
        task::{
            Task,
            tests::{queue, refs, task_of},
        },
        tasks::Tasks,
    };
    use std::{
        future::pending,
        iter,
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
        /// A pool and its parkers as [`Pool::new`] builds them, with lone
        /// runnables stealable at once, whose shared run queues claim half
        /// rounded down (see [`LocalQueue::round_down`]).
        #[cfg(feature = "loom")]
        pub(crate) fn rounding_down(workers: usize) -> (Self, Vec<Parker>) {
            let (mut pool, parkers) = Self::new(workers, Duration::ZERO);
            if pool.workers() > 1 {
                for queue in pool.queues.iter_mut() {
                    queue.round_down();
                }
            }
            (pool, parkers)
        }

        /// Advance the stamps' clock of a loom model to `instant`, as a wait
        /// that times out there would, unless it already reads later.
        #[cfg(feature = "loom")]
        pub(crate) fn advance_clock_to(&self, instant: Instant) {
            let micros = u32::try_from(instant.duration_since(self.epoch).as_micros())
                .expect("model clock overflow");
            self.model_clock
                .fetch_max(micros, std::sync::atomic::Ordering::Relaxed);
        }

        /// The microseconds a loom model's stamps' clock has advanced.
        #[cfg(feature = "loom")]
        pub(crate) fn model_clock(&self) -> u32 {
            self.model_clock.load(std::sync::atomic::Ordering::Relaxed)
        }

        /// Record whether worker `index`'s next wait ends by a re-look
        /// deadline.
        pub fn set_relooking(&self, index: u32, relooking: bool) {
            self.relooking[index as usize].store(relooking, std::sync::atomic::Ordering::SeqCst);
        }

        /// Whether worker `index`'s latest wait ends by a re-look deadline.
        pub fn relooking(&self, index: u32) -> bool {
            self.relooking[index as usize].load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Leave an unserved hint that never comes due, so no worker takes
        /// from the global queue for a hint and no push leaves another.
        pub fn suppress_unserved(&self) {
            self.unserved.store(u64::MAX, Ordering::Relaxed);
        }

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

    /// A pool of `workers` workers with no runner, whose workers never wait,
    /// so their parkers are dropped, and whose lone runnables are stealable at
    /// once.
    pub fn pool(workers: usize) -> Pool {
        aged_pool(workers, Duration::ZERO)
    }

    /// A pool of `workers` workers with no runner, whose workers never wait,
    /// so their parkers are dropped, and whose lone runnables are stealable
    /// once `steal_age` has passed since a look first saw them.
    pub fn aged_pool(workers: usize, steal_age: Duration) -> Pool {
        Pool::new(workers, steal_age).0
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

    /// A batch that brings nothing leaves no hint and wakes no worker.
    #[test]
    fn test_empty_batch_changes_nothing() {
        let pool = pool(2);
        let one = ready(&pool, 1);
        let mut parked = Searcher::new(&pool, 1);
        assert_eq!(parked.prepare_park(&one), Park::Wait);
        assert!(pool.push_batch(iter::empty()).is_ok());
        assert!(pool.idle().is_idle(1));
        assert_eq!(notifications(&pool.mailbox(1).unparker), 0);
        assert_eq!(pool.unserved(), 0);
        assert!(!pool.has_global());
        parked.finish_park();
    }

    /// A push that wakes no worker leaves an unserved hint once: later pushes
    /// keep it, however many go by, until a worker acts on it.
    #[test]
    fn test_unwoken_push_leaves_one_unserved_hint() {
        // No worker of this pool has published itself idle.
        let pool = pool(2);
        let set = Tasks::new(1);
        assert_eq!(pool.unserved(), 0);
        let mut tasks = vec![push(&pool, &set)];
        let hint = pool.unserved();
        assert_ne!(hint, 0);
        for _ in 0..10 {
            tasks.push(push(&pool, &set));
            assert_eq!(pool.unserved(), hint);
        }

        // Acting on it takes a share and clears it, so a second worker acting
        // on the same hint takes nothing.
        let mut ready = ready(&pool, 0);
        pool.take_unserved(hint, &mut ready).unwrap().discard();
        assert_eq!(pool.unserved(), 0);
        let mut other = super::tests::ready(&pool, 1);
        assert!(pool.take_unserved(hint, &mut other).is_none());
        assert!(other.is_empty());
        while let Some(runnable) = ready.pop() {
            runnable.discard();
        }
        pool.close();
        for task in tasks {
            task.clear();
        }
    }

    /// A hint outlives a take that empties the global queue, and the worker
    /// that later clears it takes what a refill queued since, which left no
    /// hint of its own.
    #[test]
    fn test_unserved_hint_can_take_a_refill() {
        let pool = pool(2);
        let set = Tasks::new(1);
        let mut ready = ready(&pool, 0);
        let first = push(&pool, &set);
        let hint = pool.unserved();
        pool.take(&mut ready).unwrap().discard();

        // The refill finds the hint left and leaves none.
        let second = push(&pool, &set);
        assert_eq!(pool.unserved(), hint);
        let taken = pool.take_unserved(hint, &mut ready).map(|runnable| {
            let task = task_of(&runnable).as_ptr();
            runnable.discard();
            task
        });

        pool.close();
        for task in [&first, &second] {
            task.clear();
        }
        assert_eq!(taken, Some(second.as_ptr()));
        assert_eq!(pool.unserved(), 0);
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
                "a take into a run queue holding {held} must fill it to half and return one more"
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
    /// reads them after the owner has popped past them. While a claim of half
    /// the run queue is held on an otherwise empty one, a take returns one
    /// runnable and queues none. Once the claim is released, a take queues its
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

    /// A search steals half of another worker's backlog, rounded up, down to
    /// a lone runnable.
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
        let first = searcher.search(&mut zero).expect("the search steals");
        assert_eq!(task_of(&first).as_ptr(), tasks[0].as_ptr());
        first.discard();
        for task in &tasks[1..3] {
            let runnable = zero.pop().unwrap();
            assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
            runnable.discard();
        }
        assert!(zero.is_empty());
        assert_eq!(two.len(), 2);

        // Of the two left, a second search takes one, and a third takes the
        // lone runnable after it.
        let mut other = Searcher::new(&pool, 1);
        for task in &tasks[3..] {
            let runnable = other.search(&mut one).expect("the search steals");
            assert!(one.is_empty());
            assert_eq!(task_of(&runnable).as_ptr(), task.as_ptr());
            runnable.discard();
        }
        assert!(!other.searched(&mut one));
        assert!(two.is_empty());
        searcher.leave_search();
        other.leave_search();
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

    /// A rescue compares its own worker's count of time with every peer's
    /// bound, so all of a pool's timers count from one origin.
    #[test]
    fn test_pool_timers_share_one_origin() {
        let pool = pool(3);
        let origin = pool.timers()[0].instant(0);

        assert!(origin.is_some());

        for timers in pool.timers() {
            assert_eq!(timers.instant(0), origin);
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

        assert_eq!(notifications(&pool.mailbox(0).unparker), 0);
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

    /// The period of a run queue head's 55-bit count.
    const PERIOD: u64 = 1 << 55;

    /// A pool whose stamps' clock reads well past its epoch, so a test can
    /// stamp a time the steal age before a sample.
    fn aged_pool_with_history(steal_age: Duration) -> Pool {
        let mut pool = aged_pool(2, steal_age);
        pool.epoch = pool
            .epoch
            .checked_sub(Duration::from_secs(10))
            .expect("the monotonic clock must have run for ten seconds");
        pool
    }

    /// Store worker zero's stamp directly, as a past look left it.
    fn stamp(pool: &Pool, key: u64, since: u64) {
        pool.seen[0].key.store(key, Ordering::Relaxed);
        pool.seen[0].since.store(since, Ordering::Relaxed);
    }

    /// A stamp whose time is newer than a look's sample, as a racing look or
    /// another core's clock can leave it, counts as no age, so the lone
    /// runnable stays young. A stamp the steal age old makes it ripe, and
    /// another count starts a fresh observation no earlier than the old one.
    #[test]
    fn test_lone_runnable_age_counts_a_newer_stamp_as_none() {
        let pool = aged_pool_with_history(Duration::from_millis(100));
        let (_, micros) = pool.clock();

        // Stamped a millisecond after the sample above, as by a racing look.
        stamp(&pool, 5, micros + 1_000);
        let mut relook = None;
        assert!(!pool.ripe(0, 5, false, &mut relook));
        assert!(relook.is_some());

        // Stamped the steal age before the sample above.
        stamp(&pool, 5, micros - 100_000);
        let mut relook = None;
        assert!(pool.ripe(0, 5, false, &mut relook));
        assert!(relook.is_none());

        // The next count is young again.
        assert!(!pool.ripe(0, 6, false, &mut relook));
        assert!(relook.is_some());
        assert_eq!(pool.seen[0].key.load(Ordering::Relaxed), 6);
        assert!(pool.seen[0].since.load(Ordering::Relaxed) >= micros);
    }

    /// A stamp keys its observation by the full 55-bit head count, so an old
    /// stamp makes no lone runnable at a later count ripe, even one that a
    /// narrower key would confuse with it, such as one sharing its low 24 bits
    /// or its `u32` position, and that look starts a fresh observation. Only
    /// a full period of the head's count brings the stamped count back, the
    /// run queue's own stall assumption.
    #[test]
    fn test_stale_stamp_matches_only_after_a_full_period() {
        let pool = aged_pool_with_history(Duration::from_millis(100));
        let (_, micros) = pool.clock();
        let start = 5;
        for (advance, ripe) in [
            (1 << 24, false),
            (1 << 32, false),
            (1 << 54, false),
            (PERIOD - 1, false),
            (PERIOD, true),
        ] {
            // Stamped a second ago, ten steal ages.
            stamp(&pool, start, micros - 1_000_000);
            let later = (start + advance) % PERIOD;
            let mut relook = None;
            assert_eq!(pool.ripe(0, later, false, &mut relook), ripe);
            assert_eq!(relook.is_none(), ripe);
            assert_eq!(pool.seen[0].key.load(Ordering::Relaxed), later);
        }
    }

    /// A new task's first runnable that a spawn queued alone is ripe at once,
    /// however long the steal age. The look neither starts an observation nor
    /// sets a re-look deadline. A woken runnable at the next count is young
    /// again.
    #[test]
    fn test_spawned_lone_runnable_is_ripe_at_once() {
        let pool = aged_pool(2, MAX_STEAL_AGE);
        let mut relook = None;
        assert!(pool.ripe(0, 5, true, &mut relook));
        assert!(relook.is_none());
        assert_eq!(pool.seen[0].key.load(Ordering::Relaxed), UNSEEN);

        assert!(!pool.ripe(0, 6, false, &mut relook));
        assert!(relook.is_some());
    }

    /// A look reports a lone runnable that a spawn queued as stealable at
    /// once, and one that a wake queued only once it ripens, through the run
    /// queue's mark for the newest spawned count.
    #[test]
    fn test_has_stealable_takes_a_spawned_lone_runnable_at_once() {
        let pool = aged_pool(2, MAX_STEAL_AGE);
        let set = Tasks::new(1);
        let (mut zero, mut one) = (ready(&pool, 0), ready(&pool, 1));

        // Spawned alone: stealable at once, and stolen.
        let (spawned, runnable) = task(&set);
        pool.enqueue_spawned(&mut zero, runnable);
        let mut relook = None;
        assert!(pool.has_stealable(1, &mut relook));
        assert!(relook.is_none());
        let stolen = pool
            .steal(1, 0, &mut one, &mut relook)
            .expect("the lone runnable is stolen");
        assert!(relook.is_none());
        assert!(one.is_empty());
        assert_eq!(task_of(&stolen).as_ptr(), spawned.as_ptr());
        stolen.discard();

        // Woken alone at the next count: young, so neither reported nor
        // stolen, and both looks set a re-look deadline.
        let (woken, runnable) = task(&set);
        pool.enqueue(&mut zero, runnable);
        assert!(!pool.has_stealable(1, &mut relook));
        assert!(relook.take().is_some());
        assert!(pool.steal(1, 0, &mut one, &mut relook).is_none());
        assert!(relook.is_some());
        zero.pop().unwrap().discard();
        for task in [spawned, woken] {
            task.clear();
        }
    }

    /// A zero steal age keeps immediate ceil stealing: a lone runnable is
    /// ripe at once with no stamp, clock or mark, and a spawn queues its
    /// runnable unmarked. A pool of one worker, which has no thief, keeps no
    /// steal age either.
    #[test]
    fn test_zero_steal_age_takes_a_lone_runnable_at_once() {
        let pool = aged_pool(2, Duration::ZERO);
        let set = Tasks::new(1);
        let mut zero = ready(&pool, 0);
        let (spawned, runnable) = task(&set);
        pool.enqueue_spawned(&mut zero, runnable);
        assert_eq!(pool.queue(0).backlog(), Backlog::Lone(0, false));
        let mut relook = None;
        assert!(pool.has_stealable(1, &mut relook));
        assert!(pool.ripe(0, 0, false, &mut relook));
        assert!(relook.is_none());
        assert_eq!(pool.seen[0].key.load(Ordering::Relaxed), UNSEEN);
        zero.pop().unwrap().discard();
        spawned.clear();

        assert_eq!(aged_pool(1, MAX_STEAL_AGE).steal_age, 0);
        assert_eq!(aged_pool(2, MIN_STEAL_AGE).steal_age, 10);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use crate::iouring::tasks::Tasks;
    use loom::thread;

    /// A look that saw a stale count alone, sampled the clock and then
    /// stalled, races a look that starts the observation of a fresh count
    /// later, while a third look reads the fresh count later still. The two
    /// counts differ only above their low 24 bits, so a key narrower than the
    /// head's count, such as one of 24 bits, would confuse them. Whatever the
    /// order, the stalled look's older time never reaches the fresh count's
    /// observation, since a time is only raised and is raised before its key
    /// is published. So the fresh count is never older than its first
    /// sighting, and no lone runnable ripens early.
    ///
    /// The fresh look's zero age is what checks the orderings, not the main
    /// look's bound. Every look loads the key before it exchanges it, so loom
    /// never lets the main look's first load return a spawned look's key, and
    /// that bound holds whatever the orderings. The fresh look, on a spawned
    /// thread, can run after the main look's exchange and read its key, so a
    /// relaxed key, or a key published before its time, would let it read the
    /// time from before that exchange and see a nonzero age.
    #[test]
    fn test_racing_looks_never_age_a_count_past_its_first_sighting() {
        /// The count the stalled look saw alone.
        const STALE: u64 = 1;
        /// A later count with the same low 24 bits.
        const FRESH: u64 = 1 + (1 << 24);
        loom::model(|| {
            let stamp = loom::sync::Arc::new(Stamp::new());
            let stale = thread::spawn({
                let stamp = stamp.clone();
                move || stamp.age(STALE, || ((), 0)).1
            });
            let fresh = thread::spawn({
                let stamp = stamp.clone();
                move || stamp.age(FRESH, || ((), 50)).1
            });

            // First seen no earlier than 50, so at most 10 old at 60.
            let (_, age) = stamp.age(FRESH, || ((), 60));
            assert!(
                age <= 10,
                "the fresh count aged {age} past its first sighting"
            );
            assert_eq!(fresh.join().unwrap(), 0);
            assert_eq!(stale.join().unwrap(), 0);
        });
    }

    /// A push into the global queue that wakes no worker leaves an unserved
    /// hint, and the worker that clears it can take the runnable. The worker
    /// waits for the hint with yields. Loom's partial order reduction never
    /// runs the pusher's load and exchange of the hint ahead of a worker's
    /// load that came first, so a worker that read the hint once could miss it
    /// in every schedule.
    #[test]
    fn test_cleared_hint_shows_its_push() {
        loom::model(|| {
            // Neither worker is published idle, so the push wakes no one.
            let pool = std::sync::Arc::new(Pool::new(2, Duration::ZERO).0);
            let set = Tasks::new(1);
            let (task, runnable) = super::tests::task(&set);

            // The pusher leaves the hint, and the worker waits for it.
            let pusher = thread::spawn({
                let pool = pool.clone();
                move || assert!(pool.push(runnable).is_ok())
            });
            let worker = thread::spawn({
                let pool = pool.clone();
                move || {
                    let mut ready = pool.queue(0).owner();
                    let mut hint = pool.unserved();
                    while hint == 0 {
                        thread::yield_now();
                        hint = pool.unserved();
                    }

                    // Clearing the hint shows the push, so the take finds it.
                    let runnable = pool.take_unserved(hint, &mut ready);
                    assert!(runnable.is_some(), "a cleared hint must show its push");
                    runnable.unwrap().discard();
                }
            });
            pusher.join().unwrap();
            worker.join().unwrap();

            // The worker cleared the only hint and took the only runnable.
            assert_eq!(pool.unserved(), 0);
            assert!(!pool.has_global());
            task.clear();
        });
    }

    /// A refill that finds a hint left stays covered when the worker that
    /// clears the hint races it: the worker's take, under the queue lock,
    /// finds the refill, or the refill sees the clear and leaves a hint of its
    /// own. A take that checked the length mirror before locking could miss
    /// the refill while the refill still saw the old hint, which fails this
    /// model.
    #[test]
    fn test_hint_clear_races_refill() {
        loom::model(|| {
            let pool = std::sync::Arc::new(Pool::new(2, Duration::ZERO).0);
            let mut ready = pool.queue(0).owner();
            let set = Tasks::new(1);
            let first = super::tests::push(&pool, &set);
            let hint = pool.unserved();
            pool.take(&mut ready).unwrap().discard();

            // Use a different timestamp if the refill marks a new hint.
            pool.model_clock
                .store(1, std::sync::atomic::Ordering::Relaxed);
            let refill = thread::spawn({
                let pool = pool.clone();
                let (task, runnable) = super::tests::task(&set);
                move || {
                    assert!(pool.push(runnable).is_ok());
                    task
                }
            });

            let took_refill = pool
                .take_unserved(hint, &mut ready)
                .is_some_and(|runnable| {
                    runnable.discard();
                    true
                });
            let second = refill.join().unwrap();
            let left_hint = pool.unserved() != 0;
            pool.close();
            first.clear();
            second.clear();
            assert!(took_refill || left_hint, "refill lost its hint");
        });
    }
}
