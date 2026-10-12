//! The pool of workers that poll ordinary tasks.
//!
//! [`Pool`] is the state the workers share: every worker's [`Slot`], which
//! holds its mailbox and the shared end of its run queue, the pool-wide global
//! queue, the wake word, and the shutdown barrier. The runner creates it before
//! any worker starts, every worker reaches it through the runner's shared
//! services, and every task's header holds a weak reference to it, so a wake
//! from any thread can find the task's pool without keeping the pool alive.
//! [`Threads`] starts the workers after worker zero, each on a thread of its
//! own, and joins them at shutdown.
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
//! Each pool worker queues its runnables in a run queue, a bounded [`Ring`] of
//! [`CAPACITY`] that only it pushes into and pops from. A push into a full run
//! queue moves its newest half and the new runnable into the global queue in
//! one batch, keeping the oldest half in the run queue. If a thief's claim
//! prevents that split, only the new runnable goes to the global queue. Values
//! claimed by a thief still occupy slots until it finishes reading them, even
//! if the owner has popped all the unclaimed values. A pool of one worker has
//! no thief, so its run queue is exclusive and pops without an atomic exchange.
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
//! one runnable more than an even split between the
//! workers, at most [`GLOBAL_BATCH`], within the cap above. The mirror is
//! stored only under the lock, after the take's pushes into the run queue, so
//! its stores follow the queue's own order, and a worker that reads the length
//! a take left also sees the runnables it moved.
//!
//! ```text
//! push   lock, refuse if closed, append, store the length, unlock, wake
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
//! while a claim is held. A worker holding no search count starts a search only
//! while the count is less than half the worker count. Otherwise it parks,
//! since a count holder finds work or hands the duty on. The check is soft:
//! workers that check at once can all pass it, and wakes reserve counts without
//! this cap, so the search count can exceed half the worker count.
//!
//! # Waking a parked worker
//!
//! The wake word holds the idle set and the search count on one cache line,
//! since every wake reads both. The idle set is one `u64` with a bit per
//! worker, which is why a pool has at most [`MAX_WORKERS`] workers. A worker's
//! bit is set while it is published as parked or about to park and no wake has
//! claimed it. Claiming a worker clears its bit, so each publication is claimed
//! at most once. The search count tracks responsibility for finding work or
//! handing the search on. A worker keeps its count across a search until it
//! parks or leaves searching. A wake reserves a count before claiming a bit,
//! transferring it to the claimed worker or returning it if the claim fails.
//! Thus a count can belong to a wake still attempting its claim, as well as to
//! a worker. The idle-bit exchange transfers the count, not the wake signal.
//! A late signal from an earlier claim cannot transfer another count.
//!
//! A push into the global queue fences and claims the lowest published worker,
//! even while another worker searches, so a burst of spawns wakes a worker per
//! push while idle bits remain. A push into a worker's own run queue that
//! leaves it holding a stealable backlog, a kick, tries to wake a worker only
//! while the search count is zero. An existing count's holder finds the
//! backlog or hands the duty on when it returns the count. Further kicks are
//! suppressed while that count is held. A wake that finds no bit to claim
//! returns the count it took, and if that was the last one, it fences and looks
//! at the idle set again, since a kick the count suppressed meanwhile may need
//! a worker that published since.
//!
//! A worker returns its count before it runs user code: before every poll, the
//! root's included, before every nonempty batch of callbacks or messages, and
//! whenever it goes round its loop again without parking. The last count
//! returned this way hands the duty on: it fences and wakes a parked worker, as
//! a kick does. A parking worker publishes its idle bit, returns its count
//! without handing it on, fences, and looks once more. A global runnable sends
//! it back to work. A stealable backlog in another run queue sends it to
//! search, unless another worker holds a count, whose last return will find the
//! backlog or wake a parked worker, this one included, so the parker waits. It
//! waits as well when a thief's claim holds room its own run queue needs, since
//! that thief holds a count. Every exit of the drive loop, unwinding included,
//! withdraws a live publication and returns a held count before the worker
//! destroys its root.
//!
//! ```text
//! push or kick                           parking worker i
//!   publish work (or hand on a search)      set bit i, return a held count
//!   fence(SeqCst)                          fence(SeqCst)
//!   kick: a count is held, return           global nonempty: withdraw, run
//!   no idle bit: return                    stealable backlog and room:
//!   reserve a count                          take count if zero: withdraw, search
//!     kick: only if still zero               count already held: wait
//!   claim lowest bit                       otherwise: wait
//!     success: signal its worker           wait: spin, or arm and attempt a wait
//!     failure: return the reserved count
//!       last return: fence and retry
//! ```
//!
//! Each side fences between its store and its loads, so one of them sees the
//! other's store. A kick that sees a count is covered by the fence after the
//! last return of a count, whose look or wake follows the kick. A push that
//! sees no idle bit missed only workers that fence after it, whose last look
//! sees the push, and workers that were claimed or withdrew and run again. A
//! push into the global queue is therefore never left queued with every worker
//! asleep, and a stealable backlog that persists is taken or offered to a
//! parked worker. A wake that arrives before the worker arms its wait is
//! latched by the worker's wake source, so the wait returns at once. A claimed
//! worker withdraws its bit as soon as its wait returns, before it runs any
//! callback, and a withdrawal reports a claim only when it ends a live
//! publication.
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
//!   Pool::new (every slot)
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
    mailbox::{Mailbox, Message},
    queue::{CAPACITY, Overflow, Push, Ring, STEALABLE},
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
            atomic::{AtomicU64, AtomicUsize, Ordering, fence},
        };
    } else {
        use commonware_utils::sync::{Condvar, Mutex, MutexGuard};
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
    }
}

/// Maximum number of runnables one take removes from the global queue,
/// including the one returned directly, bounding work under the pool-wide lock.
const GLOBAL_BATCH: usize = 128;

/// Half a run queue: what an overflow keeps, and what a take may fill one to.
const HALF: usize = CAPACITY / 2;

/// Maximum number of workers in one pool, since the idle set gives each worker
/// one bit of a `u64`.
pub const MAX_WORKERS: usize = 64;

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

/// What other threads reach of one pool worker.
pub struct Slot {
    /// The worker's mailbox.
    mailbox: Arc<Mailbox>,
    /// The shared end of the worker's run queue. The worker takes its owner
    /// when it starts.
    ring: Ring<Runnable>,
}

/// The state every wake reads, on one cache line.
struct Wake {
    /// Bit `i` is set while worker `i` is published as parked or about to
    /// park and no wake has claimed it. A wake clears the bit to claim the
    /// worker before waking it, and the worker clears it when it runs again.
    idle: AtomicU64,
    /// Search counts held by workers or reserved by wakes attempting a claim.
    /// A successful claim transfers its reservation to the worker. A kick
    /// wakes nobody while any count is held.
    searching: AtomicUsize,
}

/// State shared by a pool's workers, the wakers of its tasks, and its runner.
pub struct Pool {
    /// Every pool worker's mailbox and run queue, indexed by worker. All exist
    /// before any worker starts, so a push can wake any worker from the first
    /// spawn on.
    slots: Box<[Slot]>,
    /// The idle set and the search count. Padded, like the two fields after
    /// it, so parks, pushes, and takes do not contend for one cache line.
    wake: CachePadded<Wake>,
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
        let ring = || {
            if workers == 1 {
                Ring::exclusive()
            } else {
                Ring::shared()
            }
        };
        Self {
            slots: mailboxes
                .into_iter()
                .map(|mailbox| Slot {
                    mailbox,
                    ring: ring(),
                })
                .collect(),
            wake: CachePadded::new(Wake {
                idle: AtomicU64::new(0),
                searching: AtomicUsize::new(0),
            }),
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
        self.slots.len()
    }

    /// Mailbox of worker `index`. Panics if the index is outside the pool.
    pub fn mailbox(&self, index: u32) -> &Arc<Mailbox> {
        &self.slots[index as usize].mailbox
    }

    /// Shared end of worker `index`'s run queue, whose owner the worker takes
    /// when it starts. Panics if the index is outside the pool.
    pub fn ring(&self, index: u32) -> &Ring<Runnable> {
        &self.slots[index as usize].ring
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

        // Pairs with the fence of a parking worker: either the wake sees the
        // parking worker's bit, or that worker's last look sees the push.
        fence(Ordering::SeqCst);
        self.notify_global();
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
    /// between the workers, at most [`GLOBAL_BATCH`]. Returns the oldest and
    /// queues the rest in `ready`, no more than it has room for and no more
    /// than fill it to half, so a take into a run queue already half full
    /// returns only the oldest.
    ///
    /// The caller owns `ready` for a worker in this pool and must poll or
    /// discard the returned runnable. Returns `None` if the mirrored length
    /// is zero or another take has emptied the queue before it is locked.
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
        let share = (len / self.workers() + 1).min(GLOBAL_BATCH).min(len);

        // The caller polls the first runnable next, and the run queue takes the
        // rest. Filling at most its oldest half keeps every taken runnable out
        // of the half an overflow exports, and the room measured here only
        // grows before the pushes below.
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
    fn steal(&self, index: u32, start: usize, ready: &mut Ready) -> bool {
        let workers = self.workers();
        (0..workers)
            .map(|offset| (start + offset) % workers)
            .filter(|&victim| victim != index as usize)
            .any(|victim| self.slots[victim].ring.steal_into(ready.ring()) > 0)
    }

    /// Wake a parked worker for a run queue's new backlog, or for the search
    /// the last returned count hands on.
    #[inline]
    fn kick(&self) {
        // Pairs with the fence of a parking worker: either this wake sees its
        // publication, or its last look sees the backlog.
        fence(Ordering::SeqCst);
        self.notify();
    }

    /// Wake a parked worker for a run queue's backlog, unless a worker holding
    /// or reserving a search count will find it or hand the duty on. The caller
    /// has fenced after publishing work or returning the last search count.
    fn notify(&self) {
        loop {
            // A worker holding a count either finds the backlog or hands the
            // duty on when it returns the last count.
            if self.wake.searching.load(Ordering::SeqCst) != 0 {
                return;
            }
            let idle = self.wake.idle.load(Ordering::SeqCst);
            if idle == 0 {
                return;
            }

            // The count the claimed worker inherits. Failing to take it means
            // another worker began searching or another wake is claiming,
            // which then holds the duty.
            if self
                .wake
                .searching
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return;
            }
            if self.claim(idle) {
                return;
            }
            if !self.undo_claim() {
                return;
            }
        }
    }

    /// Wake a parked worker for a push into the global queue, even while
    /// another worker searches. Each push can wake one while idle bits remain.
    /// The claimed worker inherits a count, as with [`Self::notify`]. The
    /// caller has published the push and fenced.
    fn notify_global(&self) {
        loop {
            let idle = self.wake.idle.load(Ordering::SeqCst);
            if idle == 0 {
                return;
            }
            self.wake.searching.fetch_add(1, Ordering::SeqCst);
            if self.claim(idle) {
                return;
            }
            if !self.undo_claim() {
                return;
            }
        }
    }

    /// Return the count a wake took for a worker it found no bit to claim
    /// for. Returns whether the wake must look at the idle set again: the
    /// count may have suppressed a kick, which then relies on its last return,
    /// so the last one fences and looks for a worker that published since.
    fn undo_claim(&self) -> bool {
        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::AfterFailedClaim);
        if self.wake.searching.fetch_sub(1, Ordering::SeqCst) != 1 {
            return false;
        }
        fence(Ordering::SeqCst);
        true
    }

    /// Claim the lowest worker in the idle set, starting from `idle`, and wake
    /// it. The caller has reserved one search count. Success transfers it to
    /// the claimed worker, while failure leaves the caller obliged to return
    /// it through [`Self::undo_claim`].
    fn claim(&self, mut idle: u64) -> bool {
        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::BeforeClaim);

        // Clearing a worker's idle bit claims it, so a wake that loses the
        // exchange to another retries with the bits that remain, and each
        // publication is claimed at most once. The exchange can also fail
        // spuriously or because a worker published or withdrew its bit, and
        // the retry uses the set as it is now.
        // The reserved count precedes this exchange, so a withdrawing worker
        // that sees the cleared bit can return it before this wake is signalled.
        while idle != 0 {
            let index = idle.trailing_zeros();
            match self.wake.idle.compare_exchange_weak(
                idle,
                idle & !(1 << index),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    #[cfg(test)]
                    tests::at_wake_point(tests::WakePoint::AfterClaim);

                    // The worker's wake source latches a wake that arrives
                    // before it blocks, so the claimed worker wakes either
                    // way.
                    self.slots[index as usize].mailbox.waker.wake();
                    return true;
                }
                Err(actual) => idle = actual,
            }
        }
        false
    }

    /// Whether a run queue other than worker `index`'s holds an unclaimed
    /// backlog that a steal would take from. This is a snapshot: another
    /// worker can pop or claim the backlog before a subsequent steal.
    fn has_stealable(&self, index: u32) -> bool {
        self.slots
            .iter()
            .enumerate()
            .any(|(other, slot)| other != index as usize && slot.ring.is_stealable())
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
        for slot in self.slots.iter().skip(1) {
            let _ = slot.mailbox.send(Message::WakeRoot);
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

impl Drop for Pool {
    fn drop(&mut self) {
        // Check the wake word after all workers and wakes have released the
        // pool, without replacing an in-flight panic with an assertion failure.
        if thread::panicking() {
            return;
        }
        assert_eq!(
            self.wake.searching.load(Ordering::SeqCst),
            0,
            "search count left held"
        );
        assert_eq!(
            self.wake.idle.load(Ordering::SeqCst),
            0,
            "idle bit left published"
        );
    }
}

/// What a pool worker does after publishing itself idle and looking once
/// more, from [`Searcher::prepare_park`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Park {
    /// No work was observed or an existing count covers it, including a thief
    /// holding the slots this worker needs. Wait for a wake.
    Wait,
    /// The global queue's mirror was nonzero: run again and try to take work.
    Run,
    /// A stealable backlog was observed and this worker holds a count to search.
    Search,
}

/// A pool worker's part in searching and waking: whether its idle bit is
/// published, whether it holds a search count, and where its next search
/// starts.
///
/// Each worker has exactly one searcher, used only with that worker's run queue.
/// It searches only while unpublished and with no runnable of its own. A wait
/// must end through [`Self::finish_park`] before user code runs, and a held
/// count must be returned through [`Self::leave_search`] before user code or
/// another drive turn without parking.
///
/// Dropping it withdraws a live publication, then returns a held count, so
/// every exit of the drive loop, unwinding included, leaves the wake word as
/// if the worker had run on.
pub struct Searcher<'a> {
    /// The worker's pool.
    pool: &'a Pool,
    /// The worker's index in the pool.
    index: u32,
    /// Whether the worker's idle bit is set, or was set until a wake claimed
    /// it, since the worker last withdrew it.
    published: bool,
    /// Whether the worker holds a search count.
    searching: bool,
    /// State of the xorshift generator that picks where each search starts.
    rng: u32,
}

impl<'a> Searcher<'a> {
    /// The part of worker `index` of `pool`, published nowhere and holding no
    /// count. Panics if `index` is outside the pool. The caller must not create
    /// a second live searcher for the same worker.
    pub fn new(pool: &'a Pool, index: u32) -> Self {
        assert!((index as usize) < pool.workers());
        Self {
            pool,
            index,
            published: false,
            searching: false,
            // Zero is the generator's fixed point.
            rng: index + 1,
        }
    }

    /// Scan the other workers' run queues once and steal half of the first
    /// backlog found into `ready`, returning whether it took any. A worker
    /// holding no count first takes one, unless the search count is already
    /// at least half the worker count. A count taken or inherited stays held
    /// whether or not the steal succeeds, until the worker leaves searching or
    /// parks. The worker must be unpublished, and `ready` must be its own empty
    /// run queue. A one-worker pool returns `false` without taking a count.
    #[must_use]
    pub fn search(&mut self, ready: &mut Ready) -> bool {
        let pool = self.pool;
        if pool.workers() == 1 || (!self.searching && !self.begin()) {
            return false;
        }

        // Each search starts at a random worker, so searchers spread over the
        // victims rather than all draining the lowest.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 17;
        self.rng ^= self.rng << 5;
        let start = self.rng as usize % pool.workers();
        pool.steal(self.index, start, ready)
    }

    /// Take a search count unless the total is already at least half the
    /// worker count. Returns whether the search may run. The worker is
    /// unpublished and holds no count.
    fn begin(&mut self) -> bool {
        // The cap only limits contention, so it is a soft check: workers that
        // load the count at once can all pass it, and claimed workers inherit
        // counts without it, which is harmless.
        let searching = self.pool.wake.searching.load(Ordering::SeqCst);
        if 2 * searching >= self.pool.workers() {
            return false;
        }
        self.pool.wake.searching.fetch_add(1, Ordering::SeqCst);
        self.searching = true;
        true
    }

    /// Return a held search count, as the worker must before it runs user
    /// code. The last count returned hands the duty on. A live publication
    /// must first end through [`Self::finish_park`].
    #[inline]
    pub fn leave_search(&mut self) {
        if self.searching {
            self.end_search();
        }
    }

    /// Return the held search count, panicking if still published. The caller
    /// holds exactly one count. A worker returning the last count was the
    /// one other workers relied on to find what they kicked, so it fences and
    /// wakes a parked worker to carry on the search.
    #[inline(never)]
    fn end_search(&mut self) {
        // A published worker returns its count in its park instead, whose last
        // look covers what it would hand on, and a wake here could claim the
        // worker itself.
        assert!(!self.published, "search count returned while published");
        self.searching = false;
        let pool = self.pool;
        if pool.wake.searching.fetch_sub(1, Ordering::SeqCst) == 1 {
            pool.kick();
        }
    }

    /// Publish the worker idle, return a held count, and look once more for
    /// work: in the global queue, then in the other run queues while its own
    /// has room to steal into. `ready` must belong to this worker. Panics if
    /// already published or if `ready` is not empty.
    ///
    /// [`Park::Wait`] leaves a live publication, which the caller ends through
    /// [`Self::finish_park`] after its wait, even if that wait does not block.
    /// The other results withdraw it. [`Park::Search`] holds exactly one count
    /// for the caller's search, while [`Park::Run`] may inherit a claim's count.
    #[must_use]
    pub fn prepare_park(&mut self, ready: &Ready) -> Park {
        assert!(!self.published, "worker published twice");
        assert!(ready.is_empty(), "worker parked with runnables queued");
        let pool = self.pool;
        pool.wake.idle.fetch_or(1 << self.index, Ordering::SeqCst);
        self.published = true;

        // The look below covers whatever this worker would hand on, so the
        // count is returned without a wake.
        if mem::take(&mut self.searching) {
            pool.wake.searching.fetch_sub(1, Ordering::SeqCst);
        }

        // Pairs with the fence of a push or kick: either its wake sees this
        // publication, or the look below sees its work.
        fence(Ordering::SeqCst);
        if pool.has_global() {
            self.withdraw();
            return Park::Run;
        }

        // A steal goes only into a run queue with half of it free, and this one
        // can have less while a thief holds a claim on it, whose count then
        // covers the backlog.
        if pool.workers() == 1 || ready.room() < HALF || !pool.has_stealable(self.index) {
            return Park::Wait;
        }

        // A worker holding a count searches, or hands the duty on when it
        // returns the last count, which is ordered after this publication, so
        // it finds the backlog or wakes a parked worker, this one included.
        // Otherwise this worker takes the count and searches.
        if pool.wake.searching.load(Ordering::SeqCst) != 0
            || pool
                .wake
                .searching
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Park::Wait;
        }

        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::BeforeParkSearch);

        // A push into the global queue may have claimed this worker meanwhile,
        // bringing a count of its own. That one is returned here, and is never
        // the last, since this worker holds the count it just took.
        if self.withdraw() {
            pool.wake.searching.fetch_sub(1, Ordering::SeqCst);
        }
        self.searching = true;
        Park::Search
    }

    /// Publish the worker idle and look once more, searching again whenever
    /// the look asks it to. Requires this worker's empty run queue and no live
    /// publication, as [`Self::prepare_park`] does.
    ///
    /// `true` leaves the worker unpublished with work observed or stolen, and
    /// possibly a held count. `false` leaves it published for the caller to
    /// wait and then call [`Self::finish_park`], even if the wait does not block.
    #[must_use]
    pub fn publish_and_look(&mut self, ready: &mut Ready) -> bool {
        // A search that finds nothing keeps its count, which the next
        // publication returns. Another worker can pop or claim the backlog
        // between the look and the steal, so a failed scan must publish and
        // look again. Concurrent progress can require more than one retry.
        loop {
            match self.prepare_park(ready) {
                Park::Wait => return false,
                Park::Run => return true,
                Park::Search => {
                    if self.search(ready) {
                        return true;
                    }
                }
            }
        }
    }

    /// Withdraw the worker's publication once its wait returns, before it runs
    /// any callback. A claim leaves the worker holding the count its wake took
    /// for it. Must also be called after a wait that did not block. Panics if
    /// there is no live publication.
    pub fn finish_park(&mut self) {
        self.withdraw();
    }

    /// Clear the worker's idle bit, ending its publication. Returns whether a
    /// wake had claimed it, and keeps the count that wake took for it. Panics
    /// without a live publication, or if a claim adds to an already held count.
    fn withdraw(&mut self) -> bool {
        assert!(self.published, "withdrew an idle bit never published");
        self.published = false;
        let bit = 1 << self.index;
        let claimed = self.pool.wake.idle.fetch_and(!bit, Ordering::SeqCst) & bit == 0;
        if claimed {
            assert!(!self.searching, "published while holding a count");
            self.searching = true;
        }
        claimed
    }
}

impl Drop for Searcher<'_> {
    fn drop(&mut self) {
        // Withdraw first, folding in a count a claim brought, so returning the
        // last count below can neither be skipped nor claim this worker.
        if self.published {
            self.withdraw();
        }
        self.leave_search();
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

/// Pool fixtures, wake hooks, and tests of queueing, parking, and shutdown.
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::iouring::{
        task::{
            Task,
            tests::{queue, refs, task_of},
        },
        tasks::Tasks,
    };
    use std::{
        cell::RefCell,
        future::pending,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
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

        /// Whether worker `index` is published in the idle set.
        pub fn is_idle(&self, index: u32) -> bool {
            self.wake.idle.load(Ordering::SeqCst) & (1 << index) != 0
        }

        /// Search counts held.
        pub fn search_count(&self) -> usize {
            self.wake.searching.load(Ordering::SeqCst)
        }

        /// Whether the global queue has closed.
        pub fn is_closed(&self) -> bool {
            !self.global().open
        }
    }

    impl<'a> Searcher<'a> {
        /// The worker's pool.
        pub const fn pool(&self) -> &'a Pool {
            self.pool
        }

        /// The worker's index in the pool.
        pub const fn index(&self) -> u32 {
            self.index
        }
    }

    /// A point in a wake or a park where a test runs a hook on the calling
    /// thread.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WakePoint {
        /// In a wake that took a count, before it claims a bit.
        BeforeClaim,
        /// In a wake that claimed a bit, before it signals the claimed worker.
        AfterClaim,
        /// In a wake that found no bit to claim, before it returns its count.
        AfterFailedClaim,
        /// In a park that took a count to search, before it withdraws its bit.
        BeforeParkSearch,
    }

    /// A hook this thread runs once when it reaches its point.
    type WakeHook = (WakePoint, Box<dyn FnOnce()>);

    thread_local! {
        /// Hooks each run once by this thread at one point.
        static WAKE_HOOKS: RefCell<Vec<WakeHook>> = const { RefCell::new(Vec::new()) };
    }

    /// Run `hook` the next time this thread reaches `point`.
    pub fn on_wake_point(point: WakePoint, hook: impl FnOnce() + 'static) {
        WAKE_HOOKS.with(|hooks| hooks.borrow_mut().push((point, Box::new(hook))));
    }

    /// Run the hook this thread installed for `point`, if any.
    pub fn at_wake_point(point: WakePoint) {
        let hook = WAKE_HOOKS.with(|hooks| {
            let mut hooks = hooks.borrow_mut();
            hooks
                .iter()
                .position(|hook| hook.0 == point)
                .map(|at| hooks.remove(at).1)
        });
        if let Some(hook) = hook {
            hook();
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

    /// The owner's end of worker `index`'s run queue.
    fn ready(pool: &Pool, index: u32) -> Ready {
        Ready::new(pool.ring(index).owner())
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

    /// Queue new tasks' first runnables in `ready` through the pool, kicking
    /// as a worker's wakes do, and return the tasks.
    fn enqueue(pool: &Pool, ready: &mut Ready, set: &Tasks, count: usize) -> Vec<Task> {
        (0..count)
            .map(|_| {
                let (task, runnable) = task(set);
                pool.enqueue(ready, runnable);
                task
            })
            .collect()
    }

    /// Whether worker `index`'s wake source was signalled.
    fn signalled(pool: &Pool, index: u32) -> bool {
        pool.mailbox(index).waker.signalled()
    }

    /// Consume worker one's latched signal through a futex wait, an arm, or a spin.
    fn consume_signal(pool: &Pool, mode: usize) {
        let waker = &pool.mailbox(1).waker;
        assert!(waker.signalled());
        match mode {
            0 => assert!(waker.park_idle(0, None).is_none()),
            1 => assert!(!waker.arm(0).still_idle()),
            _ => waker.consume_signal(),
        }
        assert!(!waker.signalled());
    }

    /// Discard every runnable in the global queue and in `readies`, then
    /// clear `tasks`.
    fn release(pool: &Pool, readies: &mut [&mut Ready], tasks: Vec<Task>) {
        while let Some(runnable) = pool.pop() {
            runnable.discard();
        }
        for ready in readies {
            ready.discard();
        }
        for task in tasks {
            task.clear();
        }
    }

    /// A worker's part and the owner's end of its run queue, shared with hooks.
    type Part = Rc<RefCell<(Searcher<'static>, Ready)>>;

    /// A pool that lives as long as the test thread, for hooks that act on
    /// its workers, with every worker's part and run queue owner.
    fn leaked(workers: usize) -> (&'static Pool, Vec<Part>) {
        let pool: &'static Pool = Box::leak(Box::new(pool(workers)));
        let parts = (0..workers as u32)
            .map(|index| {
                Rc::new(RefCell::new((
                    Searcher::new(pool, index),
                    ready(pool, index),
                )))
            })
            .collect();
        (pool, parts)
    }

    /// A take preserves FIFO order and bounds its share, including the returned runnable.
    #[test]
    fn test_take_moves_a_bounded_share_of_the_global_queue() {
        for (workers, queued, taken) in [(4, 8, 3), (1, 129, 128)] {
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
    fn test_take_fills_the_ring_at_most_to_half() {
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
                GLOBAL_BATCH.min(HALF.saturating_sub(held) + 1),
                "ring held {held}"
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
        let claim = pool.ring(0).hold_claim(HALF as u32);
        while let Some(runnable) = ready.pop() {
            runnable.discard();
        }
        assert_eq!(ready.room(), 0);
        tasks.extend((0..200).map(|_| push(&pool, &set)));

        pool.take(&mut ready).unwrap().discard();
        assert!(ready.is_empty());

        // Released, the claim's slots are free again, and a take queues the
        // rest of an even split of the 199 left.
        for runnable in pool.ring(0).finish_claim(claim) {
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
    fn test_full_ring_moves_its_newest_half_to_the_global_queue() {
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
    fn test_full_ring_under_a_claim_moves_only_the_new_runnable() {
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
            let claim = pool.ring(0).hold_claim(HALF as u32);
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

            for runnable in pool.ring(0).finish_claim(claim) {
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
    fn test_search_steals_half_of_another_ring() {
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
    fn test_only_a_one_worker_pool_has_an_exclusive_ring() {
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
            let thief = Ring::shared();
            let mut into = Ready::new(thief.owner());
            let stolen = catch_unwind(AssertUnwindSafe(|| pool.ring(0).steal_into(into.ring())));
            assert_eq!(stolen.is_err(), exclusive);
            ready.discard();
            into.discard();
            for task in tasks {
                task.clear();
            }
        }
    }

    /// A push into the global queue claims the lowest published worker, which
    /// inherits a search count, and a second push claims the next even while
    /// that count is held. A kick claims nobody while a count is held, and the
    /// last count returned hands the duty on to the worker left parked.
    #[test]
    fn test_global_pushes_each_wake_a_worker_lowest_first() {
        let pool = pool(4);
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let mut parked: Vec<Searcher<'_>> =
            (1..4).map(|index| Searcher::new(&pool, index)).collect();
        for (searcher, ready) in parked.iter_mut().zip(&readies[1..]) {
            assert_eq!(searcher.prepare_park(ready), Park::Wait);
        }

        let mut tasks = vec![push(&pool, &set)];
        assert!(!pool.is_idle(1) && pool.is_idle(2));
        assert!(signalled(&pool, 1) && !signalled(&pool, 2));
        assert_eq!(pool.search_count(), 1);
        tasks.push(push(&pool, &set));
        assert!(!pool.is_idle(2) && signalled(&pool, 2));
        assert_eq!(pool.search_count(), 2);

        // A kick leaves its backlog to the workers holding counts.
        tasks.extend(enqueue(&pool, &mut readies[0], &set, STEALABLE));
        assert!(pool.is_idle(3) && !signalled(&pool, 3));

        // Each claimed worker resumes with its count. The first return is not
        // the last, and the last wakes worker three.
        parked[0].finish_park();
        parked[1].finish_park();
        assert!(parked[0].searching && parked[1].searching);
        parked[0].leave_search();
        assert!(pool.is_idle(3));
        parked[1].leave_search();
        assert!(!pool.is_idle(3) && signalled(&pool, 3));
        parked[2].finish_park();
        parked[2].leave_search();
        assert_eq!(pool.search_count(), 0);

        // With no worker published, and one that withdrew, a push wakes
        // nobody.
        while let Some(runnable) = pool.pop() {
            runnable.discard();
        }
        let mut zero = Searcher::new(&pool, 0);
        readies[0].discard();
        assert_eq!(zero.prepare_park(&readies[0]), Park::Wait);
        zero.finish_park();
        tasks.push(push(&pool, &set));
        assert!(!signalled(&pool, 0));
        assert_eq!(pool.search_count(), 0);
        drop((parked, zero));
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A push that leaves its run queue holding a stealable backlog wakes a
    /// parked worker, and a smaller one does not.
    #[test]
    fn test_kick_needs_a_stealable_backlog() {
        let pool = pool(2);
        let set = Tasks::new(1);
        let (mut zero, mut one) = (ready(&pool, 0), ready(&pool, 1));
        let mut parked = Searcher::new(&pool, 1);
        assert_eq!(parked.prepare_park(&one), Park::Wait);

        let mut tasks = enqueue(&pool, &mut zero, &set, STEALABLE - 1);
        assert!(pool.is_idle(1) && !signalled(&pool, 1));
        tasks.extend(enqueue(&pool, &mut zero, &set, 1));
        assert!(!pool.is_idle(1) && signalled(&pool, 1));

        // The woken worker holds the count its wake took and steals.
        parked.finish_park();
        assert!(parked.searching);
        assert!(parked.search(&mut one));
        parked.leave_search();
        assert_eq!(pool.search_count(), 0);
        drop(parked);
        release(&pool, &mut [&mut zero, &mut one], tasks);
    }

    /// Searches started one after another stop taking counts once half the
    /// workers hold one, and a search that finds nothing keeps its count.
    #[test]
    fn test_searches_started_in_turn_stop_at_half_the_workers() {
        let pool = pool(4);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let mut searchers: Vec<Searcher<'_>> =
            (0..4).map(|index| Searcher::new(&pool, index)).collect();
        let mut held = Vec::new();
        for (searcher, ready) in searchers.iter_mut().zip(&mut readies) {
            assert!(!searcher.search(ready));
            held.push(searcher.searching);
        }
        assert_eq!(held, [true, true, false, false]);
        assert_eq!(pool.search_count(), 2);
        for searcher in &mut searchers {
            searcher.leave_search();
        }
        assert_eq!(pool.search_count(), 0);
    }

    /// A worker the search cap refuses, which then sees a stealable backlog as
    /// it parks, leaves the backlog to the workers holding counts and waits,
    /// rather than going round its loop until they finish. The last of them to
    /// return its count wakes it.
    #[test]
    fn test_cap_refused_parker_waits_for_the_searchers() {
        let pool = pool(4);
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let mut searchers: Vec<Searcher<'_>> =
            (0..3).map(|index| Searcher::new(&pool, index)).collect();
        for (searcher, ready) in searchers.iter_mut().zip(&mut readies) {
            assert!(!searcher.search(ready));
        }
        assert!(searchers[0].searching && searchers[1].searching && !searchers[2].searching);

        // Worker three's kick finds counts held.
        let tasks = enqueue(&pool, &mut readies[3], &set, STEALABLE);
        assert_eq!(searchers[2].prepare_park(&readies[2]), Park::Wait);
        assert!(pool.is_idle(2) && !signalled(&pool, 2));

        searchers[0].leave_search();
        assert!(pool.is_idle(2));
        searchers[1].leave_search();
        assert!(!pool.is_idle(2) && signalled(&pool, 2));
        searchers[2].finish_park();
        assert!(searchers[2].search(&mut readies[2]));
        searchers[2].leave_search();
        assert_eq!(pool.search_count(), 0);
        drop(searchers);
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A parking worker that sees a stealable backlog leaves it to a worker
    /// holding a search count, whose return wakes it, or searches itself when
    /// no worker holds one.
    #[test]
    fn test_parker_seeing_a_backlog_delegates_or_searches() {
        for held in [true, false] {
            let pool = pool(3);
            let set = Tasks::new(1);
            let (mut zero, mut one, mut two) = (ready(&pool, 0), ready(&pool, 1), ready(&pool, 2));
            let mut searcher = Searcher::new(&pool, 0);
            let mut parker = Searcher::new(&pool, 1);
            if held {
                assert!(!searcher.search(&mut zero));
            }

            // A backlog queued without a kick, as a take leaves it.
            let mut tasks = Vec::new();
            for _ in 0..STEALABLE {
                let (task, runnable) = task(&set);
                queue(&mut two, runnable);
                tasks.push(task);
            }

            let park = parker.prepare_park(&one);
            if held {
                assert_eq!(park, Park::Wait);
                assert!(pool.is_idle(1));
                searcher.leave_search();
                assert!(!pool.is_idle(1) && signalled(&pool, 1));
                parker.finish_park();
            } else {
                assert_eq!(park, Park::Search);
                assert!(!pool.is_idle(1));
            }
            assert!(parker.searching);
            assert!(parker.search(&mut one));
            parker.leave_search();
            assert_eq!(pool.search_count(), 0);
            drop((searcher, parker));
            release(&pool, &mut [&mut zero, &mut one, &mut two], tasks);
        }
    }

    /// An empty destination pinned by a claim returns `Wait` with a live
    /// publication, then searches after the thief frees the slots and hands on
    /// its last search count.
    #[test]
    fn test_parker_without_room_waits_for_the_claiming_thief() {
        let pool = pool(3);
        let set = Tasks::new(1);
        let (mut zero, mut one, mut two) = (ready(&pool, 0), ready(&pool, 1), ready(&pool, 2));
        let mut parker = Searcher::new(&pool, 0);
        let mut thief = Searcher::new(&pool, 1);
        let mut tasks = Vec::new();
        for _ in 0..CAPACITY {
            let (task, runnable) = task(&set);
            queue(&mut zero, runnable);
            tasks.push(task);
        }
        assert!(thief.begin());
        let claim = pool.ring(0).hold_claim(HALF as u32);
        while let Some(runnable) = zero.pop() {
            runnable.discard();
        }
        tasks.extend(enqueue(&pool, &mut two, &set, STEALABLE));
        assert_eq!(zero.room(), 0);
        assert_eq!(parker.prepare_park(&zero), Park::Wait);
        assert!(pool.is_idle(0) && !signalled(&pool, 0));
        assert_eq!(pool.search_count(), 1);

        for runnable in pool.ring(0).finish_claim(claim) {
            runnable.discard();
        }
        thief.leave_search();
        assert!(!pool.is_idle(0) && signalled(&pool, 0));
        parker.finish_park();
        assert!(parker.search(&mut zero));
        parker.leave_search();
        assert_eq!(pool.search_count(), 0);
        release(&pool, &mut [&mut zero, &mut one, &mut two], tasks);
    }

    /// Dropping a worker's part withdraws a live publication and returns a
    /// held count, including the count a claim brought, and a worker that
    /// never published neither withdraws nor returns anything.
    #[test]
    fn test_dropping_a_searcher_restores_the_wake_word() {
        let pool = pool(2);
        let set = Tasks::new(1);
        let (mut zero, one) = (ready(&pool, 0), ready(&pool, 1));

        // Never published, holding nothing.
        drop(Searcher::new(&pool, 1));
        assert_eq!(pool.search_count(), 0);

        // Published, unclaimed.
        let mut parker = Searcher::new(&pool, 1);
        assert_eq!(parker.prepare_park(&one), Park::Wait);
        drop(parker);
        assert!(!pool.is_idle(1));

        // Published, then claimed by a push.
        let mut parker = Searcher::new(&pool, 1);
        assert_eq!(parker.prepare_park(&one), Park::Wait);
        let task = push(&pool, &set);
        assert!(!pool.is_idle(1));
        assert_eq!(pool.search_count(), 1);
        drop(parker);
        assert_eq!(pool.search_count(), 0);

        // Holding the count of a search that found nothing.
        let mut searcher = Searcher::new(&pool, 0);
        assert!(!searcher.search(&mut zero));
        assert_eq!(pool.search_count(), 1);
        drop(searcher);
        assert_eq!(pool.search_count(), 0);
        drop((zero, one));
        release(&pool, &mut [], vec![task]);
    }

    /// A kick's wake whose candidate resumes on its own before the claim
    /// returns its count, and as the last count looks again, claiming a
    /// worker that published meanwhile and left the backlog to that count.
    #[test]
    fn test_kick_whose_claim_fails_looks_again() {
        let (pool, parts) = leaked(3);
        let set = Tasks::new(1);
        {
            let (candidate, ready) = &mut *parts[1].borrow_mut();
            assert_eq!(candidate.prepare_park(ready), Park::Wait);
        }
        on_wake_point(WakePoint::BeforeClaim, {
            let part = parts[1].clone();
            move || part.borrow_mut().0.finish_park()
        });
        on_wake_point(WakePoint::AfterFailedClaim, {
            let part = parts[2].clone();
            move || {
                let (later, ready) = &mut *part.borrow_mut();
                assert_eq!(later.prepare_park(ready), Park::Wait);
            }
        });

        let tasks = enqueue(pool, &mut parts[0].borrow_mut().1, &set, STEALABLE);
        assert!(!pool.is_idle(2) && signalled(pool, 2));
        let (later, ready) = &mut *parts[2].borrow_mut();
        later.finish_park();
        assert!(later.search(ready));
        later.leave_search();
        assert_eq!(pool.search_count(), 0);
        assert!((0..3).all(|index| !pool.is_idle(index)));
        release(pool, &mut [&mut parts[0].borrow_mut().1, ready], tasks);
    }

    /// A push into the global queue whose candidate resumes on its own before
    /// the claim returns its count, and as the last count looks again,
    /// claiming a worker that published meanwhile and left a kicked backlog to
    /// that count once another worker took the push.
    #[test]
    fn test_global_push_whose_claim_fails_looks_again() {
        let (pool, parts) = leaked(4);
        let set = Rc::new(Tasks::new(1));
        let kicked = Rc::new(RefCell::new(Vec::new()));
        {
            let (candidate, ready) = &mut *parts[1].borrow_mut();
            assert_eq!(candidate.prepare_park(ready), Park::Wait);
        }
        on_wake_point(WakePoint::BeforeClaim, {
            let part = parts[1].clone();
            move || part.borrow_mut().0.finish_park()
        });
        on_wake_point(WakePoint::AfterFailedClaim, {
            let owner = parts[0].clone();
            let later = parts[2].clone();
            let set = set.clone();
            let kicked = kicked.clone();
            move || {
                // Another worker takes the push, a kick finds the count held,
                // and then a worker parks.
                pool.pop().unwrap().discard();
                kicked.borrow_mut().extend(enqueue(
                    pool,
                    &mut owner.borrow_mut().1,
                    &set,
                    STEALABLE,
                ));
                let (later, ready) = &mut *later.borrow_mut();
                assert_eq!(later.prepare_park(ready), Park::Wait);
            }
        });

        let pushed = push(pool, &set);
        assert!(!pool.is_idle(2) && signalled(pool, 2));
        let (later, ready) = &mut *parts[2].borrow_mut();
        later.finish_park();
        assert!(later.search(ready));
        later.leave_search();
        assert_eq!(pool.search_count(), 0);
        assert!((0..4).all(|index| !pool.is_idle(index)));
        let mut tasks = kicked.take();
        tasks.push(pushed);
        release(pool, &mut [&mut parts[0].borrow_mut().1, ready], tasks);
    }

    /// A push into the global queue that claims a parking worker after it took
    /// a count to search brings a second count, which the worker returns,
    /// keeping one.
    #[test]
    fn test_global_claim_of_a_worker_about_to_search_leaves_one_count() {
        let (pool, parts) = leaked(2);
        let set = Tasks::new(1);
        let mut tasks = Vec::new();
        for _ in 0..STEALABLE {
            let (task, runnable) = task(&set);
            queue(&mut parts[1].borrow_mut().1, runnable);
            tasks.push(task);
        }
        let (pushed, runnable) = task(&set);
        on_wake_point(WakePoint::BeforeParkSearch, move || {
            assert!(pool.push(runnable).is_ok());
        });

        let (searcher, ready) = &mut *parts[0].borrow_mut();
        assert_eq!(searcher.prepare_park(ready), Park::Search);
        assert!(signalled(pool, 0));
        assert_eq!(pool.search_count(), 1);
        assert!(searcher.search(ready));
        searcher.leave_search();
        assert_eq!(pool.search_count(), 0);
        assert!((0..2).all(|index| !pool.is_idle(index)));
        tasks.push(pushed);
        release(pool, &mut [ready, &mut parts[1].borrow_mut().1], tasks);
    }

    /// A worker a push claimed can resume on an independent wake before the
    /// push signals it. It then withdraws with the count the claim brought,
    /// returns it, and publishes again, and the late signal ends its next wait
    /// with no claim and no count, while a later claim brings one as usual.
    /// Each way a worker consumes a signal is checked: its futex wait, an arm
    /// that the signal turns back, and its spin.
    #[test]
    fn test_late_signal_of_a_claim_brings_no_count() {
        for mode in 0..3 {
            let (pool, parts) = leaked(2);
            {
                let (parker, ready) = &mut *parts[1].borrow_mut();
                assert_eq!(parker.prepare_park(ready), Park::Wait);
            }
            on_wake_point(WakePoint::AfterClaim, {
                let part = parts[1].clone();
                move || {
                    assert_eq!(pool.search_count(), 1);
                    assert!(!pool.is_idle(1));

                    // An independent wake resumes the claimed worker, which
                    // runs its loop and parks again.
                    pool.mailbox(1).waker.wake();
                    consume_signal(pool, mode);
                    let (parker, ready) = &mut *part.borrow_mut();
                    parker.finish_park();
                    assert!(parker.searching);
                    parker.leave_search();
                    assert_eq!(pool.search_count(), 0);
                    assert_eq!(parker.prepare_park(ready), Park::Wait);
                }
            });
            pool.notify_global();

            // The push's signal reaches the new publication, which no wake
            // claimed.
            assert!(pool.is_idle(1));
            consume_signal(pool, mode);
            {
                let (parker, ready) = &mut *parts[1].borrow_mut();
                parker.finish_park();
                assert!(!parker.searching);
                assert_eq!(pool.search_count(), 0);
                assert_eq!(parker.prepare_park(ready), Park::Wait);
            }

            // A fresh claim brings one count.
            pool.notify_global();
            consume_signal(pool, mode);
            let (parker, _) = &mut *parts[1].borrow_mut();
            parker.finish_park();
            assert!(parker.searching);
            parker.leave_search();
            assert_eq!(pool.search_count(), 0);
            assert!((0..2).all(|index| !pool.is_idle(index)));
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
