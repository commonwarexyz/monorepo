//! The pool's idle state: which pool workers are parked, which search the
//! other run queues, and how a push wakes a parked worker.
//!
//! [`Idle`] holds that state for a [`Pool`]. Each pool worker searches and
//! parks through its [`Searcher`], whose [`Searcher::prepare_park`] returns a
//! [`Park`] that says what the worker does after its last look. A push into
//! the global queue and a kick from a run queue fence in [`Pool`], then wake a
//! parked worker through [`Idle::notify_global`] and [`Idle::notify`].
//!
//! # Waking a parked worker
//!
//! [`Idle`] holds the idle set and the search count on one cache line,
//! since every wake uses both. The idle set is one `u64` with a bit per
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
//! it back to work. A held count makes it wait without reading the other run
//! queues, since that count's last return will find a backlog or wake a parked
//! worker, this one included. Otherwise a stealable backlog in another run
//! queue sends it to search. It waits as well when a thief's claim holds room
//! its own run queue needs, since that thief holds a count. Every exit of the
//! drive loop, unwinding included, withdraws a live publication and returns a
//! held count before the worker destroys its root.
//!
//! ```text
//! push or kick                           parking worker i
//!   publish work (or hand on a search)     set bit i, return a held count
//!   fence(SeqCst)                          fence(SeqCst)
//!   kick: a count is held, return          global nonempty: withdraw, run
//!   no idle bit: return                    no room, or a count held: wait
//!   reserve a count                        stealable backlog: take the count
//!     kick: only if still zero               if zero, withdraw, search
//!   claim lowest bit                       otherwise: wait
//!     success: signal its worker           wait: spin, or arm and attempt a wait,
//!     failure: return the reserved count     then withdraw, keeping a claim's count
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
//! The fences carry most of the argument. When two sides each store, pass a
//! sequentially consistent fence, and then load what the other side stores,
//! the loads cannot both read values older than those stores in modification
//! order. A load can instead see a later update, such as a claim or withdrawal
//! clearing the idle bit. The accesses to the idle state are mostly relaxed:
//! read-modify-write operations read their immediate predecessor in
//! modification order, and a stale load is covered by a fence pair. Two
//! handshakes need more. The claim's exchange releases the count it reserved
//! to the claimed worker, whose withdrawal acquires it, so the worker returns
//! that count after the reservation. A worker leaving a successful search
//! releases its count to publish the victim's claim release and its own run
//! queue's tail, since no fence separates those updates from the return.
//! Every count modification is a read-modify-write, preserving earlier
//! returns' release sequences. The last return reads those sequences, so its
//! following fence acquires the queue updates. Its look, and a worker it
//! claims, cannot then observe queue states older than those updates.
//!
//! [`MAX_WORKERS`]: super::pool::MAX_WORKERS
//!
//! # Search cap
//!
//! A worker with nothing to run searches the other run queues before it
//! parks, as [`super::pool`] describes. A worker holding no search count
//! starts a search only while the count is less than half the worker count.
//! Otherwise it parks, since a count holder finds work or hands the duty on.
//! The check is soft: workers that check at once can all pass it, and wakes
//! reserve counts without this cap, so the search count can exceed half the
//! worker count.

use super::{
    mailbox::Mailbox,
    pool::{HALF, Pool},
    task::Ready,
};
use std::{mem, sync::Arc, thread};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
    } else {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};
    }
}

/// The idle set and search count of a pool, kept on one cache line.
pub struct Idle {
    /// Bit `i` is set while worker `i` is published as parked or about to
    /// park and no wake has claimed it. A wake clears the bit to claim the
    /// worker before waking it, and the worker clears it when it runs again.
    set: AtomicU64,
    /// Search counts held by workers or reserved by wakes attempting a claim.
    /// A successful claim transfers its reservation to the worker. A kick
    /// wakes nobody while any count is held.
    searching: AtomicUsize,
}

impl Idle {
    /// The idle state of a pool with no worker published and no count held.
    // Loom's atomics have no const constructor.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new() -> Self {
        Self {
            set: AtomicU64::new(0),
            searching: AtomicUsize::new(0),
        }
    }

    /// Wake a parked worker for a run queue's backlog, unless a worker holding
    /// or reserving a search count will find it or hand the duty on. The caller
    /// has fenced after publishing work or returning the last search count.
    /// `mailboxes` are the pool's, in worker order.
    pub fn notify(&self, mailboxes: &[Arc<Mailbox>]) {
        loop {
            // A worker holding a count either finds the backlog or hands the
            // duty on when it returns the last count. The caller's fence
            // orders these loads after the work it published. A stale count
            // is covered by the fence after that count's last return, and a
            // stale idle set by the fence of the worker that published since,
            // so the loads themselves are relaxed.
            if self.searching.load(Ordering::Relaxed) != 0 {
                return;
            }
            let idle = self.set.load(Ordering::Relaxed);
            if idle == 0 {
                return;
            }

            // The count the claimed worker inherits. Failing to take it means
            // another worker began searching or another wake is claiming,
            // which then holds the duty. The reservation reaches the claimed
            // worker through the claim's release, and a failure delegates as
            // the load above does, so both orderings are relaxed.
            if self
                .searching
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                return;
            }
            if self.claim(idle, mailboxes) {
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
    /// caller has published the push and fenced. `mailboxes` are the pool's,
    /// in worker order.
    pub fn notify_global(&self, mailboxes: &[Arc<Mailbox>]) {
        loop {
            // Relaxed for the same reasons as in `notify`: the caller's
            // fence orders the load, and the reservation reaches the claimed
            // worker through the claim's release.
            let idle = self.set.load(Ordering::Relaxed);
            if idle == 0 {
                return;
            }
            self.searching.fetch_add(1, Ordering::Relaxed);
            if self.claim(idle, mailboxes) {
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
        if self.searching.fetch_sub(1, Ordering::Relaxed) != 1 {
            return false;
        }

        // Pairs with the fence in `Searcher::prepare_park`, as a kick's does:
        // a kick that saw this count returned without looking, so either the
        // loads after this fence see a bit published since, or that worker's
        // last look saw the kicked backlog. The return above is relaxed
        // because this fence, not the return, orders the loads that follow.
        // No queue updates follow the caller's fence. Its release half already
        // publishes earlier updates through the reservation RMW, which later
        // count RMWs preserve for the last return's fence to acquire.
        fence(Ordering::SeqCst);
        true
    }

    /// Claim the lowest worker in the idle set, starting from `idle`, and wake
    /// it through its mailbox in `mailboxes`, the pool's in worker order. The
    /// caller has reserved one search count. Success transfers it to the
    /// claimed worker, while failure leaves the caller obliged to return it
    /// through [`Self::undo_claim`].
    fn claim(&self, mut idle: u64, mailboxes: &[Arc<Mailbox>]) -> bool {
        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::BeforeClaim);

        // Clearing a worker's idle bit claims it, so a wake that loses the
        // exchange to another retries with the bits that remain, and each
        // publication is claimed at most once. The exchange can also fail
        // spuriously or because a worker published or withdrew its bit, and
        // the retry uses the set as it is now.
        // The exchange releases the reserved count to the claimed worker,
        // whose withdrawal acquires it, so the worker's later return of that
        // count follows the reservation in the count's modification order,
        // even when its wait returns before this wake signals it. A failed
        // exchange only yields the set to retry with, so it is relaxed.
        while idle != 0 {
            let index = idle.trailing_zeros();
            match self.set.compare_exchange_weak(
                idle,
                idle & !(1 << index),
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    #[cfg(test)]
                    tests::at_wake_point(tests::WakePoint::AfterClaim);

                    // The worker's wake source latches a wake that arrives
                    // before it blocks, so the claimed worker wakes either
                    // way.
                    mailboxes[index as usize].waker.wake();
                    return true;
                }
                Err(actual) => idle = actual,
            }
        }
        false
    }
}

impl Drop for Idle {
    fn drop(&mut self) {
        // Check the idle state after all workers and wakes have released the
        // pool, without replacing an in-flight panic with an assertion failure.
        if thread::panicking() {
            return;
        }
        assert_eq!(
            self.searching.load(Ordering::Relaxed),
            0,
            "search count left held"
        );
        assert_eq!(
            self.set.load(Ordering::Relaxed),
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
/// every exit of the drive loop, unwinding included, leaves the idle state as
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
        // counts without it, which is harmless. Nothing is published with the
        // count: a kick that sees it relies on the fence after its return.
        let searching = self.pool.idle().searching.load(Ordering::Relaxed);
        if 2 * searching >= self.pool.workers() {
            return false;
        }
        self.pool.idle().searching.fetch_add(1, Ordering::Relaxed);
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
        // Release publishes a successful steal's claim release and destination
        // tail before this worker can enter user code. Every count modification
        // is an RMW, so a later last return reads this release sequence and its
        // following fence acquires both queue updates. That fence can be in
        // `Pool::kick`, `Idle::undo_claim`, or `prepare_park`. If this is the
        // last return, both updates already precede the kick's fence in this
        // thread.
        if pool.idle().searching.fetch_sub(1, Ordering::Release) == 1 {
            pool.kick();
        }
    }

    /// Publish the worker idle, return a held count, and look once more for
    /// work: in the global queue, then, while its own run queue has room to
    /// steal into and no search count is held, in the other run queues.
    /// `ready` must belong to this worker. Panics if already published or if
    /// `ready` is not empty.
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
        pool.idle().set.fetch_or(1 << self.index, Ordering::Relaxed);
        self.published = true;

        // The look below covers whatever this worker would hand on, so the
        // count is returned without a wake. The return is relaxed because it
        // has nothing to publish: a search that stole is left through
        // `leave_search` before its runnables are polled, and this run queue
        // is empty, so the count returned here was held through a search
        // that moved nothing.
        if mem::take(&mut self.searching) {
            pool.idle().searching.fetch_sub(1, Ordering::Relaxed);
        }

        // Pairs with the fences in `Pool::push_batch`, `Pool::kick`, and
        // `Idle::undo_claim`: either the loads after their fence see the bit
        // published above, or the look below sees their work, the global
        // queue's length, a run queue's tail, or the return of a count. The
        // publication above and the count load below are relaxed, since this
        // fence pair orders them. The queue loads acquire for the queues' own
        // sake: a length a take left shows the runnables it moved.
        fence(Ordering::SeqCst);
        if pool.has_global() {
            self.withdraw();
            return Park::Run;
        }

        // A steal goes only into a run queue with half of it free, and this one
        // can have less while a thief holds a claim on it, whose count then
        // covers the backlog.
        if pool.workers() == 1 || ready.room() < HALF {
            return Park::Wait;
        }

        // A worker holding a count searches, or hands the duty on when it
        // returns the last count. A fence follows that return, a kick's, a
        // failed wake's, or the returning worker's own park's, and pairs with
        // the fence above, so a backlog is found or a parked worker, this one
        // included, is woken. A held count therefore settles the look without
        // reading the other run queues. The load is relaxed: a nonzero value
        // delegates through that later fence.
        if pool.idle().searching.load(Ordering::Relaxed) != 0 {
            return Park::Wait;
        }

        // Otherwise this worker takes the count and searches, if another run
        // queue holds a backlog. A count taken here is this worker's own, which
        // carries nothing to another thread, so the exchange is relaxed, and
        // its failure means a count appeared since the load, which delegates
        // the same way.
        if !pool.has_stealable(self.index)
            || pool
                .idle()
                .searching
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return Park::Wait;
        }

        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::BeforeParkSearch);

        // A push into the global queue may have claimed this worker meanwhile,
        // bringing a count of its own. That one is returned here, and is never
        // the last, since this worker holds the count it just took and the
        // withdrawal acquired the claim's reservation.
        if self.withdraw() {
            pool.idle().searching.fetch_sub(1, Ordering::Relaxed);
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
        // Acquire pairs with the release of a claim's exchange: a count the
        // claim reserved is held, and later returned, after the reservation.
        let claimed = self.pool.idle().set.fetch_and(!bit, Ordering::Acquire) & bit == 0;
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

/// Wake hooks and tests of waking, searching, and parking.
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::iouring::{
        pool::tests::{pool, push, ready, task},
        queue::{CAPACITY, STEALABLE},
        task::{Task, tests::queue},
        tasks::Tasks,
    };
    use std::{cell::RefCell, rc::Rc};

    impl Idle {
        /// Whether worker `index` is published in the idle set.
        pub fn is_idle(&self, index: u32) -> bool {
            self.set.load(Ordering::Relaxed) & (1 << index) != 0
        }

        /// Search counts held.
        pub fn search_count(&self) -> usize {
            self.searching.load(Ordering::Relaxed)
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
        assert!(!pool.idle().is_idle(1) && pool.idle().is_idle(2));
        assert!(signalled(&pool, 1) && !signalled(&pool, 2));
        assert_eq!(pool.idle().search_count(), 1);
        tasks.push(push(&pool, &set));
        assert!(!pool.idle().is_idle(2) && signalled(&pool, 2));
        assert_eq!(pool.idle().search_count(), 2);

        // A kick leaves its backlog to the workers holding counts.
        tasks.extend(enqueue(&pool, &mut readies[0], &set, STEALABLE));
        assert!(pool.idle().is_idle(3) && !signalled(&pool, 3));

        // Each claimed worker resumes with its count. The first return is not
        // the last, and the last wakes worker three.
        parked[0].finish_park();
        parked[1].finish_park();
        assert!(parked[0].searching && parked[1].searching);
        parked[0].leave_search();
        assert!(pool.idle().is_idle(3));
        parked[1].leave_search();
        assert!(!pool.idle().is_idle(3) && signalled(&pool, 3));
        parked[2].finish_park();
        parked[2].leave_search();
        assert_eq!(pool.idle().search_count(), 0);

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
        assert_eq!(pool.idle().search_count(), 0);
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
        assert!(pool.idle().is_idle(1) && !signalled(&pool, 1));
        tasks.extend(enqueue(&pool, &mut zero, &set, 1));
        assert!(!pool.idle().is_idle(1) && signalled(&pool, 1));

        // The woken worker holds the count its wake took and steals.
        parked.finish_park();
        assert!(parked.searching);
        assert!(parked.search(&mut one));
        parked.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
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
        assert_eq!(pool.idle().search_count(), 2);
        for searcher in &mut searchers {
            searcher.leave_search();
        }
        assert_eq!(pool.idle().search_count(), 0);
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
        assert!(pool.idle().is_idle(2) && !signalled(&pool, 2));

        searchers[0].leave_search();
        assert!(pool.idle().is_idle(2));
        searchers[1].leave_search();
        assert!(!pool.idle().is_idle(2) && signalled(&pool, 2));
        searchers[2].finish_park();
        assert!(searchers[2].search(&mut readies[2]));
        searchers[2].leave_search();
        assert_eq!(pool.idle().search_count(), 0);
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
                assert!(pool.idle().is_idle(1));
                searcher.leave_search();
                assert!(!pool.idle().is_idle(1) && signalled(&pool, 1));
                parker.finish_park();
            } else {
                assert_eq!(park, Park::Search);
                assert!(!pool.idle().is_idle(1));
            }
            assert!(parker.searching);
            assert!(parker.search(&mut one));
            parker.leave_search();
            assert_eq!(pool.idle().search_count(), 0);
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
        let claim = pool.queue(0).hold_claim(HALF as u32);
        while let Some(runnable) = zero.pop() {
            runnable.discard();
        }
        tasks.extend(enqueue(&pool, &mut two, &set, STEALABLE));
        assert_eq!(zero.room(), 0);
        assert_eq!(parker.prepare_park(&zero), Park::Wait);
        assert!(pool.idle().is_idle(0) && !signalled(&pool, 0));
        assert_eq!(pool.idle().search_count(), 1);

        for runnable in pool.queue(0).finish_claim(claim) {
            runnable.discard();
        }
        thief.leave_search();
        assert!(!pool.idle().is_idle(0) && signalled(&pool, 0));
        parker.finish_park();
        assert!(parker.search(&mut zero));
        parker.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        release(&pool, &mut [&mut zero, &mut one, &mut two], tasks);
    }

    /// Dropping a worker's part withdraws a live publication and returns a
    /// held count, including the count a claim brought, and a worker that
    /// never published neither withdraws nor returns anything.
    #[test]
    fn test_dropping_a_searcher_restores_the_idle_state() {
        let pool = pool(2);
        let set = Tasks::new(1);
        let (mut zero, one) = (ready(&pool, 0), ready(&pool, 1));

        // Never published, holding nothing.
        drop(Searcher::new(&pool, 1));
        assert_eq!(pool.idle().search_count(), 0);

        // Published, unclaimed.
        let mut parker = Searcher::new(&pool, 1);
        assert_eq!(parker.prepare_park(&one), Park::Wait);
        drop(parker);
        assert!(!pool.idle().is_idle(1));

        // Published, then claimed by a push.
        let mut parker = Searcher::new(&pool, 1);
        assert_eq!(parker.prepare_park(&one), Park::Wait);
        let task = push(&pool, &set);
        assert!(!pool.idle().is_idle(1));
        assert_eq!(pool.idle().search_count(), 1);
        drop(parker);
        assert_eq!(pool.idle().search_count(), 0);

        // Holding the count of a search that found nothing.
        let mut searcher = Searcher::new(&pool, 0);
        assert!(!searcher.search(&mut zero));
        assert_eq!(pool.idle().search_count(), 1);
        drop(searcher);
        assert_eq!(pool.idle().search_count(), 0);
        drop((zero, one));
        release(&pool, &mut [], vec![task]);
    }

    /// A kick's wake that loses its candidate, which resumes on its own before
    /// the claim, returns its count and, holding the last, looks again and
    /// claims a worker that published meanwhile and left the backlog to that
    /// count.
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
        assert!(!pool.idle().is_idle(2) && signalled(pool, 2));
        let (later, ready) = &mut *parts[2].borrow_mut();
        later.finish_park();
        assert!(later.search(ready));
        later.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..3).all(|index| !pool.idle().is_idle(index)));
        release(pool, &mut [&mut parts[0].borrow_mut().1, ready], tasks);
    }

    /// The wake of a push into the global queue that loses its candidate,
    /// which resumes on its own before the claim, returns its count and,
    /// holding the last, looks again and claims a worker that published
    /// meanwhile and left a kicked backlog to that count once another worker
    /// took the push.
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
        assert!(!pool.idle().is_idle(2) && signalled(pool, 2));
        let (later, ready) = &mut *parts[2].borrow_mut();
        later.finish_park();
        assert!(later.search(ready));
        later.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..4).all(|index| !pool.idle().is_idle(index)));
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
        assert_eq!(pool.idle().search_count(), 1);
        assert!(searcher.search(ready));
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..2).all(|index| !pool.idle().is_idle(index)));
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
                    assert_eq!(pool.idle().search_count(), 1);
                    assert!(!pool.idle().is_idle(1));

                    // An independent wake resumes the claimed worker, which
                    // runs its loop and parks again.
                    pool.mailbox(1).waker.wake();
                    consume_signal(pool, mode);
                    let (parker, ready) = &mut *part.borrow_mut();
                    parker.finish_park();
                    assert!(parker.searching);
                    parker.leave_search();
                    assert_eq!(pool.idle().search_count(), 0);
                    assert_eq!(parker.prepare_park(ready), Park::Wait);
                }
            });
            pool.idle().notify_global(pool.mailboxes());

            // The push's signal reaches the new publication, which no wake
            // claimed.
            assert!(pool.idle().is_idle(1));
            consume_signal(pool, mode);
            {
                let (parker, ready) = &mut *parts[1].borrow_mut();
                parker.finish_park();
                assert!(!parker.searching);
                assert_eq!(pool.idle().search_count(), 0);
                assert_eq!(parker.prepare_park(ready), Park::Wait);
            }

            // A fresh claim brings one count.
            pool.idle().notify_global(pool.mailboxes());
            consume_signal(pool, mode);
            let (parker, _) = &mut *parts[1].borrow_mut();
            parker.finish_park();
            assert!(parker.searching);
            parker.leave_search();
            assert_eq!(pool.idle().search_count(), 0);
            assert!((0..2).all(|index| !pool.idle().is_idle(index)));
        }
    }
}
