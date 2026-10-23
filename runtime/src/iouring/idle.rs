//! The pool's idle state: idle publications, search counts, and which worker
//! to wake for pool work.
//!
//! [`Idle`] holds that state for a [`Pool`]. Each pool worker searches and
//! parks through its [`Searcher`]. [`Searcher::prepare_park`] returns a
//! [`Park`] that says what the worker does after its last look.
//!
//! # Idle state and waker
//!
//! [`Idle`] decides whether to wake a pool worker, and which one, on a kick
//! through [`Idle::notify`] and on a push into the global queue through
//! [`Idle::notify_global`]. A successful claim clears that worker's idle bit
//! and transfers a reserved search count, then calls [`Waker::wake`] on the
//! worker's mailbox waker.
//!
//! The [`Waker`] delivers the signal to the worker's armed wait target, or
//! latches it if none is armed. Mailbox messages and driver permit waits use
//! the same waker without going through [`Idle`].
//!
//! A pool worker publishes its idle bit, returns any held search count, and
//! fences before its last look for work. If it proceeds to wait, the
//! publication stays live until withdrawal, even if a claim clears the bit.
//!
//! With unfinished I/O requests, [`Driver::park`] arms the waker's eventfd
//! target before attempting the io_uring wait. Otherwise, [`Waker::park_idle`]
//! arms its futex target after any unsuccessful spin. Both paths recheck for a
//! latched signal or pending mailbox publication after arming, so an early wake
//! can prevent blocking. After spinning or waiting, even if it did not block,
//! the worker ends its publication through [`Searcher::finish_park`] before
//! user code and keeps the count a claim brought.
//!
//! [`Driver::park`]: super::driver::Driver::park
//! [`Waker`]: super::waker::Waker
//! [`Waker::park_idle`]: super::waker::Waker::park_idle
//! [`Waker::wake`]: super::waker::Waker::wake
//!
//! # Waking a parked worker
//!
//! [`Idle`] holds the idle set and the search count on one cache line for pool
//! wake selection. The idle set is one `u64` with a bit per worker, so a pool
//! has at most [`MAX_WORKERS`] workers. A worker's bit is set while it is
//! published as parked or about to park and no wake has claimed it. Claiming a
//! worker clears its bit, so each publication is claimed at most once.
//!
//! The search count is the number of workers and wakes responsible for finding
//! work or handing the search on. A worker keeps its count across a search
//! until it parks or leaves searching. A wake reserves a count before claiming
//! a bit. A successful claim transfers the count to the claimed worker, and a
//! wake whose claim fails returns it. So a count can belong to a wake still
//! attempting its claim, as well as to a worker. The idle-bit exchange
//! transfers the count, not the wake signal. A late signal from an earlier
//! claim cannot transfer another count.
//!
//! A push into the global queue fences and claims the lowest published worker,
//! even while another worker searches, so a burst of spawns wakes a worker per
//! push while idle bits remain. A kick is a push into a worker's own run queue
//! that leaves it holding a stealable backlog. A kick tries to wake a worker
//! only while the search count is zero.
//!
//! The holder of a count finds the backlog or hands the duty on when it returns
//! the count, and further kicks are suppressed while that count is held. A wake
//! that finds no bit to claim returns the count it took. If that was the last
//! count, the wake fences and looks at the idle set again, since a kick the
//! count suppressed meanwhile may need a worker that published since.
//!
//! A worker returns its count before it runs user code: before every poll, the
//! root's included, before every nonempty batch of callbacks, and whenever it
//! goes round its loop again without parking. The last count returned this way
//! hands the duty on. It fences and wakes a parked worker, as a kick does.
//!
//! A parking worker publishes its idle bit, returns its count without handing
//! it on, fences, and looks once more. A global runnable sends it back to work.
//! That look stops before the run queues, so a worker that returned the last
//! count withdraws and then hands the duty on as a last return does, unless a
//! claim brought it a count. That count stays held until the worker returns it
//! before user code.
//!
//! A held count makes the parking worker wait without reading the other run
//! queues, since that count's last return will find a backlog or wake a parked
//! worker, this one included. Otherwise a stealable backlog in another run
//! queue sends it to search. A thief whose claim holds room in the parking
//! worker's run queue holds a count, so that wait covers it as well. Every exit
//! of the drive loop, unwinding included, withdraws a live publication and
//! returns a held count before the worker destroys its root.
//!
//! ```text
//! push or kick                           parking worker i
//!   publish work (or hand on a search)     set bit i, return a held count
//!   fence(SeqCst)                          fence(SeqCst)
//!   kick: a count is held, return          global nonempty: withdraw
//!   no idle bit: return                      last count returned, unclaimed: kick
//!   reserve a count                          run
//!     kick: only if still zero             a count held: wait
//!   claim lowest bit                       stealable backlog: take the count
//!     success: signal its worker             if zero, withdraw, search
//!     failure: return the reserved count   otherwise: wait
//!       last return: fence and retry       wait: spin, or arm and attempt a wait,
//!                                            then withdraw, keeping a claim's count
//! ```
//!
//! Each side fences between its store and its loads, so one of them sees the
//! other's store. A kick that sees a count is covered by the fence after the
//! last return of a count. That fence, and the look or wake after it, follow
//! the kick. A push that sees no idle bit missed only workers that fence after
//! it and workers that were claimed or withdrew and run again. A worker that
//! fences after the push sees it in its last look. A push into the global queue
//! is therefore never left queued with every worker asleep, and a stealable
//! backlog that persists is taken or offered to a parked worker.
//!
//! A take queues its share without a kick. A look that reads the length the
//! take left, or a later one, sees the share. A worker that parked on a zero
//! from before the push that filled the queue was seen by that push, and that
//! push wakes a worker for it.
//!
//! A wake that arrives before the worker arms its wait is latched by the
//! worker's wake source, so the wait returns at once. A claimed worker
//! withdraws its bit as soon as its wait returns, before it runs any callback,
//! and a withdrawal reports a claim only when it ends a live publication.
//!
//! The fences carry most of the argument. When two sides each store, pass a
//! sequentially consistent fence, and then load what the other side stores, the
//! loads cannot both read values older than those stores in modification order.
//! Either load can see an update later than the other side's store, such as a
//! claim or withdrawal clearing the idle bit. Most accesses to the idle state
//! are relaxed. A read-modify-write reads its immediate predecessor in
//! modification order, and a fence pair covers a stale load.
//!
//! Two handshakes need more. The claim's exchange releases the reserved count
//! to the claimed worker, and the worker's withdrawal acquires it, so the
//! worker returns that count after the reservation. A worker leaving a
//! successful search releases its count to publish the victim's claim release
//! and its own run queue's tail, since no fence separates those updates from
//! the return. Every count modification is a read-modify-write, so each one
//! extends the release sequences of earlier returns. The last return reads
//! those sequences, so its following fence acquires the queue updates. Its
//! look, and a worker it claims, cannot then observe queue states older than
//! those updates.
//!
//! [`MAX_WORKERS`]: super::pool::MAX_WORKERS
//!
//! # Search cap
//!
//! A worker with nothing to run searches the other run queues before it parks,
//! as [`super::pool`] describes. A worker holding no search count starts a
//! search only while the count is less than half the worker count. Otherwise it
//! parks, since a count holder finds work or hands the duty on. The check is
//! soft. Workers that check at once can all pass it, and wakes reserve counts
//! without this cap, so the search count can exceed half the worker count.

use super::{mailbox::Mailbox, pool::Pool, task::Ready};
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

            // With no worker published idle, there is nobody to wake.
            let idle = self.set.load(Ordering::Relaxed);
            if idle == 0 {
                return;
            }

            // Reserve the count the claimed worker inherits. If the exchange
            // fails, another worker began searching or another wake is
            // claiming, and that holder has the duty. The reservation reaches
            // the claimed worker through the claim's release, and a failure
            // delegates as the load above does, so both orderings are relaxed.
            if self
                .searching
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                return;
            }

            // A claimed worker wakes holding the reserved count, so the search
            // for the backlog becomes its duty.
            if self.claim(idle, mailboxes) {
                return;
            }

            // Every bit was claimed or withdrawn first. Return the count, and
            // look again only if it was the last one.
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
            // The caller's fence orders this load, and the reservation reaches
            // the claimed worker through the claim's release, so both are
            // relaxed, as in `notify`.
            let idle = self.set.load(Ordering::Relaxed);
            if idle == 0 {
                return;
            }

            // Reserve a count for the worker to wake. Unlike a kick, a push
            // into the global queue reserves one even while other workers
            // search, so a burst of pushes wakes a worker per push rather than
            // one at a time.
            self.searching.fetch_add(1, Ordering::Relaxed);

            // A claimed worker wakes holding the reserved count.
            if self.claim(idle, mailboxes) {
                return;
            }

            // No bit was left to claim. Return the count, as `notify` does.
            if !self.undo_claim() {
                return;
            }
        }
    }

    /// Return the count a wake reserved when it found no bit to claim. Returns
    /// whether the wake must look at the idle set again. The count may have
    /// suppressed a kick, and that kick relies on the count's last return, so
    /// the last return fences and the wake looks for a worker that published
    /// since.
    fn undo_claim(&self) -> bool {
        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::AfterFailedClaim);

        // Only the last count's return can leave a kick unanswered, so any
        // other return is done.
        if self.searching.fetch_sub(1, Ordering::Relaxed) != 1 {
            return false;
        }

        // Pairs with the fence in `Searcher::prepare_park`, as a kick's does. A
        // kick that saw this count returned without looking, so either the
        // loads after this fence see a bit published since, or that worker's
        // last look saw the kicked backlog.
        //
        // The return above is relaxed because this fence, not the return,
        // orders the loads that follow. No queue updates follow the caller's
        // fence. Its release half already publishes earlier updates through the
        // reservation RMW, and later count RMWs extend that release sequence
        // for the last return's fence to acquire.
        fence(Ordering::SeqCst);
        true
    }

    /// Claim the lowest worker in the idle set, starting from `idle`, and wake
    /// it through its mailbox. `mailboxes` are the pool's, in worker order. The
    /// caller has reserved one search count. Success transfers it to the
    /// claimed worker, while failure leaves the caller obliged to return it
    /// through [`Self::undo_claim`].
    fn claim(&self, mut idle: u64, mailboxes: &[Arc<Mailbox>]) -> bool {
        #[cfg(test)]
        tests::at_wake_point(tests::WakePoint::BeforeClaim);

        // Clearing a worker's idle bit claims it, so a wake that loses the
        // exchange to another retries with the bits that remain, and each
        // publication is claimed at most once. The exchange can also fail
        // spuriously or because a worker published or withdrew its bit, and the
        // retry uses the current set.
        //
        // The exchange releases the reserved count to the claimed worker, and
        // the worker's withdrawal acquires it. The worker's later return of
        // that count therefore follows the reservation in the count's
        // modification order, even when its wait returns before this wake
        // signals it. A failed exchange only yields the set to retry with, so
        // it is relaxed.
        while idle != 0 {
            // Claim the lowest published worker.
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

        // Every bit went to another wake or was withdrawn.
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
            "every search count must be returned before the idle state drops"
        );
        assert_eq!(
            self.set.load(Ordering::Relaxed),
            0,
            "every idle bit must be withdrawn before the idle state drops"
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
    /// The global queue's mirror was nonzero, so run again and try to take
    /// work. A last count returned in the park was handed on, unless a claim
    /// brought one.
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
/// Dropping it withdraws a live publication, then returns a held count, so a
/// worker that drops it on any exit, unwinding included, leaves the idle state
/// as if it had run on.
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
    /// The part of worker `index` of `pool`, unpublished and holding no count.
    /// Panics if `index` is outside the pool. The caller must not create a
    /// second live searcher for the same worker.
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
    /// backlog found into `ready`. Returns whether it took any. A worker
    /// holding no count first takes one, unless the search count is already at
    /// least half the worker count. A count taken or inherited stays held
    /// whether or not the steal succeeds, until the worker leaves searching or
    /// parks. The worker must be unpublished, and `ready` must be its own empty
    /// run queue. A one-worker pool returns `false` without taking a count.
    #[must_use]
    pub fn search(&mut self, ready: &mut Ready) -> bool {
        let pool = self.pool;

        // A one-worker pool has no run queue to steal from, and a worker
        // without a count needs one, under the cap, before it searches.
        if pool.workers() == 1 || (!self.searching && !self.begin()) {
            return false;
        }

        // Each search starts at a random worker, so concurrent searchers spread
        // over different victims.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 17;
        self.rng ^= self.rng << 5;

        // Scan the other run queues from `start` and steal from the first
        // backlog found.
        let start = self.rng as usize % pool.workers();
        pool.steal(self.index, start, ready)
    }

    /// Take a search count unless the total is already at least half the
    /// worker count. Returns whether the search may run. The worker is
    /// unpublished and holds no count.
    fn begin(&mut self) -> bool {
        // The cap only limits contention, so a soft check is harmless. Workers
        // that load the count at once can all pass it, and claimed workers
        // inherit counts without it. Nothing is published with the count. A
        // kick that sees it relies on the fence after its return.
        let searching = self.pool.idle().searching.load(Ordering::Relaxed);
        if 2 * searching >= self.pool.workers() {
            return false;
        }

        // Hold the count until the worker leaves searching or parks.
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

    /// Return the held search count. Panics if the worker is still published.
    /// The caller holds exactly one count. A worker returning the last count
    /// was the one other workers relied on to find what they kicked, so it
    /// fences and wakes a parked worker to carry on the search.
    #[inline(never)]
    fn end_search(&mut self) {
        // A published worker returns its count in its park. That park's last
        // look covers what the return would hand on, or the park hands the duty
        // on once withdrawn. A wake here could also claim the worker itself.
        assert!(
            !self.published,
            "a publication must end before leaving a search"
        );

        self.searching = false;
        let pool = self.pool;

        // Release publishes a successful steal's claim release and destination
        // tail before this worker can enter user code. Every count modification
        // is an RMW, so a later last return reads this release sequence and its
        // following fence acquires both queue updates. That fence can be in
        // `Pool::kick`, `Idle::undo_claim`, or `Searcher::prepare_park`. If
        // this is the last return, both updates already precede the kick's
        // fence in this thread.
        if pool.idle().searching.fetch_sub(1, Ordering::Release) == 1 {
            // That was the last count, so wake a parked worker, if any, to carry
            // on the search.
            pool.kick();
        }
    }

    /// Publish the worker idle, return a held count, and look once more for
    /// work. The look checks the global queue, then the other run queues while
    /// no search count is held. `ready` must belong to this worker. Panics if
    /// already published or if `ready` is not empty.
    ///
    /// [`Park::Wait`] leaves a live publication. The caller ends it through
    /// [`Self::finish_park`] after its wait, even if that wait does not block.
    /// The other results withdraw it. [`Park::Search`] holds exactly one count
    /// for the caller's search, while [`Park::Run`] may inherit a claim's count
    /// and otherwise hands on a last count returned here.
    #[must_use]
    pub fn prepare_park(&mut self, ready: &Ready) -> Park {
        assert!(
            !self.published,
            "a publication must end before the next one"
        );
        assert!(ready.is_empty(), "run queue must be empty to park");

        let pool = self.pool;

        // Publish this worker idle, so a wake can claim it from here on.
        pool.idle().set.fetch_or(1 << self.index, Ordering::Relaxed);
        self.published = true;

        // The look below covers whatever this worker would hand on, so the
        // count is returned without a wake, except on the global branch. The
        // return is relaxed because it has nothing to publish. A search that
        // stole is left through `leave_search` before its runnables are polled,
        // and this run queue is empty, so the count returned here was held
        // through a search that moved nothing.
        let last = mem::take(&mut self.searching)
            && pool.idle().searching.fetch_sub(1, Ordering::Relaxed) == 1;

        // Pairs with the fences in `Pool::push_batch`, `Pool::kick`, and
        // `Idle::undo_claim`. Either the loads after their fence see the bit
        // published above, or the look below sees what they published: the
        // global queue's length, a run queue's tail, or the return of a count.
        // The publication above and the count load below are relaxed, since
        // this fence pair orders them. The queue loads acquire for the queues'
        // own sake, so a length a take left shows the runnables it moved.
        fence(Ordering::SeqCst);

        // The global queue has work, so the worker runs again instead of
        // waiting. This look stops before the run queues, so it does not cover
        // a backlog whose kick the returned count suppressed. The last count is
        // handed on as a last return does, after the withdrawal so the wake
        // cannot claim this worker. A claim's count stays held until the worker
        // returns it before any user code.
        if pool.has_global() {
            if !self.withdraw() && last {
                pool.kick();
            }
            return Park::Run;
        }

        // A worker holding a count searches, or hands the duty on when it
        // returns the last count. A fence follows that return in a kick, a
        // failed wake, or the returning worker's own park. That fence pairs
        // with the fence above, so a backlog is found or a parked worker, this
        // one included, is woken. A held count therefore settles the look
        // without reading the other run queues. The load is relaxed, since a
        // nonzero value delegates through that later fence.
        if pool.idle().searching.load(Ordering::Relaxed) != 0 {
            return Park::Wait;
        }

        // Otherwise this worker takes the count and searches, if another run
        // queue holds a backlog. A count taken here is this worker's own and
        // carries nothing to another thread, so the exchange is relaxed. A
        // failed exchange means a count appeared since the load, and that count
        // delegates the same way.
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

        // Search with the count taken above.
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
        // A search that finds nothing keeps its count, and the next publication
        // returns it. Another worker can pop or claim the backlog between the
        // look and the steal, so a failed scan must publish and look again.
        // Concurrent progress can require more than one retry.
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
        assert!(self.published, "withdrawal must end a live publication");

        self.published = false;
        let bit = 1 << self.index;

        // Acquire pairs with the release of a claim's exchange, so a count the
        // claim reserved is held, and later returned, after the reservation.
        let claimed = self.pool.idle().set.fetch_and(!bit, Ordering::Acquire) & bit == 0;
        if claimed {
            // The wake that cleared the bit reserved a count for this worker,
            // and the worker takes it over.
            assert!(
                !self.searching,
                "a claimed worker must not already hold a search count"
            );
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::iouring::{
        pool::{
            HALF,
            tests::{pool, push, ready, task},
        },
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
        // Remove the hook before running it, outside the borrow, so the hook can
        // install hooks of its own.
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

    /// Whether worker `index`'s wake source was signaled.
    fn signalled(pool: &Pool, index: u32) -> bool {
        pool.mailbox(index).waker.signalled()
    }

    /// Consume worker one's latched signal through a futex wait, an arm, or a spin.
    fn consume_signal(pool: &Pool, mode: usize) {
        let waker = &pool.mailbox(1).waker;
        assert!(waker.signalled());

        // A latched signal ends the wait at once, and turns the arm back.
        match mode {
            0 => assert!(waker.park_idle(0, None).is_none()),
            1 => assert!(!waker.arm(0).still_idle()),
            _ => waker.consume_signal(),
        }

        // Each way consumes the latch, so the worker's next wait blocks.
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

    /// A push into the global queue claims the lowest published worker, and
    /// that worker inherits a search count. A second push claims the next even
    /// while that count is held. A kick claims nobody while a count is held,
    /// and the last count returned hands the duty on to the worker left parked.
    #[test]
    fn test_global_pushes_each_wake_a_worker_lowest_first() {
        let pool = pool(4);
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let mut parked: Vec<Searcher<'_>> =
            (1..4).map(|index| Searcher::new(&pool, index)).collect();

        // Workers one to three find no work and publish themselves parked.
        for (searcher, ready) in parked.iter_mut().zip(&readies[1..]) {
            assert_eq!(searcher.prepare_park(ready), Park::Wait);
        }

        // The first push claims worker one, the lowest bit, and reserves its count.
        let mut tasks = vec![push(&pool, &set)];
        assert!(!pool.idle().is_idle(1) && pool.idle().is_idle(2));
        assert!(signalled(&pool, 1) && !signalled(&pool, 2));
        assert_eq!(pool.idle().search_count(), 1);

        // A second push claims worker two, although worker one's count is held.
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

        // Worker three resumes with the count handed on, and returns it.
        parked[2].finish_park();
        parked[2].leave_search();
        assert_eq!(pool.idle().search_count(), 0);

        // With no worker published, a push wakes nobody, even after a worker
        // published and withdrew. Draining the global queue first lets worker
        // zero's park wait.
        while let Some(runnable) = pool.pop() {
            runnable.discard();
        }

        // Worker zero empties its run queue, publishes, and withdraws unclaimed.
        let mut zero = Searcher::new(&pool, 0);
        readies[0].discard();
        assert_eq!(zero.prepare_park(&readies[0]), Park::Wait);
        zero.finish_park();

        // The push finds no idle bit, so it signals nobody and reserves no count.
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

        // Worker one finds no work and publishes itself parked.
        let mut parked = Searcher::new(&pool, 1);
        assert_eq!(parked.prepare_park(&one), Park::Wait);

        // One runnable short of a stealable backlog, worker zero's pushes do not kick.
        let mut tasks = enqueue(&pool, &mut zero, &set, STEALABLE - 1);
        assert!(pool.idle().is_idle(1) && !signalled(&pool, 1));

        // The push that makes the backlog stealable kicks, and with no count
        // held, the kick claims worker one.
        tasks.extend(enqueue(&pool, &mut zero, &set, 1));
        assert!(!pool.idle().is_idle(1) && signalled(&pool, 1));

        // The woken worker holds the count its wake took and steals.
        parked.finish_park();
        assert!(parked.searching);
        assert!(parked.search(&mut one));

        // Its return is the last and hands the duty on, but no worker is parked.
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

        // Each worker searches in turn and finds nothing to steal. The first two
        // take counts and keep them, and the cap then refuses the other two.
        let mut held = Vec::new();
        for (searcher, ready) in searchers.iter_mut().zip(&mut readies) {
            assert!(!searcher.search(ready));
            held.push(searcher.searching);
        }

        assert_eq!(held, [true, true, false, false]);
        assert_eq!(pool.idle().search_count(), 2);

        // Leaving the search returns the held counts, and the others return nothing.
        for searcher in &mut searchers {
            searcher.leave_search();
        }

        assert_eq!(pool.idle().search_count(), 0);
    }

    /// A worker refused by the search cap that then sees a stealable backlog as
    /// it parks leaves the backlog to the workers holding counts and waits. The
    /// last of them to return its count wakes it.
    #[test]
    fn test_cap_refused_parker_waits_for_the_searchers() {
        let pool = pool(4);
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let mut searchers: Vec<Searcher<'_>> =
            (0..3).map(|index| Searcher::new(&pool, index)).collect();

        // Workers zero and one take the two counts the cap allows, and the cap
        // refuses worker two.
        for (searcher, ready) in searchers.iter_mut().zip(&mut readies) {
            assert!(!searcher.search(ready));
        }

        assert!(searchers[0].searching && searchers[1].searching && !searchers[2].searching);

        // Worker three's kick finds counts held.
        let tasks = enqueue(&pool, &mut readies[3], &set, STEALABLE);

        // Worker two parks despite the backlog, since the held counts cover it,
        // and no wake claims it yet.
        assert_eq!(searchers[2].prepare_park(&readies[2]), Park::Wait);
        assert!(pool.idle().is_idle(2) && !signalled(&pool, 2));

        // The first return is not the last, so worker two stays parked.
        searchers[0].leave_search();
        assert!(pool.idle().is_idle(2));

        // The last return hands the duty on and claims worker two.
        searchers[1].leave_search();
        assert!(!pool.idle().is_idle(2) && signalled(&pool, 2));

        // Worker two resumes with the count its wake took and steals the backlog.
        searchers[2].finish_park();
        assert!(searchers[2].search(&mut readies[2]));
        searchers[2].leave_search();
        assert_eq!(pool.idle().search_count(), 0);

        drop(searchers);
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A parking worker that sees a stealable backlog searches itself when no
    /// worker holds a search count. Otherwise it leaves the backlog to the
    /// worker holding a count, and that worker's return wakes it.
    #[test]
    fn test_parker_seeing_a_backlog_delegates_or_searches() {
        for held in [true, false] {
            let pool = pool(3);
            let set = Tasks::new(1);
            let (mut zero, mut one, mut two) = (ready(&pool, 0), ready(&pool, 1), ready(&pool, 2));
            let mut searcher = Searcher::new(&pool, 0);
            let mut parker = Searcher::new(&pool, 1);

            // In the first round, worker zero keeps the count of a search that
            // found nothing.
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

            // Worker one sees worker two's backlog in its last look.
            let park = parker.prepare_park(&one);

            if held {
                // The held count covers the backlog, so worker one waits unclaimed.
                assert_eq!(park, Park::Wait);
                assert!(pool.idle().is_idle(1));

                // Worker zero's return is the last, so it claims worker one.
                searcher.leave_search();
                assert!(!pool.idle().is_idle(1) && signalled(&pool, 1));
                parker.finish_park();
            } else {
                // With no count held, worker one takes one and withdraws to search.
                assert_eq!(park, Park::Search);
                assert!(!pool.idle().is_idle(1));
            }

            // Either way, worker one holds a count and steals the backlog.
            assert!(parker.searching);
            assert!(parker.search(&mut one));
            parker.leave_search();
            assert_eq!(pool.idle().search_count(), 0);

            drop((searcher, parker));
            release(&pool, &mut [&mut zero, &mut one, &mut two], tasks);
        }
    }

    /// A parker whose last look sees the global queue runs, and its look
    /// stops before the run queues. If it returned the last count, it hands
    /// the duty on, so a backlog whose kicks that count suppressed still
    /// reaches a parked worker.
    #[test]
    fn test_run_after_the_last_count_hands_the_duty_on() {
        let pool = pool(4);
        let set = Tasks::new(1);
        let (mut r0, mut r1, mut r2, mut r3) = (
            ready(&pool, 0),
            ready(&pool, 1),
            ready(&pool, 2),
            ready(&pool, 3),
        );
        let mut zero = Searcher::new(&pool, 0);
        let mut one = Searcher::new(&pool, 1);
        let mut two = Searcher::new(&pool, 2);

        // Workers zero and one find no work and park.
        assert_eq!(zero.prepare_park(&r0), Park::Wait);
        assert_eq!(one.prepare_park(&r1), Park::Wait);

        // Worker two searches, finds nothing, and keeps its count.
        assert!(!two.search(&mut r2));
        assert_eq!(pool.idle().search_count(), 1);

        // Worker three fills its run queue and overflows. Its kicks see the
        // held count, and the overflow's push claims only worker zero.
        let tasks = enqueue(&pool, &mut r3, &set, CAPACITY + 1);
        assert!(!pool.idle().is_idle(0) && signalled(&pool, 0));
        assert!(pool.idle().is_idle(1) && !signalled(&pool, 1));
        assert_eq!(pool.idle().search_count(), 2);

        // Worker zero resumes with the claim's count, takes a share, and
        // returns the count before polling. The return is not the last.
        zero.finish_park();
        pool.take(&mut r0).unwrap().discard();
        zero.leave_search();
        assert!(pool.idle().is_idle(1) && !signalled(&pool, 1));
        assert_eq!(pool.idle().search_count(), 1);

        // Worker two parks and returns the last count. Its look sees the
        // global queue, so it runs and hands the duty on to worker one.
        assert_eq!(two.prepare_park(&r2), Park::Run);
        assert!(!two.searching);
        assert!(!pool.idle().is_idle(1) && signalled(&pool, 1));
        assert_eq!(pool.idle().search_count(), 1);

        // Worker one resumes with the count its wake reserved and steals a
        // backlog.
        one.finish_park();
        assert!(one.searching);
        assert!(one.search(&mut r1));

        one.leave_search();
        assert_eq!(pool.idle().search_count(), 0);

        drop((zero, one, two));
        release(&pool, &mut [&mut r0, &mut r1, &mut r2, &mut r3], tasks);
    }

    /// A parker whose empty run queue is pinned by a thief's claim returns
    /// `Wait` with a live publication, since the thief holds a search count. It
    /// searches after the thief frees the slots and hands on the last search
    /// count.
    #[test]
    fn test_parker_without_room_waits_for_the_claiming_thief() {
        let pool = pool(3);
        let set = Tasks::new(1);
        let (mut zero, mut one, mut two) = (ready(&pool, 0), ready(&pool, 1), ready(&pool, 2));
        let mut parker = Searcher::new(&pool, 0);
        let mut thief = Searcher::new(&pool, 1);

        // Fill worker zero's run queue without kicks.
        let mut tasks = Vec::new();
        for _ in 0..CAPACITY {
            let (task, runnable) = task(&set);
            queue(&mut zero, runnable);
            tasks.push(task);
        }

        // A thief takes a count and pauses while holding a claim on half the queue.
        assert!(thief.begin());
        let claim = pool.queue(0).hold_claim(HALF as u32);

        // Worker zero runs the rest of its queue, while the claim pins half its slots.
        while let Some(runnable) = zero.pop() {
            runnable.discard();
        }

        // Worker two's backlog kicks, but the thief's count suppresses the wake.
        tasks.extend(enqueue(&pool, &mut two, &set, STEALABLE));

        // The thief's held count makes worker zero wait rather than search,
        // although a backlog is stealable.
        assert_eq!(zero.room(), 0);
        assert_eq!(parker.prepare_park(&zero), Park::Wait);
        assert!(pool.idle().is_idle(0) && !signalled(&pool, 0));
        assert_eq!(pool.idle().search_count(), 1);

        // The thief finishes its claim, freeing worker zero's slots.
        for runnable in pool.queue(0).finish_claim(claim) {
            runnable.discard();
        }

        // The thief's return is the last and hands the duty on to worker zero.
        thief.leave_search();
        assert!(!pool.idle().is_idle(0) && signalled(&pool, 0));

        // Worker zero resumes with the count its wake took and steals the backlog.
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

        // The drop withdraws the live publication.
        drop(parker);
        assert!(!pool.idle().is_idle(1));

        // Published, then claimed by a push.
        let mut parker = Searcher::new(&pool, 1);
        assert_eq!(parker.prepare_park(&one), Park::Wait);

        // The push clears the worker's bit and reserves a count for it.
        let task = push(&pool, &set);
        assert!(!pool.idle().is_idle(1));
        assert_eq!(pool.idle().search_count(), 1);

        // The drop withdraws, taking the count the claim brought, and returns it.
        drop(parker);
        assert_eq!(pool.idle().search_count(), 0);

        // Holding the count of a search that found nothing.
        let mut searcher = Searcher::new(&pool, 0);
        assert!(!searcher.search(&mut zero));
        assert_eq!(pool.idle().search_count(), 1);

        // The drop returns the held count.
        drop(searcher);
        assert_eq!(pool.idle().search_count(), 0);

        drop((zero, one));
        release(&pool, &mut [], vec![task]);
    }

    /// A kick's wake loses its candidate when the candidate resumes on its own
    /// before the claim. The wake returns its count, finds it was the last,
    /// looks again, and claims a worker that published meanwhile and left the
    /// backlog to that count.
    #[test]
    fn test_kick_whose_claim_fails_looks_again() {
        let (pool, parts) = leaked(3);
        let set = Tasks::new(1);

        // Worker one parks, the only worker the kick can claim.
        {
            let (candidate, ready) = &mut *parts[1].borrow_mut();
            assert_eq!(candidate.prepare_park(ready), Park::Wait);
        }

        // Worker one resumes on its own before the wake claims it, so the claim fails.
        on_wake_point(WakePoint::BeforeClaim, {
            let part = parts[1].clone();
            move || part.borrow_mut().0.finish_park()
        });

        // Before the failed wake returns its count, worker two parks. The held
        // count makes it wait and leave the backlog to that count's last return.
        on_wake_point(WakePoint::AfterFailedClaim, {
            let part = parts[2].clone();
            move || {
                let (later, ready) = &mut *part.borrow_mut();
                assert_eq!(later.prepare_park(ready), Park::Wait);
            }
        });

        // Worker zero's kick fails its claim, returns the last count, and looks
        // again, so it claims worker two.
        let tasks = enqueue(pool, &mut parts[0].borrow_mut().1, &set, STEALABLE);
        assert!(!pool.idle().is_idle(2) && signalled(pool, 2));

        // Worker two resumes with the count and steals, leaving a clean idle state.
        let (later, ready) = &mut *parts[2].borrow_mut();
        later.finish_park();
        assert!(later.search(ready));
        later.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..3).all(|index| !pool.idle().is_idle(index)));

        release(pool, &mut [&mut parts[0].borrow_mut().1, ready], tasks);
    }

    /// The wake of a push into the global queue loses its candidate when the
    /// candidate resumes on its own before the claim. The wake returns its
    /// count, finds it was the last, looks again, and claims a worker that
    /// published meanwhile. That worker left a kicked backlog to the count once
    /// another worker took the push.
    #[test]
    fn test_global_push_whose_claim_fails_looks_again() {
        let (pool, parts) = leaked(4);
        let set = Rc::new(Tasks::new(1));
        let kicked = Rc::new(RefCell::new(Vec::new()));

        // Worker one parks, the only worker the push can claim.
        {
            let (candidate, ready) = &mut *parts[1].borrow_mut();
            assert_eq!(candidate.prepare_park(ready), Park::Wait);
        }

        // Worker one resumes on its own before the wake claims it, so the claim fails.
        on_wake_point(WakePoint::BeforeClaim, {
            let part = parts[1].clone();
            move || part.borrow_mut().0.finish_park()
        });

        // Before the failed wake returns its count, the hook below runs.
        on_wake_point(WakePoint::AfterFailedClaim, {
            let owner = parts[0].clone();
            let later = parts[2].clone();
            let set = set.clone();
            let kicked = kicked.clone();
            move || {
                // Another worker takes the push, so worker two's park below
                // finds the global queue empty.
                pool.pop().unwrap().discard();

                // A kick from worker zero finds the count held and wakes nobody.
                kicked.borrow_mut().extend(enqueue(
                    pool,
                    &mut owner.borrow_mut().1,
                    &set,
                    STEALABLE,
                ));

                // Then worker two parks, leaving the backlog to the held count.
                let (later, ready) = &mut *later.borrow_mut();
                assert_eq!(later.prepare_park(ready), Park::Wait);
            }
        });

        // The push's wake fails its claim, returns the last count, and looks
        // again, so it claims worker two.
        let pushed = push(pool, &set);
        assert!(!pool.idle().is_idle(2) && signalled(pool, 2));

        // Worker two resumes with the count and steals the kicked backlog.
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
    /// a count to search brings a second count. The worker returns that count
    /// and keeps its own.
    #[test]
    fn test_global_claim_of_a_worker_about_to_search_leaves_one_count() {
        let (pool, parts) = leaked(2);
        let set = Tasks::new(1);

        // Worker one holds a stealable backlog queued without a kick.
        let mut tasks = Vec::new();
        for _ in 0..STEALABLE {
            let (task, runnable) = task(&set);
            queue(&mut parts[1].borrow_mut().1, runnable);
            tasks.push(task);
        }

        // Once worker zero takes a count to search, a push claims it before it
        // withdraws its bit.
        let (pushed, runnable) = task(&set);
        on_wake_point(WakePoint::BeforeParkSearch, move || {
            assert!(pool.push(runnable).is_ok());
        });

        // Worker zero searches and returns the claim's count, keeping its own.
        let (searcher, ready) = &mut *parts[0].borrow_mut();
        assert_eq!(searcher.prepare_park(ready), Park::Search);
        assert!(signalled(pool, 0));
        assert_eq!(pool.idle().search_count(), 1);

        // The kept count covers the steal, and its return leaves a clean idle state.
        assert!(searcher.search(ready));
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..2).all(|index| !pool.idle().is_idle(index)));

        tasks.push(pushed);
        release(pool, &mut [ready, &mut parts[1].borrow_mut().1], tasks);
    }

    /// A worker a push claimed can resume on an independent wake before the
    /// push signals it. It then withdraws with the count the claim brought,
    /// returns it, and publishes again. The late signal ends its next wait with
    /// no claim and no count, and a later claim brings one as usual. Each way a
    /// worker consumes a signal is checked: its futex wait, an arm that the
    /// signal turns back, and its spin.
    #[test]
    fn test_late_signal_of_a_claim_brings_no_count() {
        for mode in 0..3 {
            let (pool, parts) = leaked(2);

            // Worker one finds no work and publishes itself parked.
            {
                let (parker, ready) = &mut *parts[1].borrow_mut();
                assert_eq!(parker.prepare_park(ready), Park::Wait);
            }

            // Pause the wake after its claim, so the worker runs before the signal.
            on_wake_point(WakePoint::AfterClaim, {
                let part = parts[1].clone();
                move || {
                    // The claim cleared worker one's bit and reserved its count.
                    assert_eq!(pool.idle().search_count(), 1);
                    assert!(!pool.idle().is_idle(1));

                    // An independent wake resumes the claimed worker, and the
                    // worker runs its loop and parks again.
                    pool.mailbox(1).waker.wake();
                    consume_signal(pool, mode);

                    // Its withdrawal keeps the claim's count, and it returns
                    // that count before it publishes again.
                    let (parker, ready) = &mut *part.borrow_mut();
                    parker.finish_park();
                    assert!(parker.searching);
                    parker.leave_search();
                    assert_eq!(pool.idle().search_count(), 0);
                    assert_eq!(parker.prepare_park(ready), Park::Wait);
                }
            });

            // A push's wake claims worker one and runs the hook before it signals.
            pool.idle().notify_global(pool.mailboxes());

            // The push's signal reaches the new publication, although no wake
            // claimed it.
            assert!(pool.idle().is_idle(1));
            consume_signal(pool, mode);

            // Its withdrawal finds no claim, so it holds no count, and it parks again.
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

            // Returning that count leaves a clean idle state.
            parker.leave_search();
            assert_eq!(pool.idle().search_count(), 0);
            assert!((0..2).all(|index| !pool.idle().is_idle(index)));
        }
    }
}
