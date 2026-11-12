//! The pool's idle state: idle publications, search counts, and which worker
//! to wake for pool work.
//!
//! [`Idle`] holds that state for a [`Pool`]. Each pool worker searches and
//! parks through its [`Searcher`]. [`Searcher::prepare_park`] returns a
//! [`Park`] that says what the worker does after its last look.
//!
//! # Idle state and parker
//!
//! [`Idle`] decides whether to wake a pool worker, and which one, on a kick
//! through [`Idle::notify`] and on a push into the global queue through
//! [`Idle::notify_global`]. A successful claim clears that worker's idle bit
//! and transfers a reserved search count, then unparks the worker through its
//! mailbox's [`Unparker`].
//!
//! The unpark advances the sequence of the worker's futex word, which its next
//! wait compares against, and wakes an armed worker unless another
//! notification already did. Mailbox messages and driver permit grants unpark
//! the same word without going through [`Idle`].
//!
//! A pool worker publishes its idle bit, returns any held search count, and
//! fences before its last look for work. If it proceeds to wait, the
//! publication stays live until withdrawal, even if a claim clears the bit.
//!
//! With unfinished I/O requests, [`Driver::park`] arms the worker's word
//! before waiting on it in the io_uring ring. Otherwise, [`Parker::park`] arms
//! it after any unsuccessful spin and waits with a thread futex wait. Both
//! paths block only while the armed word still carries the sequence that the
//! worker's [`Parker`] observed before its last look, so an early unpark can
//! prevent blocking. After spinning or waiting, even if it did not block, the
//! worker ends its publication through [`Searcher::finish_park`] before user
//! code and keeps the count a claim brought.
//!
//! [`Driver::park`]: super::driver::Driver::park
//! [`Parker`]: super::park::Parker
//! [`Parker::park`]: super::park::Parker::park
//! [`Unparker`]: super::park::Unparker
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
//! transfers the count, not the notification. A late notification from an
//! earlier claim cannot transfer another count.
//!
//! A push into the global queue fences and claims the lowest published worker,
//! even while another worker searches, so a burst of spawns wakes a worker per
//! push while idle bits remain. A kick is a push into a worker's own run queue
//! that leaves it holding [`KICK`] or more runnables. A kick tries to wake a
//! worker only while the search count is zero. A lone runnable kicks no one,
//! though a worker that searches, or looks before it parks, can steal it once
//! it is ripe (see [`super::pool`]), at once if a spawn queued it.
//!
//! A look that finds a lone runnable still young treats it as no work, so it
//! takes no count for it, and records when it ripens: the worker waits no
//! longer than that before it looks again. No count holder answers for a young
//! lone runnable, so a re-look that has come due is the worker's own duty, and
//! it may take a count past the search cap (see [Search cap](#search-cap)).
//! That count is an ordinary one from then on: it suppresses kicks, is
//! returned before user code, and its last return hands the duty on. A worker
//! that already holds a count, its claim's included, searches with that one,
//! so a re-look racing a kick's claim never holds two.
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
//!   claim lowest bit                       stealable backlog (lone: ripe): take the count
//!     success: unpark its worker             if zero, withdraw
//!     failure: return the reserved count       claimed: run, otherwise search
//!       last return: fence and retry       otherwise: wait, at most until a
//!                                            young lone runnable ripens
//!                                          wait: spin, or arm and attempt a wait,
//!                                            then withdraw, keeping a claim's count
//! ```
//!
//! Each side fences between its store and its loads, so one of them sees the
//! other's store. A kick that sees a count is covered by the fence after the
//! last return of a count. That fence, and the look or wake after it, follow
//! the kick. A push that sees no idle bit missed only workers that fence after
//! it and workers that were claimed or withdrew and run again. A worker that
//! fences after the push sees it in its last look. A push into the global queue
//! is therefore never left queued with every worker asleep, and a backlog of
//! [`KICK`] or more that persists is taken or offered to a parked worker. A
//! lone runnable that no look sees ripe can wait for its owner. A worker whose
//! look saw it young, and that has nothing else to run, waits no longer than
//! until it ripens and then searches again, past the cap if need be. That
//! search clears the re-look before it reads any run queue, though, and can
//! steal other work before its scan reaches the runnable, and racing looks can
//! keep the runnable young for longer (see [`super::pool`]). The steal age is
//! therefore when a lone runnable may move, not a bound on its wait: the
//! runnable can wait until its owner or a later look reaches it. A worker that
//! waits because a count is held, without reading the run queues, relies on
//! that count's last return, which looks or kicks as above, or keeps a re-look
//! an earlier look recorded.
//!
//! A take queues its share without a kick. A look that reads the length the
//! take left, or a later one, sees the share. A worker that parked on a zero
//! from before the push that filled the queue was seen by that push, and that
//! push wakes a worker for it.
//!
//! A notification that arrives before the worker arms its wait moves the
//! sequence the wait compares against, so the wait returns at once. A claimed
//! worker withdraws its bit as soon as its wait returns, before it runs any
//! callback, and a withdrawal reports a claim only when it ends a live
//! publication.
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
//! [`KICK`]: super::pool::KICK
//!
//! # Search cap
//!
//! A worker with nothing to run searches the other run queues before it parks,
//! as [`super::pool`] describes. A worker holding no search count starts a
//! search only while the count is less than half the worker count. Otherwise it
//! parks, since a count holder finds work or hands the duty on. The check is
//! soft. Workers that check at once can all pass it, and wakes reserve counts
//! without this cap, so the search count can exceed half the worker count. A
//! worker whose re-look of a young lone runnable has come due searches even at
//! the cap, for two reasons. No count holder waits for that runnable to ripen,
//! and a due re-look that the cap refused would stay recorded, so every wait
//! it bounds would return at once until the counts drop.
//!
//! A re-look that the cap refuses before it is due stays recorded, so the
//! worker still waits no longer than that. Its deadline can pass after the
//! search sampled the clock but before the cap refused it, which costs one
//! wait that returns at once, since the next search sees the re-look due. A
//! re-look whose runnable has gone since, run by its owner or stolen, also
//! passes the cap once when it comes due. That only adds contention: the count
//! it takes is an ordinary one, and its search clears the re-look.

use super::{mailbox::Mailbox, pool::Pool, task::Ready};
use std::{mem, sync::Arc, thread, time::Instant};

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
    /// in worker order. Returns whether it woke a worker.
    pub fn notify_global(&self, mailboxes: &[Arc<Mailbox>]) -> bool {
        loop {
            // The caller's fence orders this load, and the reservation reaches
            // the claimed worker through the claim's release, so both are
            // relaxed, as in `notify`.
            let idle = self.set.load(Ordering::Relaxed);
            if idle == 0 {
                return false;
            }

            // Reserve a count for the worker to wake. Unlike a kick, a push
            // into the global queue reserves one even while other workers
            // search, so a burst of pushes wakes a worker per push rather than
            // one at a time.
            self.searching.fetch_add(1, Ordering::Relaxed);

            // A claimed worker wakes holding the reserved count.
            if self.claim(idle, mailboxes) {
                return true;
            }

            // No bit was left to claim. Return the count, as `notify` does.
            if !self.undo_claim() {
                return false;
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
        // unparks it. A failed exchange only yields the set to retry with, so
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

                    // An unpark before the worker blocks moves the sequence
                    // its wait compares against, so the claimed worker wakes
                    // either way.
                    mailboxes[index as usize].unparker.unpark();
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
    /// No work was observed, a young lone runnable counting as none, or an
    /// existing count covers it, including a thief holding the slots this
    /// worker needs. Wait for a wake, and no longer than [`Searcher::relook`].
    Wait,
    /// The global queue's mirror was nonzero, or a push into it claimed this
    /// worker after it took a count to search, so run again and try to take
    /// work. A last count returned in the park was handed on, unless a claim
    /// brought one.
    Run,
    /// A stealable backlog was observed, this worker holds a count to search,
    /// and no wake claimed its publication.
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
    /// When the earliest young lone runnable that the worker's looks have
    /// refused since its last search that scanned ripens, if any. The worker
    /// looks again by then rather than waiting for a wake.
    relook: Option<Instant>,
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
            relook: None,
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
    ///
    /// A search that scans clears [`Self::relook`] first, and a young lone
    /// runnable it refuses brings it forward. A re-look that has come due is
    /// the worker's own duty, so it then takes a count even at the cap. One
    /// the cap refuses before it is due stays, so the worker still waits no
    /// longer than that. Passing the cap also keeps a due re-look from
    /// staying recorded, where it would end every wait at once.
    #[must_use]
    pub fn search(&mut self, ready: &mut Ready) -> bool {
        let pool = self.pool;
        let due = self.relook.is_some_and(|relook| relook <= pool.now());

        // A one-worker pool has no run queue to steal from, and a worker
        // without a count needs one, under the cap, before it searches.
        if pool.workers() == 1 || (!self.searching && !self.begin(due)) {
            return false;
        }
        self.relook = None;

        // Each search starts at a random worker, so concurrent searchers spread
        // over different victims.
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 17;
        self.rng ^= self.rng << 5;

        // Scan the other run queues from `start` and steal from the first
        // backlog found.
        let start = self.rng as usize % pool.workers();
        pool.steal(self.index, start, ready, &mut self.relook)
    }

    /// When the earliest young lone runnable refused since the last search
    /// that scanned ripens. A worker that waits after its look waits no longer
    /// than this, so it looks again once the runnable may be stolen. The
    /// instant can already have passed by the time the worker waits.
    pub const fn relook(&self) -> Option<Instant> {
        self.relook
    }

    /// Take a search count unless the total is already at least half the
    /// worker count and `due` is false. Returns whether the search may run.
    /// The worker is unpublished and holds no count.
    fn begin(&mut self, due: bool) -> bool {
        // The cap only limits contention, so a soft check is harmless. Workers
        // that load the count at once can all pass it, and claimed workers
        // inherit counts without it. A worker whose re-look came due passes it
        // as well, since no other worker waits for that lone runnable to ripen
        // and a due re-look left recorded would end every wait at once.
        // Nothing is published with the count. A kick that sees it relies on
        // the fence after its return.
        let searching = self.pool.idle().searching.load(Ordering::Relaxed);
        if !due && 2 * searching >= self.pool.workers() {
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
    /// The wait lasts until a wake, and no longer than [`Self::relook`], which
    /// a young lone runnable the look refuses brings forward. The other results
    /// withdraw the publication. [`Park::Search`] holds exactly one count for
    /// the caller's search, while [`Park::Run`] may inherit a claim's count
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
        // carries nothing to another thread, so the exchange is relaxed. Its
        // last return still hands the duty on, as any count's does. A failed
        // exchange means a count appeared since the load, and that count
        // delegates the same way. A young lone runnable is no backlog yet: the
        // look records when it ripens instead, and the worker waits until then
        // at most, so no count is held for it.
        if !pool.has_stealable(self.index, &mut self.relook)
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
        // withdrawal acquired the claim's reservation. The claim notifies this
        // worker, possibly later, since the withdrawal can acquire the claim
        // before its unpark runs. The worker runs again with the count it keeps
        // instead of searching and publishing again under the same observation.
        // Only a publication that no wake claimed leads to a search, so the
        // last looks of a turn collect at most one claim.
        if self.withdraw() {
            pool.idle().searching.fetch_sub(1, Ordering::Relaxed);
            return Park::Run;
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
    /// wait, no longer than [`Self::relook`], and then call
    /// [`Self::finish_park`], even if the wait does not block.
    #[must_use]
    pub fn publish_and_look(&mut self, ready: &mut Ready) -> bool {
        // A search that finds nothing keeps its count, and the next publication
        // returns it. Another worker can pop or claim the backlog between the
        // look and the steal, so a failed scan must publish and look again.
        // Concurrent progress can require more than one retry. Each retry
        // follows a publication that no wake claimed, so only the last
        // publication of a call can bring a claim's notification.
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
            #[cfg(test)]
            tests::at_wake_point(tests::WakePoint::AfterClaimedWithdrawal);

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
        park::{Parker, tests::notifications},
        pool::{
            HALF, KICK, Pool,
            tests::{aged_pool, pool, push, ready, task},
        },
        queue::CAPACITY,
        task::{Task, tests::queue},
        tasks::Tasks,
    };
    use std::{cell::RefCell, rc::Rc, time::Duration};

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
        /// In a wake that claimed a bit, before it notifies the claimed worker.
        AfterClaim,
        /// In a wake that found no bit to claim, before it returns its count.
        AfterFailedClaim,
        /// In a park that took a count to search, before it withdraws its bit.
        BeforeParkSearch,
        /// In a withdrawal that found its bit claimed, before the worker takes
        /// over the claim's count.
        AfterClaimedWithdrawal,
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

    /// Drop every hook this thread installed and has not run. Loom runs every
    /// thread of a model on one thread, across executions.
    #[cfg(feature = "loom")]
    pub fn clear_wake_hooks() {
        // Drop the hooks outside the borrow, as `at_wake_point` runs them.
        let hooks = WAKE_HOOKS.with(|hooks| mem::take(&mut *hooks.borrow_mut()));
        drop(hooks);
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

    /// Whether worker `index` was unparked since its word was created.
    fn notified(pool: &Pool, index: u32) -> bool {
        notifications(&pool.mailbox(index).unparker) != 0
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

    /// A worker's part, the owner's end of its run queue, and its parker,
    /// shared with hooks.
    type Part = Rc<RefCell<(Searcher<'static>, Ready, Parker)>>;

    /// A pool that lives as long as the test thread, for hooks that act on
    /// its workers, with every worker's part, run queue owner, and parker.
    fn leaked(workers: usize) -> (&'static Pool, Vec<Part>) {
        let (pool, parkers) = Pool::new(workers, Duration::ZERO);
        let pool: &'static Pool = Box::leak(Box::new(pool));

        let parts = (0..workers as u32)
            .zip(parkers)
            .map(|(index, parker)| {
                Rc::new(RefCell::new((
                    Searcher::new(pool, index),
                    ready(pool, index),
                    parker,
                )))
            })
            .collect();
        (pool, parts)
    }

    /// Wait until the stamps' clock of `pool` reaches `instant`.
    fn wait_until(pool: &Pool, instant: Instant) {
        while pool.now() < instant {
            std::hint::spin_loop();
        }
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
        assert!(notified(&pool, 1) && !notified(&pool, 2));
        assert_eq!(pool.idle().search_count(), 1);

        // A second push claims worker two, although worker one's count is held.
        tasks.push(push(&pool, &set));
        assert!(!pool.idle().is_idle(2) && notified(&pool, 2));
        assert_eq!(pool.idle().search_count(), 2);

        // A kick leaves its backlog to the workers holding counts.
        tasks.extend(enqueue(&pool, &mut readies[0], &set, KICK));
        assert!(pool.idle().is_idle(3) && !notified(&pool, 3));

        // Each claimed worker resumes with its count. The first return is not
        // the last, and the last wakes worker three.
        parked[0].finish_park();
        parked[1].finish_park();
        assert!(parked[0].searching && parked[1].searching);

        parked[0].leave_search();
        assert!(pool.idle().is_idle(3));

        parked[1].leave_search();
        assert!(!pool.idle().is_idle(3) && notified(&pool, 3));

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

        // The push finds no idle bit, so it notifies nobody and reserves no count.
        tasks.push(push(&pool, &set));
        assert!(!notified(&pool, 0));
        assert_eq!(pool.idle().search_count(), 0);

        drop((parked, zero));
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A push that leaves its run queue holding [`KICK`] runnables wakes a
    /// parked worker, and a lone runnable, though stealable, does not.
    #[test]
    fn test_kick_needs_two_queued_runnables() {
        let pool = pool(2);
        let set = Tasks::new(1);
        let (mut zero, mut one) = (ready(&pool, 0), ready(&pool, 1));

        // Worker one finds no work and publishes itself parked.
        let mut parked = Searcher::new(&pool, 1);
        assert_eq!(parked.prepare_park(&one), Park::Wait);

        // A lone runnable is stealable, but its push does not kick.
        let mut tasks = enqueue(&pool, &mut zero, &set, KICK - 1);
        assert!(pool.queue(0).is_stealable());
        assert!(pool.idle().is_idle(1) && !notified(&pool, 1));

        // The push that queues a second one kicks, and with no count held,
        // the kick claims worker one.
        tasks.extend(enqueue(&pool, &mut zero, &set, 1));
        assert!(!pool.idle().is_idle(1) && notified(&pool, 1));

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
        let tasks = enqueue(&pool, &mut readies[3], &set, KICK);

        // Worker two parks despite the backlog, since the held counts cover it,
        // and no wake claims it yet.
        assert_eq!(searchers[2].prepare_park(&readies[2]), Park::Wait);
        assert!(pool.idle().is_idle(2) && !notified(&pool, 2));

        // The first return is not the last, so worker two stays parked.
        searchers[0].leave_search();
        assert!(pool.idle().is_idle(2));

        // The last return hands the duty on and claims worker two.
        searchers[1].leave_search();
        assert!(!pool.idle().is_idle(2) && notified(&pool, 2));

        // Worker two resumes with the count its wake took and steals the backlog.
        searchers[2].finish_park();
        assert!(searchers[2].search(&mut readies[2]));
        searchers[2].leave_search();
        assert_eq!(pool.idle().search_count(), 0);

        drop(searchers);
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A worker whose re-look of a young lone runnable has come due searches
    /// even when the cap would refuse it, since no count holder waits for that
    /// runnable to ripen. Worker one's look sees the lone runnable young and
    /// records its re-look, and leaving the search keeps no count for it. By
    /// the time that re-look is due, two other counts are held, which reaches
    /// the cap of a pool of four, yet worker one's search takes a count and
    /// steals the now ripe runnable. That count is an ordinary one: the cap's
    /// holders still hold theirs, and leaving the search returns it alone.
    #[test]
    fn test_due_relook_searches_at_the_cap() {
        let pool = aged_pool(4, Duration::from_micros(10));
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let tasks = enqueue(&pool, &mut readies[0], &set, 1);
        let mut searcher = Searcher::new(&pool, 1);

        // The first look refuses the young lone runnable and records when it
        // ripens, and no count stays held for it.
        assert!(!searcher.search(&mut readies[1]));
        let relook = searcher
            .relook()
            .expect("the young lone runnable is looked at again");
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        wait_until(&pool, relook);

        // Two other workers now hold the counts the cap allows.
        pool.idle().searching.fetch_add(2, Ordering::Relaxed);
        assert!(searcher.search(&mut readies[1]));
        assert_eq!(pool.idle().search_count(), 3);
        assert_eq!(searcher.relook(), None);
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 2);
        pool.idle().searching.fetch_sub(2, Ordering::Relaxed);
        assert_eq!(readies[1].len(), 1);

        drop(searcher);
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A search that scans clears the worker's re-look before it reads any run
    /// queue, so a steal from another run queue first forgets the young lone
    /// runnable the re-look was for. Worker one's look refuses worker zero's
    /// young lone runnable. Once its re-look is due, its search starts at
    /// worker two, whose spawned runnable is ripe at once, and steals that one.
    /// Idle again with the cap reached, the worker cannot search, and its look
    /// leaves the run queues to the count holders with no deadline, so worker
    /// zero's runnable waits for its owner or another worker's look.
    #[test]
    fn test_steal_elsewhere_forgets_the_relook() {
        let pool = aged_pool(4, Duration::from_micros(10));
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let mut tasks = enqueue(&pool, &mut readies[0], &set, 1);
        let mut searcher = Searcher::new(&pool, 1);

        // The first look refuses the young lone runnable and records when it
        // ripens.
        assert!(!searcher.search(&mut readies[1]));
        let relook = searcher
            .relook()
            .expect("the young lone runnable is looked at again");
        searcher.leave_search();

        // A spawn queues a runnable on worker two that is ripe at once, and
        // the re-look comes due.
        let (spawned, runnable) = task(&set);
        pool.enqueue_spawned(&mut readies[2], runnable);
        tasks.push(spawned);
        wait_until(&pool, relook);

        // The generator's state 2 starts the next search at worker two in a
        // pool of four. The search clears the re-look and steals there, before
        // its scan reaches worker zero.
        searcher.rng = 2;
        assert!(searcher.search(&mut readies[1]));
        assert_eq!(readies[0].len(), 1, "the search must start at worker two");
        assert!(readies[2].is_empty());
        assert_eq!(searcher.relook(), None);
        searcher.leave_search();
        readies[1].discard();

        // Idle again with two other workers holding the counts the cap allows,
        // the worker cannot search, and its look leaves the run queues to the
        // count holders. No re-look bounds its wait.
        pool.idle().searching.fetch_add(2, Ordering::Relaxed);
        assert!(!searcher.search(&mut readies[1]));
        assert_eq!(searcher.prepare_park(&readies[1]), Park::Wait);
        assert_eq!(searcher.relook(), None);
        assert_eq!(readies[0].len(), 1);
        searcher.finish_park();
        pool.idle().searching.fetch_sub(2, Ordering::Relaxed);
        assert_eq!(pool.idle().search_count(), 0);

        drop(searcher);
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A re-look that comes due after its lone runnable left passes the cap
    /// once. Worker one's look refuses worker zero's young lone runnable,
    /// which its owner then runs. With two other counts held in a pool of
    /// four, worker one's search past the re-look still takes a count, which
    /// is an ordinary one: the search finds nothing and keeps it, and leaving
    /// the search returns it alone. The search also cleared the re-look, so
    /// the cap refuses the next one.
    #[test]
    fn test_stale_relook_passes_the_cap_once() {
        let pool = aged_pool(4, Duration::from_micros(10));
        let set = Tasks::new(1);
        let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
        let tasks = enqueue(&pool, &mut readies[0], &set, 1);
        let mut searcher = Searcher::new(&pool, 1);

        // The look refuses the young lone runnable, and its owner then runs it.
        assert!(!searcher.search(&mut readies[1]));
        let relook = searcher
            .relook()
            .expect("the young lone runnable is looked at again");
        searcher.leave_search();
        readies[0].discard();

        // Two other workers hold the counts the cap allows by the time the
        // re-look is due.
        pool.idle().searching.fetch_add(2, Ordering::Relaxed);
        wait_until(&pool, relook);

        // The stale re-look passes the cap, and the search that finds nothing
        // keeps its count and clears the re-look.
        assert!(!searcher.search(&mut readies[1]));
        assert!(searcher.searching);
        assert_eq!(searcher.relook(), None);
        assert_eq!(pool.idle().search_count(), 3);

        // Leaving the search returns that count alone, and with no re-look
        // left the cap refuses the next search.
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 2);
        assert!(!searcher.search(&mut readies[1]));
        assert!(!searcher.searching);
        assert_eq!(searcher.prepare_park(&readies[1]), Park::Wait);
        searcher.finish_park();
        pool.idle().searching.fetch_sub(2, Ordering::Relaxed);
        assert_eq!(pool.idle().search_count(), 0);

        drop(searcher);
        let mut readies: Vec<&mut Ready> = readies.iter_mut().collect();
        release(&pool, &mut readies, tasks);
    }

    /// A worker waiting for its re-look that a kick claims first resumes with
    /// the kick's count and searches with it, even once its re-look has come
    /// due, so it never holds a second count. Worker one's look refuses a
    /// young lone runnable and parks. A second push kicks and claims it. Its
    /// search, past the re-look, steals with the claim's count, and leaving the
    /// search returns the only count.
    #[test]
    fn test_kick_claiming_a_relooking_worker_brings_its_only_count() {
        let pool = aged_pool(2, Duration::from_micros(10));
        let set = Tasks::new(1);
        let (mut zero, mut one) = (ready(&pool, 0), ready(&pool, 1));
        let mut tasks = enqueue(&pool, &mut zero, &set, 1);
        let mut searcher = Searcher::new(&pool, 1);

        // The look refuses the young lone runnable, and the worker waits for
        // its re-look with no count held.
        assert_eq!(searcher.prepare_park(&one), Park::Wait);
        let relook = searcher
            .relook()
            .expect("the young lone runnable is looked at again");
        assert_eq!(pool.idle().search_count(), 0);

        // A second push kicks and claims the waiting worker.
        tasks.extend(enqueue(&pool, &mut zero, &set, 1));
        assert!(!pool.idle().is_idle(1) && notified(&pool, 1));
        assert_eq!(pool.idle().search_count(), 1);

        // Resumed once its re-look is due, it searches with the claim's count.
        searcher.finish_park();
        assert!(searcher.searching);
        wait_until(&pool, relook);
        assert!(searcher.search(&mut one));
        assert_eq!(pool.idle().search_count(), 1);
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);

        drop(searcher);
        release(&pool, &mut [&mut zero, &mut one], tasks);
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
            let mut holder = Searcher::new(&pool, 0);
            let mut searcher = Searcher::new(&pool, 1);

            // In the first round, worker zero keeps the count of a search that
            // found nothing.
            if held {
                assert!(!holder.search(&mut zero));
            }

            // A backlog queued without a kick, as a take leaves it.
            let mut tasks = Vec::new();
            for _ in 0..KICK {
                let (task, runnable) = task(&set);
                queue(&mut two, runnable);
                tasks.push(task);
            }

            // Worker one sees worker two's backlog in its last look.
            let park = searcher.prepare_park(&one);

            if held {
                // The held count covers the backlog, so worker one waits unclaimed.
                assert_eq!(park, Park::Wait);
                assert!(pool.idle().is_idle(1));

                // Worker zero's return is the last, so it claims worker one.
                holder.leave_search();
                assert!(!pool.idle().is_idle(1) && notified(&pool, 1));
                searcher.finish_park();
            } else {
                // With no count held, worker one takes one and withdraws to search.
                assert_eq!(park, Park::Search);
                assert!(!pool.idle().is_idle(1));
            }

            // Either way, worker one holds a count and steals the backlog.
            assert!(searcher.searching);
            assert!(searcher.search(&mut one));
            searcher.leave_search();
            assert_eq!(pool.idle().search_count(), 0);

            drop((holder, searcher));
            release(&pool, &mut [&mut zero, &mut one, &mut two], tasks);
        }
    }

    /// A worker whose last look sees the global queue runs, and its look
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
        assert!(!pool.idle().is_idle(0) && notified(&pool, 0));
        assert!(pool.idle().is_idle(1) && !notified(&pool, 1));
        assert_eq!(pool.idle().search_count(), 2);

        // Worker zero resumes with the claim's count, takes a share, and
        // returns the count before polling. The return is not the last.
        zero.finish_park();
        pool.take(&mut r0).unwrap().discard();
        zero.leave_search();
        assert!(pool.idle().is_idle(1) && !notified(&pool, 1));
        assert_eq!(pool.idle().search_count(), 1);

        // Worker two parks and returns the last count. Its look sees the
        // global queue, so it runs and hands the duty on to worker one.
        assert_eq!(two.prepare_park(&r2), Park::Run);
        assert!(!two.searching);
        assert!(!pool.idle().is_idle(1) && notified(&pool, 1));
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

    /// A worker whose empty run queue is pinned by a thief's claim returns
    /// `Wait` with a live publication, since the thief holds a search count. It
    /// searches after the thief frees the slots and hands on the last search
    /// count.
    #[test]
    fn test_parker_without_room_waits_for_the_claiming_thief() {
        let pool = pool(3);
        let set = Tasks::new(1);
        let (mut zero, mut one, mut two) = (ready(&pool, 0), ready(&pool, 1), ready(&pool, 2));
        let mut searcher = Searcher::new(&pool, 0);
        let mut thief = Searcher::new(&pool, 1);

        // Fill worker zero's run queue without kicks.
        let mut tasks = Vec::new();
        for _ in 0..CAPACITY {
            let (task, runnable) = task(&set);
            queue(&mut zero, runnable);
            tasks.push(task);
        }

        // A thief takes a count and pauses while holding a claim on half the queue.
        assert!(thief.begin(false));
        let claim = pool.queue(0).hold_claim(HALF as u32);

        // Worker zero runs the rest of its queue, while the claim pins half its slots.
        while let Some(runnable) = zero.pop() {
            runnable.discard();
        }

        // Worker two's backlog kicks, but the thief's count suppresses the wake.
        tasks.extend(enqueue(&pool, &mut two, &set, KICK));

        // The thief's held count makes worker zero wait rather than search,
        // although a backlog is stealable.
        assert_eq!(zero.room(), 0);
        assert_eq!(searcher.prepare_park(&zero), Park::Wait);
        assert!(pool.idle().is_idle(0) && !notified(&pool, 0));
        assert_eq!(pool.idle().search_count(), 1);

        // The thief finishes its claim, freeing worker zero's slots.
        for runnable in pool.queue(0).finish_claim(claim) {
            runnable.discard();
        }

        // The thief's return is the last and hands the duty on to worker zero.
        thief.leave_search();
        assert!(!pool.idle().is_idle(0) && notified(&pool, 0));

        // Worker zero resumes with the count its wake took and steals the backlog.
        searcher.finish_park();
        assert!(searcher.search(&mut zero));
        searcher.leave_search();
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
        let mut searcher = Searcher::new(&pool, 1);
        assert_eq!(searcher.prepare_park(&one), Park::Wait);

        // The drop withdraws the live publication.
        drop(searcher);
        assert!(!pool.idle().is_idle(1));

        // Published, then claimed by a push.
        let mut searcher = Searcher::new(&pool, 1);
        assert_eq!(searcher.prepare_park(&one), Park::Wait);

        // The push clears the worker's bit and reserves a count for it.
        let task = push(&pool, &set);
        assert!(!pool.idle().is_idle(1));
        assert_eq!(pool.idle().search_count(), 1);

        // The drop withdraws, taking the count the claim brought, and returns it.
        drop(searcher);
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
            let (candidate, ready, _) = &mut *parts[1].borrow_mut();
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
                let (later, ready, _) = &mut *part.borrow_mut();
                assert_eq!(later.prepare_park(ready), Park::Wait);
            }
        });

        // Worker zero's kick fails its claim, returns the last count, and looks
        // again, so it claims worker two.
        let tasks = enqueue(pool, &mut parts[0].borrow_mut().1, &set, KICK);
        assert!(!pool.idle().is_idle(2) && notified(pool, 2));

        // Worker two resumes with the count and steals, leaving a clean idle state.
        let (later, ready, _) = &mut *parts[2].borrow_mut();
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
            let (candidate, ready, _) = &mut *parts[1].borrow_mut();
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
                kicked
                    .borrow_mut()
                    .extend(enqueue(pool, &mut owner.borrow_mut().1, &set, KICK));

                // Then worker two parks, leaving the backlog to the held count.
                let (later, ready, _) = &mut *later.borrow_mut();
                assert_eq!(later.prepare_park(ready), Park::Wait);
            }
        });

        // The push's wake fails its claim, returns the last count, and looks
        // again, so it claims worker two.
        let pushed = push(pool, &set);
        assert!(!pool.idle().is_idle(2) && notified(pool, 2));

        // Worker two resumes with the count and steals the kicked backlog.
        let (later, ready, _) = &mut *parts[2].borrow_mut();
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
    /// a count to search brings a second count. The worker returns that count,
    /// keeps its own, and runs again.
    #[test]
    fn test_global_claim_of_a_worker_about_to_search_leaves_one_count() {
        let (pool, parts) = leaked(2);
        let set = Tasks::new(1);

        // Worker one holds a backlog queued without a kick.
        let mut tasks = Vec::new();
        for _ in 0..KICK {
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

        // Worker zero returns the claim's count, keeping its own, and runs again.
        let (searcher, ready, _) = &mut *parts[0].borrow_mut();
        assert_eq!(searcher.prepare_park(ready), Park::Run);
        assert!(notified(pool, 0));
        assert_eq!(pool.idle().search_count(), 1);

        // The kept count covers the steal, and its return leaves a clean idle state.
        assert!(searcher.search(ready));
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..2).all(|index| !pool.idle().is_idle(index)));

        tasks.push(pushed);
        release(pool, &mut [ready, &mut parts[1].borrow_mut().1], tasks);
    }

    /// A push into the global queue that claims a parking worker after it took
    /// a count to search sends it back to run, even though the backlog is gone.
    /// The worker does not search or publish again under the observation the
    /// claim moved, so one last look collects at most one claim.
    #[test]
    fn test_claim_of_a_worker_about_to_search_ends_its_last_look() {
        let (pool, parts) = leaked(2);
        let set = Tasks::new(1);

        // Worker zero holds a stealable backlog queued without a kick.
        let mut tasks = Vec::new();
        for _ in 0..KICK {
            let (task, runnable) = task(&set);
            queue(&mut parts[0].borrow_mut().1, runnable);
            tasks.push(task);
        }

        // Once worker one takes a count to search, a push claims it, another
        // worker takes the pushed runnable, and worker zero drains its backlog.
        let (pushed, runnable) = task(&set);
        tasks.push(pushed);
        on_wake_point(WakePoint::BeforeParkSearch, {
            let victim = parts[0].clone();
            move || {
                assert!(pool.push(runnable).is_ok());
                pool.pop().unwrap().discard();
                victim.borrow_mut().1.discard();
            }
        });

        // The claim ends the last look: worker one is unpublished, notified,
        // and holds one count.
        let (searcher, ready, _) = &mut *parts[1].borrow_mut();
        assert!(searcher.publish_and_look(ready));
        assert!(notified(pool, 1));
        assert!(!pool.idle().is_idle(1));
        assert_eq!(pool.idle().search_count(), 1);

        // Returning that count leaves a clean idle state.
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..2).all(|index| !pool.idle().is_idle(index)));

        release(pool, &mut [ready, &mut parts[0].borrow_mut().1], tasks);
    }

    /// A worker a push claimed can resume on an independent wake before the
    /// push notifies it. It then withdraws with the count the claim brought,
    /// returns it, and publishes again, and the late notification ends its
    /// next wait with no claim and no count, while a later claim brings one as
    /// usual.
    #[test]
    fn test_late_notification_of_a_claim_brings_no_count() {
        let (pool, parts) = leaked(2);
        let unparker = &pool.mailbox(1).unparker;

        // Worker one finds no work and publishes itself parked.
        {
            let (searcher, ready, _) = &mut *parts[1].borrow_mut();
            assert_eq!(searcher.prepare_park(ready), Park::Wait);
        }

        // Pause the wake after its claim, so the worker runs before the
        // notification.
        on_wake_point(WakePoint::AfterClaim, {
            let part = parts[1].clone();
            move || {
                // The claim cleared worker one's bit and reserved its count.
                assert_eq!(pool.idle().search_count(), 1);
                assert!(!pool.idle().is_idle(1));

                // An independent wake resumes the claimed worker, which runs
                // its loop and parks again.
                let before = notifications(unparker);
                unparker.unpark();
                assert_eq!(notifications(unparker), before + 1);

                // Its withdrawal keeps the claim's count, and it returns that
                // count before it publishes again.
                let (searcher, ready, _) = &mut *part.borrow_mut();
                searcher.finish_park();
                assert!(searcher.searching);
                searcher.leave_search();
                assert_eq!(pool.idle().search_count(), 0);
                assert_eq!(searcher.prepare_park(ready), Park::Wait);
            }
        });

        // A push's wake claims worker one and runs the hook before it notifies.
        let before = notifications(unparker);
        pool.idle().notify_global(pool.mailboxes());

        // The push's notification follows the hook's independent wake and
        // reaches the new publication, which no wake claimed.
        assert_eq!(notifications(unparker), before + 2);
        assert!(pool.idle().is_idle(1));

        // Its withdrawal finds no claim, so it holds no count, and it parks again.
        {
            let (searcher, ready, _) = &mut *parts[1].borrow_mut();
            searcher.finish_park();
            assert!(!searcher.searching);
            assert_eq!(pool.idle().search_count(), 0);
            assert_eq!(searcher.prepare_park(ready), Park::Wait);
        }

        // A fresh claim notifies once and brings one count.
        let before = notifications(unparker);
        pool.idle().notify_global(pool.mailboxes());
        assert_eq!(notifications(unparker), before + 1);
        let (searcher, _, _) = &mut *parts[1].borrow_mut();
        searcher.finish_park();
        assert!(searcher.searching);

        // Returning that count leaves a clean idle state.
        searcher.leave_search();
        assert_eq!(pool.idle().search_count(), 0);
        assert!((0..2).all(|index| !pool.idle().is_idle(index)));
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::{
        tests::{WakePoint, clear_wake_hooks, on_wake_point},
        *,
    };
    use crate::iouring::{
        park::Parker,
        pool::{
            Pool,
            tests::{aged_pool, pool, ready, task},
        },
        task::{AfterPoll, Runnable, Task, tests::refs},
        tasks::Tasks,
    };
    use loom::{cell::Cell, thread};
    use std::{rc::Rc, time::Duration};

    /// A pool of `workers` workers with no runner, whose lone runnables are
    /// stealable once `steal_age` has passed since a look first saw them,
    /// and the parker of worker `index`. The other parkers are dropped, so
    /// only that worker waits.
    fn pool_with_parker(workers: usize, steal_age: Duration, index: usize) -> (Pool, Parker) {
        let (pool, mut parkers) = Pool::new(workers, steal_age);
        (pool, parkers.swap_remove(index))
    }

    /// Runs of the tasks a model queues: per task and in all, with a
    /// condition variable for an owner that blocks until enough have run.
    struct Runs {
        /// Polls of each task.
        each: Vec<AtomicUsize>,
        /// Polls of all tasks.
        all: loom::sync::Mutex<usize>,
        /// Signalled on every poll.
        ran: loom::sync::Condvar,
    }

    impl Runs {
        /// No runs yet of `tasks` tasks.
        fn new(tasks: usize) -> Arc<Self> {
            Arc::new(Self {
                each: (0..tasks).map(|_| AtomicUsize::new(0)).collect(),
                all: loom::sync::Mutex::new(0),
                ran: loom::sync::Condvar::new(),
            })
        }

        /// Polls of all tasks so far.
        fn total(&self) -> usize {
            *self.all.lock().unwrap()
        }

        /// Block until `count` polls have run.
        fn wait(&self, count: usize) {
            let mut all = self.all.lock().unwrap();
            while *all < count {
                all = self.ran.wait(all).unwrap();
            }
        }

        /// Whether every task ran exactly once.
        fn exactly_once(&self) -> bool {
            self.each
                .iter()
                .all(|runs| runs.load(Ordering::Relaxed) == 1)
        }
    }

    /// Queue tasks `range` of `runs` in `ready` through `Pool::enqueue`, as a
    /// worker's own wakes do, so a push that leaves [`KICK`] queued kicks.
    /// Each task completes on its first poll, recording it.
    fn enqueue_runs(
        pool: &Arc<Pool>,
        set: &Tasks,
        ready: &mut Ready,
        runs: &Arc<Runs>,
        range: std::ops::Range<usize>,
    ) -> Vec<Task> {
        queue_runs(pool, set, ready, runs, range, false)
    }

    /// Queue tasks as [`enqueue_runs`] does, through
    /// `Pool::enqueue_spawned`, as a spawn does, if `spawned` is set.
    fn queue_runs(
        pool: &Arc<Pool>,
        set: &Tasks,
        ready: &mut Ready,
        runs: &Arc<Runs>,
        range: std::ops::Range<usize>,
        spawned: bool,
    ) -> Vec<Task> {
        range
            .map(|index| {
                let runs = runs.clone();
                let future = std::future::poll_fn(move |_| {
                    runs.each[index].fetch_add(1, Ordering::Relaxed);
                    *runs.all.lock().unwrap() += 1;
                    runs.ran.notify_all();
                    std::task::Poll::Ready(())
                });
                let (task, runnable) = Task::new(future, set, Arc::downgrade(pool));
                assert!(set.insert(task.clone()).is_ok());
                if spawned {
                    pool.enqueue_spawned(ready, runnable);
                } else {
                    pool.enqueue(ready, runnable);
                }
                task
            })
            .collect()
    }

    /// Poll every runnable in `ready`, the calling worker's run queue. The
    /// poll that completes the last task of `runs` notifies every worker of
    /// `pool`, so none waits for work that no longer exists.
    fn run_queued(pool: &Pool, set: &Tasks, ready: &mut Ready, runs: &Runs) {
        while let Some(runnable) = ready.pop() {
            match runnable.poll(set.id()) {
                AfterPoll::Retire(task) => drop(set.remove(&task)),
                _ => panic!("a model task completes on its first poll"),
            }
            if runs.total() == runs.each.len() {
                for worker in 0..pool.workers() as u32 {
                    pool.mailbox(worker).unparker.unpark();
                }
            }
        }
    }

    /// Run worker `index` of `pool`, whose word `parker` owns, through the
    /// drive loop's search, park and retry until every task of `runs` has
    /// run: search while holding a count, then publish and look, running
    /// whatever either finds, and otherwise wait for a wake. A wait after a
    /// look that refused a young lone runnable times out when it ripens, which
    /// the model clock stands for: the clock moves there, and the worker looks
    /// again. A wake before then would only repeat the refusing look, or bring
    /// a claim's count that the next search uses as the re-look's would be.
    fn search_until_done(
        pool: &Pool,
        set: &Tasks,
        searcher: &mut Searcher<'_>,
        parker: &Parker,
        index: u32,
        runs: &Runs,
    ) {
        let mut ready = pool.queue(index).owner();
        while runs.total() < runs.each.len() {
            let seen = parker.observe();
            if searcher.search(&mut ready) || searcher.publish_and_look(&mut ready) {
                searcher.leave_search();
                run_queued(pool, set, &mut ready, runs);
                continue;
            }
            if runs.total() < runs.each.len() {
                match searcher.relook() {
                    Some(relook) => pool.advance_clock_to(relook),
                    None => {
                        parker.park(seen, None);
                    }
                }
            }
            searcher.finish_park();
        }
    }

    /// Check what every model leaves behind: each task ran exactly once, the
    /// search count and idle bits are restored, the owner's run queue is
    /// empty, and only the set's reference to each task remains.
    fn check_done(pool: &Pool, runs: &Runs, owner: &Ready, tasks: Vec<Task>) {
        assert!(runs.exactly_once());
        assert_eq!(pool.idle().searching.load(Ordering::Relaxed), 0);
        assert_eq!(pool.idle().set.load(Ordering::Relaxed), 0);
        assert!(owner.is_empty());
        for task in tasks {
            assert_eq!(refs(&task), 1);
        }
    }

    /// A searcher's released claim reaches the last return of a search count.
    /// Worker zero queued four runnables while both peers held counts, so its
    /// kicks left the backlog to them. Worker one steals and returns its count
    /// while worker two parks. If worker one still holds its count, its return
    /// must wake worker two. Otherwise worker two's last look must see what
    /// the released claim left and search rather than wait. A lost handoff
    /// leaves worker two waiting, which loom reports as a deadlock.
    ///
    /// This model stands in for the task loop model
    /// `test_search_return_publishes_the_steal_to_the_last_return` on ordinary
    /// run queues, where that model has too many schedules to explore. The
    /// bug that model exists to find is a lost handoff between a thief's
    /// released claim and the last return of a search count, which strands a
    /// backlog with every remaining worker parked. Only four operations take
    /// part in that handoff: the claim release (an exchange on the victim's
    /// head), the thief's count return in `Searcher::end_search` (a Release
    /// decrement, then a kick when it was the last), the parking worker's
    /// count return and fence in `Searcher::prepare_park`, and its look at
    /// the other run queues with the search it starts. This model starts from
    /// the state the task loop model reaches before the handoff, a backlog
    /// behind two held counts with its owner blocked, and explores every
    /// interleaving of those operations with no preemption bound, the parking
    /// worker's wait and wake included. The task loop model adds task polls,
    /// completion counting and a worker driving the whole loop, none of which
    /// reads or writes the head, the count or the idle set at a different
    /// point of the handoff, so a schedule that loses the handoff there loses
    /// it here as well. Weakening the Release in `Searcher::end_search` to
    /// Relaxed makes this model deadlock.
    /// `test_ceil_steal_continues_to_the_last_lone_runnable` covers the search,
    /// retry, execution and next park that follow on ordinary run queues, and
    /// the task loop model still runs on rounding-down run queues.
    #[test]
    fn test_last_search_return_observes_a_released_claim() {
        loom::model(|| {
            let (pool, parker) = pool_with_parker(3, Duration::ZERO, 2);
            let pool = std::sync::Arc::new(pool);
            let set = Tasks::new(1);
            let mut owner = pool.queue(0).owner();
            let tasks: Vec<_> = (0..4)
                .map(|_| {
                    let (task, runnable) = Task::new(
                        std::future::pending::<()>(),
                        &set,
                        std::sync::Arc::downgrade(&pool),
                    );
                    pool.enqueue(&mut owner, runnable);
                    task
                })
                .collect();

            // Model both peers holding counts after empty searches. Neither
            // peer published an idle bit for the enqueues above to claim.
            pool.idle().searching.store(2, Ordering::Relaxed);
            let thief = thread::spawn({
                let pool = pool.clone();
                move || {
                    let mut ready = pool.queue(1).owner();
                    let mut searcher = Searcher::new(&pool, 1);
                    searcher.searching = true;
                    assert!(pool.steal(1, 0, &mut ready, &mut None));
                    searcher.leave_search();
                    ready.discard();
                }
            });
            let last = thread::spawn({
                let pool = pool.clone();
                move || {
                    let mut ready = pool.queue(2).owner();
                    let mut searcher = Searcher::new(&pool, 2);
                    searcher.searching = true;
                    let seen = parker.observe();
                    match searcher.prepare_park(&ready) {
                        // Worker one's return, if still to come, must wake it.
                        Park::Wait => {
                            parker.park(seen, None);
                            searcher.finish_park();
                        }
                        // A search may still lose to a claim, but it is the
                        // worker's own retry rather than a wait.
                        Park::Search => {}
                        Park::Run => panic!("the global queue is empty"),
                    }
                    searcher.leave_search();
                    ready.discard();
                }
            });
            thief.join().unwrap();
            last.join().unwrap();
            assert_eq!(pool.idle().searching.load(Ordering::Relaxed), 0);
            owner.discard();
            for task in tasks {
                assert_eq!(refs(&task), 1);
                task.clear();
            }
        });
    }

    /// A worker's last look before parking finds a lone runnable, which a
    /// claim rounded up can take, while its owner pops it. The pop's exchange
    /// and the claim's arbitrate, so the runnable is taken exactly once, and
    /// the parking worker searches or waits without leaving a search count or
    /// an idle bit behind.
    #[test]
    fn test_parking_look_and_owner_pop_race_for_a_lone_runnable() {
        loom::model(|| {
            let pool = std::sync::Arc::new(pool(2));
            let set = Tasks::new(1);
            let mut owner = pool.queue(0).owner();
            let (task, runnable) = Task::new(
                std::future::pending::<()>(),
                &set,
                std::sync::Arc::downgrade(&pool),
            );
            // A lone push kicks no worker.
            pool.enqueue(&mut owner, runnable);

            let parker = thread::spawn({
                let pool = pool.clone();
                move || {
                    let mut ready = pool.queue(1).owner();
                    let mut searcher = Searcher::new(&pool, 1);
                    let mut stolen = Vec::new();
                    match searcher.prepare_park(&ready) {
                        Park::Search => {
                            if searcher.search(&mut ready) {
                                stolen.extend(std::iter::from_fn(|| ready.pop()));
                            }
                            searcher.leave_search();
                        }
                        Park::Wait => searcher.finish_park(),
                        Park::Run => panic!("the global queue is empty"),
                    }
                    stolen
                }
            });

            let mut taken: Vec<Runnable> = owner.pop().into_iter().collect();
            taken.extend(parker.join().unwrap());
            assert_eq!(taken.len(), 1, "the lone runnable is taken exactly once");
            assert_eq!(pool.idle().searching.load(Ordering::Relaxed), 0);
            assert_eq!(pool.idle().set.load(Ordering::Relaxed), 0);
            task.clear();
            for runnable in taken {
                runnable.discard();
            }
        });
    }

    /// A ceil steal continues through the search count protocol to the last
    /// lone runnable. Worker zero queued three runnables while both peers held
    /// search counts, so its kicks left them to the peers, and it blocks as in
    /// a long poll until all three have run, which only the peers can do.
    /// Worker one searches once, taking half the backlog rounded up, returns
    /// its count and runs what it took. Worker two searches, parks and
    /// retries as the drive loop does. Whichever of them returns the last
    /// count either finds the lone remainder in its last look or wakes the
    /// other, so worker two takes it. A lost handoff leaves worker two parked
    /// and worker zero blocked, which loom reports as a deadlock. Every task
    /// runs exactly once, and the search counts and idle bits are restored.
    #[test]
    fn test_ceil_steal_continues_to_the_last_lone_runnable() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let (pool, parker) = pool_with_parker(3, Duration::ZERO, 2);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(3);
            let mut owner = pool.queue(0).owner();
            pool.idle().searching.store(2, Ordering::Relaxed);
            let tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..3);

            let first = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut ready = pool.queue(1).owner();
                    let mut searcher = Searcher::new(&pool, 1);
                    searcher.searching = true;
                    let _ = searcher.search(&mut ready);
                    searcher.leave_search();
                    run_queued(&pool, &set, &mut ready, &runs);
                }
            });
            let last = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 2);
                    searcher.searching = true;
                    search_until_done(&pool, &set, &mut searcher, &parker, 2, &runs);
                }
            });
            runs.wait(3);
            first.join().unwrap();
            last.join().unwrap();
            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A lone push races a worker's last look before parking, then a second
    /// push reaches the kick threshold. The lone runnable may stay with its
    /// owner, which takes it back unless the parking worker's look stole it
    /// first. The backlog of two must then be taken or offered: the owner
    /// blocks as in a long poll until one of them has run on the other
    /// worker, which searches, parks and retries as the drive loop does. A
    /// backlog left behind with the other worker parked deadlocks, which loom
    /// reports. Every task runs exactly once, and the search count and idle
    /// bits are restored.
    #[test]
    fn test_lone_push_racing_the_last_look_then_a_kick() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(3);
        builder.check(|| {
            let (pool, parker) = pool_with_parker(2, Duration::ZERO, 1);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(3);
            let parking = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 1);
                    search_until_done(&pool, &set, &mut searcher, &parker, 1, &runs);
                }
            });

            let mut owner = pool.queue(0).owner();
            let mut tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..1);
            run_queued(&pool, &set, &mut owner, &runs);
            tasks.extend(enqueue_runs(&pool, &set, &mut owner, &runs, 1..3));
            runs.wait(2);
            run_queued(&pool, &set, &mut owner, &runs);
            parking.join().unwrap();
            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A lone runnable queued behind a long poll is young when the other
    /// worker first looks, so that look takes no count for it and leaves a
    /// re-look deadline, and the worker waits only until then. Its owner blocks
    /// as in a long poll until the runnable has run, which only the re-look can
    /// do. A worker that waited without the deadline would stay parked, which
    /// loom reports as a deadlock. The runnable runs exactly once, and the
    /// search count and idle bits are restored.
    #[test]
    fn test_young_lone_runnable_is_taken_on_the_relook() {
        loom::model(|| {
            let (pool, parker) = pool_with_parker(2, Duration::from_micros(50), 1);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(1);
            let mut owner = pool.queue(0).owner();
            let tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..1);

            let thief = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 1);
                    search_until_done(&pool, &set, &mut searcher, &parker, 1, &runs);
                }
            });
            runs.wait(1);
            thief.join().unwrap();

            // The owner never pops, so only a re-look once the steal age had
            // passed on the model clock can have taken the runnable.
            assert!(pool.model_clock() >= 50);
            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A young lone runnable that the other worker's look refused goes back
    /// to its owner, whose pop races that worker's re-look. The pop and the
    /// claim arbitrate, so the runnable runs exactly once, and no count or
    /// idle bit is left behind.
    #[test]
    fn test_owner_pop_races_the_relook_of_a_young_lone_runnable() {
        loom::model(|| {
            let (pool, parker) = pool_with_parker(2, Duration::from_micros(50), 1);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(1);
            let mut owner = pool.queue(0).owner();
            let tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..1);

            let thief = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 1);
                    search_until_done(&pool, &set, &mut searcher, &parker, 1, &runs);
                }
            });
            run_queued(&pool, &set, &mut owner, &runs);
            runs.wait(1);
            thief.join().unwrap();
            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A new task's first runnable that a spawn queued alone behind a long
    /// poll is ripe at once, however long the steal age. The other worker's
    /// look takes a count for it and steals it, and its owner blocks until it
    /// has run, so only that steal can run it. The model clock never moves,
    /// so no re-look took it. The runnable runs exactly once, and the search
    /// count and idle bits are restored.
    #[test]
    fn test_spawned_lone_runnable_is_taken_at_once() {
        loom::model(|| {
            let (pool, parker) = pool_with_parker(2, Duration::from_micros(50), 1);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(1);
            let mut owner = pool.queue(0).owner();
            let tasks = queue_runs(&pool, &set, &mut owner, &runs, 0..1, true);

            let thief = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 1);
                    search_until_done(&pool, &set, &mut searcher, &parker, 1, &runs);
                }
            });
            runs.wait(1);
            thief.join().unwrap();
            assert_eq!(
                pool.model_clock(),
                0,
                "the spawned runnable waited to ripen"
            );
            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A re-look races a kick. The other worker's look refuses a young lone
    /// runnable, taking no count for it, and waits for its re-look, while the
    /// owner, blocked as in a long poll until one runnable has run elsewhere,
    /// pushes a second one. That push's kick can find the worker's count of a
    /// failed search held, claim the worker while it waits for its re-look,
    /// or lose its claim to the worker resuming for a due re-look, which takes
    /// a count past the cap. Either way the worker searches with exactly one
    /// count and takes a runnable, so the owner resumes. A lost handoff leaves
    /// the worker parked and the owner blocked, which loom reports as a
    /// deadlock, and a second count or a leaked one fails the final checks.
    /// The owner then runs what is left, racing the worker's next re-look.
    #[test]
    fn test_relook_races_a_kick() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let (pool, parker) = pool_with_parker(2, Duration::from_micros(50), 1);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(2);
            let mut owner = pool.queue(0).owner();
            let mut tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..1);

            let thief = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 1);
                    search_until_done(&pool, &set, &mut searcher, &parker, 1, &runs);
                }
            });
            tasks.extend(enqueue_runs(&pool, &set, &mut owner, &runs, 1..2));
            runs.wait(1);
            run_queued(&pool, &set, &mut owner, &runs);
            runs.wait(2);
            thief.join().unwrap();
            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A worker woken before its re-look has come due, which the cap then
    /// refuses, keeps the re-look, so it still waits no longer than that. With
    /// two other counts held in a pool of four, its search reads no queue, and
    /// its look leaves the backlog to the count holders, but its wait remains
    /// bounded by the lone runnable's ripening. The re-look can come due right
    /// after the cap refused it, as when its deadline passes between the
    /// search's clock sample and its cap check. The wait then returns at once,
    /// and the next search sees the re-look due, passes the cap and steals.
    ///
    /// One thread runs this model, so loom explores no race in it. It runs
    /// under loom for the model clock, which moves only where the model
    /// advances it, so a stalled test thread cannot bring the re-look due
    /// before the cap check.
    #[test]
    fn test_early_relook_refused_by_the_cap_keeps_its_deadline() {
        loom::model(|| {
            let pool = aged_pool(4, Duration::from_micros(50));
            let set = Tasks::new(1);
            let mut readies: Vec<Ready> = (0..4).map(|index| ready(&pool, index)).collect();
            let (lone, runnable) = task(&set);
            pool.enqueue(&mut readies[0], runnable);
            let mut searcher = Searcher::new(&pool, 1);

            // The first look refuses the young lone runnable.
            assert!(!searcher.search(&mut readies[1]));
            let relook = searcher
                .relook()
                .expect("the young lone runnable is looked at again");
            searcher.leave_search();

            // Woken early, with two other workers holding the counts the cap
            // allows, the worker cannot search.
            pool.idle().searching.fetch_add(2, Ordering::Relaxed);
            assert!(!searcher.search(&mut readies[1]));

            // The re-look comes due right after the refusal. The look leaves
            // the backlog to the count holders and keeps the re-look, which
            // has passed, so the wait returns at once.
            pool.advance_clock_to(relook);
            assert_eq!(searcher.prepare_park(&readies[1]), Park::Wait);
            assert_eq!(searcher.relook(), Some(relook));
            assert!(relook <= pool.now());
            searcher.finish_park();

            // The next search sees the re-look due, so it takes a count past
            // the cap and steals the now ripe runnable.
            assert!(searcher.search(&mut readies[1]));
            assert_eq!(pool.idle().search_count(), 3);
            assert_eq!(searcher.relook(), None);
            searcher.leave_search();
            pool.idle().searching.fetch_sub(2, Ordering::Relaxed);
            assert_eq!(pool.idle().search_count(), 0);
            assert_eq!(readies[1].len(), 1);

            drop(searcher);
            for ready in &mut readies {
                ready.discard();
            }
            lone.clear();
        });
    }

    /// A count taken by the exchange in the look of [`Searcher::prepare_park`]
    /// hands on what its steal left. Worker zero queued three runnables before
    /// its peers started, so its kicks found nobody, and it blocks as in a long
    /// poll until all three ran elsewhere. Worker one publishes and looks once,
    /// takes a count by that exchange and steals two, then returns its count,
    /// runs what it took and stops, as a worker that enters a long poll would.
    /// Worker two searches, parks and retries. If it parked on worker one's
    /// count, the return of that last count must wake it. Otherwise the
    /// remainder stays queued with every worker blocked, which loom reports as
    /// a deadlock.
    ///
    /// Worker one's look loads the count before its exchange takes it, and
    /// loom does not move such an exchange ahead of a load of another thread
    /// that it scheduled earlier. The owner blocks before either worker runs,
    /// and worker one is spawned first, so loom's first schedule runs worker
    /// one's exchange before worker two starts. Backtracking then moves worker
    /// two's scan and park, which read what worker one writes, between worker
    /// one's exchange and its return, where worker two parks on worker one's
    /// count. Skipping the kick of that count's last return makes this model
    /// deadlock.
    #[test]
    fn test_count_taken_in_a_look_hands_on_its_remainder() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let (pool, parker) = pool_with_parker(3, Duration::ZERO, 2);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(3);
            let mut owner = pool.queue(0).owner();
            let tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..3);

            // Worker one looks once, steals with the count its look took, and
            // stops as for a long poll.
            let first = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut ready = pool.queue(1).owner();
                    let mut searcher = Searcher::new(&pool, 1);
                    if searcher.publish_and_look(&mut ready) {
                        searcher.leave_search();
                        run_queued(&pool, &set, &mut ready, &runs);
                    } else {
                        searcher.finish_park();
                    }
                }
            });

            // Worker two searches, parks and retries as the drive loop does.
            let last = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 2);
                    search_until_done(&pool, &set, &mut searcher, &parker, 2, &runs);
                }
            });

            // The owner blocks as in a long poll until all three ran elsewhere.
            runs.wait(3);
            first.join().unwrap();
            last.join().unwrap();

            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// A kick whose claim fails looks again for a worker that published since.
    /// Worker one publishes and looks before any work exists, and its wait then
    /// returns for a reason of its own, as for its I/O, so it withdraws without
    /// searching. Worker zero queues two runnables, whose second push kicks
    /// and can find only worker one's bit, and blocks as in a long poll until
    /// one of them ran elsewhere, then runs the rest. Worker two searches,
    /// parks and retries, and can park on the kick's reservation after the
    /// claim failed. If the kick returned that count without looking again,
    /// worker two would stay parked with worker zero blocked, which loom
    /// reports as a deadlock.
    ///
    /// The kick loads the count and the idle set before its exchanges on them,
    /// and loom does not move such an exchange ahead of a load of another
    /// thread that it scheduled earlier. The kick runs on the main thread,
    /// which loom's first schedule runs until it blocks, so the kick comes
    /// before the workers' loads. Backtracking then moves worker one's
    /// publication ahead of the kick's look at the idle set and its withdrawal
    /// between that look and the claim, since loom explores another thread's
    /// write between a load and the exchange that follows it, and worker two's
    /// park after the kick's reservation. Returning after a failed claim
    /// without looking again makes this model deadlock.
    #[test]
    fn test_failed_claim_looks_again_for_a_later_publication() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let (pool, parker) = pool_with_parker(3, Duration::ZERO, 2);
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(2);
            let mut owner = pool.queue(0).owner();

            // Worker one parks once and withdraws without waiting, as for its
            // I/O, unless its look saw the backlog and sent it to search.
            let busy = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut ready = pool.queue(1).owner();
                    let mut searcher = Searcher::new(&pool, 1);
                    match searcher.prepare_park(&ready) {
                        Park::Wait => searcher.finish_park(),
                        Park::Search => {
                            if searcher.search(&mut ready) {
                                searcher.leave_search();
                                run_queued(&pool, &set, &mut ready, &runs);
                            }
                        }
                        Park::Run => panic!("the global queue is empty"),
                    }
                }
            });

            // Worker two searches, parks and retries as the drive loop does.
            let last = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut searcher = Searcher::new(&pool, 2);
                    search_until_done(&pool, &set, &mut searcher, &parker, 2, &runs);
                }
            });

            // The owner's second push kicks. The owner then blocks as in a long
            // poll until one runnable ran elsewhere, and runs the rest.
            let tasks = enqueue_runs(&pool, &set, &mut owner, &runs, 0..2);
            runs.wait(1);
            run_queued(&pool, &set, &mut owner, &runs);
            runs.wait(2);
            busy.join().unwrap();
            last.join().unwrap();

            check_done(&pool, &runs, &owner, tasks);
        });
    }

    /// The wake of a push into the global queue whose claim fails looks again
    /// for a worker that published since. A push from outside the pool can
    /// find only worker zero's bit. Worker zero publishes and looks once: its
    /// look sees the push and withdraws, or it waits until the push claims it.
    /// It then runs the pushed runnable, whose work queues two runnables in
    /// worker zero's own run queue and blocks as in a long poll until one of
    /// them ran elsewhere. Worker one starts once the push is taken, so its
    /// looks never find the global queue nonempty, and searches, parks and
    /// retries as the drive loop does. While the push's reservation is held,
    /// its look waits without reading the run queues. If the push returned
    /// that count without looking again, worker one would stay parked with
    /// worker zero blocked, which loom reports as a deadlock.
    ///
    /// The push runs on the main thread, which loom's first schedule runs
    /// until it blocks, so the push's look at the idle set comes before
    /// worker zero publishes. Backtracking then moves worker zero's turn,
    /// from its publication to its long poll, ahead of that look, which can
    /// still read worker zero's withdrawn bit, since nothing orders the
    /// withdrawal before that relaxed load. The claim then fails, and
    /// backtracking moves worker one's park ahead of the push's return of its
    /// count, since that park reads the count. Returning after a failed claim
    /// without looking again makes this model deadlock.
    #[test]
    fn test_failed_global_claim_looks_again_for_a_later_publication() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let (pool, parkers) = Pool::new(2, Duration::ZERO);
            let mut parkers = parkers.into_iter();
            let (first, second) = (parkers.next().unwrap(), parkers.next().unwrap());
            let pool = Arc::new(pool);
            let set = Arc::new(Tasks::new(1));
            let runs = Runs::new(2);

            // Worker zero parks once, then runs the push and the work it queues.
            let owner = thread::spawn({
                let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                move || {
                    let mut ready = pool.queue(0).owner();
                    let mut searcher = Searcher::new(&pool, 0);
                    let seen = first.observe();
                    match searcher.prepare_park(&ready) {
                        Park::Run => {}
                        Park::Wait => {
                            first.park(seen, None);
                            searcher.finish_park();
                        }
                        Park::Search => panic!("no run queue holds a backlog yet"),
                    }
                    searcher.leave_search();
                    pool.pop().expect("the push is queued").discard();

                    // Worker one searches, parks and retries as the drive loop
                    // does.
                    let last = thread::spawn({
                        let (pool, set, runs) = (pool.clone(), set.clone(), runs.clone());
                        move || {
                            let mut searcher = Searcher::new(&pool, 1);
                            search_until_done(&pool, &set, &mut searcher, &second, 1, &runs);
                        }
                    });

                    // The pushed runnable's second push kicks. It then blocks
                    // as in a long poll until one runnable ran elsewhere, and
                    // worker zero runs the rest.
                    let tasks = enqueue_runs(&pool, &set, &mut ready, &runs, 0..2);
                    runs.wait(1);
                    run_queued(&pool, &set, &mut ready, &runs);
                    runs.wait(2);
                    last.join().unwrap();
                    (ready, tasks)
                }
            });

            // The push can find only worker zero's bit.
            let (pushed, runnable) =
                Task::new(std::future::pending::<()>(), &set, Arc::downgrade(&pool));
            assert!(pool.push(runnable).is_ok());
            let (ready, tasks) = owner.join().unwrap();

            check_done(&pool, &runs, &ready, tasks);
            assert_eq!(refs(&pushed), 1);
            pushed.clear();
        });
    }

    /// A claimed worker returns the count its wake reserved only after that
    /// reservation. The claim's exchange releases the reservation and the
    /// worker's withdrawal acquires it, even when the worker withdraws before
    /// the wake unparks it. Every write to the count is a read-modify-write,
    /// which loom resolves to the newest value, so the count alone cannot
    /// show a return ordered before the reservation. A cell that the wake
    /// writes after its reservation, before its claim, and that the worker
    /// reads right after a withdrawal that found it claimed, checks the
    /// handshake instead: without it, loom reports the read as a causality
    /// violation.
    ///
    /// Worker one publishes and looks once while a push from outside the pool
    /// tries to claim it. Its look sees the push, or its wait returns for a
    /// reason of its own, as for its I/O. Either way it withdraws without
    /// waiting, so the push's unpark cannot order the read by another route.
    /// Only the push claims, and worker one publishes once, so each hook point
    /// is reached at most once. The hooks live in a thread local that every
    /// loom thread of an execution shares and that outlives executions, so
    /// each execution starts and ends by clearing them. Weakening the claim's
    /// release or the withdrawal's acquire to Relaxed makes the read a
    /// causality violation.
    #[test]
    fn test_claimed_withdrawal_follows_the_reservation() {
        loom::model(|| {
            clear_wake_hooks();
            let pool = Arc::new(pool(2));
            let set = Tasks::new(1);
            let reserved = Rc::new(Cell::new(false));
            on_wake_point(WakePoint::BeforeClaim, {
                let reserved = reserved.clone();
                move || reserved.set(true)
            });
            on_wake_point(WakePoint::AfterClaimedWithdrawal, move || {
                assert!(reserved.get(), "a claim follows its reservation");
            });

            // Worker one publishes and looks once, then withdraws without
            // waiting.
            let worker = thread::spawn({
                let pool = pool.clone();
                move || {
                    let ready = pool.queue(1).owner();
                    let mut searcher = Searcher::new(&pool, 1);
                    match searcher.prepare_park(&ready) {
                        Park::Run => {}
                        Park::Wait => searcher.finish_park(),
                        Park::Search => panic!("no run queue holds a backlog"),
                    }
                    searcher.leave_search();
                }
            });

            let (pushed, runnable) =
                Task::new(std::future::pending::<()>(), &set, Arc::downgrade(&pool));
            assert!(pool.push(runnable).is_ok());
            worker.join().unwrap();
            clear_wake_hooks();

            assert_eq!(pool.idle().searching.load(Ordering::Relaxed), 0);
            assert_eq!(pool.idle().set.load(Ordering::Relaxed), 0);
            pool.pop().expect("the push is queued").discard();
            assert_eq!(refs(&pushed), 1);
            pushed.clear();
        });
    }
}
