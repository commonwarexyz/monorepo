//! Worker sleep timers, reachable from any thread.
//!
//! # Timers
//!
//! Each worker's sleep registrations live in its [`Timers`]: a mutex over a
//! slab of registrations and a hierarchical wheel of their deadlines
//! ([`Wheel`] with 1024 ns ticks), plus a published bound that is never later
//! than their earliest live firing time. The pool owns every pool worker's
//! timers, so that peers can reach them, and a dedicated worker owns private
//! ones.
//!
//! Timers count time in nanoseconds since their origin, the instant of their
//! creation. Registration converts a deadline to that count, zero for one
//! before the origin, which is due at once, and the wheel rounds it up to its
//! firing time, never before the deadline. A deadline at most [`MAX_TIMEOUT`]
//! ahead stays far below the end of the count, about 584 years after the
//! origin, so rounding never saturates. The published bound and the owner's
//! latest expiry time are counts of the timers' own, so a peer converts its
//! current time for each worker's timers it checks.
//!
//! # Registration and Completion
//!
//! A [`Sleep`] fixes its deadline as an [`Instant`] when it is created, at
//! most [`MAX_TIMEOUT`] ahead, and registers on the worker of its first
//! pending poll, which keeps the registration for life. Every poll first
//! compares the deadline with this thread's latest worker service time: the
//! time at which its worker last started, ran a service pass, or returned from
//! an idle wait, each of which polls can follow before the next service pass.
//! A deadline at or before that time has passed, so the poll completes the
//! sleep at once, wherever it was registered.
//!
//! A first poll otherwise reads the clock and completes a deadline that has
//! passed. One case spares the common timeout that read. A sleep of at least
//! [`UNCHECKED_SLEEP`], on a thread whose service time is not later than the
//! sleep's creation, registers unchecked. That thread's worker has taken no
//! service time since the sleep was created, so the deadline has passed only
//! if the thread has polled for longer than the sleep without serving its
//! timers. The registration then fires at the worker's next service pass, or
//! at a peer's rescue. A poll that observes closure reads the clock as well,
//! to complete a deadline that has passed.
//!
//! Polls on any thread act on the registering worker's timers directly. So
//! does a drop on any thread but the registering worker's, or on that worker
//! once it is closing, which removes the registration at once. A drop on the
//! registering worker otherwise queues the registration's identity in the
//! worker's [`Local`] without a lock (see below). A poll that completes a
//! sleep early ends its registration as a drop on its thread would.
//!
//! Waker clones, wakes, and waker destruction never run under the timers' lock
//! or a worker borrow, since they may reenter the runtime. A pending poll
//! clones a changed waker outside the lock, while wakes and released wakers go
//! through the current worker's [`Deferred`] batch, or are dropped at once on
//! a thread without a worker.
//!
//! # Lock-Free Polls
//!
//! A pending poll at an unchanged epoch takes no lock if its waker is a
//! runtime task's waker with the stored waker's identity. Only the sleep
//! writes its registration's waker, and every other party that ends a waiting
//! registration whose sleep can still poll it (expiry, rescue, closure)
//! advances the timers' epoch inside its critical section, before it runs the
//! deferred wake that consumes the stored waker. The owner's removal of a
//! registration that its sleep dropped or completed early advances nothing
//! (see below). A sleeper caches the epoch at which it last saw its
//! registration waiting.
//!
//! Matching the stored waker's identity alone is not enough. Once an ending
//! consumes that waker, a waker implementation may give its identity to
//! another task without synchronizing with the consumption, and a poll from
//! that task could read the old epoch. Keeping a clone of the waker does not
//! prevent this, since an executor may keep a task's storage alive for its
//! wakers and still give it to a new task once the old one finishes. A runtime
//! task's waker carries its task header, whose address recurs only after the
//! consumption (see [`Task::is_waker`]), and hence after the epoch advance. A
//! matching poll that misses an ending therefore belongs to the task that the
//! ending wakes, whose poll scheduled by that wake reads the advanced epoch
//! and takes the lock. The wake itself, not the epoch's atomic ordering,
//! orders that poll after the advance. A task's wake is a releasing exchange
//! on its state, and each of its polls begins with an acquiring one (see
//! [`super::task`]), so the poll observes everything that the waking thread
//! wrote before the wake.
//!
//! A poll with any other waker locks and compares it with the stored one. An
//! equivalent waker stays pending without a clone. A changed one is cloned
//! after the lock is released and stored in a second critical section, which
//! checks the registration again. A changed task waker is cloned before the
//! lock and stored in one critical section.
//!
//! # Expiry and Rescue
//!
//! The owner expires due registrations in its service pass, at most
//! [`BUDGET`] per pass. A pool worker fires no more than its run queue has
//! room for, and at least one, since wakes that overflow the queue would move
//! its newest runnables, such as a task that has just requeued itself, behind
//! them in the global queue. The room bounds only the sleeps' own wakes. The
//! wakes of requests that complete in the same service pass, and those of its
//! rescue of stalled peers, can add more. A saturated pool worker therefore
//! fires only what its run queue can take, and the sleeps that one task
//! multiplexes complete at that rate, although their wakes reach a single
//! task. It fires them in the wheel's order, bucket by bucket in time order.
//! Within a bucket that a pass reaches after some of its deadlines passed, as
//! a worker that is behind reaches buckets of 65 us on level one and of 4.2 ms
//! on level two, the due ones fire in registration order rather than deadline
//! order.
//!
//! A pass that leaves due registrations behind keeps the published bound at
//! or below its time, so the worker serves again before it parks, and a pool
//! worker serves again after a short slice of task polls rather than a full
//! batch, once its run queue has room (see [`super::runtime`]). So does a
//! pass that leaves a wheel bucket partly refiled. The wheel bounds a crowded
//! bucket by its start (see [`Wheel::bound`]), so the owner, parked or not,
//! starts to refile it then, in such consecutive passes, rather than at its
//! first deadline. Refiles wake nothing, so the room in the run queue caps
//! only fires, and those passes refile with a full budget.
//!
//! A poll that does not return freezes its worker's service, timers included.
//! A pool worker that is not closing therefore checks its peers' published
//! bounds in its service pass, at most once per [`RESCUE_INTERVAL`]. It
//! expires, with one full budget per peer and its own callback batch, the due
//! registrations of a peer whose bound is overdue by [`RESCUE_THRESHOLD`] and
//! whose owner has run no expiry pass for as long, skipping timers whose lock
//! is held. An owner that is still draining a backlog keeps it, since a
//! rescuer's wakes join the rescuer's run queue, and a run queue they overflow
//! moves its newest runnables, such as a task that has just requeued itself,
//! behind the backlog in the global queue. The published bound of a crowded
//! bucket is its start, so a peer also takes up the refiling that an owner has
//! left for that long, one budget per check. A dedicated worker's timers are
//! private, so no peer checks them.
//!
//! A parked worker, or one spinning idle before it parks, runs no service pass
//! and checks nothing, and its timed wake covers only its own timers and
//! request deadlines. A frozen worker's timers therefore wait for the next
//! service pass of some peer, whatever wakes that peer, and while every peer
//! stays parked, for the frozen poll to return.
//!
//! # Drops on the Owner
//!
//! The owner's service pass removes the queued registrations before its
//! expiry, so the owner never fires one. It locks once per [`BUDGET`] of
//! them, as cleanup does, so no critical section removes more than one
//! budget. A queued registration keeps its slot until then, unless the owner
//! registers first. Each registration on the owner removes the most recently
//! queued one in the critical section that it takes anyway, and so frees that
//! slot for itself. Serial registrations and drops within one task poll
//! therefore reuse one slot however many there are. A registration takes
//! a new slot only when none is free, so the timers' slots stay within the
//! most registrations that waited at once. Each service pass leaves the queue
//! empty, whether its removals or the registrations emptied it, and shrinks a
//! capacity beyond [`DROPPED_CAPACITY`] to it. A callback that drops a sleep
//! after the service pass makes the worker serve again before it parks.
//!
//! An identity queued after its registration fired is stale. An early
//! completion queues one, and so does the drop of a sleep that did not observe
//! the firing, such as one whose select took another branch, or whose poll
//! observed it and then unwound. It no longer matches its slot's generation,
//! so its removal never reaches a later registration in that slot. A peer's
//! rescue can also fire a queued registration first and wake its sleep's
//! waker once, a spurious wake that the future contract allows, and the
//! removal then finds nothing. No sleep remains to poll a queued
//! registration, so its removal ends nothing that the epoch guards.
//!
//! # Bounds and Lock Order
//!
//! The timers' lock is a leaf, taken while a worker may be borrowed but never
//! the other way around. Only the owner, while it runs and is not closing,
//! registers, so no other thread can introduce a deadline earlier than the
//! owner's cached bound. Drops, the owner's removal of queued ones, and peer
//! expiry only remove registrations, which can leave cached and published
//! bounds early but never late. An early bound costs spurious expiry passes or
//! lock attempts until expiry has drained the wheel bucket whose minimum was
//! removed (see [`Wheel`]). A removal that empties the wheel publishes no
//! bound. When the owner's service pass removes its queued registrations and
//! that empties the wheel, it also clears the owner's cached bound, so a
//! worker whose sleeps were all dropped on it parks without a timed wake. A
//! removal on another thread, or one that leaves other registrations, can
//! leave the cached bound early, and an idle owner then takes a timed wake at
//! the removed firing time. A queued registration keeps both bounds until its
//! removal. A registration that crowds a wheel bucket lowers the owner's
//! cached bound to the bucket's start, which may have passed, and the
//! published one only to its own firing time. The owner refiles the bucket
//! from its next pass on, and until that pass publishes the wheel's bound,
//! peers see no overdue time that it has had no pass to serve.
//!
//! # Closure
//!
//! Worker cleanup removes the queued registrations and then closes the timers.
//! Later registration is rejected, every waiting registration ends and its
//! sleeper is woken, but no dropped one's, and the timers free their storage.
//! A sleep that outlives its worker therefore keeps empty timers alive, not
//! the worker's peak population of registrations. A registration that fired
//! holds nothing by then, since firing removes it. Its sleep takes a missing
//! registration in open timers as fired, since no other party removes the
//! registration of a sleep that can still be polled. Closure ends waiting
//! registrations as expiry does, advancing the epoch before their wakes, so a
//! lock-free poll cannot miss it. The worker is closing by then, so no drop
//! queues afterwards. Closed timers hold no registration. A poll that takes
//! the lock reports closure, and a drop, an early completion, or a removal of
//! queued identities finds nothing to remove. A sleep that observes closure
//! completes if its deadline has passed by then, as every fired one's has, and
//! its poll panics otherwise, since a sleep has no error output.

use super::{
    runtime::{Deferred, Local, MAX_TIMEOUT},
    slab::{Id, Slab},
    task::Task,
    wheel::{BUDGET, InstantExt as _, Wheel},
};
use crossbeam_utils::CachePadded;
use std::{
    cell::Cell,
    future::Future,
    mem,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Mutex, MutexGuard,
            atomic::{AtomicU64, Ordering},
        };
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
        use std::sync::atomic::{AtomicU64, Ordering};
    }
}

/// Resolution of the sleep wheel in nanoseconds. Rounding a deadline up to it
/// adds less than the latency of one wake.
const RESOLUTION: u64 = 1024;

/// How long a worker's published bound must be overdue, and its owner's latest
/// expiry pass past, before a busy peer expires its due registrations. An
/// owner whose turns stay short serves a small backlog well within it, and
/// drains a large one itself as fast as its run queue takes it, so peers act
/// on a worker that has not run an expiry pass for about this long, such as
/// one stalled in a long poll.
const RESCUE_THRESHOLD: Duration = Duration::from_millis(1);

/// Least time between two checks of the peers' bounds by one pool worker, a
/// quarter of [`RESCUE_THRESHOLD`]. Checks run only in the worker's service
/// pass, so a stalled worker's timers fire within about 1.25 ms of their
/// deadline, or of the worker's latest expiry pass if that is later, while
/// some peer runs short turns, and later when every peer's turns are long, the
/// timers' lock is held, or a backlog needs several budgeted passes. While
/// every peer is parked, none checks, and the timers wait for a peer's next
/// wake or for their owner.
pub const RESCUE_INTERVAL: Duration = Duration::from_micros(250);

/// Capacity that a worker's service pass leaves its emptied queue of dropped
/// registrations, if it had grown beyond. It fits sixteen budgets of drops,
/// which serve a busy worker without reallocation, while a larger burst gives
/// its storage back, whether the pass removed its registrations or later
/// registrations took their slots.
pub const DROPPED_CAPACITY: usize = 16 * BUDGET as usize;

/// Shortest sleep whose first poll may register without reading the clock.
/// Such a poll trusts that the deadline is still ahead when its thread's
/// worker has taken no service time since the sleep was created. It is wrong
/// only on a thread that has polled for the whole sleep, so for at least this
/// long, without serving its timers, whose registered sleeps are as late until
/// a peer rescues them (see [`RESCUE_THRESHOLD`]). A shorter sleep, or one
/// created before the service time, reads the clock.
const UNCHECKED_SLEEP: Duration = Duration::from_millis(1);

thread_local! {
    /// Time at which this thread's worker last started, ran a service pass, or
    /// returned from an idle wait, `None` on a thread that never ran a worker.
    static TURN: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// How a registration ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    /// Its deadline passed.
    Fired,
    /// Its worker closed before its sleep observed it, after which the sleep
    /// cannot tell whether it fired.
    Closed,
}

/// State behind the timers' lock.
struct Registrations {
    /// The waker of the latest pending poll of every waiting registration,
    /// until closure, after which it is empty and holds no storage. Firing a
    /// registration removes it.
    entries: Slab<Waker>,
    /// Deadlines of the waiting registrations, keyed by slab index, empty and
    /// holding no slot storage after closure.
    wheel: Wheel<RESOLUTION>,
    /// Set once by the owner's cleanup, after which nothing registers and no
    /// identity resolves.
    closed: bool,
    /// Number of critical sections in which expiry, rescue or closure ended a
    /// waiting registration, advanced by [`Timers::end`]. The owner's removal
    /// of a registration that its sleep dropped or completed early leaves it
    /// alone, since no sleeper remains to read it for that registration. A
    /// sleeper caches it whenever it sees its registration waiting.
    epoch: u64,
}

impl Registrations {
    /// Fire at most `fires` of the registrations due at `now`. Fires and
    /// refiles spend from one [`BUDGET`] of units, so a small `fires` leaves
    /// the rest of it to refiles.
    fn expire(&mut self, now: u64, fires: u32, ending: &mut Ending<'_>) {
        let Self { entries, wheel, .. } = self;
        let mut budget = BUDGET;
        wheel.expire_capped(now, &mut budget, fires, &mut |index| {
            // A slot is resident exactly while its registration waits, and
            // firing removes the registration.
            let id = entries.id_at(index as usize).unwrap();
            let waker = entries.remove(id).unwrap();
            ending.end(waker);
        });
    }

    /// Reject later registrations, end every waiting one, and free their
    /// storage, so that a sleep that outlives its worker keeps no more than
    /// empty timers alive. The wakes are deferred, so no waker is woken or
    /// destroyed here.
    fn close(&mut self, ending: &mut Ending<'_>) {
        let Self {
            entries,
            wheel,
            closed,
            ..
        } = self;
        *closed = true;

        // Visit every slot by index, since identities are not kept anywhere
        // else.
        for index in 0..entries.slots() {
            let Some(id) = entries.id_at(index) else {
                continue;
            };
            if let Some(waker) = entries.remove(id) {
                ending.end(waker);
            }
        }

        // Replacing the slab and clearing the wheel, rather than leaving them
        // empty, frees their storage.
        *entries = Slab::default();
        wheel.clear();
    }
}

/// Ends waiting registrations on behalf of a party other than their sleeps,
/// within one critical section opened by [`Timers::end`].
struct Ending<'a> {
    /// Wakes of the ended registrations, run after the lock is released.
    wakes: &'a mut Vec<Waker>,
    /// Whether any registration ended.
    ended: bool,
}

impl Ending<'_> {
    /// Record that a waiting registration ended, deferring the wake of
    /// `waker`, the one it stored.
    fn end(&mut self, waker: Waker) {
        self.wakes.push(waker);
        self.ended = true;
    }
}

/// One worker's sleep registrations. Every access to the registrations
/// locks them briefly. The bound, the pass time and the epoch beside them are
/// atomics, which a peer's rescue check and a lock-free poll read without the
/// lock (see the module documentation).
pub struct Timers {
    /// Registrations and their wheel.
    registrations: CachePadded<Mutex<Registrations>>,
    /// Bound on the earliest firing time in nanoseconds since the origin,
    /// `u64::MAX` for none. Written only under the lock, never later than
    /// the earliest waiting registration's firing time. Peers read it to find
    /// a stalled owner.
    published: CachePadded<AtomicU64>,
    /// Time of the owner's latest expiry pass in nanoseconds since the origin,
    /// zero before the first. Written only by the owner. Peers read it to
    /// leave an owner that is still serving its due registrations to itself.
    served: CachePadded<AtomicU64>,
    /// The registrations' epoch as polls read it without the lock. Stored
    /// only under the lock, by [`Self::end`], before the ended
    /// registrations' wakes run, so a sleeper that saw its registration
    /// waiting at some epoch and reads the same epoch later either still
    /// waits or is woken afterwards by the ending that its read missed.
    epoch: CachePadded<AtomicU64>,
    /// The instant of the timers' creation, from which their wheel, bound and
    /// expiry times count nanoseconds.
    origin: Instant,
}

impl Timers {
    /// Empty timers whose origin is the current time.
    pub fn new() -> Self {
        Self {
            registrations: CachePadded::new(Mutex::new(Registrations {
                entries: Slab::default(),
                wheel: Wheel::new(0),
                closed: false,
                epoch: 0,
            })),
            published: CachePadded::new(AtomicU64::new(u64::MAX)),
            served: CachePadded::new(AtomicU64::new(0)),
            epoch: CachePadded::new(AtomicU64::new(0)),
            origin: Instant::now(),
        }
    }

    /// Nanoseconds of `instant` since the origin, zero for an earlier one.
    #[inline]
    pub fn nanos(&self, instant: Instant) -> u64 {
        instant.nanos_since(self.origin)
    }

    /// The instant `nanos` after the origin, or `None` for `u64::MAX`,
    /// which bounds no registration.
    #[inline]
    pub fn instant(&self, nanos: u64) -> Option<Instant> {
        self.origin.after_nanos(nanos)
    }

    /// Lock the registrations, counting the acquisition in tests.
    #[inline]
    fn lock(&self) -> MutexGuard<'_, Registrations> {
        #[cfg(test)]
        tests::count_lock();
        self.guard()
    }

    /// Lock the registrations.
    #[inline]
    fn guard(&self) -> MutexGuard<'_, Registrations> {
        // Loom's mutex reports poisoning, the standard build's does not.
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let registrations = self.registrations.lock().unwrap();
            } else {
                let registrations = self.registrations.lock();
            }
        }
        registrations
    }

    /// Lock the registrations unless another thread holds them.
    #[inline]
    fn try_guard(&self) -> Option<MutexGuard<'_, Registrations>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                let registrations = self.registrations.try_lock().ok();
            } else {
                let registrations = self.registrations.try_lock();
            }
        }
        registrations
    }

    /// Run `pass` on `registrations`, which the caller holds locked, with
    /// wakes deferred to `deferred`, and advance the epoch before the lock is
    /// released if the pass ended any waiting registration. Expiry, rescue
    /// and closure end waiting registrations only through the [`Ending`] of
    /// such a pass. Only a sleep itself, or the owner for a sleep dropped or
    /// completed early on it, removes one any other way.
    fn end(
        &self,
        registrations: &mut Registrations,
        deferred: &mut Deferred,
        pass: impl FnOnce(&mut Registrations, &mut Ending<'_>),
    ) {
        let mut ending = Ending {
            wakes: &mut deferred.wakes,
            ended: false,
        };
        pass(registrations, &mut ending);
        if ending.ended {
            // The store precedes the deferred wakes, which run after the lock
            // is released, so a poll that one of them schedules reads the
            // new epoch and takes the lock. Sleepers cache the count itself,
            // which they can read only while they hold the lock.
            registrations.epoch += 1;
            self.epoch.store(registrations.epoch, Ordering::Release);
        }
    }

    /// Register `waker` at `deadline`. Called only by the owner, which checked
    /// that it is not closing, with the registrations that sleeps dropped on
    /// it queued in `dropped`. The latest of them leaves first, in the same
    /// critical section, as the owner's service pass would remove it, moving
    /// its waker to `deferred` if it still waits, so that the new registration
    /// can take its slot. Returns the registration and the time by which the
    /// owner's next expiry pass must reach it, in nanoseconds since the origin,
    /// for the owner's cached bound: its firing time, or the earlier start of a
    /// wheel bucket that it crowds (see [`Wheel::insert`]).
    fn register(
        self: &Arc<Self>,
        waker: Waker,
        deadline: Instant,
        dropped: &mut Vec<Id>,
        deferred: &mut Deferred,
    ) -> (Sleeper, u64) {
        let task = TaskIdentity::stored(&waker);
        let nanos = self.nanos(deadline);
        let recycled = dropped.pop();
        if recycled.is_some() {
            // A removal releases at most one waker, so no push under the lock
            // reallocates.
            deferred.drops.reserve(1);
        }
        let mut registrations = self.lock();
        assert!(
            !registrations.closed,
            "io_uring sleep polled after its worker closed"
        );
        let Registrations { entries, wheel, .. } = &mut *registrations;

        // An identity that no longer resolves, such as a fired registration's,
        // matches nothing.
        if let Some(recycled) = recycled
            && let Some(released) = entries.remove(recycled)
        {
            wheel.remove(recycled.index);
            deferred.drops.push(released);
        }
        let id = entries.insert(waker);
        let at = wheel.insert(id.index, nanos);

        // Peers act on overdue times, so the published bound takes the firing
        // time and not the start of a crowded bucket, which may have passed
        // before the owner had a pass to refile it. Every write of the
        // published bound holds the lock, so lowering it with a plain load
        // and store loses no other update.
        let fires = Wheel::<RESOLUTION>::rounded(nanos);
        if fires < self.published.load(Ordering::Relaxed) {
            self.published.store(fires, Ordering::Relaxed);
        }

        // Cache the epoch read while the registration waits. A later poll
        // with a matching task waker that reads this epoch may skip the lock,
        // since an ending that its load misses still wakes the stored waker
        // (see the module documentation).
        let epoch = registrations.epoch;
        drop(registrations);

        let sleeper = Sleeper {
            timers: self.clone(),
            id,
            deadline,
            task,
            epoch,
        };
        (sleeper, at)
    }

    /// The owner's expiry pass at `now`, in nanoseconds since the origin. It
    /// fires at most `fires` due registrations, no more than one [`BUDGET`]
    /// of them, refiles later ones within the rest of that budget, and
    /// publishes the new bound, which the owner caches. A pool worker passes
    /// the room in its run queue as `fires`, so a saturated worker fires only
    /// what that queue can take, in the wheel's order (see the module
    /// documentation), while a crowded wheel bucket cascades as fast as beside
    /// an empty queue. The room bounds only these wakes, not others that the
    /// same service pass collects. A peer's rescue keeps a full budget. The
    /// bound stays at or below `now` while due registrations remain.
    pub fn expire(&self, now: u64, fires: u32, deferred: &mut Deferred) -> u64 {
        let mut registrations = self.lock();
        self.end(&mut registrations, deferred, |registrations, ending| {
            registrations.expire(now, fires, ending);
        });

        // Peers read the bound to find due registrations, and the pass time
        // to leave an owner that serves them itself alone.
        let bound = registrations.wheel.bound();
        self.published.store(bound, Ordering::Relaxed);
        self.served.store(now, Ordering::Relaxed);
        bound
    }

    /// A peer's expiry pass at `now`, in nanoseconds since the origin,
    /// skipped while the lock is held or after closure. Returns whether it ran.
    fn rescue(&self, now: u64, deferred: &mut Deferred) -> bool {
        // A held lock means another party is acting on these timers, so the
        // rescuer moves on rather than wait, and checks them again later.
        let Some(mut registrations) = self.try_guard() else {
            return false;
        };
        if registrations.closed {
            return false;
        }
        self.end(&mut registrations, deferred, |registrations, ending| {
            registrations.expire(now, BUDGET, ending);
        });

        // The pass time stays the owner's own, so a stalled owner stays
        // eligible for the next rescue.
        self.published
            .store(registrations.wheel.bound(), Ordering::Relaxed);
        true
    }

    /// Close the timers at their owner's cleanup: reject later registrations,
    /// wake every waiting sleeper, whose next poll observes the closure, and
    /// free the storage of every registration. Repeated calls do nothing.
    pub fn close(&self, deferred: &mut Deferred) {
        let mut registrations = self.lock();
        if registrations.closed {
            return;
        }
        self.end(&mut registrations, deferred, Registrations::close);

        // Closed timers hold no registration, so they bound nothing.
        self.published.store(u64::MAX, Ordering::Relaxed);
    }

    /// Remove the registration `id` at once, unlinking it from the wheel, if
    /// it still waits. Returns its waker if it waited. A removal that empties
    /// the wheel publishes no bound. Closed timers hold no registration, so
    /// this finds nothing in them.
    #[inline]
    fn remove(&self, id: Id) -> Option<Waker> {
        let mut registrations = self.lock();
        let Registrations { entries, wheel, .. } = &mut *registrations;
        let waker = entries.remove(id)?;
        wheel.remove(id.index);

        // An empty wheel has no firing time to publish.
        if wheel.is_empty() {
            self.published.store(u64::MAX, Ordering::Relaxed);
        }
        Some(waker)
    }

    /// The owner's removal of the registrations in `dropped`, whose sleeps
    /// were dropped on it, in critical sections of at most [`BUDGET`] removals
    /// each, so that a poll or drop on another thread waits for at most one
    /// budget of them. One that still waits leaves the wheel and moves its
    /// waker to `deferred`, to be destroyed after the lock. An identity that
    /// no longer resolves, such as a fired registration's, matches nothing,
    /// and closed timers hold no registration to match. Empties `dropped` and
    /// returns whether the wheel is empty, in which case it publishes no
    /// bound.
    pub fn drain(&self, dropped: &mut Vec<Id>, deferred: &mut Deferred) -> bool {
        loop {
            // Each critical section removes the newest budget of identities
            // from the end of the queue, leaving `rest` for the next one.
            let rest = dropped.len().saturating_sub(BUDGET as usize);

            // Each identity releases at most one waker, so no push under the
            // lock reallocates, and the reservation never exceeds one budget.
            deferred.drops.reserve(dropped.len() - rest);
            let mut registrations = self.lock();
            let Registrations { entries, wheel, .. } = &mut *registrations;
            for id in dropped.drain(rest..) {
                // A fired registration's identity no longer resolves.
                if let Some(waker) = entries.remove(id) {
                    wheel.remove(id.index);
                    deferred.drops.push(waker);
                }
            }
            let empty = wheel.is_empty();
            if empty {
                self.published.store(u64::MAX, Ordering::Relaxed);
            }
            drop(registrations);
            if dropped.is_empty() {
                return empty;
            }
        }
    }

    /// Expire, at `now`, the due registrations of the timers in `all` of
    /// every worker but `own` whose published bound is overdue by
    /// [`RESCUE_THRESHOLD`] and whose owner has run no expiry pass for as
    /// long, with one budget per worker, skipping timers whose lock is held.
    /// Each worker's timers compare `now` in their own nanoseconds. Wakes
    /// land in `deferred`.
    pub fn rescue_peers(all: &[Arc<Self>], own: usize, now: Instant, deferred: &mut Deferred) {
        let threshold = RESCUE_THRESHOLD.as_nanos() as u64;
        for (index, timers) in all.iter().enumerate() {
            if index == own {
                continue;
            }

            // The bound only selects timers worth locking. The lock
            // synchronizes their state, so a stale bound costs one check,
            // never a timer.
            let bound = timers.published.load(Ordering::Relaxed);
            if bound == u64::MAX {
                continue;
            }
            let now = timers.nanos(now);
            if now < bound.saturating_add(threshold) {
                continue;
            }

            // An owner that served recently drains its own backlog. Like the
            // bound, a stale time only delays or advances one check.
            let served = timers.served.load(Ordering::Relaxed);
            if now < served.saturating_add(threshold) {
                continue;
            }
            timers.rescue(now, deferred);
        }
    }
}

/// The identity that a pending poll's waker may match to skip the timers'
/// lock: the stored waker's data address if it is a runtime task's waker,
/// whose identity cannot recur before an ending is visible to the poll (see
/// the module documentation), or `None` for a waker of any other kind, which
/// nothing matches. The address is held as an integer so that a sleep stays
/// `Send` and `Sync`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskIdentity(Option<NonZeroUsize>);

impl TaskIdentity {
    /// The identity of a newly stored `waker`.
    fn stored(waker: &Waker) -> Self {
        // A task waker's data is its task header, which is never null.
        Self(
            Task::is_waker(waker)
                .then(|| NonZeroUsize::new(waker.data().addr()))
                .flatten(),
        )
    }

    /// Whether a poll with `waker` may skip the lock at an unchanged epoch.
    #[inline]
    fn matches(self, waker: &Waker) -> bool {
        // The address proves the identity only for a task waker, since a
        // waker of another kind may carry the same data address.
        self.0
            .is_some_and(|data| Task::is_waker(waker) && waker.data().addr() == data.get())
    }
}

/// A sleep's registration, polled and dropped on any thread.
struct Sleeper {
    /// The registering worker's timers, kept for life.
    timers: Arc<Timers>,
    /// Identity in the timers.
    id: Id,
    /// The sleep's deadline, which polls compare with their thread's latest
    /// worker service time.
    deadline: Instant,
    /// The stored waker's task identity, which a poll may match to skip the
    /// lock while the registration waits, updated whenever this sleeper
    /// stores a waker.
    task: TaskIdentity,
    /// The timers' epoch, read under their lock when this sleeper last saw its
    /// registration waiting.
    epoch: u64,
}

impl Sleeper {
    /// Poll the registration. A deadline at or before this thread's latest
    /// worker service time completes it at once, ending the registration as a
    /// drop would (see [`Self::abandon`]). Every ready result ends the
    /// registration, so the sleeper needs no [`Self::abandon`] afterwards, and
    /// one after closure finds nothing.
    ///
    /// A poll at an unchanged epoch returns pending without the lock if its
    /// waker matches [`TaskIdentity`], a task waker with the stored waker's
    /// address. The registration then still waits with an equivalent waker,
    /// or an ending that the epoch read missed wakes the stored waker
    /// afterwards. Only this sleeper writes its waker. Expiry, rescue and
    /// closure advance the epoch under the lock before their wakes, and the
    /// stored waker's identity cannot recur before its wake (see the module
    /// documentation). Any other poll locks.
    fn poll(&mut self, cx: &Context<'_>) -> Poll<Outcome> {
        if Sleep::reached(self.deadline) {
            self.abandon();
            return Poll::Ready(Outcome::Fired);
        }

        // An ending that this load misses wakes the stored waker afterwards,
        // and the poll that wake schedules reads the advanced epoch.
        let waker = cx.waker();
        let matched = self.task.matches(waker);
        if matched && self.timers.epoch.load(Ordering::Acquire) == self.epoch {
            return Poll::Pending;
        }
        self.poll_locked(waker, matched)
    }

    /// The part of [`Self::poll`] that takes the lock, after its waker failed
    /// to match [`TaskIdentity`] (`matched` is false) or matched at a moved
    /// epoch. A waker's clone may reenter the runtime, so a changed waker is
    /// cloned outside the lock: a task waker that failed to match, which
    /// differs from the stored one, before locking, and any other waker once
    /// a critical section has found that it differs, after which a second one
    /// checks the registration again. Kept out of line, since it locks
    /// anyway, so that the code of the first poll and of the lock-free path
    /// stays compact.
    #[inline(never)]
    fn poll_locked(&mut self, waker: &Waker, matched: bool) -> Poll<Outcome> {
        // A task waker that failed to match differs from the stored one, so
        // it is cloned now and stored in the first critical section.
        let mut clone = (!matched && Task::is_waker(waker)).then(|| waker.clone());
        loop {
            let mut registrations = self.timers.lock();

            // Closed timers hold no registration. Closure ended this one and
            // woke its waker if it still waited.
            if registrations.closed {
                drop(registrations);
                Self::release(clone);
                return Poll::Ready(Outcome::Closed);
            }
            let Some(current) = registrations.entries.get_mut(self.id) else {
                // Only firing removes the registration of a sleep that can
                // still be polled.
                drop(registrations);
                Self::release(clone);
                return Poll::Ready(Outcome::Fired);
            };

            // Only this sleeper writes its waker, so its cached identity is
            // the stored waker's.
            debug_assert_eq!(self.task, TaskIdentity::stored(current));
            let displaced = match clone.take() {
                // An equivalent waker needs no replacement, nor a clone.
                unused if current.will_wake(waker) => unused,
                Some(clone) => {
                    self.task = TaskIdentity::stored(&clone);
                    Some(mem::replace(current, clone))
                }
                // Clone a changed waker of another kind after the lock, then
                // check again, since an ending may come first.
                None => {
                    drop(registrations);
                    clone = Some(waker.clone());
                    continue;
                }
            };

            // Cache the epoch read while the registration waits with an
            // equivalent waker. A later poll with a matching task waker that
            // reads this epoch may skip the lock.
            self.epoch = registrations.epoch;
            drop(registrations);
            Self::release(displaced);
            return Poll::Pending;
        }
    }

    /// End the registration of a dropped sleep, or of one that a poll
    /// completed early, in one access to the current worker. On the
    /// registering worker, while it is not closing, this takes no lock: the
    /// registration's identity joins the worker's queue, whose registrations
    /// its next service pass, or its cleanup before closure, removes, unless
    /// its next registrations remove them first. Anywhere else the
    /// registration is removed at once, and its waker, if it still waited,
    /// goes to the current worker's callback batch, or is dropped at once on
    /// a thread without a worker.
    fn abandon(&self) {
        // The open owner queues the identity without a lock, and anyone else
        // removes the registration at once.
        let unreleased = Local::with_current(|local| match local {
            Some(local) if Arc::ptr_eq(&self.timers, &local.timers) && !local.closing => {
                local.timers_dropped.push(self.id);
                None
            }
            local => self.evict(local),
        });

        // A waker returned without a worker is destroyed outside the access.
        drop(unreleased);
    }

    /// The part of [`Self::abandon`] off an open owner: remove the
    /// registration at once, then release its waker to `local`'s callback
    /// batch, or, without a worker, return it to be dropped after the access.
    /// Kept out of line, since it locks anyway, so that the owner's path stays
    /// compact.
    #[inline(never)]
    fn evict(&self, local: Option<&mut Local>) -> Option<Waker> {
        let removed = self.timers.remove(self.id);
        let Some(local) = local else {
            return removed;
        };
        if let Some(removed) = removed {
            local.deferred.drops.push(removed);
        }
        None
    }

    /// Destroy `waker`, if any, in the current worker's next callback batch,
    /// whose failures that worker retains, or at once on a thread without a
    /// worker. The caller holds no worker borrow and no timers' lock.
    #[inline]
    fn release(waker: Option<Waker>) {
        let Some(waker) = waker else {
            return;
        };
        let waker = Local::with_current(|local| match local {
            Some(local) => {
                local.deferred.drops.push(waker);
                None
            }
            None => Some(waker),
        });
        drop(waker);
    }
}

/// Ownership held by a sleep between polls.
enum State {
    /// Sleep that has not needed a registration yet.
    Unregistered {
        /// When the sleep completes.
        deadline: Instant,
        /// When the sleep was created, kept only by a sleep of at least
        /// [`UNCHECKED_SLEEP`], whose first poll may register unchecked.
        created: Option<Instant>,
    },
    /// Registration in the timers of the worker of the first pending poll.
    Registered(Sleeper),
    /// Immediate or completed sleep, requiring no worker access.
    Done,
}

/// Sleep future.
pub struct Sleep {
    /// Deadline or registration, retained without any worker reference.
    state: State,
}

impl Sleep {
    /// Establish a relative deadline, clamping the duration to [`MAX_TIMEOUT`].
    ///
    /// Zero sleeps take the ready path without reading a clock or accessing TLS.
    pub fn new(duration: Duration) -> Self {
        if duration.is_zero() {
            return Self { state: State::Done };
        }
        let created = Instant::now();
        let duration = duration.min(MAX_TIMEOUT);
        Self {
            state: State::Unregistered {
                deadline: created + duration,
                created: (duration >= UNCHECKED_SLEEP).then_some(created),
            },
        }
    }

    /// Convert a wall-clock deadline once, completing immediately if it has passed.
    pub fn until(deadline: SystemTime) -> Self {
        // A deadline in the past converts to a zero duration, which is ready.
        let duration = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();

        Self::new(duration)
    }

    /// Record the time of this worker's start, service pass, or return from an
    /// idle wait, which sleeps polled on this thread compare their deadlines
    /// with.
    #[inline]
    pub fn set_turn(now: Instant) {
        TURN.set(Some(now));
    }

    /// Whether `deadline` is at or before this thread's latest worker service
    /// time, which never runs ahead of the clock, so that it has passed.
    #[inline]
    fn reached(deadline: Instant) -> bool {
        TURN.get().is_some_and(|turn| deadline <= turn)
    }

    /// Whether the first poll of a sleep may take its deadline to be ahead
    /// without reading the clock. It may if the sleep kept `created`, its
    /// creation time, and this thread's latest worker service time is not
    /// later.
    #[inline]
    fn unchecked(created: Option<Instant>) -> bool {
        created.is_some_and(|created| TURN.get().is_some_and(|turn| turn <= created))
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();

        match &mut this.state {
            State::Done => Poll::Ready(()),
            State::Registered(sleeper) => {
                let outcome = std::task::ready!(sleeper.poll(cx));

                // A closed worker discarded the registration, which may have
                // fired or not. Only a deadline that has passed, as every
                // fired one's has, may still complete. Until it has, the sleep
                // stays registered, so every poll observes the closure again,
                // and its drop finds nothing in the closed timers.
                assert!(
                    outcome == Outcome::Fired || sleeper.deadline <= Instant::now(),
                    "io_uring sleep polled after its worker closed"
                );
                this.state = State::Done;
                Poll::Ready(())
            }
            State::Unregistered { deadline, created } => {
                let (deadline, created) = (*deadline, *created);

                // The latest service time on this thread never runs ahead of
                // the clock, so a deadline at or before it has passed, and the
                // sleep needs neither a worker nor a registration. Otherwise
                // the clock decides, unless the sleep may register unchecked.
                if Self::reached(deadline)
                    || (!Self::unchecked(created) && deadline <= Instant::now())
                {
                    this.state = State::Done;
                    return Poll::Ready(());
                }

                // A running worker registers the sleep. An unchecked deadline
                // that has passed fires at the worker's next service pass that
                // reaches its firing time, or at a peer's rescue.
                let owner = match Local::current() {
                    Some(owner) if !owner.borrow().closing => owner,
                    owner => {
                        // Without one, only a deadline that has passed completes.
                        assert!(
                            deadline <= Instant::now(),
                            "{}",
                            if owner.is_some() {
                                "io_uring sleep polled after its worker closed"
                            } else {
                                "io_uring sleep requires a current worker"
                            }
                        );
                        this.state = State::Done;
                        return Poll::Ready(());
                    }
                };

                // Clone before the worker borrow and the timers' lock, under
                // which no user code may run.
                let waker = cx.waker().clone();
                let mut guard = owner.borrow_mut();
                let local = &mut *guard;
                let (sleeper, at) = local.timers.register(
                    waker,
                    deadline,
                    &mut local.timers_dropped,
                    &mut local.deferred,
                );

                // The owner's cached bound never trails a live registration.
                local.timers_next = local.timers_next.min(at);
                drop(guard);
                this.state = State::Registered(sleeper);
                Poll::Pending
            }
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        // Only a registered sleep holds anything in a worker's timers.
        if let State::Registered(sleeper) = &self.state {
            sleeper.abandon();
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        Clock as _, Runner as _, Spawner as _, Supervisor as _,
        iouring::{
            Config, Runner,
            operation::tests::{Reentrant, poll_on_foreign_thread},
        },
        utils::{extract_panic_message, reschedule},
    };
    use commonware_utils::channel::oneshot;
    use futures::{FutureExt as _, poll};
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Barrier, OnceLock,
            atomic::{AtomicBool, AtomicUsize},
            mpsc,
        },
        task::{RawWaker, RawWakerVTable, Wake},
        thread,
    };

    impl Sleep {
        /// Sleep until one exact monotonic deadline, created now.
        fn at(deadline: Instant) -> Self {
            let created = Instant::now();
            let duration = deadline.saturating_duration_since(created);
            Self {
                state: State::Unregistered {
                    deadline,
                    created: (duration >= UNCHECKED_SLEEP).then_some(created),
                },
            }
        }

        /// The deadline of a sleep that has not registered, and its creation
        /// time if it kept one.
        fn unregistered(&self) -> (Instant, Option<Instant>) {
            let State::Unregistered { deadline, created } = self.state else {
                panic!("sleep is not unregistered");
            };
            (deadline, created)
        }
    }

    impl Timers {
        /// Empty timers whose time counts from `origin`, which must not be
        /// later than the current time.
        fn with_origin(origin: Instant) -> Self {
            Self {
                origin,
                ..Self::new()
            }
        }

        /// Number of waiting registrations.
        fn live(&self) -> usize {
            self.guard().entries.len()
        }

        /// Number of registrations resident in the wheel.
        fn resident(&self) -> usize {
            self.guard().wheel.len()
        }

        /// Number of slab slots, taken or free, which never shrinks before
        /// closure.
        fn slots(&self) -> usize {
            self.guard().entries.slots()
        }

        /// Storage capacity of the slab and of the wheel's links, in slots.
        fn capacity(&self) -> (usize, usize) {
            let registrations = self.guard();
            (
                registrations.entries.capacity(),
                registrations.wheel.capacity(),
            )
        }

        /// Register `waker` at `deadline`, in nanoseconds since the origin, as
        /// the owner would with no queued registrations of dropped sleeps.
        pub(super) fn register_alone(
            self: &Arc<Self>,
            waker: Waker,
            deadline: u64,
        ) -> (Sleeper, u64) {
            let deadline = self.instant(deadline).unwrap();
            self.register(waker, deadline, &mut Vec::new(), &mut Deferred::default())
        }

        /// The wheel's bound, as an expiry pass would publish it.
        fn bound(&self) -> u64 {
            self.guard().wheel.bound()
        }

        /// The published bound.
        fn published(&self) -> u64 {
            self.published.load(Ordering::Relaxed)
        }

        /// The epoch.
        fn epoch(&self) -> u64 {
            self.epoch.load(Ordering::Relaxed)
        }

        /// Whether the owner's cleanup closed the timers.
        pub(crate) fn is_closed(&self) -> bool {
            self.guard().closed
        }

        /// Whether the registration `id` still waits.
        fn holds(&self, id: Id) -> bool {
            self.guard().entries.get(id).is_some()
        }

        /// Whether the registration `id` waits with a waker that wakes `waker`'s task.
        fn waits_with(&self, id: Id, waker: &Waker) -> bool {
            matches!(
                self.guard().entries.get(id),
                Some(current) if current.will_wake(waker)
            )
        }

        /// Hold the lock, for tests of contention.
        fn hold(&self) -> MutexGuard<'_, impl Sized> {
            self.guard()
        }

        /// Register a timer that is already due, so the owner's next expiry
        /// pass fires it without any wait on the clock. Returns its firing
        /// time, for the owner's cached bound.
        pub(crate) fn insert_due(self: &Arc<Self>, waker: Waker) -> u64 {
            let (_, at) = self.register_alone(waker, 0);
            at
        }
    }

    thread_local! {
        /// Locks taken by [`Timers::lock`] on this thread.
        static LOCKS: Cell<usize> = const { Cell::new(0) };
    }

    /// Count a timers' lock taken on this thread.
    pub(super) fn count_lock() {
        LOCKS.set(LOCKS.get() + 1);
    }

    /// Timers' locks taken on this thread so far.
    fn locks() -> usize {
        LOCKS.get()
    }

    /// The time of this thread's latest worker service pass.
    pub fn turn() -> Option<Instant> {
        TURN.get()
    }

    /// Counts wakes.
    #[derive(Default)]
    struct Count(
        /// Number of wakes so far.
        AtomicUsize,
    );

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Count {
        /// Number of wakes so far.
        fn get(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// A counting waker and its counter.
    fn counter() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    /// Register `deadline` on `timers` as a first pending poll with `waker` would.
    fn register(timers: &Arc<Timers>, deadline: u64, waker: &Waker) -> Sleeper {
        timers.register_alone(waker.clone(), deadline).0
    }

    /// Poll `sleeper` with `waker`.
    fn poll_with(sleeper: &mut Sleeper, waker: &Waker) -> Poll<Outcome> {
        sleeper.poll(&Context::from_waker(waker))
    }

    /// Poll `sleep` once with `waker`, which must leave it pending.
    fn pend(sleep: &mut Sleep, waker: &Waker) {
        assert!(
            sleep
                .poll_unpin(&mut Context::from_waker(waker))
                .is_pending()
        );
    }

    /// The current worker's cached bound.
    fn timers_next() -> u64 {
        Local::current().unwrap().borrow().timers_next
    }

    /// Run a callback batch as a worker would, outside the timers' lock.
    fn run(deferred: &mut Deferred) {
        for waker in deferred.wakes.drain(..) {
            waker.wake();
        }
        deferred.drops.clear();
    }

    /// A deadline one second after the timers' origin, in nanoseconds, which
    /// passes only at the explicit expiry times of a test.
    const fn later() -> u64 {
        1_000_000_000
    }

    /// The registration of a sleep that has registered.
    fn registration(sleep: &Sleep) -> (Arc<Timers>, Id) {
        let State::Registered(sleeper) = &sleep.state else {
            panic!("sleep did not register");
        };
        (sleeper.timers.clone(), sleeper.id)
    }

    #[test]
    fn test_elapsed_sleeps_are_ready_without_a_worker() {
        let mut cx = Context::from_waker(Waker::noop());

        // The last case has a deadline that passed between creation and polling.
        for mut sleep in [
            Sleep::new(Duration::ZERO),
            Sleep::until(SystemTime::UNIX_EPOCH),
            Sleep::at(Instant::now()),
        ] {
            assert!(sleep.poll_unpin(&mut cx).is_ready());
            assert!(matches!(sleep.state, State::Done));
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_lock_free_poll_state_is_one_word() {
        // What a poll may match without the lock is a task waker's address,
        // one word with a niche, and an unregistered sleep's deadline fits
        // beside the niche in a registered sleep's deadline.
        assert_eq!(size_of::<TaskIdentity>(), size_of::<usize>());
        assert_eq!(size_of::<Sleeper>(), 56);
        assert_eq!(size_of::<Sleep>(), 56);
    }

    #[test]
    fn test_far_future_sleep_clamps_the_deadline() {
        // Each deadline lies its duration, clamped to the longest timeout,
        // after the clock reads around it.
        let timers = Timers::new();
        for (duration, expected) in [
            (Duration::MAX, MAX_TIMEOUT),
            (Duration::from_secs(1), Duration::from_secs(1)),
        ] {
            let before = Instant::now();
            let sleep = Sleep::new(duration);
            let after = Instant::now();
            let (deadline, created) = sleep.unregistered();
            assert!(created.is_some_and(|created| created >= before && created <= after));
            assert!(deadline >= before + expected);
            assert!(deadline <= after + expected);

            // The timers round it up to a firing time well inside its range,
            // never before the deadline.
            let firing = Wheel::<RESOLUTION>::rounded(timers.nanos(deadline));
            assert!(firing < Wheel::<RESOLUTION>::MAX / 2);
            assert!(timers.instant(firing).unwrap() >= deadline);
        }

        // A deadline before the origin is due at the origin.
        if let Some(earlier) = timers.origin.checked_sub(Duration::from_secs(1)) {
            assert_eq!(timers.nanos(earlier), 0);
        }
    }

    #[test]
    fn test_expiry_wakes_once_and_poll_reports_fired() {
        // Registering publishes the rounded deadline, and a poll stays pending.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut sleeper = register(&timers, deadline, &waker);
        assert_eq!(timers.published(), Wheel::<RESOLUTION>::rounded(deadline));
        assert!(poll_with(&mut sleeper, &waker).is_pending());

        // One nanosecond before the rounded deadline fires nothing.
        let mut deferred = Deferred::default();
        let firing = Wheel::<RESOLUTION>::rounded(deadline);
        let bound = timers.expire(firing - 1, BUDGET, &mut deferred);
        assert_eq!(bound, firing);
        assert!(deferred.is_empty());

        // At the rounded deadline, the pass defers the wake to the caller, and
        // the next poll reports the firing.
        assert_eq!(timers.expire(firing, BUDGET, &mut deferred), u64::MAX);
        assert_eq!(timers.published(), u64::MAX);
        assert_eq!(count.get(), 0, "woken under the expiry pass");
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(poll_with(&mut sleeper, &waker), Poll::Ready(Outcome::Fired));
        drop(sleeper);
        assert_eq!(timers.live(), 0);

        // Repeating expiry cannot wake it twice, and both sides released it.
        timers.expire(firing + 4096, BUDGET, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_changed_waker_on_another_thread_is_woken() {
        // Register with one waker, then poll on another thread with a second.
        let timers = Arc::new(Timers::new());
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        let deadline = later();
        let sleeper = register(&timers, deadline, &first_waker);
        let mut sleeper = thread::spawn(move || {
            let mut sleeper = sleeper;
            assert!(poll_with(&mut sleeper, &second_waker).is_pending());

            // An unchanged waker stays pending without a clone.
            assert!(poll_with(&mut sleeper, &second_waker).is_pending());
            sleeper
        })
        .join()
        .unwrap();

        // Off a worker, the displaced waker is released at once.
        assert_eq!(Arc::strong_count(&first), 2);
        let mut deferred = Deferred::default();
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);
        assert_eq!(first.get(), 0, "woke the displaced waker");
        assert_eq!(second.get(), 1);
        assert_eq!(
            poll_with(&mut sleeper, &first_waker),
            Poll::Ready(Outcome::Fired)
        );
    }

    #[test]
    fn test_drop_on_another_thread_removes_and_releases() {
        // An earlier registration keeps the timers nonempty, and the timers
        // holds the only clone of the later one's waker.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = later();
        let early = register(&timers, deadline - 1, Waker::noop());
        let sleeper = register(&timers, deadline, &waker);
        drop(waker);

        // Dropping it on another thread removes the registration and releases
        // its waker there.
        thread::spawn(move || sleeper.abandon()).join().unwrap();
        assert_eq!(Arc::strong_count(&count), 1, "kept the waker");
        assert_eq!(timers.live(), 1);
        assert_eq!(timers.resident(), 1);

        // Dropping the other here empties the timers, so expiry wakes nothing.
        early.abandon();
        assert_eq!(timers.live(), 0);
        assert_eq!(timers.bound(), u64::MAX);
        let mut deferred = Deferred::default();
        timers.expire(deadline + 4096, BUDGET, &mut deferred);
        assert!(deferred.is_empty());
        assert_eq!(count.get(), 0);
    }

    #[test]
    fn test_close_wakes_pending_and_reports_closed() {
        // Fire one of two registrations, leaving the other pending.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut pending = register(&timers, deadline + 1_000_000, &waker);
        let mut fired = register(&timers, deadline, &waker);
        let mut deferred = Deferred::default();
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);

        // Closure appends to existing deferred work without invoking it, and
        // repeating it changes nothing.
        deferred.wakes.push(Waker::noop().clone());
        timers.close(&mut deferred);
        timers.close(&mut deferred);
        assert_eq!(deferred.wakes.len(), 2);
        assert_eq!(count.get(), 1);
        run(&mut deferred);
        assert_eq!(count.get(), 2);
        assert_eq!(timers.published(), u64::MAX);
        assert!(timers.is_closed());

        // Closure discarded both registrations, fired or pending, and each
        // reports closure.
        assert_eq!(timers.live(), 0);
        assert_eq!(poll_with(&mut fired, &waker), Poll::Ready(Outcome::Closed));
        assert_eq!(
            poll_with(&mut pending, &waker),
            Poll::Ready(Outcome::Closed)
        );
        let rejected = catch_unwind(AssertUnwindSafe(|| register(&timers, deadline, &waker)));
        assert!(rejected.is_err(), "closed timers accepted a registration");
        assert_eq!(timers.live(), 0);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_drop_after_close_is_harmless() {
        // Closing the timers wakes the pending registrations.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let abandoned = register(&timers, later(), &waker);
        let queued = register(&timers, later(), &waker);
        let mut repolled = register(&timers, later(), &waker);
        assert!(poll_with(&mut repolled, &waker).is_pending());
        let mut deferred = Deferred::default();
        timers.close(&mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 3);

        // A drop on a thread without a worker and a removal of late or
        // repeated queued identities find nothing to remove.
        thread::spawn(move || abandoned.abandon()).join().unwrap();
        let mut dropped = vec![queued.id, queued.id];
        drop(queued);
        assert!(timers.drain(&mut dropped, &mut deferred));
        assert!(dropped.is_empty());
        assert!(deferred.is_empty());

        // Repolls observe closure.
        for _ in 0..2 {
            assert_eq!(
                poll_with(&mut repolled, &waker),
                Poll::Ready(Outcome::Closed)
            );
        }

        // Closure woke each waker once and released the timers' clones.
        assert_eq!(timers.live(), 0);
        assert_eq!(timers.published(), u64::MAX);
        assert_eq!(count.get(), 3);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_closure_frees_the_storage_of_every_registration() {
        /// Registrations enough to grow the slab and the wheel's links.
        const COUNT: usize = 100_000;

        // One registration outlives the rest.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let mut sleepers: Vec<_> = (0..COUNT)
            .map(|_| register(&timers, later(), &waker))
            .collect();
        let mut escaped = sleepers.pop().unwrap();
        for sleeper in sleepers {
            sleeper.abandon();
        }
        let (slots, links) = timers.capacity();
        assert!(slots >= COUNT, "the slab holds {slots} slots");
        assert!(links >= COUNT, "the wheel holds {links} links");

        // Closure ends the escaped registration with a deferred wake, and
        // frees the storage of both.
        let mut deferred = Deferred::default();
        timers.close(&mut deferred);
        assert_eq!(deferred.wakes.len(), 1);
        assert!(deferred.drops.is_empty());
        assert_eq!(timers.capacity(), (0, 0), "closed timers kept storage");
        run(&mut deferred);
        assert_eq!(count.get(), 1);

        // The escaped sleeper observes closure, and its poll and drop
        // allocate nothing.
        assert_eq!(
            poll_with(&mut escaped, &waker),
            Poll::Ready(Outcome::Closed)
        );
        drop(escaped);
        assert_eq!(timers.capacity(), (0, 0));
        assert_eq!(Arc::strong_count(&count), 2);
    }

    /// A sleep registered on `timers` at `deadline` with `waker`, as a first
    /// pending poll on their owner would leave it.
    fn registered(timers: &Arc<Timers>, deadline: Instant, waker: &Waker) -> Sleep {
        let mut deferred = Deferred::default();
        let (sleeper, _) = timers.register(waker.clone(), deadline, &mut Vec::new(), &mut deferred);
        Sleep {
            state: State::Registered(sleeper),
        }
    }

    #[test]
    fn test_fired_sleep_completes_after_closure() {
        // No service pass ran on this thread, so polls take the lock.
        assert!(turn().is_none());

        // A registration whose deadline has passed fires, and its timers
        // close before its sleep observes the firing.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = Instant::now();
        let mut sleep = registered(&timers, deadline, &waker);
        let epoch = timers.epoch();
        let mut deferred = Deferred::default();
        timers.expire(timers.nanos(deadline) + RESOLUTION, BUDGET, &mut deferred);
        assert_eq!(timers.epoch(), epoch + 1);
        run(&mut deferred);
        assert_eq!(count.get(), 1);

        // Closure ends nothing more, so it keeps the epoch, and discards the
        // fired registration.
        timers.close(&mut deferred);
        assert!(deferred.is_empty());
        assert_eq!(timers.epoch(), epoch + 1);
        assert_eq!(timers.live(), 0);

        // The deadline has passed, so the sleep completes, and a repoll
        // stays complete.
        let mut cx = Context::from_waker(&waker);
        assert!(sleep.poll_unpin(&mut cx).is_ready());
        assert!(matches!(sleep.state, State::Done));
        assert!(sleep.poll_unpin(&mut cx).is_ready());
        drop(sleep);
        assert_eq!(count.get(), 1);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_closed_sleep_completes_only_past_its_deadline() {
        // No service pass ran on this thread, so polls take the lock.
        assert!(turn().is_none());

        // Two pending registrations close, one whose deadline has passed and
        // one whose deadline is ahead.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let mut passed = registered(&timers, Instant::now(), &waker);
        let mut ahead = registered(&timers, Instant::now() + Duration::from_secs(60), &waker);
        let mut deferred = Deferred::default();
        timers.close(&mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 2);

        // The first completes, and a repoll stays complete. The second has
        // no error output, so its poll panics.
        let mut cx = Context::from_waker(&waker);
        assert!(passed.poll_unpin(&mut cx).is_ready());
        assert!(passed.poll_unpin(&mut cx).is_ready());
        let panic = catch_unwind(AssertUnwindSafe(|| ahead.poll_unpin(&mut cx)))
            .expect_err("a closed sleep completed before its deadline");
        assert!(
            extract_panic_message(&*panic)
                .starts_with("io_uring sleep polled after its worker closed")
        );

        // Neither drop finds anything left to release.
        drop(passed);
        drop(ahead);
        assert_eq!(timers.live(), 0);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_closed_sleep_ahead_of_its_deadline_never_completes() {
        // No service pass ran on this thread, so polls take the lock.
        assert!(turn().is_none());

        // A pending registration whose deadline is ahead closes.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let mut ahead = registered(&timers, Instant::now() + Duration::from_secs(60), &waker);
        let mut deferred = Deferred::default();
        timers.close(&mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);

        // The sleep has no error output, so every poll before its deadline
        // panics, including one that follows a caught panic, and each one
        // observes the closure under the lock.
        let mut cx = Context::from_waker(&waker);
        for _ in 0..3 {
            let before = locks();
            let panic = catch_unwind(AssertUnwindSafe(|| ahead.poll_unpin(&mut cx)))
                .expect_err("a closed sleep completed before its deadline");
            assert!(
                extract_panic_message(&*panic)
                    .starts_with("io_uring sleep polled after its worker closed")
            );
            assert_eq!(locks() - before, 1);
            assert!(matches!(ahead.state, State::Registered(_)));
        }

        // Its drop finds nothing left to release.
        drop(ahead);
        assert_eq!(timers.live(), 0);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_rescue_skips_held_or_closed_timers() {
        // An overdue registration on timers whose lock this thread holds.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = later();
        let _sleeper = register(&timers, deadline, &waker);
        let held = timers.hold();

        // Rescue from another thread skips the timers instead of waiting.
        let rescued = thread::scope(|scope| {
            scope
                .spawn(|| timers.rescue(deadline + RESOLUTION, &mut Deferred::default()))
                .join()
                .unwrap()
        });
        assert!(!rescued);

        // Once the lock is free, rescue fires the registration.
        drop(held);
        let mut deferred = Deferred::default();
        assert!(timers.rescue(deadline + RESOLUTION, &mut deferred));
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(timers.published(), u64::MAX);

        // Closed timers are never rescued, even past a pending deadline.
        let _pending = register(&timers, deadline + 1_000_000, &waker);
        timers.close(&mut deferred);
        run(&mut deferred);
        assert!(!timers.rescue(deadline + 2_000_000, &mut deferred));
        assert!(deferred.is_empty());
    }

    #[test]
    fn test_rescue_selects_only_peers_overdue_by_the_threshold() {
        // One registration on each of three workers' timers with one origin,
        // all firing at `firing`.
        let threshold = RESCUE_THRESHOLD.as_nanos() as u64;
        let origin = Instant::now();
        let all: Vec<_> = (0..3)
            .map(|_| Arc::new(Timers::with_origin(origin)))
            .collect();
        let (count, waker) = counter();
        let deadline = later();
        let firing = Wheel::<RESOLUTION>::rounded(deadline);
        let _sleepers: Vec<_> = all
            .iter()
            .map(|timers| register(timers, deadline, &waker))
            .collect();

        // Overdue by less than the threshold, nobody is rescued.
        let mut deferred = Deferred::default();
        let at = |nanos| all[0].instant(nanos).unwrap();
        Timers::rescue_peers(&all, 0, at(firing + threshold - 1), &mut deferred);
        assert!(deferred.is_empty());

        // At the threshold, every peer is, but never the caller's own timers.
        Timers::rescue_peers(&all, 0, at(firing + threshold), &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 2);
        assert_eq!(all[0].resident(), 1);
        assert_eq!(all[1].resident(), 0);
        assert_eq!(all[2].resident(), 0);
    }

    #[test]
    fn test_rescue_leaves_a_backlog_to_an_owner_that_serves() {
        // Three budgets of registrations on worker 1's timers, all firing at
        // `firing`, of two workers' timers with one origin.
        let threshold = RESCUE_THRESHOLD.as_nanos() as u64;
        let origin = Instant::now();
        let all: Vec<_> = (0..2)
            .map(|_| Arc::new(Timers::with_origin(origin)))
            .collect();
        let (count, waker) = counter();
        let deadline = later();
        let firing = Wheel::<RESOLUTION>::rounded(deadline);
        let budget = BUDGET as usize;
        let _sleepers: Vec<_> = (0..3 * budget)
            .map(|_| register(&all[1], deadline, &waker))
            .collect();

        // The owner's late pass fires one budget and leaves the rest due, with
        // its bound at or before their firing time.
        let served = firing + 2 * threshold;
        let mut deferred = Deferred::default();
        assert!(all[1].expire(served, BUDGET, &mut deferred) <= firing);
        assert_eq!(deferred.wakes.len(), budget);
        run(&mut deferred);

        // The bound is overdue by more than the threshold, but while the
        // owner's pass is recent, peers leave the backlog to the owner.
        let at = |nanos| all[0].instant(nanos).unwrap();
        Timers::rescue_peers(&all, 0, at(served + threshold - 1), &mut deferred);
        assert!(deferred.is_empty());

        // An owner that has not served for the threshold is rescued, one
        // budget per check. A rescue leaves the owner's pass time alone, so
        // the next check, however soon, rescues the owner again.
        Timers::rescue_peers(&all, 0, at(served + threshold), &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 2 * budget);
        Timers::rescue_peers(&all, 0, at(served + threshold), &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 3 * budget);
    }

    #[test]
    fn test_early_completion_is_bounded_by_the_turn_time() {
        // One registration well in the future.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut sleeper = register(&timers, deadline, &waker);

        // A poll completes early once the worker's turn time reaches the
        // deadline. Reset the turn time so later tests on this thread see none.
        Sleep::set_turn(timers.instant(deadline - 1).unwrap());
        assert!(poll_with(&mut sleeper, &waker).is_pending());
        Sleep::set_turn(timers.instant(deadline).unwrap());
        assert_eq!(poll_with(&mut sleeper, &waker), Poll::Ready(Outcome::Fired));
        TURN.set(None);
        drop(sleeper);

        // The poll removed the registration without a wake.
        assert_eq!(timers.resident(), 0);
        assert_eq!(timers.live(), 0);
        let mut deferred = Deferred::default();
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        assert!(deferred.is_empty());
        assert_eq!(count.get(), 0, "woke an early completion");
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_reused_slot_belongs_to_the_new_registration() {
        // A registration after a cancellation reuses its slot under a new
        // generation, and the old identifier no longer resolves.
        let timers = Arc::new(Timers::new());
        let deadline = later();
        let old = register(&timers, deadline, Waker::noop());
        let old_id = old.id;
        old.abandon();
        let (count, waker) = counter();
        let mut current = register(&timers, deadline + 1_000_000, &waker);
        assert_eq!(old_id.index, current.id.index);
        assert_ne!(old_id.generation, current.id.generation);
        assert!(!timers.holds(old_id));

        // The old deadline fires nothing, the new one at its own.
        let mut deferred = Deferred::default();
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        assert!(deferred.is_empty());
        timers.expire(deadline + 1_000_000 + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(poll_with(&mut current, &waker), Poll::Ready(Outcome::Fired));
    }

    /// Run `test` inside a runtime task's poll, with that task's waker.
    fn with_task_waker(test: impl FnOnce(&Waker) + Send + 'static) {
        Runner::default().start(|context| async move {
            context
                .spawn(|_| async move {
                    let waker = std::future::poll_fn(|cx| Poll::Ready(cx.waker().clone())).await;
                    assert!(Task::is_waker(&waker));
                    test(&waker);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_task_waker_polls_without_the_lock() {
        with_task_waker(|waker| {
            // A registration with a task's waker, on timers of no worker.
            let timers = Arc::new(Timers::new());
            let sleeper = register(&timers, later(), waker);

            // While this thread holds the lock, a poll with the registered
            // waker on another thread returns pending, which it could not if
            // it locked.
            let held = timers.hold();
            let (sender, receiver) = mpsc::channel();
            let poller = thread::spawn({
                let waker = waker.clone();
                move || {
                    let mut sleeper = sleeper;
                    let pending = poll_with(&mut sleeper, &waker).is_pending();
                    sender.send((pending, locks())).unwrap();
                    sleeper
                }
            });
            let (pending, locked) = receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("a poll with an unchanged task waker waited for the lock");
            assert!(pending);
            assert_eq!(locked, 0);
            drop(held);
            poller.join().unwrap().abandon();
        });
    }

    #[test]
    fn test_waker_of_another_kind_at_a_task_address_takes_the_lock() {
        /// The vtable of a waker of no task, whose functions never use its
        /// data.
        static FORGED_VTABLE: RawWakerVTable =
            RawWakerVTable::new(forged_clone, forged_ignore, forged_ignore, forged_ignore);

        /// Clone a forged waker.
        unsafe fn forged_clone(data: *const ()) -> RawWaker {
            RawWaker::new(data, &FORGED_VTABLE)
        }

        /// Wake or drop a forged waker.
        const unsafe fn forged_ignore(_: *const ()) {}

        with_task_waker(|waker| {
            // A registration with a task's waker, and a waker of another kind
            // that carries the same data address.
            let timers = Arc::new(Timers::new());
            let mut sleeper = register(&timers, later(), waker);
            // SAFETY: No function of the vtable dereferences the data.
            let forged = unsafe { Waker::from_raw(RawWaker::new(waker.data(), &FORGED_VTABLE)) };

            // The address alone matches nothing. The poll locks, finds that
            // the waker differs, and stores its clone in a second critical
            // section.
            let before = locks();
            assert!(poll_with(&mut sleeper, &forged).is_pending());
            assert_eq!(locks() - before, 2);
            assert!(timers.waits_with(sleeper.id, &forged));
            sleeper.abandon();
        });
    }

    #[test]
    fn test_changed_waker_is_cloned_outside_the_lock() {
        // Register with a first waker, then poll with a second, neither of
        // them a task waker.
        let timers = Arc::new(Timers::new());
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        let deadline = later();
        let mut sleeper = register(&timers, deadline, &first_waker);
        let before = locks();
        assert!(poll_with(&mut sleeper, &second_waker).is_pending());

        // The poll found the waker changed in one critical section, cloned it
        // after the lock, and stored the clone in a second one. Off a worker,
        // the displaced first waker was released at once.
        assert_eq!(locks() - before, 2);
        assert!(timers.waits_with(sleeper.id, &second_waker));
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(Arc::strong_count(&second), 3);

        // Later polls with the second waker lock once each and clone nothing.
        let before = locks();
        assert!(poll_with(&mut sleeper, &second_waker).is_pending());
        assert!(poll_with(&mut sleeper, &second_waker).is_pending());
        assert_eq!(locks() - before, 2);
        assert_eq!(Arc::strong_count(&second), 3);

        // Once fired, a poll with a changed waker locks once and reports the
        // firing without a clone.
        let mut deferred = Deferred::default();
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);
        assert_eq!((first.get(), second.get()), (0, 1));
        let before = locks();
        assert_eq!(
            poll_with(&mut sleeper, &first_waker),
            Poll::Ready(Outcome::Fired)
        );
        assert_eq!(locks() - before, 1);
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(Arc::strong_count(&second), 2);
    }

    #[test]
    fn test_endings_invalidate_lock_free_polls() {
        with_task_waker(|waker| {
            /// A party other than the sleep that ends a waiting registration
            /// at a given time.
            type End = fn(&Timers, u64, &mut Deferred);

            // Expiry, rescue, and closure each end a waiting registration.
            let ends: [(End, Outcome); 3] = [
                (
                    |timers, now, deferred| {
                        timers.expire(now, BUDGET, deferred);
                    },
                    Outcome::Fired,
                ),
                (
                    |timers, now, deferred| assert!(timers.rescue(now, deferred)),
                    Outcome::Fired,
                ),
                (
                    |timers, _, deferred| timers.close(deferred),
                    Outcome::Closed,
                ),
            ];
            for (end, outcome) in ends {
                // A pending registration with a task's waker, polled without
                // the lock.
                let timers = Arc::new(Timers::new());
                let deadline = later();
                let mut sleeper = register(&timers, deadline, waker);
                let before = locks();
                assert!(poll_with(&mut sleeper, waker).is_pending());
                assert_eq!(locks(), before);

                // A pass that ends nothing keeps the epoch, and an ending
                // advances it before its wake runs.
                let epoch = timers.epoch();
                let mut deferred = Deferred::default();
                timers.expire(deadline - RESOLUTION, BUDGET, &mut deferred);
                assert_eq!(timers.epoch(), epoch);
                end(&timers, deadline + RESOLUTION, &mut deferred);
                assert_eq!(timers.epoch(), epoch + 1);
                assert_eq!(deferred.wakes.len(), 1);
                run(&mut deferred);

                // The next poll with the same waker locks and observes the
                // ending.
                let before = locks();
                assert_eq!(poll_with(&mut sleeper, waker), Poll::Ready(outcome));
                assert_eq!(locks() - before, 1);
            }
        });
    }

    #[test]
    fn test_epoch_change_costs_one_lock() {
        with_task_waker(|waker| {
            // A waiting registration with a task's waker, and an earlier one
            // that fires.
            let timers = Arc::new(Timers::new());
            let deadline = later();
            let mut waiting = register(&timers, deadline + 1_000_000, waker);
            let _fired = register(&timers, deadline, Waker::noop());
            let mut deferred = Deferred::default();
            timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
            run(&mut deferred);

            // The firing advanced the epoch, so the waiting sleeper's next poll
            // locks once, finds it waiting, and caches the new epoch.
            let before = locks();
            assert!(poll_with(&mut waiting, waker).is_pending());
            assert_eq!(locks() - before, 1);

            // Later polls take no lock.
            assert!(poll_with(&mut waiting, waker).is_pending());
            assert_eq!(locks() - before, 1);
            waiting.abandon();
        });
    }

    /// Wait without sleeping until both of two threads have called this for
    /// `round`, counting arrivals in `arrived`, so their next steps overlap.
    /// Returns false at once if `gone` reports that the other thread exited.
    fn meet(arrived: &AtomicUsize, round: usize, gone: impl Fn() -> bool) -> bool {
        arrived.fetch_add(1, Ordering::SeqCst);
        while arrived.load(Ordering::SeqCst) < 2 * (round + 1) {
            if gone() {
                return false;
            }
            std::hint::spin_loop();
        }
        true
    }

    #[test]
    fn test_lock_free_polls_race_expiry_without_losing_wakes() {
        with_task_waker(|waker| {
            // A thread polls each registration it receives with the
            // registered task waker until it completes. `woken` counts the
            // expiries whose wakes have run.
            let timers = Arc::new(Timers::new());
            let arrived = Arc::new(AtomicUsize::new(0));
            let woken = Arc::new(AtomicUsize::new(0));
            let (sender, receiver) = mpsc::channel::<Sleeper>();
            let poller = thread::spawn({
                let arrived = arrived.clone();
                let woken = woken.clone();
                let waker = waker.clone();
                move || {
                    for (round, mut sleeper) in receiver.into_iter().enumerate() {
                        meet(&arrived, round, || false);

                        // Poll spuriously while the expiry runs, then only
                        // after a wake. A wake that ran before a poll began
                        // must make that poll ready, since no later wake
                        // comes.
                        let mut polls = 0;
                        loop {
                            let seen = woken.load(Ordering::SeqCst);
                            if let Poll::Ready(outcome) = poll_with(&mut sleeper, &waker) {
                                assert_eq!(outcome, Outcome::Fired);
                                break;
                            }
                            polls += 1;
                            if polls < 256 {
                                continue;
                            }
                            let start = Instant::now();
                            while woken.load(Ordering::SeqCst) == seen {
                                assert!(
                                    start.elapsed() < Duration::from_secs(10),
                                    "lost a wake in round {round}"
                                );
                                thread::yield_now();
                            }
                        }
                    }
                }
            });

            // Expire each registration at a varying point among the polls. A
            // poller that exited early failed, which joining it reports.
            for round in 0..2000 {
                let deadline = later();
                let sleeper = register(&timers, deadline, waker);
                sender.send(sleeper).unwrap();
                if !meet(&arrived, round, || poller.is_finished()) {
                    break;
                }
                for _ in 0..round % 256 {
                    std::hint::spin_loop();
                }
                let mut deferred = Deferred::default();
                timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
                run(&mut deferred);
                woken.fetch_add(1, Ordering::SeqCst);
            }
            drop(sender);
            poller.join().unwrap();
            assert_eq!(timers.live(), 0);
        });
    }

    #[test]
    fn test_emptying_drop_publishes_no_bound() {
        // Two registrations, so dropping the earlier leaves the later one.
        let timers = Arc::new(Timers::new());
        let deadline = later();
        let early = register(&timers, deadline, Waker::noop());
        let late = register(&timers, deadline + 1_000_000, Waker::noop());

        // A drop that leaves a registration keeps the published bound, which
        // is then early.
        early.abandon();
        assert_eq!(timers.published(), Wheel::<RESOLUTION>::rounded(deadline));

        // A drop that empties the wheel publishes none.
        late.abandon();
        assert_eq!(timers.published(), u64::MAX);
    }

    #[test]
    fn test_crowded_bucket_is_refiled_before_its_firing_time() {
        // Eight budgets of sleeps share one deadline a minute ahead, and with
        // it one high wheel bucket, which they crowd.
        let timers = Arc::new(Timers::new());
        let deadline = 60_000_000_000;
        let firing = Wheel::<RESOLUTION>::rounded(deadline);
        let mut cached = u64::MAX;
        let sleepers: Vec<_> = (0..8 * BUDGET)
            .map(|_| {
                let (sleeper, at) = timers.register_alone(Waker::noop().clone(), deadline);
                cached = cached.min(at);
                sleeper
            })
            .collect();

        // The owner's cached bound falls to the bucket's start, the wheel's
        // bound, while peers still read the firing time.
        assert!(cached < firing);
        assert_eq!(cached, timers.bound());
        assert_eq!(timers.published(), firing);

        // Passes at the bounds they return refile the bucket down the levels
        // and fire nothing, each publishing its bound.
        let mut deferred = Deferred::default();
        let mut bound = cached;
        while bound < firing {
            bound = timers.expire(bound, BUDGET, &mut deferred);
            assert!(deferred.is_empty());
            assert_eq!(timers.published(), bound);
        }
        assert_eq!(bound, firing);

        // So the first pass at the firing time spends its whole budget on
        // firing.
        assert!(timers.expire(firing, BUDGET, &mut deferred) <= firing);
        assert_eq!(deferred.wakes.len(), BUDGET as usize);
        assert_eq!(timers.resident(), sleepers.len() - BUDGET as usize);
    }

    /// A waker that fails if its clone, wake, or drop runs while its timers
    /// are locked or its thread's worker is borrowed.
    struct LockCheck {
        /// The timers whose lock must be free during every callback.
        timers: Arc<Timers>,
        /// Number of callbacks run.
        callbacks: AtomicUsize,
    }

    /// The vtable of every [`LockCheck`] waker.
    static LOCK_CHECK_VTABLE: RawWakerVTable = RawWakerVTable::new(
        LockCheck::clone,
        LockCheck::wake,
        LockCheck::wake_by_ref,
        LockCheck::drop,
    );

    impl LockCheck {
        /// A waker of `this`.
        fn waker(this: &Arc<Self>) -> Waker {
            let data = Arc::into_raw(this.clone()).cast::<()>();
            // SAFETY: The vtable's functions treat `data` as one Arc reference.
            unsafe { Waker::from_raw(RawWaker::new(data, &LOCK_CHECK_VTABLE)) }
        }

        /// Count a callback, failing if the timers are locked or this thread's
        /// worker is borrowed.
        fn check(&self) {
            assert!(
                self.timers.try_guard().is_some(),
                "waker callback under the timers' lock"
            );
            assert!(
                Local::current().is_none_or(|local| local.try_borrow_mut().is_ok()),
                "waker callback under a worker borrow"
            );
            self.callbacks.fetch_add(1, Ordering::SeqCst);
        }

        /// Clone the waker, as one more Arc reference, after a check.
        unsafe fn clone(data: *const ()) -> RawWaker {
            // SAFETY: `data` is one Arc reference, borrowed here.
            let this = mem::ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Self>()) });
            this.check();
            let data = Arc::into_raw(Arc::clone(&this)).cast::<()>();
            RawWaker::new(data, &LOCK_CHECK_VTABLE)
        }

        /// Wake and consume the waker after a check.
        unsafe fn wake(data: *const ()) {
            // SAFETY: `data` is one Arc reference, consumed here.
            let this = unsafe { Arc::from_raw(data.cast::<Self>()) };
            this.check();
        }

        /// Wake the waker without consuming it after a check.
        unsafe fn wake_by_ref(data: *const ()) {
            // SAFETY: `data` is one Arc reference, borrowed here.
            let this = mem::ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Self>()) });
            this.check();
        }

        /// Drop the waker's Arc reference after a check.
        unsafe fn drop(data: *const ()) {
            // SAFETY: `data` is one Arc reference, consumed here.
            let this = unsafe { Arc::from_raw(data.cast::<Self>()) };
            this.check();
        }
    }

    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_callbacks_never_run_under_the_timers_lock() {
        // Three checked wakers on one worker's timers.
        let timers = Arc::new(Timers::new());
        let checks: Vec<_> = (0..3)
            .map(|_| {
                Arc::new(LockCheck {
                    timers: timers.clone(),
                    callbacks: AtomicUsize::new(0),
                })
            })
            .collect();
        let wakers: Vec<_> = checks.iter().map(LockCheck::waker).collect();
        let deadline = later();

        // Register, refresh (a clone and a displaced drop), repoll unchanged,
        // expire and wake, and observe the firing.
        let mut fired = register(&timers, deadline, &wakers[0]);
        assert!(poll_with(&mut fired, &wakers[1]).is_pending());
        assert!(poll_with(&mut fired, &wakers[1]).is_pending());
        let mut deferred = Deferred::default();
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);
        assert_eq!(
            poll_with(&mut fired, &wakers[1]),
            Poll::Ready(Outcome::Fired)
        );

        // Drop a waiting registration off a worker, remove one whose sleep
        // left its identity for its owner's batch, and close one.
        let cancelled = register(&timers, deadline, &wakers[2]);
        cancelled.abandon();
        let abandoned = register(&timers, deadline, &wakers[2]);
        let mut dropped = vec![abandoned.id];
        drop(abandoned);
        assert!(timers.drain(&mut dropped, &mut deferred));
        run(&mut deferred);
        let mut closed = register(&timers, deadline + 1_000_000, &wakers[2]);
        timers.close(&mut deferred);
        run(&mut deferred);
        assert_eq!(
            poll_with(&mut closed, &wakers[2]),
            Poll::Ready(Outcome::Closed)
        );

        // Every waker ran a callback, and the timers released all their clones.
        drop(wakers);
        for check in &checks {
            assert!(check.callbacks.load(Ordering::SeqCst) > 0);
            assert_eq!(Arc::strong_count(check), 1);
        }
    }

    #[test]
    fn test_expiry_races_foreign_polls() {
        let timers = Arc::new(Timers::new());
        for round in 0..300 {
            // A registration moves to a thread that changes its waker while
            // this one expires it.
            let deadline = later();
            let (_, first_waker) = counter();
            let sleeper = register(&timers, deadline, &first_waker);
            let barrier = Arc::new(Barrier::new(2));
            let poller = {
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let mut sleeper = sleeper;
                    barrier.wait();

                    // Change the waker twice, racing the expiry.
                    let (_, second_waker) = counter();
                    let (third, third_waker) = counter();
                    if poll_with(&mut sleeper, &second_waker).is_ready() {
                        return;
                    }
                    if poll_with(&mut sleeper, &third_waker).is_ready() {
                        return;
                    }

                    // Pending leaves the last waker to be woken.
                    let start = Instant::now();
                    while third.get() == 0 {
                        assert!(
                            start.elapsed() < Duration::from_secs(10),
                            "lost a wake in round {round}"
                        );
                        thread::yield_now();
                    }
                    assert_eq!(
                        poll_with(&mut sleeper, &third_waker),
                        Poll::Ready(Outcome::Fired)
                    );
                })
            };

            // Expire as the poller starts.
            barrier.wait();
            let mut deferred = Deferred::default();
            timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
            run(&mut deferred);
            poller.join().unwrap();
        }
        assert_eq!(timers.live(), 0);
    }

    #[test]
    fn test_drops_race_expiry() {
        let timers = Arc::new(Timers::new());
        for _ in 0..300 {
            // Eight registrations, whose only waker clones the timers hold.
            let deadline = later();
            let (count, waker) = counter();
            let sleepers: Vec<_> = (0..8)
                .map(|_| register(&timers, deadline, &waker))
                .collect();
            drop(waker);

            // Drop them on another thread while this one expires them.
            let dropper = thread::spawn(move || {
                for sleeper in sleepers {
                    sleeper.abandon();
                }
            });
            let mut deferred = Deferred::default();
            timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
            run(&mut deferred);
            dropper.join().unwrap();

            // Either way, every registration is gone and every clone released.
            assert_eq!(timers.live(), 0);
            assert_eq!(Arc::strong_count(&count), 1, "leaked a waker");
        }
    }

    #[test]
    fn test_waker_refresh_and_clone_panic_preserve_cancellation() {
        Runner::default().start(|_| async {
            // A first poll registers with the first waker.
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let first = Arc::new(Reentrant::default());
            let first_waker = first.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            let (timers, id) = registration(&sleep);

            // A replacement keeps the registration and defers destruction of
            // its previous waker until after the poll.
            let second = Arc::new(Reentrant::default());
            let second_waker = second.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            assert!(timers.waits_with(id, &second_waker));
            assert_eq!(first.drops.load(Ordering::Relaxed), 0);
            reschedule().await;
            assert_eq!(first.drops.load(Ordering::Relaxed), 1);

            // Restoring the first waker now panics during cloning. The second
            // waker and the registration must survive.
            first
                .panic_callback
                .store(Reentrant::CLONE, Ordering::Relaxed);
            let panic = catch_unwind(AssertUnwindSafe(|| {
                let _ = sleep.poll_unpin(&mut Context::from_waker(&first_waker));
            }))
            .expect_err("changed sleep waker must clone");
            assert_eq!(extract_panic_message(&*panic), "waker callback panic 1");
            assert!(timers.waits_with(id, &second_waker));

            // Dropping it on its worker leaves the registration to the next
            // service pass, which removes it and defers destruction of its
            // waker until after the pass.
            drop(sleep);
            assert!(timers.holds(id));
            assert_eq!(second.drops.load(Ordering::Relaxed), 0);
            reschedule().await;
            assert!(!timers.holds(id));
            assert_eq!(second.drops.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn test_foreign_drop_removes_the_registration() {
        for poll_first in [false, true] {
            Runner::default().start(|_| async move {
                // Register on the owner, then drop the sleep on another
                // thread, optionally after polling it there.
                let mut sleep = Sleep::new(Duration::from_secs(60));
                assert!(poll!(&mut sleep).is_pending());
                let (timers, id) = registration(&sleep);
                thread::spawn(move || {
                    if poll_first {
                        assert!(
                            sleep
                                .poll_unpin(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                    }
                    drop(sleep);
                })
                .join()
                .unwrap();

                // The foreign drop removed the registration without the owner.
                assert!(!timers.holds(id));
            });
        }
    }

    #[test]
    fn test_sleep_moves_between_threads() {
        for return_to_owner in [false, true] {
            Runner::default().start(|_| async move {
                // Register on the owner and poll on two foreign threads, then
                // complete on the owner or on yet another thread.
                let start = Instant::now();
                let mut sleep = Sleep::new(Duration::from_millis(20));
                assert!(poll!(&mut sleep).is_pending());
                let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
                let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
                if return_to_owner {
                    sleep.await;
                } else {
                    let (sender, receiver) = oneshot::channel();
                    let thread = thread::spawn(move || {
                        futures::executor::block_on(sleep);
                        sender.send(()).unwrap();
                    });
                    receiver.await.unwrap();
                    thread.join().unwrap();
                }

                // Completion on any thread respects the deadline.
                assert!(start.elapsed() >= Duration::from_millis(20));
            });
        }

        // Once the owner fired it, any thread observes the completion at once.
        Runner::default().start(|context| async move {
            let mut sleep = Sleep::new(Duration::from_millis(20));
            assert!(poll!(&mut sleep).is_pending());
            context.sleep(Duration::from_millis(30)).await;
            thread::spawn(move || {
                assert!(
                    sleep
                        .poll_unpin(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                );
            })
            .join()
            .unwrap();
        });
    }

    #[test]
    fn test_foreign_poll_and_drop_free_the_slot_for_reuse() {
        Runner::default().start(|_| async {
            // Register, poll once on another thread, and drop the sleep on
            // its worker, whose next service pass frees the slot.
            let mut sleep = Sleep::new(Duration::from_secs(60));
            assert!(poll!(&mut sleep).is_pending());
            let (timers, old) = registration(&sleep);
            let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
            drop(sleep);
            reschedule().await;

            // A replacement reuses the slot under a new generation.
            let mut replacement = Sleep::new(Duration::from_secs(60));
            assert!(poll!(&mut replacement).is_pending());
            let (_, current) = registration(&replacement);
            assert_eq!(old.index, current.index);
            assert_ne!(old.generation, current.generation);

            // After a worker turn, only the replacement is held, until it drops
            // and the next service pass removes it.
            reschedule().await;
            assert!(poll!(&mut replacement).is_pending());
            assert!(!timers.holds(old));
            assert!(timers.holds(current));
            drop(replacement);
            reschedule().await;
            assert!(!timers.holds(current));
        });
    }

    #[test]
    fn test_closure_wakes_a_foreign_waker_and_rejects_the_sleep() {
        for foreign_waker in [false, true] {
            let local = Arc::new(Reentrant::default());
            let foreign = Arc::new(Reentrant::default());
            let (mut sleep,) = Runner::default().start(|_| async {
                // Register on the owner, then poll on another thread with the
                // same or a foreign waker, and let the runner close.
                let mut sleep = Sleep::new(Duration::from_secs(60));
                assert!(
                    sleep
                        .poll_unpin(&mut Context::from_waker(&local.waker()))
                        .is_pending()
                );
                let waker = if foreign_waker {
                    foreign.waker()
                } else {
                    local.waker()
                };
                (poll_on_foreign_thread(sleep, waker),)
            });

            // Closure woke the waker of the latest poll.
            let woken = if foreign_waker { &foreign } else { &local };
            assert_eq!(woken.wakes.load(Ordering::Relaxed), 1);

            // Polling the closed, unexpired sleep panics, and dropping it
            // leaves no waker clone behind.
            let result = catch_unwind(AssertUnwindSafe(|| {
                sleep.poll_unpin(&mut Context::from_waker(Waker::noop()))
            }));
            assert!(
                extract_panic_message(&*result.unwrap_err())
                    .starts_with("io_uring sleep polled after its worker closed")
            );
            drop(sleep);
            assert_eq!(Arc::strong_count(&local), 1);
            assert_eq!(Arc::strong_count(&foreign), 1);
        }
    }

    #[test]
    fn test_closure_wakes_a_pending_poll_on_another_thread() {
        // A foreign thread blocks on the sleep and signals after its first poll.
        let (registered, ready) = mpsc::channel();
        let poller = Runner::default().start(|_| async move {
            let mut sleep = Box::pin(Sleep::new(Duration::from_secs(60)));
            assert!(poll!(sleep.as_mut()).is_pending());
            let poller = thread::spawn(move || {
                let mut first = true;
                let waiting = std::future::poll_fn(move |cx| {
                    let result = sleep.as_mut().poll(cx);
                    if mem::take(&mut first) {
                        registered.send(()).unwrap();
                    }
                    result
                });
                catch_unwind(AssertUnwindSafe(|| futures::executor::block_on(waiting)))
            });

            // The foreign poll installed its waker before the runner closes.
            ready.recv().unwrap();
            poller
        });

        // Closure woke the poller, whose next poll rejects the unexpired sleep.
        let panic = poller
            .join()
            .unwrap()
            .expect_err("closure must reject the sleep");
        assert!(
            extract_panic_message(&*panic)
                .starts_with("io_uring sleep polled after its worker closed")
        );
    }

    #[test]
    fn test_worker_closure_releases_escaped_sleep() {
        // A sleep registered with a counting waker escapes its runner.
        let counter = Arc::new(Count::default());
        let (mut sleep,) = Runner::default().start(|_| async {
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let waker = Waker::from(counter.clone());
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            (sleep,)
        });

        // Shutdown ends the registration and wakes its waker.
        assert_eq!(Arc::strong_count(&counter), 1);
        assert_eq!(counter.get(), 1);

        // Sleep has no error output. Polling after closure must panic rather
        // than report that an unelapsed deadline completed.
        let panic = catch_unwind(AssertUnwindSafe(|| {
            sleep.poll_unpin(&mut Context::from_waker(Waker::noop()))
        }))
        .expect_err("registered sleep must reject polling after closure");
        assert!(
            extract_panic_message(&*panic)
                .starts_with("io_uring sleep polled after its worker closed")
        );
        drop(sleep);
    }

    #[test]
    fn test_closed_sleep_past_its_deadline_completes() {
        // A sleep registered with 30 ms left escapes its runner, which closes.
        let (mut sleep,) = Runner::default().start(|_| async {
            let mut sleep = Sleep::new(Duration::from_millis(30));
            assert!(poll!(&mut sleep).is_pending());
            (sleep,)
        });

        // Once the deadline passes, polling completes instead of panicking.
        thread::sleep(Duration::from_millis(40));
        assert!(
            sleep
                .poll_unpin(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }

    #[test]
    fn test_storm_beyond_one_budget_drains() {
        Runner::default().start(|_| async {
            // Four budgets of sleeps share one exact deadline.
            let deadline = Instant::now() + Duration::from_millis(5);
            let sleeps: Vec<_> = (0..4 * BUDGET).map(|_| Sleep::at(deadline)).collect();

            // All of them complete, none before the deadline.
            futures::future::join_all(sleeps).await;
            assert!(Instant::now() >= deadline);
        });
    }

    #[test]
    fn test_dedicated_worker_fires_a_full_budget_per_pass() {
        Runner::default().start(|context| async move {
            context
                .dedicated()
                .spawn(|_| async {
                    // One more than a budget of sleeps share a deadline that
                    // passes before the next service pass.
                    let (count, waker) = counter();
                    let deadline = Instant::now() + Duration::from_millis(2);
                    let mut sleeps: Vec<_> = (0..=BUDGET).map(|_| Sleep::at(deadline)).collect();
                    for sleep in &mut sleeps {
                        pend(sleep, &waker);
                    }
                    let (timers, _) = registration(&sleeps[0]);
                    thread::sleep(Duration::from_millis(3));

                    // A dedicated worker has no run queue to cap its expiry,
                    // so its next service pass fires a full budget.
                    reschedule().await;
                    assert_eq!(count.get(), BUDGET as usize);
                    assert_eq!(timers.resident(), 1);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_exact_deadlines_share_one_firing_time() {
        Runner::default().start(|context| async move {
            // A dedicated worker's timers are private, so nothing else registers.
            context
                .dedicated()
                .spawn(|_| async {
                    let deadline = Instant::now() + Duration::from_secs(60);
                    let mut first = Sleep::at(deadline);
                    let mut second = Sleep::at(deadline);
                    assert!(poll!(&mut first).is_pending());
                    assert!(poll!(&mut second).is_pending());

                    // Both are resident at one firing time, which the worker
                    // caches as its next bound.
                    let (timers, _) = registration(&first);
                    assert_eq!(timers.resident(), 2);
                    assert_eq!(
                        timers.bound(),
                        Wheel::<RESOLUTION>::rounded(timers.nanos(deadline))
                    );
                    let local = Local::current().unwrap();
                    assert_eq!(local.borrow().timers_next, timers.bound());
                })
                .await
                .unwrap();
        });
    }

    /// Spin until the clock reaches `deadline`, without yielding to the
    /// worker.
    fn spin_until(deadline: Instant) {
        while Instant::now() < deadline {
            std::hint::spin_loop();
        }
    }

    #[test]
    fn test_first_poll_reads_the_clock_for_a_short_sleep() {
        Runner::default().start(|context| async move {
            context
                .spawn(|_| async {
                    // The worker has polled for longer than the unchecked
                    // bound since its latest service pass.
                    let served = turn().expect("a worker has a service time");
                    spin_until(served + 2 * UNCHECKED_SLEEP);

                    // A sleep shorter than the bound passes its deadline
                    // during synchronous work, with no service pass since.
                    let mut sleep = Sleep::new(UNCHECKED_SLEEP / 10);
                    let (deadline, created) = sleep.unregistered();
                    assert!(created.is_none());
                    spin_until(deadline);
                    assert_eq!(turn(), Some(served));

                    // Its first poll reads the clock and completes it.
                    assert!(poll!(&mut sleep).is_ready());
                    assert!(matches!(sleep.state, State::Done));
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_first_poll_reads_the_clock_after_a_service_pass() {
        Runner::default().start(|context| async move {
            context
                .spawn(|_| async {
                    // A sleep at least as long as the unchecked bound, which a
                    // service pass follows before its first poll.
                    let mut sleep = Sleep::new(5 * UNCHECKED_SLEEP);
                    let (deadline, created) = sleep.unregistered();
                    assert!(Sleep::unchecked(created));
                    while turn().unwrap() <= created.unwrap() {
                        reschedule().await;
                    }
                    assert!(!Sleep::unchecked(created));

                    // Its deadline passes during synchronous work, after the
                    // worker's latest service time unless the host stalled.
                    spin_until(deadline);

                    // Its first poll reads the clock and completes it.
                    assert!(poll!(&mut sleep).is_ready());
                    assert!(matches!(sleep.state, State::Done));
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_first_poll_on_a_new_worker_completes_a_passed_deadline() {
        Runner::default().start(|context| async move {
            // A sleep at least as long as the unchecked bound passes its
            // deadline before a new worker polls it for the first time.
            let mut sleep = Sleep::new(2 * UNCHECKED_SLEEP);
            let (deadline, _) = sleep.unregistered();
            spin_until(deadline);
            let (started, ready) = context
                .dedicated()
                .spawn(move |_| async move {
                    // The worker polls its root before its first service pass,
                    // with the time of its start as its service time.
                    (turn(), poll!(&mut sleep).is_ready())
                })
                .await
                .unwrap();
            assert!(started.is_some_and(|started| started >= deadline));
            assert!(ready);
        });
    }

    #[test]
    fn test_first_poll_in_a_later_runner_completes_a_passed_deadline() {
        // A runner leaves its latest service time on this thread.
        Runner::default().start(|_| reschedule());
        let left = turn().expect("the runner ran no service pass");

        // A sleep at least as long as the unchecked bound, created after that
        // time, passes its deadline before the root of a second runner on this
        // thread polls it, ahead of that runner's first service pass.
        let mut sleep = Sleep::new(2 * UNCHECKED_SLEEP);
        let (deadline, created) = sleep.unregistered();
        assert!(created.is_some_and(|created| left <= created));
        spin_until(deadline);
        let ready = Runner::default().start(move |_| async move { poll!(&mut sleep).is_ready() });
        assert!(ready);
    }

    #[test]
    fn test_first_poll_after_an_idle_wait_completes_a_passed_deadline() {
        let cfg = Config::default().with_worker_threads(2);
        Runner::new(cfg).start(|context| async move {
            // A task waits for a sleep, and reports the result of the sleep's
            // first poll and whether the root's worker made it.
            let root = thread::current().id();
            let (waiting, waited) = oneshot::channel();
            let (sender, receiver) = oneshot::channel::<Sleep>();
            let (polled, first) = mpsc::channel();
            let task = context.spawn(move |_| async move {
                waiting.send(()).unwrap();
                let mut sleep = receiver.await.unwrap();
                let ready = poll!(&mut sleep).is_ready();
                polled
                    .send((thread::current().id() == root, ready))
                    .unwrap();
            });
            waited.await.unwrap();

            // The root keeps its worker in one poll from here on, so only the
            // other worker can run the task. That worker finds nothing to do
            // meanwhile, and waits idle.
            thread::sleep(Duration::from_millis(50));

            // A sleep at least as long as the unchecked bound is created after
            // the other worker's latest service pass, and passes its deadline
            // while that worker still waits.
            let sleep = Sleep::new(2 * UNCHECKED_SLEEP);
            let (deadline, _) = sleep.unregistered();
            spin_until(deadline + UNCHECKED_SLEEP);

            // A wake from outside the pool queues the task in the global
            // queue, which the other worker takes from as soon as it returns
            // from its wait, before its next service pass.
            thread::spawn(move || assert!(sender.send(sleep).is_ok()))
                .join()
                .unwrap();
            let (on_root, ready) = first
                .recv_timeout(Duration::from_secs(10))
                .expect("the other worker did not poll the task");
            assert!(!on_root);
            assert!(
                ready,
                "a first poll after an idle wait missed a passed deadline"
            );
            task.await.unwrap();
        });
    }

    #[test]
    fn test_unchecked_first_poll_registers_without_reading_the_clock() {
        Runner::default().start(|context| async move {
            context
                .spawn(|_| async {
                    // A sleep as long as the unchecked bound, created after
                    // the worker's latest service time, passes its deadline
                    // during synchronous work as long as itself.
                    let served = turn().expect("a worker has a service time");
                    let mut sleep = Sleep::new(UNCHECKED_SLEEP);
                    let (deadline, created) = sleep.unregistered();
                    assert!(Sleep::unchecked(created));
                    spin_until(deadline);
                    assert_eq!(turn(), Some(served));

                    // The first poll registers without reading the clock, and
                    // the worker's cached bound covers the registration.
                    assert!(poll!(&mut sleep).is_pending());
                    let (timers, id) = registration(&sleep);
                    let firing = Wheel::<RESOLUTION>::rounded(timers.nanos(deadline));
                    assert!(Local::current().unwrap().borrow().timers_next <= firing);

                    // Until a service pass, polls with the task's waker stay
                    // pending without the lock.
                    let before = locks();
                    assert!(poll!(&mut sleep).is_pending());
                    assert_eq!(locks(), before);

                    // A later service pass completes it, and its owner's next
                    // one removes the registration if the completing poll
                    // queued it there.
                    sleep.await;
                    let start = Instant::now();
                    while timers.holds(id) {
                        assert!(start.elapsed() < Duration::from_secs(10));
                        reschedule().await;
                    }

                    // A deadline that a service pass has reached completes at
                    // the first poll, without registering.
                    let deadline = Instant::now() + 2 * UNCHECKED_SLEEP;
                    let mut sleep = Sleep::at(deadline);
                    while turn().unwrap() < deadline {
                        reschedule().await;
                    }
                    assert!(poll!(&mut sleep).is_ready());
                    assert!(matches!(sleep.state, State::Done));
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_only_task_wakers_poll_without_the_lock() {
        Runner::default().start(|context| async move {
            // The root's waker is not a task waker, so each repoll locks once.
            let mut sleep = Sleep::new(Duration::from_secs(60));
            assert!(poll!(&mut sleep).is_pending());
            let before = locks();
            assert!(poll!(&mut sleep).is_pending());
            assert!(poll!(&mut sleep).is_pending());
            assert_eq!(locks() - before, 2);

            // A task's waker matches from the first repoll, so no repoll
            // takes the lock.
            let (sleep,) = context
                .child("first")
                .spawn(|_| async {
                    let mut sleep = Sleep::new(Duration::from_secs(60));
                    assert!(poll!(&mut sleep).is_pending());
                    let before = locks();
                    assert!(poll!(&mut sleep).is_pending());
                    assert!(poll!(&mut sleep).is_pending());
                    assert_eq!(locks(), before);
                    (sleep,)
                })
                .await
                .unwrap();

            // Another task's waker is cloned before the lock and stored in one
            // critical section, after which its polls take no lock.
            context
                .child("second")
                .spawn(|_| async move {
                    let mut sleep = sleep;
                    let before = locks();
                    assert!(poll!(&mut sleep).is_pending());
                    assert!(poll!(&mut sleep).is_pending());
                    assert_eq!(locks() - before, 1);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_early_completion_on_the_owner_queues_its_registration() {
        Runner::default().start(|context| async move {
            // A dedicated worker's timers are private, so nothing else
            // registers or serves them.
            context
                .dedicated()
                .spawn(|_| async {
                    // A sleep registers on its worker, whose service time then
                    // reaches its deadline.
                    let deadline = Instant::now() + 5 * UNCHECKED_SLEEP;
                    let mut sleep = Sleep::at(deadline);
                    pend(&mut sleep, Waker::noop());
                    let (timers, id) = registration(&sleep);
                    while turn().is_none_or(|turn| turn < deadline) {
                        reschedule().await;
                    }

                    // The next poll completes the sleep without a lock and
                    // queues its registration, fired or not, as a drop on its
                    // worker would.
                    let before = locks();
                    assert!(poll!(&mut sleep).is_ready());
                    assert!(matches!(sleep.state, State::Done));
                    assert_eq!(locks(), before);
                    assert_eq!(queued(), 1);

                    // The next service pass removes it, unless it has fired.
                    reschedule().await;
                    assert_eq!(queued(), 0);
                    assert!(!timers.holds(id));
                    assert_eq!(timers.live(), 0);
                })
                .await
                .unwrap();
        });
    }

    /// What [`FirstPolls`] found when woken.
    struct FirstPoll {
        /// Whether its thread's worker was closing.
        closing: bool,
        /// Whether a first poll completed a deadline that passed after the
        /// worker's latest service time.
        passed: bool,
        /// The panic message of a first poll of a deadline still ahead.
        ahead: String,
        /// Whether a first poll that skips the clock completed a deadline
        /// that passed after the worker's latest service time.
        unchecked: bool,
    }

    /// A waker that, when woken, polls new sleeps for the first time.
    #[derive(Default)]
    struct FirstPolls(
        /// What the polls found.
        OnceLock<FirstPoll>,
    );

    impl Wake for FirstPolls {
        fn wake(self: Arc<Self>) {
            let closing = Local::current().is_some_and(|local| local.borrow().closing);
            let mut cx = Context::from_waker(Waker::noop());

            // A deadline after the latest service time that has passed.
            let deadline = loop {
                let now = Instant::now();
                if turn().is_none_or(|turn| now > turn) {
                    break now;
                }
            };
            let passed = Sleep::at(deadline).poll_unpin(&mut cx).is_ready();

            // A deadline well ahead.
            let ahead = catch_unwind(AssertUnwindSafe(|| {
                let _ = Sleep::new(Duration::from_secs(60)).poll_unpin(&mut cx);
            }))
            .expect_err("a sleep registered on a closing worker");
            let ahead = extract_panic_message(&*ahead);

            // A sleep created after the latest service time skips the clock
            // on its first poll. Its deadline has passed by then, so the
            // closing worker completes it rather than registering it.
            let mut sleep = Sleep::new(UNCHECKED_SLEEP);
            assert!(sleep.unregistered().1.is_some());
            std::thread::sleep(UNCHECKED_SLEEP);
            let unchecked = catch_unwind(AssertUnwindSafe(|| sleep.poll_unpin(&mut cx).is_ready()))
                .unwrap_or(false);
            assert!(
                self.0
                    .set(FirstPoll {
                        closing,
                        passed,
                        ahead,
                        unchecked
                    })
                    .is_ok()
            );
        }
    }

    #[test]
    fn test_first_poll_on_a_closing_worker_reads_the_clock() {
        // A pending sleep escapes its runner with a waker that polls new
        // sleeps when the closing worker wakes it.
        let polls = Arc::new(FirstPolls::default());
        let (sleep,) = Runner::default().start(|_| async {
            let mut sleep = Sleep::new(Duration::from_secs(60));
            let waker = Waker::from(polls.clone());
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            (sleep,)
        });
        drop(sleep);

        // On the closing worker, a deadline that passed after its service
        // time completed, and one ahead was rejected.
        let FirstPoll {
            closing,
            passed,
            ahead,
            unchecked,
        } = polls.0.get().expect("closure did not wake the sleep");
        assert!(*closing);
        assert!(*passed);
        assert_eq!(ahead, "io_uring sleep polled after its worker closed");
        assert!(*unchecked);
    }

    #[test]
    fn test_first_poll_without_a_worker_rejects_a_deadline_ahead() {
        // A sleep whose deadline is ahead, polled on a thread with no worker.
        let mut sleep = Sleep::new(Duration::from_secs(60));

        // It cannot register, and has no error output, so the poll panics.
        let panic = catch_unwind(AssertUnwindSafe(|| {
            sleep.poll_unpin(&mut Context::from_waker(Waker::noop()))
        }))
        .expect_err("a sleep registered without a worker");
        assert_eq!(
            extract_panic_message(&*panic),
            "io_uring sleep requires a current worker"
        );
    }

    #[test]
    fn test_owner_drops_take_no_lock_until_the_next_service_pass() {
        Runner::default().start(|context| async move {
            // A dedicated worker's timers are private, so its service passes
            // lock them only for these sleeps.
            context
                .dedicated()
                .spawn(|_| async {
                    // Four registrations hold clones of one counting waker.
                    let (count, waker) = counter();
                    let mut kept = Sleep::new(Duration::from_secs(120));
                    pend(&mut kept, &waker);
                    let mut dropped: Vec<_> = (0..3)
                        .map(|_| Sleep::new(Duration::from_secs(60)))
                        .collect();
                    for sleep in &mut dropped {
                        pend(sleep, &waker);
                    }
                    let (timers, _) = registration(&kept);
                    let ids: Vec<_> = dropped.iter().map(|sleep| registration(sleep).1).collect();
                    assert_eq!(Arc::strong_count(&count), 6);

                    // Dropping three of them on their worker takes no lock and
                    // leaves their registrations, and the timers' clones, in
                    // place.
                    let before = locks();
                    drop(dropped);
                    assert_eq!(locks(), before);
                    assert!(ids.iter().all(|&id| timers.holds(id)));
                    assert_eq!(timers.resident(), 4);
                    assert_eq!(Arc::strong_count(&count), 6);

                    // The next service pass removes all three in one critical
                    // section and releases their clones without waking them,
                    // and the worker's queue keeps its capacity.
                    reschedule().await;
                    assert_eq!(locks() - before, 1);
                    assert!(ids.iter().all(|&id| !timers.holds(id)));
                    assert_eq!(timers.resident(), 1);
                    assert_eq!(Arc::strong_count(&count), 3);
                    assert_eq!(count.get(), 0);
                    assert!(Local::current().unwrap().borrow().timers_dropped.capacity() >= 3);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_owner_drop_fired_before_the_next_service_pass_is_removed_once() {
        Runner::default().start(|context| async move {
            context
                .dedicated()
                .spawn(|_| async {
                    // A sleep registers on its worker and is dropped there,
                    // which leaves its registration waiting.
                    let (count, waker) = counter();
                    let deadline = Instant::now() + Duration::from_secs(60);
                    let mut sleep = Sleep::at(deadline);
                    pend(&mut sleep, &waker);
                    let (timers, id) = registration(&sleep);
                    drop(sleep);

                    // A peer's rescue fires it first, which wakes the dropped
                    // sleep's waker once, spuriously.
                    {
                        let mut deferred = Deferred::default();
                        assert!(timers.rescue(timers.nanos(deadline) + RESOLUTION, &mut deferred));
                        run(&mut deferred);
                    }
                    assert_eq!(count.get(), 1);
                    assert!(!timers.holds(id));
                    assert_eq!(timers.resident(), 0);

                    // The next service pass finds nothing to remove for the
                    // queued identity, and clears the worker's cached bound.
                    reschedule().await;
                    assert!(!timers.holds(id));
                    assert_eq!(timers.live(), 0);
                    assert_eq!(count.get(), 1);
                    assert_eq!(Arc::strong_count(&count), 2);
                    assert_eq!(timers_next(), u64::MAX);

                    // Its slot is free for the next registration.
                    let mut next = Sleep::at(deadline + Duration::from_secs(60));
                    pend(&mut next, &waker);
                    assert_eq!(registration(&next).1.index, id.index);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_closure_wakes_no_sleep_dropped_on_its_worker() {
        // The root registers two sleeps on worker zero, lets one escape, and
        // drops the other in its last poll, after which no service pass runs
        // before cleanup closes the timers.
        let (dropped, dropped_waker) = counter();
        let (escaped, escaped_waker) = counter();
        let (sleep,) = Runner::default().start(|_| async {
            let mut kept = Sleep::new(Duration::from_secs(60));
            pend(&mut kept, &escaped_waker);
            let mut sleep = Sleep::new(Duration::from_secs(60));
            pend(&mut sleep, &dropped_waker);
            drop(sleep);
            (kept,)
        });

        // Cleanup removed the dropped sleep's registration and released its
        // waker before closure, which woke only the escaped one.
        assert_eq!(dropped.get(), 0, "closure woke a dropped sleep");
        assert_eq!(Arc::strong_count(&dropped), 2);
        assert_eq!(escaped.get(), 1);
        drop(sleep);
    }

    #[test]
    fn test_registration_reuses_the_slot_of_the_latest_drop() {
        Runner::default().start(|context| async move {
            context
                .dedicated()
                .spawn(|_| async {
                    // Two sleeps register on their worker and are dropped
                    // there, which queues both registrations.
                    let mut first = Sleep::new(Duration::from_secs(60));
                    pend(&mut first, Waker::noop());
                    let mut second = Sleep::new(Duration::from_secs(60));
                    pend(&mut second, Waker::noop());
                    let (timers, first_id) = registration(&first);
                    let (_, second_id) = registration(&second);
                    drop(first);
                    drop(second);
                    assert_eq!(queued(), 2);

                    // A registration removes the latest queued one in its
                    // critical section and takes its slot under a new
                    // generation, which the old identity does not resolve to.
                    let mut current = Sleep::new(Duration::from_secs(60));
                    let before = locks();
                    pend(&mut current, Waker::noop());
                    assert_eq!(locks() - before, 1);
                    let (_, current_id) = registration(&current);
                    assert_eq!(current_id.index, second_id.index);
                    assert_ne!(current_id.generation, second_id.generation);
                    assert!(!timers.holds(second_id));
                    assert_eq!(queued(), 1);

                    // The next service pass removes the other one and leaves
                    // the new registration waiting.
                    reschedule().await;
                    assert_eq!(queued(), 0);
                    assert!(!timers.holds(first_id));
                    assert!(timers.holds(current_id));
                    assert_eq!(timers.resident(), 1);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_drop_on_another_worker_removes_at_once() {
        Runner::default().start(|context| async move {
            // A sleep registers on worker zero with a counted waker.
            let observed = Arc::new(Reentrant::default());
            let mut sleep = Sleep::new(Duration::from_secs(60));
            pend(&mut sleep, &observed.waker());
            let (timers, id) = registration(&sleep);
            assert_eq!(observed.drops.load(Ordering::Relaxed), 1);

            // A dedicated worker drops it, which removes the registration in
            // one critical section and releases its waker after the poll.
            context
                .dedicated()
                .spawn(move |_| async move {
                    let before = locks();
                    drop(sleep);
                    assert_eq!(locks() - before, 1);
                    assert!(!timers.holds(id));
                    assert_eq!(observed.drops.load(Ordering::Relaxed), 1);
                    reschedule().await;
                    assert_eq!(observed.drops.load(Ordering::Relaxed), 2);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_closing_worker_removes_a_dropped_sleep_at_once() {
        /// Drops its sleep, registered on the current worker, and records
        /// whether that worker was closing and removed the registration at
        /// once.
        struct DropCheck {
            /// The registered sleep.
            sleep: Option<Sleep>,
            /// Set if the drop found the worker closing and removed the
            /// registration at once.
            removed: Arc<AtomicBool>,
        }

        impl Drop for DropCheck {
            fn drop(&mut self) {
                let sleep = self.sleep.take().unwrap();
                let (timers, id) = registration(&sleep);
                let closing = Local::current().unwrap().borrow().closing;
                drop(sleep);
                self.removed
                    .store(closing && !timers.holds(id), Ordering::SeqCst);
            }
        }

        // The only pool worker polls a task that registers a sleep and never
        // finishes, so that worker drops the sleep while it closes.
        let removed = Arc::new(AtomicBool::new(false));
        let cfg = Config::default().with_worker_threads(1);
        Runner::new(cfg).start(|context| {
            let removed = removed.clone();
            async move {
                let (registered, ready) = oneshot::channel();
                context.spawn(move |_| async move {
                    let mut sleep = Sleep::new(Duration::from_secs(60));
                    assert!(poll!(&mut sleep).is_pending());
                    let _check = DropCheck {
                        sleep: Some(sleep),
                        removed,
                    };
                    registered.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                ready.await.unwrap();
            }
        });
        assert!(
            removed.load(Ordering::SeqCst),
            "a closing worker left a dropped sleep's registration queued"
        );
    }

    #[commonware_macros::test_group("miri")]
    #[test]
    fn test_stale_identity_of_an_unwound_poll_removes_nothing() {
        // A sleep registered on timers of no worker, and a waker whose clone
        // fires the registration as a peer's rescue would.
        let timers = Arc::new(Timers::new());
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut sleep = registered(&timers, deadline, Waker::noop());
        let (_, old) = registration(&sleep);
        let check = Arc::new(FireOnClone {
            at: timers.nanos(deadline) + RESOLUTION,
            timers: timers.clone(),
            armed: AtomicBool::new(false),
        });
        let waker = FireOnClone::waker(&check);

        // A poll with the changed waker clones it after the lock, and the
        // rescue fires the registration meanwhile. The poll concludes the
        // firing, then unwinds from the destructor of the clone, so the sleep
        // keeps the concluded identity.
        check.armed.store(true, Ordering::SeqCst);
        let polled = catch_unwind(AssertUnwindSafe(|| {
            sleep.poll_unpin(&mut Context::from_waker(&waker))
        }));
        check.armed.store(false, Ordering::SeqCst);
        assert!(polled.is_err());
        assert!(!timers.holds(old));

        // A new registration reuses the slot. The stale identity reaches it
        // neither through the owner's removal of queued identities, where a
        // drop of the sleep on its worker would leave it, nor through a drop
        // of the sleep anywhere else.
        let later = deadline + Duration::from_secs(60);
        let current = registered(&timers, later, &waker);
        let (_, current_id) = registration(&current);
        assert_eq!(current_id.index, old.index);
        let mut deferred = Deferred::default();
        assert!(!timers.drain(&mut vec![old], &mut deferred));
        assert!(deferred.is_empty());
        drop(sleep);
        assert!(timers.holds(current_id));
        assert_eq!(timers.resident(), 1);

        // The new registration fires at its own time and wakes its waker,
        // after which every reference to the waker is released.
        timers.expire(timers.nanos(later) + RESOLUTION, BUDGET, &mut deferred);
        assert_eq!(deferred.wakes.len(), 1);
        run(&mut deferred);
        drop(current);
        drop(waker);
        assert_eq!(Arc::strong_count(&check), 1);
    }

    #[test]
    fn test_drained_drops_that_empty_the_wheel_clear_both_bounds() {
        Runner::default().start(|context| async move {
            // A dedicated worker's timers are private, so these are its only
            // registrations, whose earliest firing time the worker caches and
            // publishes.
            context
                .dedicated()
                .spawn(|_| async {
                    let mut sleeps: Vec<_> = (60..63)
                        .map(|seconds| Sleep::new(Duration::from_secs(seconds)))
                        .collect();
                    for sleep in &mut sleeps {
                        pend(sleep, Waker::noop());
                    }
                    let (timers, _) = registration(&sleeps[0]);
                    let firing = timers.bound();
                    assert_eq!(timers.published(), firing);
                    assert_eq!(timers_next(), firing);

                    // Drops on the worker keep both bounds until the next
                    // service pass, whose batch keeps them, early, while a
                    // registration remains.
                    let last = sleeps.pop().unwrap();
                    drop(sleeps);
                    assert_eq!(timers.published(), firing);
                    assert_eq!(timers_next(), firing);
                    reschedule().await;
                    assert_eq!(timers.resident(), 1);
                    assert_eq!(timers.published(), firing);
                    assert_eq!(timers_next(), firing);

                    // A batch that empties the wheel leaves no firing time, so
                    // the worker takes no timed wake for it.
                    drop(last);
                    reschedule().await;
                    assert_eq!(timers.published(), u64::MAX);
                    assert_eq!(timers_next(), u64::MAX);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_crowding_first_polls_lower_the_cached_bound_to_the_bucket_start() {
        Runner::default().start(|context| async move {
            context
                .dedicated()
                .spawn(|_| async {
                    // Eight budgets of sleeps a minute ahead crowd one high
                    // wheel bucket, each registered by its first poll.
                    let mut sleeps: Vec<_> = (0..8 * BUDGET)
                        .map(|_| Sleep::new(Duration::from_secs(60)))
                        .collect();
                    for sleep in &mut sleeps {
                        pend(sleep, Waker::noop());
                    }

                    // The worker caches the wheel's bound, the bucket's start,
                    // while peers read the earliest firing time.
                    let (timers, _) = registration(&sleeps[0]);
                    assert!(timers_next() < timers.published());
                    assert_eq!(timers_next(), timers.bound());
                })
                .await
                .unwrap();
        });
    }

    /// Identities queued on the current worker by sleeps dropped there.
    fn queued() -> usize {
        Local::current().unwrap().borrow().timers_dropped.len()
    }

    #[test]
    fn test_serial_owner_drops_reuse_one_slot() {
        Runner::default().start(|context| async move {
            // A dedicated worker's timers are private, so only these sleeps
            // take their slots.
            context
                .dedicated()
                .spawn(|_| async {
                    // A kept registration holds the earliest firing time.
                    let mut kept = Sleep::new(Duration::from_secs(60));
                    pend(&mut kept, Waker::noop());
                    let (timers, _) = registration(&kept);
                    let firing = timers.bound();
                    assert_eq!(timers_next(), firing);

                    // Many later sleeps register and drop in turn within one
                    // poll. Each registration removes the previous sleep's
                    // queued registration and takes its slot, so the queue
                    // holds one identity, the wheel two registrations, and the
                    // slab two slots, and the kept registration keeps both
                    // bounds.
                    let cycles = 10 * BUDGET as usize;
                    let before = locks();
                    for _ in 0..cycles {
                        let mut sleep = Sleep::new(Duration::from_secs(120));
                        pend(&mut sleep, Waker::noop());
                        drop(sleep);
                        assert_eq!(queued(), 1);
                        assert_eq!(timers.live(), 2);
                        assert_eq!(timers.resident(), 2);
                        assert_eq!(timers.slots(), 2);
                    }
                    assert_eq!(timers_next(), firing);
                    assert_eq!(timers.published(), firing);

                    // Each registration locked once, and no drop locked.
                    assert_eq!(locks() - before, cycles);

                    // The next service pass removes the last one.
                    reschedule().await;
                    assert_eq!(queued(), 0);
                    assert_eq!(timers.live(), 1);
                    assert_eq!(timers.resident(), 1);
                    assert_eq!(timers.slots(), 2);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_registration_releases_a_dropped_waker_outside_the_lock() {
        Runner::default().start(|context| async move {
            context
                .dedicated()
                .spawn(|_| async {
                    // A sleep on the worker's private timers holds a clone of
                    // a waker that checks that its callbacks run outside the
                    // timers' lock and the worker borrow.
                    let timers = Local::current().unwrap().borrow().timers.clone();
                    let check = Arc::new(LockCheck {
                        timers: timers.clone(),
                        callbacks: AtomicUsize::new(0),
                    });
                    let waker = LockCheck::waker(&check);
                    let mut dropped = Sleep::new(Duration::from_secs(60));
                    pend(&mut dropped, &waker);
                    let (_, dropped_id) = registration(&dropped);
                    assert_eq!(check.callbacks.load(Ordering::SeqCst), 1);

                    // Dropping it on its worker queues its registration
                    // without a lock or a callback.
                    let before = locks();
                    drop(dropped);
                    assert_eq!(locks(), before);
                    assert!(timers.holds(dropped_id));
                    assert_eq!(Arc::strong_count(&check), 3);

                    // The next registration removes it in its one critical
                    // section, before any service pass, and leaves the
                    // released clone to the worker's callback batch.
                    let mut next = Sleep::new(Duration::from_secs(60));
                    pend(&mut next, Waker::noop());
                    assert_eq!(locks() - before, 1);
                    assert_eq!(queued(), 0);
                    assert!(!timers.holds(dropped_id));
                    assert_eq!(timers.live(), 1);
                    assert_eq!(check.callbacks.load(Ordering::SeqCst), 1);
                    assert_eq!(Arc::strong_count(&check), 3);

                    // The batch destroys it after the poll, outside the lock
                    // and the borrow.
                    reschedule().await;
                    assert_eq!(check.callbacks.load(Ordering::SeqCst), 2);
                    assert_eq!(Arc::strong_count(&check), 2);
                })
                .await
                .unwrap();
        });
    }

    #[test]
    fn test_registration_removes_the_latest_queued_registration() {
        let timers = Arc::new(Timers::new());
        let deadline = later();
        let mut deferred = Deferred::default();

        // A fired registration whose sleep was dropped on its worker left its
        // slot free, and the next registration takes it.
        let fired = register(&timers, deadline, Waker::noop());
        timers.expire(deadline + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);
        let mut dropped = vec![fired.id];
        let waker = Waker::noop().clone();
        let at = timers.instant(deadline).unwrap();
        let (next, _) = timers.register(waker.clone(), at, &mut dropped, &mut deferred);
        assert!(dropped.is_empty());
        assert!(deferred.drops.is_empty());
        assert_eq!(next.id.index, fired.id.index);
        assert!(!timers.holds(fired.id));

        // A stale identity, whose slot that registration took, removes
        // nothing.
        dropped.push(fired.id);
        let (other, _) = timers.register(waker.clone(), at, &mut dropped, &mut deferred);
        assert!(timers.holds(next.id));
        assert_ne!(other.id.index, next.id.index);

        // A waiting one leaves the wheel and releases its waker to the batch.
        dropped.push(next.id);
        let (last, _) = timers.register(waker, at, &mut dropped, &mut deferred);
        assert_eq!(deferred.drops.len(), 1);
        assert_eq!(last.id.index, next.id.index);
        assert!(!timers.holds(next.id));
        assert_eq!(timers.resident(), 2);
    }

    #[test]
    fn test_queued_drops_are_removed_one_budget_per_lock() {
        // More than two budgets of registrations whose sleeps were dropped on
        // their worker.
        let timers = Arc::new(Timers::new());
        let budget = BUDGET as usize;
        let count = 2 * budget + 7;
        let deadline = later();
        let mut dropped: Vec<_> = (0..count)
            .map(|_| register(&timers, deadline, Waker::noop()).id)
            .collect();

        // The removal locks once per budget, releases every waker to the
        // batch, and empties the wheel, which then publishes no bound.
        let mut deferred = Deferred::default();
        let before = locks();
        assert!(timers.drain(&mut dropped, &mut deferred));
        assert_eq!(locks() - before, count.div_ceil(budget));
        assert!(dropped.is_empty());
        assert_eq!(deferred.drops.len(), count);
        assert_eq!(timers.live(), 0);
        assert_eq!(timers.published(), u64::MAX);
    }

    #[test]
    fn test_service_pass_bounds_the_capacity_of_the_queue() {
        Runner::default().start(|context| async move {
            // A dedicated worker's timers are private, so only these sleeps
            // use its queue.
            context
                .dedicated()
                .spawn(|_| async {
                    let capacity = || Local::current().unwrap().borrow().timers_dropped.capacity();
                    let burst = 4 * DROPPED_CAPACITY;
                    let registered = || {
                        (0..burst)
                            .map(|_| {
                                let mut sleep = Sleep::new(Duration::from_secs(60));
                                pend(&mut sleep, Waker::noop());
                                sleep
                            })
                            .collect::<Vec<_>>()
                    };

                    // A burst of drops on the worker grows its queue beyond the
                    // bound, and as many registrations take their slots, which
                    // empties the queue without a service pass.
                    drop(registered());
                    assert_eq!(queued(), burst);
                    assert!(capacity() > DROPPED_CAPACITY);
                    let sleeps = registered();
                    assert_eq!(queued(), 0);
                    assert!(capacity() > DROPPED_CAPACITY);

                    // The next service pass gives the burst's storage back,
                    // down to at least the bound.
                    reschedule().await;
                    assert!((DROPPED_CAPACITY..burst).contains(&capacity()));

                    // So does one that drains a burst.
                    drop(sleeps);
                    assert!(capacity() >= burst);
                    reschedule().await;
                    assert_eq!(queued(), 0);
                    let kept = capacity();
                    assert!((DROPPED_CAPACITY..burst).contains(&kept));

                    // A queue within the bound keeps its capacity.
                    let mut sleep = Sleep::new(Duration::from_secs(60));
                    pend(&mut sleep, Waker::noop());
                    drop(sleep);
                    reschedule().await;
                    assert_eq!(capacity(), kept);
                })
                .await
                .unwrap();
        });
    }

    /// A waker that drops its sleep when destroyed.
    struct DropSleep(
        /// The sleep, taken by the destructor.
        Option<Sleep>,
    );

    // This waker owns a destructor, which Waker::noop cannot model.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for DropSleep {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for DropSleep {
        fn drop(&mut self) {
            drop(self.0.take());
        }
    }

    #[test]
    fn test_worker_serves_a_drop_by_its_callbacks_before_parking() {
        Runner::default().start(|context| async move {
            // On a dedicated worker, a sleep with a counted waker belongs to
            // the waker of another sleep, which fires soon.
            let observed = Arc::new(Reentrant::default());
            let (release, released) = oneshot::channel::<()>();
            let holder = context.child("holder").dedicated().spawn({
                let observed = observed.clone();
                move |_| async move {
                    let mut owned = Sleep::new(Duration::from_secs(60));
                    pend(&mut owned, &observed.waker());
                    let mut trigger = Sleep::new(Duration::from_millis(1));
                    pend(&mut trigger, &Waker::from(Arc::new(DropSleep(Some(owned)))));
                    released.await.unwrap();
                    drop(trigger);
                }
            });

            // The firing's wake runs in a callback after the service pass and
            // drops the first sleep on its worker. The worker serves again
            // before parking until the first sleep's deadline, which releases
            // its registered waker.
            let start = Instant::now();
            while observed.drops.load(Ordering::Relaxed) < 2 {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "the worker parked with a dropped sleep's removal queued"
                );
                context.sleep(Duration::from_millis(1)).await;
            }
            release.send(()).unwrap();
            holder.await.unwrap();
        });
    }

    /// A waker that is not a task waker, whose clone, while armed, fires its
    /// registration as a peer's rescue would, and whose destructor, while
    /// armed, panics after releasing its reference.
    struct FireOnClone {
        /// The timers of the registration.
        timers: Arc<Timers>,
        /// The time of the rescue, in the timers' nanoseconds.
        at: u64,
        /// Whether clones fire and destructors panic.
        armed: AtomicBool,
    }

    /// The vtable of every [`FireOnClone`] waker.
    static FIRE_ON_CLONE_VTABLE: RawWakerVTable = RawWakerVTable::new(
        FireOnClone::clone,
        FireOnClone::wake,
        FireOnClone::wake_by_ref,
        FireOnClone::drop,
    );

    impl FireOnClone {
        /// A waker of `this`.
        fn waker(this: &Arc<Self>) -> Waker {
            let data = Arc::into_raw(this.clone()).cast::<()>();
            // SAFETY: The vtable's functions treat `data` as one Arc reference.
            unsafe { Waker::from_raw(RawWaker::new(data, &FIRE_ON_CLONE_VTABLE)) }
        }

        /// Fire the registration if armed, then clone the waker, as one more
        /// Arc reference.
        unsafe fn clone(data: *const ()) -> RawWaker {
            // SAFETY: `data` is one live Arc reference, borrowed here.
            let this = unsafe { &*data.cast::<Self>() };
            if this.armed.load(Ordering::SeqCst) {
                let mut deferred = Deferred::default();
                assert!(this.timers.rescue(this.at, &mut deferred));
                run(&mut deferred);
            }
            // SAFETY: `data` is one live Arc reference.
            unsafe { Arc::increment_strong_count(data.cast::<Self>()) };
            RawWaker::new(data, &FIRE_ON_CLONE_VTABLE)
        }

        /// Consume the waker without panicking.
        unsafe fn wake(data: *const ()) {
            // SAFETY: `data` is one Arc reference, consumed here.
            drop(unsafe { Arc::from_raw(data.cast::<Self>()) });
        }

        /// Wake nothing.
        const unsafe fn wake_by_ref(_: *const ()) {}

        /// Release the waker's Arc reference, then panic if armed.
        unsafe fn drop(data: *const ()) {
            // SAFETY: `data` is one Arc reference, consumed here.
            let this = unsafe { Arc::from_raw(data.cast::<Self>()) };
            let armed = this.armed.load(Ordering::SeqCst);
            drop(this);
            assert!(!armed, "waker destructor panic");
        }
    }

    /// A self-waking task, as busy load that needs no service of its own.
    struct Busy {
        /// Set to complete the task.
        stop: Arc<AtomicBool>,
        /// Set once the task is polled off the root thread.
        elsewhere: Arc<AtomicBool>,
        /// The thread that polls the test's root task.
        root: thread::ThreadId,
    }

    impl Future for Busy {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if thread::current().id() != self.root {
                self.elsewhere.store(true, Ordering::Release);
            }
            if self.stop.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[test]
    fn test_sleep_completes_after_its_concluding_poll_unwound() {
        // No service pass ran on this thread, so polls take the lock.
        assert!(turn().is_none());

        // A registration on timers of no worker.
        let timers = Arc::new(Timers::new());
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut sleep = registered(&timers, deadline, Waker::noop());

        // A poll with a changed waker, on this thread without a worker, clones
        // it after the lock, and a peer's rescue fires the registration
        // meanwhile. The poll observes the firing, then unwinds from the
        // destructor of the clone.
        let check = Arc::new(FireOnClone {
            at: timers.nanos(deadline) + RESOLUTION,
            timers: timers.clone(),
            armed: AtomicBool::new(false),
        });
        let waker = FireOnClone::waker(&check);
        check.armed.store(true, Ordering::SeqCst);
        let polled = catch_unwind(AssertUnwindSafe(|| {
            sleep.poll_unpin(&mut Context::from_waker(&waker))
        }));
        check.armed.store(false, Ordering::SeqCst);
        assert!(polled.is_err());
        assert_eq!(timers.live(), 0);

        // The sleep fired, so a later poll completes it.
        assert!(
            sleep
                .poll_unpin(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(sleep);
        drop(waker);
        assert_eq!(Arc::strong_count(&check), 1);
    }

    #[test]
    fn test_busy_peer_rescues_a_stalled_owner() {
        let cfg = Config::default().with_worker_threads(2);
        Runner::new(cfg).start(|context| async move {
            // Wait until a busy task runs on the other worker, which then
            // keeps running service passes that rescue overdue peer timers.
            let root = thread::current().id();
            let stop = Arc::new(AtomicBool::new(false));
            let elsewhere = Arc::new(AtomicBool::new(false));
            let busy: Vec<_> = (0..2)
                .map(|_| {
                    let task = Busy {
                        stop: stop.clone(),
                        elsewhere: elsewhere.clone(),
                        root,
                    };
                    context.child("busy").spawn(move |_| task)
                })
                .collect();
            let start = Instant::now();
            while !elsewhere.load(Ordering::Acquire) {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "no busy task moved"
                );
                reschedule().await;
            }

            // Register on worker zero, then stall it inside this poll until
            // the sleep fires, which only the peer can make happen meanwhile.
            let (count, waker) = counter();
            let mut sleep = Sleep::new(Duration::from_millis(5));
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let start = Instant::now();
            while count.get() == 0 {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "the busy peer did not rescue the stalled owner's sleep"
                );
                std::hint::spin_loop();
            }

            // Finish the sleep and the busy tasks.
            sleep.await;
            stop.store(true, Ordering::Release);
            for task in busy {
                task.await.unwrap();
            }
        });
    }

    #[test]
    fn test_waking_peer_rescues_a_stalled_owner() {
        /// Period of the wakes that reach the pool from outside.
        const PERIOD: Duration = Duration::from_millis(10);

        let cfg = Config::default().with_worker_threads(2);
        Runner::new(cfg).start(|context| async move {
            // A task that only waits for wakes from a thread outside the pool,
            // one per period. Each wake queues it in the global queue, which
            // only the other worker can take from while this one stalls, so
            // that worker parks and wakes once per period. The task holds no
            // sleep, which a rescue by this worker could move here.
            let stop = Arc::new(AtomicBool::new(false));
            let (parked, wakers) = mpsc::channel::<Waker>();
            let task = context.child("heartbeat").spawn({
                let stop = stop.clone();
                move |_| {
                    std::future::poll_fn(move |cx| {
                        // Hand the waker over before reading the flag, so the
                        // wake that follows the flag finds it.
                        parked.send(cx.waker().clone()).unwrap();
                        if stop.load(Ordering::Acquire) {
                            return Poll::Ready(());
                        }
                        Poll::Pending
                    })
                }
            });
            let clock = thread::spawn({
                let stop = stop.clone();
                move || {
                    while !stop.load(Ordering::Acquire) {
                        thread::sleep(PERIOD);
                        if let Some(waker) = wakers.try_iter().last() {
                            waker.wake();
                        }
                    }
                    wakers
                }
            });

            // Let the other worker settle into its park between wakes.
            context.sleep(2 * PERIOD).await;

            // Register on worker zero, then stall it inside this poll until
            // the sleep fires, which only the peer can make happen meanwhile.
            let (count, waker) = counter();
            let mut sleep = Sleep::new(Duration::from_millis(5));
            pend(&mut sleep, &waker);
            let start = Instant::now();
            while count.get() == 0 {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "the waking peer did not rescue the stalled owner's sleep"
                );
                std::hint::spin_loop();
            }

            // Finish the sleep, the clock and the task.
            sleep.await;
            stop.store(true, Ordering::Release);
            let wakers = clock.join().unwrap();
            if let Some(waker) = wakers.try_iter().last() {
                waker.wake();
            }
            task.await.unwrap();
        });
    }

    #[test]
    fn test_polling_worker_completes_a_due_sleep_of_a_stalled_owner() {
        // One pool worker, so no peer can rescue its timers. A dedicated
        // worker polls the sleep every 200 us while the owner stalls.
        let cfg = Config::default().with_worker_threads(1);
        Runner::new(cfg).start(|context| async move {
            let (sender, receiver) = mpsc::channel::<Sleep>();
            let done = Arc::new(AtomicBool::new(false));
            let poller = context.child("poller").dedicated().spawn({
                let done = done.clone();
                move |context| async move {
                    let mut sleep = loop {
                        if let Ok(sleep) = receiver.try_recv() {
                            break sleep;
                        }
                        context.sleep(Duration::from_micros(200)).await;
                    };
                    loop {
                        if poll!(&mut sleep).is_ready() {
                            done.store(true, Ordering::Release);
                            return;
                        }
                        context.sleep(Duration::from_micros(200)).await;
                    }
                }
            });

            // Register on the pool worker, hand the sleep to the poller, and
            // stall until the poller completes it, which the owner cannot make
            // happen meanwhile.
            let mut sleep = Sleep::new(Duration::from_millis(5));
            assert!(poll!(&mut sleep).is_pending());
            sender.send(sleep).unwrap();
            let start = Instant::now();
            while !done.load(Ordering::Acquire) {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "the polling worker did not complete the sleep"
                );
                std::hint::spin_loop();
            }
            poller.await.unwrap();
        });
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use crate::iouring::{
        mailbox::Mailbox,
        pool::Pool,
        task::{AfterPoll, Ready},
        tasks::Tasks,
    };
    use loom::{
        sync::atomic::{AtomicBool, AtomicUsize},
        thread,
    };
    use std::task::{RawWaker, RawWakerVTable, Wake};

    /// One waker slot of an executor that hands the slot to a new task once
    /// every waker of its previous task is gone, using only relaxed atomics,
    /// as a waker implementation may. The state packs a reference count, in
    /// units of [`Slot::REF`], above the bit of the task the slot serves.
    struct Slot {
        /// Reference count and task bit.
        state: AtomicUsize,
        /// Whether a wake reached each task, indexed by its bit.
        woken: [AtomicBool; 2],
    }

    impl Slot {
        /// One reference in the state.
        const REF: usize = 2;

        /// The bit of the slot's second task. The first task's is zero.
        const SECOND: usize = 1;

        /// A slot serving its first task, with the reference of one waker.
        fn new() -> Self {
            Self {
                state: AtomicUsize::new(Self::REF),
                woken: [AtomicBool::new(false), AtomicBool::new(false)],
            }
        }

        /// A waker carrying a reference the caller counted.
        fn waker(this: &Arc<Self>) -> Waker {
            let data = Arc::as_ptr(this).cast::<()>();
            // SAFETY: The vtable's functions treat `data` as a slot that the
            // test keeps alive while any of its wakers exists, and the caller
            // counted the waker's reference.
            unsafe { Waker::from_raw(RawWaker::new(data, &SLOT_VTABLE)) }
        }

        /// Hand the slot to its second task once no waker of the first
        /// remains, returning that task's first waker.
        fn reuse(this: &Arc<Self>) -> Option<Waker> {
            this.state
                .compare_exchange(
                    0,
                    Self::REF | Self::SECOND,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .ok()?;
            Some(Self::waker(this))
        }

        /// Whether a wake has reached the task with bit `task`. A load rather
        /// than a swap, so that loom lets a waiting thread see the wake once
        /// it yields.
        fn woke(&self, task: usize) -> bool {
            self.woken[task].load(Ordering::Acquire)
        }

        /// The slot behind a waker's data.
        ///
        /// # Safety
        ///
        /// `data` must come from [`Slot::waker`], and its slot must be alive.
        const unsafe fn of<'a>(data: *const ()) -> &'a Self {
            // SAFETY: Per the contract.
            unsafe { &*data.cast::<Self>() }
        }

        /// Count one more reference.
        unsafe fn clone(data: *const ()) -> RawWaker {
            // SAFETY: A live waker's slot is alive.
            unsafe { Self::of(data) }
                .state
                .fetch_add(Self::REF, Ordering::Relaxed);
            RawWaker::new(data, &SLOT_VTABLE)
        }

        /// Notify the task the slot serves, keeping the reference.
        unsafe fn wake_by_ref(data: *const ()) {
            // SAFETY: A live waker's slot is alive, and its task cannot change
            // while the waker counts a reference.
            let slot = unsafe { Self::of(data) };
            let task = slot.state.load(Ordering::Relaxed) & Self::SECOND;
            slot.woken[task].store(true, Ordering::Release);
        }

        /// Release the reference, without ordering, which lets the slot serve
        /// another task with no happens-before edge from this release.
        unsafe fn drop(data: *const ()) {
            // SAFETY: A live waker's slot is alive.
            unsafe { Self::of(data) }
                .state
                .fetch_sub(Self::REF, Ordering::Relaxed);
        }

        /// Notify the task the slot serves and release the reference.
        unsafe fn wake(data: *const ()) {
            // SAFETY: The waker is live until this call consumes it.
            unsafe {
                Self::wake_by_ref(data);
                Self::drop(data);
            }
        }
    }

    /// The vtable of every [`Slot`] waker, which is not a task waker.
    static SLOT_VTABLE: RawWakerVTable =
        RawWakerVTable::new(Slot::clone, Slot::wake, Slot::wake_by_ref, Slot::drop);

    /// End every registration of `timers` on another thread, by closure if
    /// `close` is set and by expiry otherwise, and wake their wakers after the
    /// lock, as a worker's callback batch does.
    fn end(timers: &Arc<Timers>, close: bool) -> thread::JoinHandle<()> {
        let timers = timers.clone();
        thread::spawn(move || {
            let mut deferred = Deferred::default();
            if close {
                timers.close(&mut deferred);
            } else {
                timers.expire(u64::MAX, BUDGET, &mut deferred);
            }
            for waker in deferred.wakes.drain(..) {
                waker.wake();
            }
        })
    }

    /// A deadline one second after new timers' origin, in nanoseconds.
    const fn later() -> u64 {
        1_000_000_000
    }

    #[test]
    fn test_recycled_identity_of_a_consumed_waker_takes_the_lock() {
        for close in [false, true] {
            loom::model(move || {
                // A finished task handed its registered sleep to the slot's
                // next task. The registration holds the first task's last
                // waker.
                let slot = Arc::new(Slot::new());
                let timers = Arc::new(Timers::new());
                let (mut sleeper, _) = timers.register_alone(Slot::waker(&slot), later());
                let ending = end(&timers, close);

                // Once the ending consumes that waker, the next task can take
                // over the slot without synchronizing with the ending, and
                // poll with the same identity. That poll must observe the
                // ending, which woke only the finished task.
                if let Some(waker) = Slot::reuse(&slot) {
                    assert!(
                        sleeper.poll(&Context::from_waker(&waker)).is_ready(),
                        "a poll with a recycled identity missed the ending"
                    );
                    ending.join().unwrap();
                    assert!(!slot.woke(Slot::SECOND));
                } else {
                    ending.join().unwrap();
                }
            });
        }
    }

    /// A task's storage in an executor that keeps it alive for every waker,
    /// as an [`Arc`] does, and gives it to a new task once its task finishes,
    /// with only relaxed atomics. A wake of a finished task is ignored.
    struct Kept {
        /// [`Kept::FINISHED`], [`Kept::IGNORED`], [`Kept::RUNNING`], or
        /// [`Kept::WOKEN`].
        phase: AtomicUsize,
    }

    impl Kept {
        /// The task finished.
        const FINISHED: usize = 0;

        /// The task finished, and a wake for it was ignored since.
        const IGNORED: usize = 1;

        /// A task runs.
        const RUNNING: usize = 2;

        /// A wake reached the running task.
        const WOKEN: usize = 3;
    }

    impl Wake for Kept {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        /// Notify a running task, publishing to its executor, or record
        /// without ordering that a wake came for a finished one.
        fn wake_by_ref(self: &Arc<Self>) {
            let mut phase = self.phase.load(Ordering::Relaxed);
            loop {
                let (next, order) = if phase < Self::RUNNING {
                    (Self::IGNORED, Ordering::Relaxed)
                } else {
                    (Self::WOKEN, Ordering::Release)
                };
                match self
                    .phase
                    .compare_exchange(phase, next, order, Ordering::Relaxed)
                {
                    Ok(_) => return,
                    Err(actual) => phase = actual,
                }
            }
        }
    }

    #[test]
    fn test_reused_storage_of_a_kept_waker_takes_the_lock() {
        for close in [false, true] {
            loom::model(move || {
                // A task registers a sleep and repolls it, and finishes after
                // handing the sleep to the next task of its storage. A clone
                // of its waker stays alive throughout.
                let kept = Arc::new(Kept {
                    phase: AtomicUsize::new(Kept::RUNNING),
                });
                let waker = Waker::from(kept.clone());
                let timers = Arc::new(Timers::new());
                let (mut sleeper, _) = timers.register_alone(waker.clone(), later());
                assert!(sleeper.poll(&Context::from_waker(&waker)).is_pending());
                kept.phase.store(Kept::FINISHED, Ordering::Relaxed);

                // The ending wakes the finished task, which ignores the wake.
                let ending = end(&timers, close);

                // Once the ignored wake came, the storage serves the next task
                // without synchronizing with the ending. The kept clone does
                // not prevent this, and the next task polls with the same
                // identity. That poll must observe the ending, since no wake
                // reaches the next task.
                if kept
                    .phase
                    .compare_exchange(
                        Kept::IGNORED,
                        Kept::RUNNING,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    let next = Waker::from(kept.clone());
                    assert!(next.will_wake(&waker));
                    let polled = sleeper.poll(&Context::from_waker(&next));
                    ending.join().unwrap();
                    assert_eq!(kept.phase.load(Ordering::Relaxed), Kept::RUNNING);
                    assert!(
                        polled.is_ready(),
                        "a poll with a kept identity missed the ending"
                    );
                } else {
                    ending.join().unwrap();
                }
            });
        }
    }

    /// Continue from `after`, the result of a poll of the model's only task,
    /// as the pool's only worker does. That worker polls again at once after a
    /// wake during a poll, and otherwise only a runnable that a wake published
    /// to the global queue. Returns whether the task completed.
    fn work(pool: &Pool, set: &Tasks, ready: &mut Ready, mut after: AfterPoll) -> bool {
        loop {
            let runnable = match after {
                AfterPoll::Done => match pool.take(ready) {
                    Some(runnable) => runnable,
                    None => return false,
                },
                AfterPoll::Requeue(runnable) => runnable,
                AfterPoll::Retire(task) => {
                    drop(set.remove(&task));
                    return true;
                }
            };
            after = runnable.poll(set.id());
        }
    }

    #[test]
    fn test_task_polls_racing_an_ending_observe_it() {
        for (close, adopt) in [(false, false), (false, true), (true, false), (true, true)] {
            loom::model(move || {
                // A pool with no runner, so every wake that publishes a
                // runnable pushes it to the global queue, which this thread
                // serves as the pool's only worker.
                let pool = Arc::new(Pool::new(vec![Arc::new(Mailbox::new().unwrap())]));
                let set = Tasks::new(1);
                let mut ready = pool.queue(0).owner();
                let timers = Arc::new(Timers::new());

                // With `adopt`, the registration holds a waker of no task,
                // which the task's first poll replaces with its own under the
                // lock. Otherwise that poll registers, and wakes the task so
                // that a poll without the lock follows.
                let mut sleeper =
                    adopt.then(|| timers.register_alone(Waker::noop().clone(), later()).0);
                let future = {
                    let timers = timers.clone();
                    std::future::poll_fn(move |cx| {
                        if let Some(sleeper) = &mut sleeper {
                            return sleeper.poll(cx).map(|_| ());
                        }
                        sleeper = Some(timers.register_alone(cx.waker().clone(), later()).0);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    })
                };
                let (task, runnable) = Task::new(future, &set, Arc::downgrade(&pool));
                assert!(set.insert(task).is_ok());

                // The ending races every poll of the task, except that
                // closure follows the poll that registers, since only an open
                // owner registers and closure is that owner's own.
                let (ending, after) = if close && !adopt {
                    let after = runnable.poll(set.id());
                    (end(&timers, close), after)
                } else {
                    (end(&timers, close), runnable.poll(set.id()))
                };
                let mut completed = work(&pool, &set, &mut ready, after);

                // By its exit, the ending has woken the waker that it found.
                ending.join().unwrap();
                completed = completed || work(&pool, &set, &mut ready, AfterPoll::Done);

                // An expiry that ran before the registration ended nothing,
                // so a later pass ends it. After an ending that a poll
                // missed, that pass ends nothing and wakes no one.
                if !completed {
                    end(&timers, close).join().unwrap();
                    completed = work(&pool, &set, &mut ready, AfterPoll::Done);
                }
                assert!(completed, "the task missed the ending of its sleep");
            });
        }
    }
}
