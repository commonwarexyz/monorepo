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
//! pending poll, which keeps the registration for life. A first poll on a
//! worker first compares the deadline with the worker's service time
//! ([`Local::now`]): the time at which the worker last started or ran a
//! service pass, each of which polls can follow before the next service pass.
//! A deadline at or before that time has passed, so the poll completes the
//! sleep at once, without a registration.
//!
//! A first poll otherwise reads the clock and completes a deadline that has
//! passed. One case spares the common timeout that read. A sleep of at least
//! [`UNCHECKED_SLEEP`], on a worker whose current service time is not later
//! than the sleep's creation, registers unchecked. That worker has taken no
//! service time since the sleep was created, so the deadline has passed only
//! if its thread has polled for longer than the sleep without serving its
//! timers. The registration then fires at the worker's next service pass, or
//! at a peer's rescue. A first poll without a worker, or on a closing one,
//! reads the clock and completes only a deadline that has passed. A poll that
//! observes closure reads the clock as well, to complete a deadline that has
//! passed.
//!
//! Polls can follow an idle wait before the next service pass as well. The
//! wait marks the service time stale rather than reading the clock. The next
//! first poll on the worker reads the clock instead, records that time as the
//! current service time, and compares the deadline with it alone. Repolls of
//! registered sleeps read neither the service time nor the clock, so a worker
//! that wakes only to repoll held sleeps reads no clock for them.
//!
//! A repoll of a registered sleep instead compares the deadline with the time
//! of its registering worker's latest expiry pass, which the worker's timers
//! publish (see [`Timers::expire`]). That time never runs ahead of the clock
//! either, so a deadline at or before it has passed, and the poll completes
//! the sleep at once, on any thread, whether or not that pass fired the
//! registration. A pass that ran out of fires leaves due registrations
//! waiting, and a task that holds several of them, woken by the one that
//! fired, completes the others at their repolls. A registered sleep otherwise
//! completes once its registration fires, at its owner's expiry or a peer's
//! rescue, or once its worker closes.
//!
//! Polls and drops on any thread act on the registering worker's timers
//! directly, and a drop removes the registration at once. A poll that
//! completes a sleep early ends its registration as a drop would.
//!
//! Waker clones, wakes, and waker destruction never run under the timers' lock
//! or a worker borrow, since they may reenter the runtime. A pending poll
//! clones a changed waker outside the lock, while wakes and released wakers go
//! through the current worker's [`Deferred`] batch, or are dropped at once on
//! a thread without a worker.
//!
//! # Lock-Free Polls
//!
//! A pending poll at an unchanged epoch takes no lock if its waker has the
//! stored waker's identity and is of one of two kinds. One is a runtime
//! task's waker. The other is the waker that the polling thread's worker
//! polls its root with, which serves the runner's root future and the task of
//! a dedicated worker, and which gives a registration an identity only when
//! that thread stores it. Only the sleep writes its registration's waker, and
//! every other party that ends a waiting registration whose sleep can still
//! poll it (expiry, rescue, closure) advances the timers' epoch inside its
//! critical section, before it runs the deferred wake that consumes the
//! stored waker. A sleep that is dropped or completes early removes its own
//! registration and advances nothing, since it never polls that registration
//! again. A sleeper caches the epoch at which it last saw its registration
//! waiting.
//!
//! Matching the stored waker's identity alone is not enough. Once an ending
//! consumes that waker, a waker implementation may give its identity to
//! another task without synchronizing with the consumption, and a poll from
//! that task could read the old epoch. Keeping a clone of the waker does not
//! prevent this, since an executor may keep a task's storage alive for its
//! wakers and still give it to a new task once the old one finishes. The
//! identity of either kind is an address inside an allocation that each of
//! its wakers keeps alive, a task's header or the [`RootWaker`] in a root's
//! shared allocation, and a poll matches only with a waker whose allocation
//! is alive. If that allocation is not the stored waker's, both contain the
//! identity's address, so the stored waker's was freed before the other was
//! made. The free follows the consumption, and the later allocation follows
//! the free (see [`Task::is_waker`] and [`RootWaker::is_current`]), whichever
//! kind each of the two is of, so the poll follows the epoch advance and reads
//! it. A matching poll that misses an ending therefore polls with a waker of
//! the task or root that the ending wakes, whose poll scheduled by that wake
//! reads the advanced epoch and takes the lock. The wake itself, not the
//! epoch's atomic ordering, orders that poll after the advance.
//!
//! A task's wake is a releasing exchange on its state, and each of its polls
//! begins with an acquiring one (see [`super::task`]), so the poll observes
//! everything that the waking thread wrote before the wake.
//!
//! A root has no such state. One thread polls it, and its waker matches only
//! on that thread, while the worker there drives it. An ending on that thread
//! precedes every later poll there. An ending on any other thread wakes the
//! root with a message, sent after the advance under the lock of its worker's
//! [mailbox](super::mailbox). The root's thread takes the message under the
//! same lock before it polls the root for that wake. A matching poll that
//! follows the take observes the advance. One that precedes the take is
//! followed by that root poll, whether the root or another future on its
//! thread polled with its waker. A wake reaches no root poll only if the
//! worker stops driving its root first. Such a wake sets a flag that the
//! worker no longer reads, finds the worker closing or its mailbox closed or
//! gone, or leaves a message that the worker discards, and the waker matches
//! nothing once the worker has stopped. A clone of a root's waker that
//! another thread polls with never matches.
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
//! multiplexes fire at that rate, although their wakes reach a single task.
//! Those that the task repolls once a pass has reached their deadlines
//! complete without their fires (see above). It fires them in the wheel's
//! order, bucket by bucket in time order.
//! Within a bucket that a pass reaches after some of its deadlines passed, as
//! a worker that is behind reaches buckets of 65 us on level one and of 4.2 ms
//! on level two, the due ones fire in registration order rather than deadline
//! order.
//!
//! A pass that leaves due registrations behind keeps the published bound at
//! or below its time, so the worker serves again before it parks, and a pool
//! worker serves again after a short slice of task polls rather than a full
//! batch, once its run queue has room (see [`super::runtime`]). Refiles wake
//! nothing, so the room in the run queue caps only fires, and a pass whose
//! fires are capped still refiles from its whole budget.
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
//! behind the backlog in the global queue. A dedicated worker's timers are
//! private, so no peer checks them.
//!
//! A parked worker, or one spinning idle before it parks, runs no service pass
//! and checks nothing, and its timed wake covers only its own timers and
//! request deadlines. A frozen worker's timers therefore wait for the next
//! service pass of some peer, whatever wakes that peer, and while every peer
//! stays parked, for the frozen poll to return.
//!
//! # Bounds and Lock Order
//!
//! The timers' lock is a leaf, taken while a worker may be borrowed but never
//! the other way around. Only the owner, while it runs and is not closing,
//! registers, so no other thread can introduce a deadline earlier than the
//! owner's cached bound. Drops, early completions and peer expiry only remove
//! registrations, which can leave cached and published bounds early but never
//! late. An early bound costs spurious expiry passes or lock attempts until
//! expiry has drained the wheel bucket whose minimum was removed (see
//! [`Wheel`]). A removal that empties the wheel publishes no bound. Drops and
//! early completions leave the owner's cached bound where it was, so an owner
//! that is about to park takes the wheel's bound again (see
//! [`Timers::refresh`]). An idle owner therefore waits for no removed firing
//! time unless it was the minimum of a wheel bucket that expiry has not
//! drained, which costs it timed wakes until expiry drains that bucket.
//!
//! # Closure
//!
//! Worker cleanup closes the timers. Later registration is rejected, every
//! waiting registration ends and its sleeper is woken, and the timers free
//! their storage. A sleep that outlives its worker therefore keeps empty
//! timers alive, not the worker's peak population of registrations. A
//! registration that fired holds nothing by then, since firing removes it.
//! Its sleep takes a missing registration in open timers as fired, since no
//! other party removes the registration of a sleep that can still be polled.
//! Closure ends waiting registrations as expiry does, advancing the epoch
//! before their wakes, so a lock-free poll cannot miss it. Closed timers hold
//! no registration. A poll that takes the lock reports closure, and a drop or
//! an early completion finds nothing to remove. A sleep that observes closure
//! completes if its deadline has passed by then, as every fired one's has, and
//! its poll panics otherwise, since a sleep has no error output.

use super::{
    runtime::{Deferred, Local, MAX_TIMEOUT},
    slab::{Id, Slab},
    task::{RootWaker, Task},
    wheel::{BUDGET, InstantExt as _, Wheel},
};
use crossbeam_utils::CachePadded;
use std::{
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

/// Shortest sleep whose first poll may register without reading the clock.
/// Such a poll trusts that the deadline is still ahead when its worker has
/// taken no service time ([`Local::now`]) since the sleep was created. It is
/// wrong only on a worker that has polled for the whole sleep, so for at least
/// this long, without serving its timers, whose registered sleeps are as late
/// until a peer rescues them (see [`RESCUE_THRESHOLD`]). A shorter sleep, one
/// created before the service time, or one first polled after an idle wait,
/// reads the clock.
const UNCHECKED_SLEEP: Duration = Duration::from_millis(1);

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
    /// waiting registration, advanced by [`Timers::end`]. A sleep that is
    /// dropped or completes early removes its own registration and leaves it
    /// alone, since that sleep never reads it for the registration again. A
    /// sleeper caches it whenever it sees its registration waiting.
    epoch: u64,
}

impl Registrations {
    /// Fire at most `fires` of the registrations due at `now`. Fires and
    /// refiles spend from one [`BUDGET`] of units, so a small `fires` leaves
    /// the rest of it to refiles.
    fn expire(&mut self, now: u64, fires: u32, ending: &mut Ending<'_>) {
        let Self { entries, wheel, .. } = self;

        // Each pass spends at most one budget, however many fires it allows.
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

        // From here on nothing registers and no identity resolves.
        *closed = true;

        // Visit every slot by index, since identities are not kept anywhere
        // else.
        for index in 0..entries.slots() {
            // A free slot holds no registration.
            let Some(id) = entries.id_at(index) else {
                continue;
            };

            // Every waiting registration ends, and its sleeper's next poll
            // observes the closure.
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
    /// It never runs ahead of the clock, so repolls of registered sleeps
    /// complete those whose deadlines it has reached, even before they fire.
    served: CachePadded<AtomicU64>,
    /// The registrations' epoch as polls read it without the lock. Stored
    /// only under the lock, by [`Self::end`], before the ended
    /// registrations' wakes run, so a sleeper that saw its registration
    /// waiting at some epoch and reads the same epoch later either still
    /// waits or is polled again for the wake of the ending that its read
    /// missed.
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
    /// such a pass. Only a sleep that is dropped or completes early removes a
    /// waiting registration any other way, and only its own.
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

        // The pass records the wake of every registration that it ends.
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
    /// that it is not closing. Returns the registration and its firing time
    /// in nanoseconds since the origin, for the owner's cached bound.
    fn register(self: &Arc<Self>, waker: Waker, deadline: Instant) -> (Sleeper, u64) {
        // The identity comes from the waker that the registration stores, so
        // that later polls with the same waker may match it without the lock.
        let identity = Identity::stored(&waker);
        let nanos = self.nanos(deadline);
        let mut registrations = self.lock();

        // Only an owner that is not closing registers, and closure happens on
        // that owner, so its timers are still open.
        assert!(
            !registrations.closed,
            "io_uring sleep polled after its worker closed"
        );
        let Registrations { entries, wheel, .. } = &mut *registrations;

        // The registration's slab index keys its wheel slot.
        let id = entries.insert(waker);
        wheel.insert(id.index, nanos);

        // Every write of the published bound holds the lock, so lowering it
        // with a plain load and store loses no other update.
        let fires = Wheel::<RESOLUTION>::rounded(nanos);

        if fires < self.published.load(Ordering::Relaxed) {
            self.published.store(fires, Ordering::Relaxed);
        }

        // Cache the epoch read while the registration waits. A later poll
        // with a matching waker that reads this epoch may skip the lock,
        // since an ending that its load misses still wakes the stored waker
        // (see the module documentation).
        let epoch = registrations.epoch;
        drop(registrations);

        let sleeper = Sleeper {
            timers: self.clone(),
            id,
            deadline: nanos,
            identity,
            epoch,
        };

        (sleeper, fires)
    }

    /// The owner's expiry pass at `now`, in nanoseconds since the origin. It
    /// fires at most `fires` due registrations, no more than one [`BUDGET`]
    /// of them, refiles later ones within the rest of that budget, and
    /// publishes the new bound, which the owner caches. A pool worker passes
    /// the room in its run queue as `fires`, so a saturated worker fires only
    /// what that queue can take, in the wheel's order (see the module
    /// documentation), while its refiles keep the rest of the budget. The
    /// room bounds only these wakes, not others that the same service pass
    /// collects. A peer's rescue keeps a full budget. The bound stays at or
    /// below `now` while due registrations remain.
    pub fn expire(&self, now: u64, fires: u32, deferred: &mut Deferred) -> u64 {
        let mut registrations = self.lock();

        // Fires end waiting registrations, so the pass runs through
        // [`Self::end`], which advances the epoch before their wakes run.
        self.end(&mut registrations, deferred, |registrations, ending| {
            registrations.expire(now, fires, ending);
        });

        // Peers read the bound to find due registrations, and the pass time
        // to leave an owner that serves them itself alone. Repolls read the
        // pass time to complete sleeps whose deadlines it has reached.
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

        // Closed timers hold no registration to fire.
        if registrations.closed {
            return false;
        }

        // As in the owner's pass, fires advance the epoch before their wakes.
        self.end(&mut registrations, deferred, |registrations, ending| {
            registrations.expire(now, BUDGET, ending);
        });

        // The pass time stays the owner's own, so a stalled owner stays
        // eligible for the next rescue.
        self.published
            .store(registrations.wheel.bound(), Ordering::Relaxed);

        true
    }

    /// The wheel's bound, published and returned for the owner's cached
    /// bound, which the owner takes before it parks. Drops and early
    /// completions leave that cache where it was, so without this an idle
    /// owner would take a timed wake at the firing time of a sleep that is
    /// gone. The bound can stay early after a bucket's minimum leaves, by a
    /// removal or by a pass that runs out of budget in that bucket (see
    /// [`Wheel::bound`]).
    pub fn refresh(&self) -> u64 {
        let registrations = self.lock();
        let bound = registrations.wheel.bound();
        self.published.store(bound, Ordering::Relaxed);

        bound
    }

    /// Close the timers at their owner's cleanup: reject later registrations,
    /// wake every waiting sleeper, whose next poll observes the closure, and
    /// free the storage of every registration. Repeated calls do nothing.
    pub fn close(&self, deferred: &mut Deferred) {
        let mut registrations = self.lock();

        // A repeated call finds every registration ended already.
        if registrations.closed {
            return;
        }

        // Closure ends waiting registrations as expiry does, advancing the
        // epoch before their wakes, so a lock-free poll cannot miss it.
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

        // A registration that fired is gone, and a later one in its slot has
        // another generation, which this identity does not resolve to.
        let waker = entries.remove(id)?;
        wheel.remove(id.index);

        // An empty wheel has no firing time to publish.
        if wheel.is_empty() {
            self.published.store(u64::MAX, Ordering::Relaxed);
        }

        Some(waker)
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
            // The worker serves its own timers in its own expiry pass.
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

            // Each worker's timers count time from their own origin.
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
/// lock: the stored waker's data address if it is a runtime task's waker or
/// the root waker of the thread that stored it, whose identity cannot recur
/// before an ending is visible to the poll (see the module documentation), or
/// `None` for a waker of any other kind, which nothing matches. The address
/// is held as an integer so that a sleep stays `Send` and `Sync`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity(Option<NonZeroUsize>);

impl Identity {
    /// The identity of a newly stored `waker`.
    fn stored(waker: &Waker) -> Self {
        // A task waker's data is its task header and a root waker's is its
        // shared allocation, neither of which is null.
        Self(
            (Task::is_waker(waker) || RootWaker::is_current(waker))
                .then(|| NonZeroUsize::new(waker.data().addr()))
                .flatten(),
        )
    }

    /// Whether a poll with `waker` may skip the lock at an unchanged epoch.
    #[inline]
    fn matches(self, waker: &Waker) -> bool {
        // The address proves the identity only for a task waker or this
        // thread's root waker, since a waker of another kind may carry the
        // same data address.
        self.0.is_some_and(|data| {
            waker.data().addr() == data.get()
                && (Task::is_waker(waker) || RootWaker::is_current(waker))
        })
    }
}

/// A sleep's registration, polled and dropped on any thread.
struct Sleeper {
    /// The registering worker's timers, kept for life.
    timers: Arc<Timers>,
    /// Identity in the timers.
    id: Id,
    /// The sleep's deadline in nanoseconds since the timers' origin, which
    /// every poll compares with the owner's latest expiry pass time, and a
    /// poll that observes closure with the clock.
    deadline: u64,
    /// The stored waker's identity, which a poll may match to skip the
    /// lock while the registration waits, updated whenever this sleeper
    /// stores a waker.
    identity: Identity,
    /// The timers' epoch, read under their lock when this sleeper last saw its
    /// registration waiting.
    epoch: u64,
}

impl Sleeper {
    /// Poll the registration. A deadline at or before the time of the owner's
    /// latest expiry pass completes it at once, fired or not, ending the
    /// registration as a drop would (see [`Self::abandon`]). Otherwise it is
    /// ready once it has fired or its worker has closed. Every ready result
    /// ends the registration, so the sleeper needs no [`Self::abandon`]
    /// afterwards, and one after closure finds nothing.
    ///
    /// A poll at an unchanged epoch returns pending without the lock if its
    /// waker matches [`Identity`], a task waker or this thread's root waker
    /// with the stored waker's address. The registration then still waits
    /// with an equivalent waker, or an ending that the epoch read missed
    /// wakes the stored waker, and the poll that this wake schedules is still
    /// to come. Only this sleeper writes its waker. Expiry, rescue and
    /// closure advance the epoch under the lock before their wakes, and the
    /// stored waker's identity cannot recur before its wake (see the module
    /// documentation). Any other poll locks.
    fn poll(&mut self, cx: &Context<'_>) -> Poll<Outcome> {
        // The owner's latest expiry pass time never runs ahead of the clock,
        // so a deadline that it has reached has passed. The sleep completes
        // without a clock read, and its registration ends as a drop's would.
        // A stale load only leaves the completion to a later poll or to the
        // firing.
        if self.deadline <= self.timers.served.load(Ordering::Relaxed) {
            self.abandon();
            return Poll::Ready(Outcome::Fired);
        }

        // An ending that this load misses wakes the stored waker, and the
        // poll that this wake schedules follows this one and reads the
        // advanced epoch.
        let waker = cx.waker();
        let matched = self.identity.matches(waker);

        if matched && self.timers.epoch.load(Ordering::Acquire) == self.epoch {
            return Poll::Pending;
        }

        self.poll_locked(waker, matched)
    }

    /// The part of [`Self::poll`] that takes the lock, after its waker failed
    /// to match [`Identity`] (`matched` is false) or matched at a moved
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

            // Only this sleeper writes its waker, so a cached identity is the
            // stored waker's address, and a stored task waker has one. A root
            // waker has one only if its own thread stored it, which a poll
            // on another thread cannot check.
            assert!(
                self.identity.0.map_or_else(
                    || !Task::is_waker(current),
                    |data| current.data().addr() == data.get()
                ),
                "cached identity does not match the stored waker"
            );

            let displaced = match clone.take() {
                // An equivalent waker needs no replacement, nor a clone.
                unused if current.will_wake(waker) => unused,
                // Store the changed waker's clone, and cache its identity for
                // later polls with the same waker.
                Some(clone) => {
                    self.identity = Identity::stored(&clone);
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
            // equivalent waker. A later poll with a matching waker that reads
            // this epoch may skip the lock.
            self.epoch = registrations.epoch;

            // The displaced waker, or the unused clone, is destroyed after
            // the lock is released, since its drop may reenter the runtime.
            drop(registrations);
            Self::release(displaced);
            return Poll::Pending;
        }
    }

    /// End the registration of a dropped sleep, or of one that a poll
    /// completed early, by removing it at once under the timers' lock, on any
    /// thread. Its waker, if it still waited, goes to the current worker's
    /// callback batch, or is dropped at once on a thread without a worker.
    fn abandon(&self) {
        Self::release(self.timers.remove(self.id));
    }

    /// Destroy `waker`, if any, in the current worker's next callback batch,
    /// whose failures that worker retains, or at once on a thread without a
    /// worker. The caller holds no worker borrow and no timers' lock.
    #[inline]
    fn release(waker: Option<Waker>) {
        let Some(waker) = waker else {
            return;
        };

        // A waker's drop may reenter the runtime, so a worker defers it to its
        // callback batch, and a thread without one drops it after the access.
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

        // Only a sleep of at least [`UNCHECKED_SLEEP`] keeps its creation
        // time, which lets its first poll register without reading the clock.
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

    /// Whether the deadline of a sleep's first poll on `local`'s open worker
    /// has passed, given `created`, the sleep's creation time if it kept one.
    /// A current service time at or after the deadline completes it.
    /// Otherwise the clock decides, unless the sleep kept `created` and the
    /// service time is not later, in which case the deadline is taken to be
    /// ahead. A stale service time gives way to the clock, whose reading
    /// becomes the current one.
    #[inline]
    fn passed(local: &mut Local, deadline: Instant, created: Option<Instant>) -> bool {
        // After an idle wait the clock decides, and its reading becomes the
        // current service time for the first polls that follow.
        if local.now_stale {
            local.now = Instant::now();
            local.now_stale = false;
            return deadline <= local.now;
        }

        // A current service time decides a deadline that it has reached.
        // Otherwise the clock decides, unless the sleep kept its creation time
        // and no service time was taken since, so that the deadline is taken
        // to be ahead without a clock read.
        let now = local.now;
        deadline <= now
            || (!created.is_some_and(|created| now <= created) && deadline <= Instant::now())
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();

        match &mut this.state {
            // A completed sleep stays complete.
            State::Done => Poll::Ready(()),
            State::Registered(sleeper) => {
                // Every ready outcome has ended the registration.
                let outcome = std::task::ready!(sleeper.poll(cx));

                // A closed worker discarded the registration, which may have
                // fired or not. Only a deadline that has passed, as every
                // fired one's has, may still complete. Until it has, the sleep
                // stays registered, so every poll observes the closure again,
                // and its drop finds nothing in the closed timers.
                assert!(
                    outcome == Outcome::Fired
                        || sleeper.deadline <= sleeper.timers.nanos(Instant::now()),
                    "io_uring sleep polled after its worker closed"
                );
                this.state = State::Done;
                Poll::Ready(())
            }
            State::Unregistered { deadline, created } => {
                // Copy the fields out, so that the state can be replaced.
                let (deadline, created) = (*deadline, *created);

                // Only a running worker registers the sleep.
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

                // The worker's service time never runs ahead of the clock, so
                // a deadline at or before it has passed, and the sleep needs
                // no registration. Otherwise the clock decides, unless the
                // sleep may register unchecked. An unchecked deadline that has
                // passed fires at the worker's next service pass that reaches
                // its firing time, or at a peer's rescue.
                if Self::passed(&mut owner.borrow_mut(), deadline, created) {
                    this.state = State::Done;
                    return Poll::Ready(());
                }

                // Clone before the worker borrow and the timers' lock, under
                // which no user code may run.
                let waker = cx.waker().clone();
                let mut local = owner.borrow_mut();
                let (sleeper, fires) = local.timers.register(waker, deadline);

                // The owner's cached bound never trails a live registration.
                local.timers_next = local.timers_next.min(fires);
                drop(local);
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
        Runner as _, Spawner as _, Supervisor as _,
        iouring::{Config, Runner, operation::tests::poll_on_foreign_thread},
        utils::{extract_panic_message, reschedule},
    };
    use commonware_utils::channel::oneshot;
    use futures::{FutureExt as _, poll};
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            OnceLock, Weak,
            atomic::{AtomicBool, AtomicUsize},
        },
        task::{RawWaker, RawWakerVTable, Wake},
        thread,
    };

    impl Timers {
        /// Number of waiting registrations.
        fn live(&self) -> usize {
            self.guard().entries.len()
        }

        /// Number of registrations resident in the wheel.
        fn resident(&self) -> usize {
            self.guard().wheel.len()
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
        /// the owner would.
        pub(super) fn register_at(self: &Arc<Self>, waker: Waker, deadline: u64) -> (Sleeper, u64) {
            self.register(waker, self.instant(deadline).unwrap())
        }

        /// The published bound.
        fn published(&self) -> u64 {
            self.published.load(Ordering::Relaxed)
        }

        /// The owner's expiry pass at `now`, as [`Self::expire`] runs it,
        /// with the published pass time left as it was, as a poll that loaded
        /// it before the pass sees it. A poll that loads the new time completes
        /// every deadline that it reached without the lock, so tests of how
        /// polls observe endings under the lock fire through this.
        fn expire_unseen(&self, now: u64, fires: u32, deferred: &mut Deferred) -> u64 {
            let served = self.served.load(Ordering::Relaxed);
            let bound = self.expire(now, fires, deferred);
            self.served.store(served, Ordering::Relaxed);

            bound
        }

        /// Whether the owner's cleanup closed the timers.
        pub(crate) fn is_closed(&self) -> bool {
            self.guard().closed
        }

        /// Whether the registration `id` waits with a waker that wakes `waker`'s task.
        fn waits_with(&self, id: Id, waker: &Waker) -> bool {
            matches!(
                self.guard().entries.get(id),
                Some(current) if current.will_wake(waker)
            )
        }

        /// Register a timer that is already due, so the owner's next expiry
        /// pass fires it without any wait on the clock. Returns its firing
        /// time, for the owner's cached bound.
        pub(crate) fn insert_due(self: &Arc<Self>, waker: Waker) -> u64 {
            let (_, at) = self.register_at(waker, 0);
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

    /// The service time that a first poll on the current worker compares
    /// with, which such a poll reads from the clock and records if an idle
    /// wait left the recorded one stale, or `None` without a worker.
    pub fn turn() -> Option<Instant> {
        let local = Local::current()?;
        let mut local = local.borrow_mut();

        if local.now_stale {
            local.now = Instant::now();
            local.now_stale = false;
        }

        Some(local.now)
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

    /// A waker of a root that no worker drives, which the caller records on
    /// its thread with [`RootWaker::install`] as a worker's drive loop would.
    fn root_waker() -> Waker {
        Waker::from(RootWaker::new(Weak::new()))
    }

    /// Register `deadline` on `timers` as a first pending poll with `waker` would.
    fn register(timers: &Arc<Timers>, deadline: u64, waker: &Waker) -> Sleeper {
        timers.register_at(waker.clone(), deadline).0
    }

    /// A sleep registered on `timers` at `deadline` with `waker`, as a first
    /// pending poll on their owner would leave it.
    fn registered(timers: &Arc<Timers>, deadline: u64, waker: &Waker) -> Sleep {
        Sleep {
            state: State::Registered(register(timers, deadline, waker)),
        }
    }

    /// The registration of a sleep that has registered.
    fn registration(sleep: &Sleep) -> &Sleeper {
        let State::Registered(sleeper) = &sleep.state else {
            panic!("sleep did not register");
        };

        sleeper
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

    #[test]
    fn test_sleep_without_a_worker_completes_only_once_elapsed() {
        // A sleep of no duration, one until a wall-clock time in the past, and
        // one whose deadline passed before its first poll complete.
        let mut cx = Context::from_waker(Waker::noop());
        let elapsed = Sleep {
            state: State::Unregistered {
                deadline: Instant::now(),
                created: None,
            },
        };

        for mut sleep in [
            Sleep::new(Duration::ZERO),
            Sleep::until(SystemTime::UNIX_EPOCH),
            elapsed,
        ] {
            assert!(sleep.poll_unpin(&mut cx).is_ready());
            assert!(matches!(sleep.state, State::Done));
        }

        // The longest duration is clamped to the longest timeout, which the
        // clock can represent.
        let before = Instant::now();
        let mut sleep = Sleep::new(Duration::MAX);
        let State::Unregistered { deadline, .. } = sleep.state else {
            panic!("a sleep registered at its creation");
        };

        assert!(deadline >= before + MAX_TIMEOUT);
        assert!(deadline <= Instant::now() + MAX_TIMEOUT);

        // A sleep whose deadline is ahead cannot register, and has no error
        // output, so its poll panics.
        let panic = catch_unwind(AssertUnwindSafe(|| sleep.poll_unpin(&mut cx)))
            .expect_err("a sleep registered without a worker");

        assert_eq!(
            extract_panic_message(&*panic),
            "io_uring sleep requires a current worker"
        );
    }

    #[test]
    fn test_expiry_wakes_once_and_poll_reports_fired() {
        // An earlier registration, then a later one, publish the earlier
        // firing time.
        let timers = Arc::new(Timers::new());
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        let deadline = later();
        let firing = Wheel::<RESOLUTION>::rounded(deadline);
        let mut sleeper = register(&timers, deadline, &first_waker);
        let _late = register(&timers, deadline + 1_000_000, Waker::noop());

        assert_eq!(timers.published(), firing);

        // A poll with another waker stores it and releases the first one.
        assert!(poll_with(&mut sleeper, &second_waker).is_pending());
        assert!(timers.waits_with(sleeper.id, &second_waker));
        assert_eq!(Arc::strong_count(&first), 2);

        // A pass before the deadline fires nothing.
        let mut deferred = Deferred::default();

        assert_eq!(timers.expire(deadline - 1, BUDGET, &mut deferred), firing);
        assert!(deferred.is_empty());

        // At the firing time, the pass defers the wake of the stored waker to
        // its caller, and publishes the next firing time.
        let next = timers.expire_unseen(firing, BUDGET, &mut deferred);

        assert_eq!(second.get(), 0, "woken under the expiry pass");
        assert_eq!(timers.published(), next);

        run(&mut deferred);

        assert_eq!((first.get(), second.get()), (0, 1));

        // The next poll, which has not seen the pass time, observes the firing
        // under the lock.
        assert_eq!(
            poll_with(&mut sleeper, &second_waker),
            Poll::Ready(Outcome::Fired)
        );

        // No later pass wakes it again, and the timers released its waker.
        timers.expire(firing + RESOLUTION, BUDGET, &mut deferred);

        assert!(deferred.is_empty());
        assert_eq!(Arc::strong_count(&second), 2);
    }

    #[test]
    fn test_repoll_completes_a_deadline_that_the_latest_pass_reached() {
        // Two registrations at one deadline, polled with one waker, as a task
        // that holds both would poll them.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut first = register(&timers, deadline, &waker);
        let mut second = register(&timers, deadline, &waker);

        // A pass before the deadline completes neither.
        let mut deferred = Deferred::default();
        timers.expire(deadline - 1, BUDGET, &mut deferred);

        assert!(poll_with(&mut first, &waker).is_pending());
        assert!(poll_with(&mut second, &waker).is_pending());

        // A pass with room for one fire reaches the deadline and fires one of
        // them, whose wake reaches the task.
        timers.expire(deadline + RESOLUTION, 1, &mut deferred);
        run(&mut deferred);

        assert_eq!(count.get(), 1);
        assert_eq!(timers.live(), 1);

        // The task's repolls complete both. The one that the pass left
        // waiting completes before any pass fires it, and its removal wakes
        // nothing and releases its waker.
        assert_eq!(poll_with(&mut first, &waker), Poll::Ready(Outcome::Fired));
        assert_eq!(poll_with(&mut second, &waker), Poll::Ready(Outcome::Fired));
        assert_eq!((timers.live(), timers.resident()), (0, 0));
        assert_eq!(count.get(), 1);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_drop_removes_the_registration_and_releases_its_waker() {
        // Two sleeps wait on timers that hold a clone of their waker each.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let early = registered(&timers, later(), &waker);
        let late = registered(&timers, 2 * later(), &waker);
        let firing = timers.published();

        // Dropping the later one removes its registration and releases its
        // waker at once, off a worker. The bound stays while the other waits.
        drop(late);

        assert_eq!((timers.live(), timers.resident()), (1, 1));
        assert_eq!(Arc::strong_count(&count), 3);
        assert_eq!(timers.published(), firing);

        // Dropping the other empties the wheel, which then publishes no bound.
        drop(early);

        assert_eq!((timers.live(), timers.resident()), (0, 0));
        assert_eq!(Arc::strong_count(&count), 2);
        assert_eq!(timers.published(), u64::MAX);

        // No later pass wakes either.
        let mut deferred = Deferred::default();
        timers.expire(3 * later(), BUDGET, &mut deferred);

        assert!(deferred.is_empty());
    }

    #[test]
    fn test_closed_sleeps_are_woken_and_complete_only_past_their_deadline() {
        // Two sleeps wait when their timers close, one whose deadline has
        // passed and one whose deadline is ahead.
        let timers = Arc::new(Timers::new());
        let (count, waker) = counter();
        let mut passed = registered(&timers, 1, &waker);
        let mut ahead = registered(&timers, 60 * later(), &waker);

        // Closure wakes each once, however often it is repeated, frees the
        // storage of the registrations, and publishes no bound.
        let mut deferred = Deferred::default();
        timers.close(&mut deferred);
        timers.close(&mut deferred);
        run(&mut deferred);

        assert_eq!(count.get(), 2);
        assert!(timers.is_closed());
        assert_eq!(timers.capacity(), (0, 0));
        assert_eq!(timers.published(), u64::MAX);

        // The first completes, and a repoll stays complete.
        let mut cx = Context::from_waker(&waker);

        assert!(passed.poll_unpin(&mut cx).is_ready());
        assert!(passed.poll_unpin(&mut cx).is_ready());

        // The second has no error output, so every poll before its deadline
        // panics, including one that follows a caught panic.
        for _ in 0..2 {
            let panic = catch_unwind(AssertUnwindSafe(|| ahead.poll_unpin(&mut cx)))
                .expect_err("a closed sleep completed before its deadline");

            assert_eq!(
                extract_panic_message(&*panic),
                "io_uring sleep polled after its worker closed"
            );
        }

        // Closed timers reject a registration.
        let rejected = catch_unwind(AssertUnwindSafe(|| register(&timers, later(), &waker)));

        assert!(rejected.is_err(), "closed timers accepted a registration");

        // Neither drop finds anything left to release.
        drop(passed);
        drop(ahead);

        assert_eq!(timers.live(), 0);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_endings_invalidate_lock_free_polls() {
        /// A party other than the sleep that ends a waiting registration at
        /// a given time.
        type End = fn(&Timers, u64, &mut Deferred);

        // This thread records a root's waker, as a worker's drive loop does.
        // Expiry, rescue, and closure each end a waiting registration. Polls
        // that see the expiry's pass time complete without the lock, so the
        // polls below must not see it.
        let root = root_waker();
        let _scope = RootWaker::install(&root);
        let ends: [(End, Outcome); 3] = [
            (
                |timers, now, deferred| {
                    timers.expire_unseen(now, BUDGET, deferred);
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
            // A waiting registration with the root's waker, polled without
            // the lock.
            let timers = Arc::new(Timers::new());
            let mut sleeper = register(&timers, later(), &root);
            let before = locks();

            assert!(poll_with(&mut sleeper, &root).is_pending());
            assert_eq!(locks(), before);

            // The ending advances the epoch before its wake runs.
            let mut deferred = Deferred::default();
            end(&timers, later() + RESOLUTION, &mut deferred);
            run(&mut deferred);

            // The next poll with the same waker locks and observes the ending.
            let before = locks();

            assert_eq!(poll_with(&mut sleeper, &root), Poll::Ready(outcome));
            assert_eq!(locks() - before, 1);
        }
    }

    #[test]
    fn test_only_the_stored_root_waker_on_its_thread_skips_the_lock() {
        /// The vtable of a waker of no task or root, whose functions never
        /// use its data.
        static FORGED_VTABLE: RawWakerVTable =
            RawWakerVTable::new(forged_clone, forged_ignore, forged_ignore, forged_ignore);

        /// Clone a forged waker.
        unsafe fn forged_clone(data: *const ()) -> RawWaker {
            RawWaker::new(data, &FORGED_VTABLE)
        }

        /// Wake or drop a forged waker.
        const unsafe fn forged_ignore(_: *const ()) {}

        // A registration stores the waker of the root that this thread
        // records, whose polls take no lock.
        let timers = Arc::new(Timers::new());
        let root = root_waker();
        let scope = RootWaker::install(&root);
        let mut sleeper = register(&timers, later(), &root);
        let before = locks();

        assert!(poll_with(&mut sleeper, &root).is_pending());
        assert_eq!(locks(), before);

        // SAFETY: No function of the vtable dereferences the data.
        let forged = unsafe { Waker::from_raw(RawWaker::new(root.data(), &FORGED_VTABLE)) };

        // A waker of another kind that carries the same data address matches
        // nothing, so its poll stores it under the lock.
        assert!(poll_with(&mut sleeper, &forged).is_pending());
        assert!(timers.waits_with(sleeper.id, &forged));

        // Nor does the root's waker match while another waker is stored.
        assert!(poll_with(&mut sleeper, &root).is_pending());
        assert!(timers.waits_with(sleeper.id, &root));

        // On another thread, the stored waker matches nothing, whether that
        // thread records no root or a root of its own, so each poll locks.
        let mut sleeper = thread::spawn({
            let root = root.clone();
            move || {
                let before = locks();

                assert!(poll_with(&mut sleeper, &root).is_pending());
                assert_eq!(locks() - before, 1);

                let other = root_waker();
                let _scope = RootWaker::install(&other);

                assert!(poll_with(&mut sleeper, &root).is_pending());
                assert_eq!(locks() - before, 2);

                sleeper
            }
        })
        .join()
        .unwrap();

        // Once the record ends, as when a worker stops driving its root, the
        // stored waker matches nothing on this thread either.
        drop(scope);
        let before = locks();

        assert!(poll_with(&mut sleeper, &root).is_pending());
        assert_eq!(locks() - before, 1);
    }

    #[test]
    fn test_another_tasks_waker_is_stored_under_the_lock() {
        Runner::default().start(|context| async move {
            // The wakers of two tasks.
            let mut wakers = Vec::new();

            for label in ["first", "second"] {
                let task = context
                    .child(label)
                    .spawn(|_| std::future::poll_fn(|cx| Poll::Ready(cx.waker().clone())));
                wakers.push(task.await.unwrap());
            }

            assert!(wakers.iter().all(Task::is_waker));

            // A registration stores the first task's waker, whose polls take
            // no lock.
            let timers = Arc::new(Timers::new());
            let mut sleeper = register(&timers, later(), &wakers[0]);
            let before = locks();

            assert!(poll_with(&mut sleeper, &wakers[0]).is_pending());
            assert_eq!(locks(), before);

            // The second task's waker matches nothing. Its poll clones it
            // before the lock and stores it in one critical section.
            assert!(poll_with(&mut sleeper, &wakers[1]).is_pending());
            assert_eq!(locks() - before, 1);
            assert!(timers.waits_with(sleeper.id, &wakers[1]));
        });
    }

    /// A waker that fails if its clone, wake, or drop runs while its timers
    /// are locked or its thread's worker is borrowed.
    struct LockCheck {
        /// The timers whose lock must be free during every callback.
        timers: Arc<Timers>,
        /// The time, in the timers' nanoseconds, at which every clone first
        /// expires them as a peer's rescue would, or `None` for no rescue.
        rescue: Option<u64>,
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
        /// Checks for `timers`, one per element of `rescues`, and a waker
        /// of each.
        fn wakers(
            timers: &Arc<Timers>,
            rescues: impl IntoIterator<Item = Option<u64>>,
        ) -> (Vec<Arc<Self>>, Vec<Waker>) {
            rescues
                .into_iter()
                .map(|rescue| {
                    let check = Arc::new(Self {
                        timers: timers.clone(),
                        rescue,
                        callbacks: AtomicUsize::new(0),
                    });
                    let data = Arc::into_raw(check.clone()).cast::<()>();

                    // SAFETY: The vtable's functions treat `data` as one Arc
                    // reference.
                    let waker = unsafe { Waker::from_raw(RawWaker::new(data, &LOCK_CHECK_VTABLE)) };

                    (check, waker)
                })
                .unzip()
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

        /// Clone the waker, as one more Arc reference, after a check and the
        /// rescue, if any.
        unsafe fn clone(data: *const ()) -> RawWaker {
            // SAFETY: `data` is one Arc reference, borrowed here.
            let this = mem::ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Self>()) });
            this.check();

            if let Some(at) = this.rescue {
                let mut deferred = Deferred::default();

                assert!(this.timers.rescue(at, &mut deferred));

                run(&mut deferred);
            }

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
        // Three checked wakers on one worker's timers. Cloning the last one
        // also expires the timers, as a peer's rescue would.
        let timers = Arc::new(Timers::new());
        let deadline = later();
        let (checks, wakers) =
            LockCheck::wakers(&timers, [None, None, Some(deadline + RESOLUTION)]);

        // Register, refresh (a clone and a displaced drop), repoll unchanged,
        // expire and wake, and observe the firing under the lock.
        let mut fired = register(&timers, deadline, &wakers[0]);

        assert!(poll_with(&mut fired, &wakers[1]).is_pending());
        assert!(poll_with(&mut fired, &wakers[1]).is_pending());

        let mut deferred = Deferred::default();
        timers.expire_unseen(deadline + RESOLUTION, BUDGET, &mut deferred);
        run(&mut deferred);

        assert_eq!(
            poll_with(&mut fired, &wakers[1]),
            Poll::Ready(Outcome::Fired)
        );

        // A poll clones a changed waker between two critical sections. The
        // second one observes a rescue that fires the registration in between.
        let mut raced = register(&timers, deadline, &wakers[0]);

        assert_eq!(
            poll_with(&mut raced, &wakers[2]),
            Poll::Ready(Outcome::Fired)
        );

        // Drop a waiting registration, and close one.
        let dropped = register(&timers, deadline + 1_000_000, &wakers[1]);
        dropped.abandon();

        let mut closed = register(&timers, deadline + 1_000_000, &wakers[1]);
        timers.close(&mut deferred);
        run(&mut deferred);

        assert_eq!(
            poll_with(&mut closed, &wakers[1]),
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
    fn test_wakers_released_on_a_worker_wait_for_its_callback_batch() {
        Runner::default().start(|_| async {
            // Two sleeps register on this worker, the earlier one first, with
            // a waker that checks that its callbacks run outside the timers'
            // lock and the worker borrow.
            let timers = Local::current().unwrap().borrow().timers.clone();
            let (checks, wakers) = LockCheck::wakers(&timers, [None, None]);
            let mut early = Sleep::new(Duration::from_secs(60));
            pend(&mut early, &wakers[0]);
            let mut late = Sleep::new(Duration::from_secs(120));
            pend(&mut late, &wakers[0]);
            let id = registration(&early).id;

            // The worker's cached bound is no later than the earlier firing
            // time.
            let firing = Wheel::<RESOLUTION>::rounded(registration(&early).deadline);

            assert!(Local::current().unwrap().borrow().timers_next <= firing);

            // A poll with another waker stores it, and a drop removes the
            // registration at once. Each leaves the waker that the timers
            // held to the worker's next callback batch.
            pend(&mut early, &wakers[1]);

            assert!(timers.waits_with(id, &wakers[1]));

            drop(early);

            assert!(!timers.waits_with(id, &wakers[1]));
            assert_eq!(Arc::strong_count(&checks[0]), 4);
            assert_eq!(Arc::strong_count(&checks[1]), 3);

            // The batch destroys both after the poll.
            reschedule().await;

            assert_eq!(Arc::strong_count(&checks[0]), 3);
            assert_eq!(Arc::strong_count(&checks[1]), 2);
        });
    }

    #[test]
    fn test_sleep_moves_between_threads() {
        Runner::default().start(|_| async {
            // A sleep registers on its worker and is polled on another thread.
            let start = Instant::now();
            let mut sleep = Sleep::new(Duration::from_millis(20));

            assert!(poll!(&mut sleep).is_pending());

            let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());

            // A third thread awaits it, which the worker's expiry wakes.
            let (sender, receiver) = oneshot::channel();
            let thread = thread::spawn(move || {
                futures::executor::block_on(sleep);
                sender.send(()).unwrap();
            });

            receiver.await.unwrap();
            thread.join().unwrap();

            // Completion on any thread respects the deadline.
            assert!(start.elapsed() >= Duration::from_millis(20));
        });
    }

    /// A waker that, when woken, polls for the first time a sleep whose
    /// deadline passed after its thread's worker last took a service time.
    #[derive(Default)]
    struct FirstPoll(
        /// Whether a closing worker woke the waker and the poll completed.
        OnceLock<bool>,
    );

    impl Wake for FirstPoll {
        fn wake(self: Arc<Self>) {
            // An open worker would register this sleep without reading the
            // clock, since it has taken no service time since its creation.
            let closing = Local::current().is_some_and(|local| local.borrow().closing);
            let mut cx = Context::from_waker(Waker::noop());
            let mut sleep = Sleep::new(UNCHECKED_SLEEP);
            thread::sleep(UNCHECKED_SLEEP);
            let ready = catch_unwind(AssertUnwindSafe(|| sleep.poll_unpin(&mut cx).is_ready()));

            assert!(self.0.set(closing && ready.unwrap_or(false)).is_ok());
        }
    }

    #[test]
    fn test_closure_wakes_an_escaped_sleep_and_rejects_its_polls() {
        // A pending sleep escapes its runner with a waker that polls a new
        // sleep when the closing worker wakes it.
        let polled = Arc::new(FirstPoll::default());
        let (mut sleep,) = Runner::default().start(|_| async {
            let mut sleep = Sleep::new(Duration::from_secs(60));
            pend(&mut sleep, &Waker::from(polled.clone()));

            (sleep,)
        });

        // Closure woke the waker once, on the closing worker, which cannot
        // register, so the first poll there completed the passed deadline.
        assert_eq!(polled.0.get(), Some(&true));

        // The escaped sleep's deadline is ahead, so its poll panics.
        let mut cx = Context::from_waker(Waker::noop());
        let panic = catch_unwind(AssertUnwindSafe(|| sleep.poll_unpin(&mut cx)))
            .expect_err("a closed sleep completed before its deadline");

        assert_eq!(
            extract_panic_message(&*panic),
            "io_uring sleep polled after its worker closed"
        );

        // Its drop finds nothing, and closure released the timers' clone of
        // the waker.
        drop(sleep);

        assert_eq!(Arc::strong_count(&polled), 1);
    }

    #[test]
    fn test_busy_peer_rescues_a_stalled_owner() {
        let cfg = Config::default().with_worker_threads(2);
        Runner::new(cfg).start(|context| async move {
            // Two self-waking tasks keep the pool busy without any service of
            // their own. Once one of them runs on the other worker, that
            // worker keeps running service passes, which check its peers'
            // timers.
            let root = thread::current().id();
            let stop = Arc::new(AtomicBool::new(false));
            let elsewhere = Arc::new(AtomicBool::new(false));
            let busy: Vec<_> = (0..2)
                .map(|_| {
                    let (stop, elsewhere) = (stop.clone(), elsewhere.clone());
                    context.child("busy").spawn(move |_| {
                        std::future::poll_fn(move |cx| {
                            if thread::current().id() != root {
                                elsewhere.store(true, Ordering::Release);
                            }

                            if stop.load(Ordering::Acquire) {
                                return Poll::Ready(());
                            }

                            cx.waker().wake_by_ref();

                            Poll::Pending
                        })
                    })
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

            // Register on this worker, then stall it inside this poll until
            // the sleep fires, which only the peer can make happen meanwhile.
            let (count, waker) = counter();
            let mut sleep = Sleep::new(Duration::from_millis(5));
            pend(&mut sleep, &waker);
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
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use crate::iouring::{
        mailbox::{Mailbox, Message},
        pool::Pool,
        task::{AfterPoll, Ready},
        tasks::Tasks,
    };
    use loom::{
        sync::atomic::{AtomicBool, AtomicUsize},
        thread,
    };
    use std::task::Wake;

    /// End every registration of `timers`, by closure if `close` is set and
    /// by a peer's rescue otherwise, and wake their wakers after the lock, as
    /// a worker's callback batch does. A rescue records no pass time, so the
    /// repolls that follow see the ending only through the epoch, which is
    /// what the models check. An owner's expiry would record a pass time that
    /// completes them whatever the epoch says.
    fn end_here(timers: &Timers, close: bool) {
        let mut deferred = Deferred::default();

        if close {
            timers.close(&mut deferred);
        } else {
            // A rescue skips timers whose lock another thread holds, so retry.
            while !timers.rescue(u64::MAX, &mut deferred) {
                thread::yield_now();
            }
        }

        for waker in deferred.wakes.drain(..) {
            waker.wake();
        }
    }

    /// End every registration of `timers` on another thread, as
    /// [`end_here`] does.
    fn end(timers: &Arc<Timers>, close: bool) -> thread::JoinHandle<()> {
        let timers = timers.clone();
        thread::spawn(move || end_here(&timers, close))
    }

    /// A deadline one second after new timers' origin, in nanoseconds.
    const fn later() -> u64 {
        1_000_000_000
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
                let (mut sleeper, _) = timers.register_at(waker.clone(), later());

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
                    adopt.then(|| timers.register_at(Waker::noop().clone(), later()).0);

                let future = {
                    let timers = timers.clone();
                    std::future::poll_fn(move |cx| {
                        if let Some(sleeper) = &mut sleeper {
                            return sleeper.poll(cx).map(|_| ());
                        }

                        sleeper = Some(timers.register_at(cx.waker().clone(), later()).0);
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

    #[test]
    fn test_root_polls_racing_an_ending_observe_it() {
        for (close, adopt) in [(false, false), (false, true), (true, false), (true, true)] {
            loom::model(move || {
                // A worker's mailbox and root waker. This thread stands for
                // that worker. It alone polls with the waker, and after a
                // pending poll it polls again only for a wake, which reaches
                // it from another thread as a message.
                let mailbox = Arc::new(Mailbox::new().unwrap());
                let root = Waker::from(RootWaker::new(Arc::downgrade(&mailbox)));
                let _scope = RootWaker::install(&root);
                let cx = Context::from_waker(&root);
                let timers = Arc::new(Timers::new());

                // With `adopt`, the registration holds a waker of no root,
                // which the root's first poll replaces with its own under the
                // lock. Otherwise the root registered, and its polls take no
                // lock until one observes the ending.
                let stored = if adopt { Waker::noop() } else { &root };

                let (mut sleeper, _) = timers.register_at(stored.clone(), later());

                assert_eq!(sleeper.identity.matches(&root), !adopt);

                // The ending races the root's first poll, and sets `ended`
                // once its wakes have run.
                let ended = Arc::new(AtomicBool::new(false));
                let ending = thread::spawn({
                    let ended = ended.clone();
                    move || {
                        end_here(&timers, close);
                        ended.store(true, Ordering::Release);
                    }
                });

                let mut inbox = Vec::new();
                let mut polled = sleeper.poll(&cx);

                while polled.is_pending() {
                    // A pending poll left the root's waker stored, so the
                    // ending wakes the root. The poll that follows the take
                    // of that wake's message must observe the ending. When
                    // the take precedes the flag, the mailbox's lock is the
                    // only edge from the ending to that poll. The flag is
                    // read before the take, so that a message missing after
                    // it means a missing wake.
                    assert!(sleeper.identity.matches(&root));

                    let ended = ended.load(Ordering::Acquire);

                    if mailbox.take(&mut inbox) {
                        assert!(matches!(inbox.as_slice(), [Message::WakeRoot]));

                        inbox.clear();
                        polled = sleeper.poll(&cx);

                        assert!(
                            polled.is_ready(),
                            "a root poll that followed the wake missed the ending"
                        );
                    } else {
                        assert!(!ended, "the ending woke no root");
                        thread::yield_now();
                    }
                }

                ending.join().unwrap();
            });
        }
    }
}
