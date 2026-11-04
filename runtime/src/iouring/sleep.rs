//! Worker sleep timers, reachable from any thread.
//!
//! Every pool worker's sleep registrations live in a [`TimerShard`] that the
//! pool owns, so that peers can reach them, and a dedicated worker owns a
//! private one. A shard is a mutex over a slab of registrations and a
//! hierarchical wheel of their deadlines ([`Wheel`] with 1024 ns ticks), plus
//! a published bound that is never later than its earliest live firing time.
//!
//! A [`Sleep`] fixes its deadline in monotonic nanoseconds ([`clock`]) when
//! it is created and registers on the worker of its first pending poll, which
//! keeps the registration for life. Polls and drops on any thread act on that
//! shard directly, and a drop unlinks its registration at once. Waker clones,
//! wakes, and waker destruction never run under the shard lock or a worker
//! borrow: a pending poll clones a changed waker before it relocks, while
//! wakes and released wakers go through the current worker's [`Deferred`]
//! batch, or are dropped at once on a thread without a worker.
//!
//! The owner expires due registrations in its service pass, at most
//! [`BUDGET`] per pass. A pass that leaves due registrations behind keeps the
//! shard's bound at or below its time, so the worker serves again before it
//! parks. A pending poll on a worker whose latest service time has reached the
//! deadline completes the sleep at once, wherever it was registered.
//!
//! A poll that does not return freezes its worker's service, timers included.
//! A busy pool worker therefore checks its peers' published bounds in its
//! service pass, at most once per [`RESCUE_INTERVAL`], and expires, with its
//! own budget and callback batch, the due registrations of a peer whose bound
//! is overdue by [`RESCUE_THRESHOLD`], skipping a shard whose lock is held.
//! Parked workers do not check, so a frozen worker's timers wait for some
//! peer's service. A dedicated worker's shard is private, so no peer checks it.
//!
//! Lock order and ownership: the shard lock is a leaf, taken while a worker
//! may be borrowed but never the other way around. Only the owner, while it
//! runs and is not closing, registers, so no other thread can introduce a
//! deadline earlier than the owner's cached bound. Drops and peer expiry only
//! remove registrations, which can leave cached and published bounds early but
//! never late. An early bound costs spurious expiry passes or lock attempts
//! until expiry has drained the wheel bucket whose minimum was removed (see
//! [`Wheel`]).
//!
//! Worker cleanup closes the shard: later registration is rejected and every
//! pending sleeper is woken. A sleep then observes how its registration ended.
//! A fired one completes. A closed one completes if its deadline has passed
//! by then, and its poll panics otherwise, since a sleep has no error output.

use super::{
    clock,
    runtime::{Deferred, Local},
    slab::{Id, Slab},
    wheel::{BUDGET, Wheel},
};
use commonware_utils::sync::Mutex;
use crossbeam_utils::CachePadded;
use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
};

/// Resolution of the sleep wheel in nanoseconds. Rounding a deadline up to it
/// adds less than the latency of one wake.
const RES: u64 = 1024;

/// How long a shard's published bound must be overdue before a busy peer
/// expires its due registrations. An owner whose turns stay short serves a
/// small backlog well within it, so peers act on a worker that has not run a
/// service pass for about this long, such as one stalled in a long poll, or on
/// a backlog that the owner's budgeted passes have not drained within it.
pub const RESCUE_THRESHOLD: Duration = Duration::from_millis(1);

/// Least time between two checks of the peers' bounds by one pool worker, a
/// quarter of [`RESCUE_THRESHOLD`]. Checks run in the worker's service pass,
/// so a stalled worker's timers fire within about 1.25 ms of their deadline
/// while some peer runs short turns, and later when every peer's turns are
/// long, the shard's lock is held, or a backlog needs several budgeted passes.
pub const RESCUE_INTERVAL: Duration = Duration::from_micros(250);

/// How a registration ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    /// Its deadline passed.
    Fired,
    /// Its worker closed first.
    Closed,
}

/// A registration's state in its shard's slab.
enum Entry {
    /// Resident in the wheel, with the waker of its latest pending poll.
    Waiting(Waker),
    /// Expired, until its sleep observes it.
    Fired,
    /// Ended by worker closure, until its sleep observes it.
    Closed,
}

/// State behind a shard's lock.
struct Registrations {
    /// Every registration not yet observed or dropped by its sleep.
    entries: Slab<Entry>,
    /// Deadlines of the waiting registrations, keyed by slab index.
    wheel: Wheel<RES>,
    /// Set once by the owner's cleanup, after which nothing registers.
    closed: bool,
}

impl Registrations {
    /// Fire the registrations due at `now`, within one budget, deferring
    /// their wakes.
    fn expire(&mut self, now: u64, deferred: &mut Deferred) {
        let Self { entries, wheel, .. } = self;
        let mut budget = BUDGET;
        wheel.expire(now, &mut budget, &mut |index| {
            // A slot is resident exactly while its entry waits.
            let id = entries.id_at(index as usize).unwrap();
            let entry = entries.get_mut(id).unwrap();
            let Entry::Waiting(waker) = mem::replace(entry, Entry::Fired) else {
                unreachable!("resident timer is not waiting");
            };
            deferred.wakes.push(waker);
        });
    }
}

/// One worker's sleep registrations, locked briefly by every access.
pub struct TimerShard {
    /// Registrations and their wheel.
    registrations: CachePadded<Mutex<Registrations>>,
    /// Bound on the earliest firing time, `u64::MAX` for none. Written only
    /// under the lock, never later than the earliest waiting registration's
    /// firing time. Peers read it to find a stalled owner.
    published: CachePadded<AtomicU64>,
}

impl TimerShard {
    /// An empty shard whose wheel starts at the current time.
    pub fn new() -> Self {
        Self {
            registrations: CachePadded::new(Mutex::new(Registrations {
                entries: Slab::default(),
                wheel: Wheel::new(clock::now()),
                closed: false,
            })),
            published: CachePadded::new(AtomicU64::new(u64::MAX)),
        }
    }

    /// Register `waker` at `deadline`. Called only by the owner, which
    /// checked that it is not closing. Returns the registration and the time
    /// at which it fires, for the owner's cached bound.
    fn register(self: &Arc<Self>, waker: Waker, deadline: u64) -> (Sleeper, u64) {
        let mut registrations = self.registrations.lock();
        assert!(
            !registrations.closed,
            "io_uring sleep polled after its worker closed"
        );
        let id = registrations.entries.insert(Entry::Waiting(waker));
        registrations.wheel.insert(id.index, deadline);
        let at = Wheel::<RES>::rounded(deadline);
        if at < self.published.load(Ordering::Relaxed) {
            self.published.store(at, Ordering::Relaxed);
        }
        drop(registrations);

        let sleeper = Sleeper {
            shard: self.clone(),
            id,
            deadline,
        };
        (sleeper, at)
    }

    /// The owner's expiry pass at `now`: fire due registrations within one
    /// budget and publish the new bound, which the owner caches. The bound
    /// stays at or below `now` while due registrations remain.
    pub fn expire(&self, now: u64, deferred: &mut Deferred) -> u64 {
        let mut registrations = self.registrations.lock();
        registrations.expire(now, deferred);
        let bound = registrations.wheel.bound();
        self.published.store(bound, Ordering::Relaxed);
        bound
    }

    /// A peer's expiry pass at `now`, skipped while the lock is held or after
    /// closure. Returns whether it ran.
    fn rescue(&self, now: u64, deferred: &mut Deferred) -> bool {
        let Some(mut registrations) = self.registrations.try_lock() else {
            return false;
        };
        if registrations.closed {
            return false;
        }
        registrations.expire(now, deferred);
        self.published
            .store(registrations.wheel.bound(), Ordering::Relaxed);
        true
    }

    /// Close the shard at its owner's cleanup: reject later registrations and
    /// wake every waiting sleeper, whose next poll observes the closure.
    /// Repeated calls do nothing.
    pub fn close(&self, deferred: &mut Deferred) {
        let mut registrations = self.registrations.lock();
        let Registrations {
            entries,
            wheel,
            closed,
        } = &mut *registrations;
        if *closed {
            return;
        }
        *closed = true;
        wheel.clear();
        for index in 0..entries.slots() {
            let Some(id) = entries.id_at(index) else {
                continue;
            };
            let entry = entries.get_mut(id).unwrap();
            if matches!(entry, Entry::Waiting(_)) {
                let Entry::Waiting(waker) = mem::replace(entry, Entry::Closed) else {
                    unreachable!();
                };
                deferred.wakes.push(waker);
            }
        }
        self.published.store(u64::MAX, Ordering::Relaxed);
    }
}

/// Expire, at `now`, the due registrations of every shard but `own` whose
/// published bound is overdue by [`RESCUE_THRESHOLD`], with one budget per
/// shard, skipping a shard whose lock is held. Wakes land in `deferred`.
pub fn rescue(shards: &[Arc<TimerShard>], own: usize, now: u64, deferred: &mut Deferred) {
    let threshold = RESCUE_THRESHOLD.as_nanos() as u64;
    for (index, shard) in shards.iter().enumerate() {
        if index == own {
            continue;
        }

        // The bound only selects shards worth locking. The lock synchronizes
        // their state, so a stale bound costs one check, never a timer.
        let bound = shard.published.load(Ordering::Relaxed);
        if bound == u64::MAX || now < bound.saturating_add(threshold) {
            continue;
        }
        shard.rescue(now, deferred);
    }
}

/// A sleep's registration, polled and dropped on any thread.
struct Sleeper {
    /// The registering worker's shard, kept for life.
    shard: Arc<TimerShard>,
    /// Identity in the shard.
    id: Id,
    /// Deadline in nanoseconds.
    deadline: u64,
}

impl Sleeper {
    /// Poll the registration. A deadline at or before this thread's latest
    /// worker service time completes it at once. A ready result consumes the
    /// registration, so the sleeper must then be dropped without
    /// [`Self::cancel`].
    fn poll(&mut self, cx: &Context<'_>) -> Poll<Outcome> {
        if self.deadline <= clock::turn() {
            self.cancel();
            return Poll::Ready(Outcome::Fired);
        }

        let mut registrations = self.shard.registrations.lock();
        match registrations.entries.get(self.id) {
            Some(Entry::Waiting(current)) if current.will_wake(cx.waker()) => {
                return Poll::Pending;
            }
            Some(Entry::Waiting(_)) => {}
            Some(_) => return Poll::Ready(conclude(&mut registrations.entries, self.id)),
            None => unreachable!("io_uring sleep registration missing"),
        }
        drop(registrations);

        // A waker's clone may reenter the runtime, so clone outside the lock
        // and recheck, since expiry or closure may have ended the registration.
        let waker = cx.waker().clone();
        let mut registrations = self.shard.registrations.lock();
        match registrations.entries.get_mut(self.id) {
            Some(Entry::Waiting(current)) => {
                let displaced = mem::replace(current, waker);
                drop(registrations);
                release(displaced);
                Poll::Pending
            }
            Some(_) => {
                let outcome = conclude(&mut registrations.entries, self.id);
                drop(registrations);
                release(waker);
                Poll::Ready(outcome)
            }
            None => unreachable!("io_uring sleep registration missing"),
        }
    }

    /// Remove the registration and release its waker outside the lock.
    fn cancel(&mut self) {
        let removed = {
            let mut registrations = self.shard.registrations.lock();
            let Registrations { entries, wheel, .. } = &mut *registrations;
            let removed = entries.remove(self.id);
            if matches!(removed, Some(Entry::Waiting(_))) {
                wheel.remove(self.id.index);
            }
            removed
        };
        if let Some(Entry::Waiting(waker)) = removed {
            release(waker);
        }
    }
}

/// Consume the ended registration `id`, returning how it ended.
fn conclude(entries: &mut Slab<Entry>, id: Id) -> Outcome {
    match entries.remove(id) {
        Some(Entry::Fired) => Outcome::Fired,
        Some(Entry::Closed) => Outcome::Closed,
        _ => unreachable!("only an ended registration concludes"),
    }
}

/// Destroy a cancelled or displaced waker in the current worker's next
/// callback batch, whose failures that worker retains, or at once on a thread
/// without a worker. The caller holds no worker borrow and no shard lock.
fn release(waker: Waker) {
    let waker = Local::with_current(|local| match local {
        Some(local) => {
            local.deferred.drops.push(waker);
            None
        }
        None => Some(waker),
    });
    drop(waker);
}

/// Ownership held by a sleep between polls.
enum State {
    /// Sleep that has not needed a registration yet, with its deadline in
    /// nanoseconds.
    Unregistered(u64),
    /// Registration in the shard of the worker of the first pending poll.
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
    /// Establish a relative deadline, saturating at the end of the monotonic
    /// clock's range.
    ///
    /// Zero sleeps take the ready path without reading a clock or accessing TLS.
    pub fn new(duration: Duration) -> Self {
        if duration.is_zero() {
            return Self { state: State::Done };
        }
        Self {
            state: State::Unregistered(clock::after(duration)),
        }
    }

    /// Convert a wall-clock deadline once, completing immediately if it has passed.
    pub fn until(deadline: SystemTime) -> Self {
        let duration = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();

        Self::new(duration)
    }

    /// Sleep until one exact monotonic deadline.
    #[cfg(test)]
    fn at(deadline: std::time::Instant) -> Self {
        Self {
            state: State::Unregistered(clock::nanos(deadline)),
        }
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
                let deadline = sleeper.deadline;
                this.state = State::Done;

                // A closed worker ended the registration early. Only a
                // deadline that has passed since may still complete.
                assert!(
                    outcome == Outcome::Fired || deadline <= clock::now(),
                    "io_uring sleep polled after its worker closed"
                );
                Poll::Ready(())
            }
            State::Unregistered(deadline) => {
                let deadline = *deadline;

                // Synchronous work may have made the worker's cached time stale.
                // An elapsed first poll needs neither a worker nor a registration.
                if deadline <= clock::now() {
                    this.state = State::Done;
                    return Poll::Ready(());
                }
                let owner = Local::current().expect("io_uring sleep requires a current worker");
                assert!(
                    !owner.borrow().closing,
                    "io_uring sleep polled after its worker closed"
                );

                // Clone before the worker borrow and the shard lock, under
                // which no user code may run.
                let waker = cx.waker().clone();
                let mut local = owner.borrow_mut();
                let (sleeper, at) = local.timers.register(waker, deadline);

                // The owner's cached bound never trails a live registration.
                local.timers_next = local.timers_next.min(at);
                drop(local);
                this.state = State::Registered(sleeper);
                Poll::Pending
            }
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let State::Registered(sleeper) = &mut self.state {
            sleeper.cancel();
        }
    }
}

#[cfg(test)]
impl TimerShard {
    /// Number of registrations, waiting or awaiting observation.
    pub fn live(&self) -> usize {
        self.registrations.lock().entries.len()
    }

    /// Number of registrations resident in the wheel.
    pub fn resident(&self) -> usize {
        self.registrations.lock().wheel.len()
    }

    /// The exact bound, as an expiry pass would publish it.
    pub fn bound(&self) -> u64 {
        self.registrations.lock().wheel.bound()
    }

    /// The published bound.
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    /// Whether the owner's cleanup closed the shard.
    pub fn is_closed(&self) -> bool {
        self.registrations.lock().closed
    }

    /// Whether the registration `id` is still held, in any state.
    fn holds(&self, id: Id) -> bool {
        self.registrations.lock().entries.get(id).is_some()
    }

    /// Whether the registration `id` waits with a waker that wakes `waker`'s task.
    fn waits_with(&self, id: Id, waker: &Waker) -> bool {
        matches!(
            self.registrations.lock().entries.get(id),
            Some(Entry::Waiting(current)) if current.will_wake(waker)
        )
    }

    /// Hold the lock, for tests of contention.
    fn hold(&self) -> commonware_utils::sync::MutexGuard<'_, impl Sized> {
        self.registrations.lock()
    }
}

#[cfg(test)]
mod tests {
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
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Barrier, OnceLock,
            atomic::{AtomicBool, AtomicUsize},
            mpsc,
        },
        task::{RawWaker, RawWakerVTable, Wake},
        thread,
        time::Instant,
    };

    impl TimerShard {
        /// Register a timer that is already due, so the next expiry sweep
        /// collects it without any wait on the clock.
        pub(crate) fn insert_due(self: &Arc<Self>, waker: Waker) -> u64 {
            let (_, at) = self.register(waker, 0);
            at
        }
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

    /// Register `deadline` on `shard` as a first pending poll with `waker` would.
    fn register(shard: &Arc<TimerShard>, deadline: u64, waker: &Waker) -> Sleeper {
        shard.register(waker.clone(), deadline).0
    }

    /// Poll `sleeper` with `waker`.
    fn poll_with(sleeper: &mut Sleeper, waker: &Waker) -> Poll<Outcome> {
        sleeper.poll(&Context::from_waker(waker))
    }

    /// Run a callback batch as a worker would, outside the shard lock.
    fn run(deferred: &mut Deferred) {
        for waker in deferred.wakes.drain(..) {
            waker.wake();
        }
        deferred.drops.clear();
    }

    /// A deadline well after the current time.
    fn later() -> u64 {
        clock::now() + 1_000_000_000
    }

    /// The registration of a sleep that has registered.
    fn registration(sleep: &Sleep) -> (Arc<TimerShard>, Id) {
        let State::Registered(sleeper) = &sleep.state else {
            panic!("sleep did not register");
        };
        (sleeper.shard.clone(), sleeper.id)
    }

    #[test]
    fn test_elapsed_sleeps_are_ready_without_a_worker() {
        let mut cx = Context::from_waker(Waker::noop());

        // The last case has a deadline that passed between creation and polling.
        for mut sleep in [
            Sleep::new(Duration::ZERO),
            Sleep::until(SystemTime::UNIX_EPOCH),
            Sleep {
                state: State::Unregistered(clock::now()),
            },
        ] {
            assert!(sleep.poll_unpin(&mut cx).is_ready());
            assert!(matches!(sleep.state, State::Done));
        }
    }

    #[test]
    fn test_far_future_sleep_saturates_the_deadline() {
        // A duration past the end of time saturates to the latest deadline.
        let sleep = Sleep::new(Duration::MAX);
        assert!(matches!(sleep.state, State::Unregistered(clock::MAX)));

        // A finite deadline lies one second after the clock reads around it.
        let before = clock::now();
        let sleep = Sleep::new(Duration::from_secs(1));
        let State::Unregistered(deadline) = sleep.state else {
            panic!("positive sleep must retain a deadline");
        };
        assert!(deadline >= before + 1_000_000_000);
        assert!(deadline <= clock::now() + 1_000_000_000);
    }

    #[test]
    fn test_expiry_wakes_once_and_poll_reports_fired() {
        // Registering publishes the rounded deadline, and a poll stays pending.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut sleeper = register(&shard, deadline, &waker);
        assert_eq!(shard.published(), Wheel::<RES>::rounded(deadline));
        assert!(poll_with(&mut sleeper, &waker).is_pending());

        // One nanosecond before the rounded deadline fires nothing.
        let mut deferred = Deferred::default();
        let firing = Wheel::<RES>::rounded(deadline);
        let bound = shard.expire(firing - 1, &mut deferred);
        assert_eq!(bound, firing);
        assert!(deferred.is_empty());

        // At the rounded deadline, the pass defers the wake to the caller, and
        // the next poll reports the firing.
        assert_eq!(shard.expire(firing, &mut deferred), u64::MAX);
        assert_eq!(shard.published(), u64::MAX);
        assert_eq!(count.get(), 0, "woken under the expiry pass");
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(poll_with(&mut sleeper, &waker), Poll::Ready(Outcome::Fired));
        drop(sleeper);
        assert_eq!(shard.live(), 0);

        // Repeating expiry cannot wake it twice, and both sides released it.
        shard.expire(firing + 4096, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_changed_waker_on_another_thread_is_woken() {
        // Register with one waker, then poll on another thread with a second.
        let shard = Arc::new(TimerShard::new());
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        let deadline = later();
        let sleeper = register(&shard, deadline, &first_waker);
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
        shard.expire(deadline + RES, &mut deferred);
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
        // An earlier registration keeps the shard nonempty, and the shard
        // holds the only clone of the later one's waker.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut early = register(&shard, deadline - 1, Waker::noop());
        let sleeper = register(&shard, deadline, &waker);
        drop(waker);

        // Cancelling on another thread removes the registration and releases
        // its waker there.
        thread::spawn(move || {
            let mut sleeper = sleeper;
            sleeper.cancel();
        })
        .join()
        .unwrap();
        assert_eq!(Arc::strong_count(&count), 1, "kept the waker");
        assert_eq!(shard.live(), 1);
        assert_eq!(shard.resident(), 1);

        // Cancelling the other empties the shard, so expiry wakes nothing.
        early.cancel();
        assert_eq!(shard.live(), 0);
        assert_eq!(shard.bound(), u64::MAX);
        let mut deferred = Deferred::default();
        shard.expire(deadline + 4096, &mut deferred);
        assert!(deferred.is_empty());
        assert_eq!(count.get(), 0);
    }

    #[test]
    fn test_close_wakes_pending_and_reports_closed() {
        // Fire one of two registrations, leaving the other pending.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut pending = register(&shard, deadline + 1_000_000, &waker);
        let mut fired = register(&shard, deadline, &waker);
        let mut deferred = Deferred::default();
        shard.expire(deadline + RES, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);

        // Closure appends to existing deferred work without invoking it, and
        // repeating it changes nothing.
        deferred.wakes.push(Waker::noop().clone());
        shard.close(&mut deferred);
        shard.close(&mut deferred);
        assert_eq!(deferred.wakes.len(), 2);
        assert_eq!(count.get(), 1);
        run(&mut deferred);
        assert_eq!(count.get(), 2);
        assert_eq!(shard.published(), u64::MAX);
        assert!(shard.is_closed());

        // A fired registration stays fired, a pending one reports closure.
        assert_eq!(poll_with(&mut fired, &waker), Poll::Ready(Outcome::Fired));
        assert_eq!(
            poll_with(&mut pending, &waker),
            Poll::Ready(Outcome::Closed)
        );
        let rejected = catch_unwind(AssertUnwindSafe(|| register(&shard, deadline, &waker)));
        assert!(rejected.is_err(), "a closed shard accepted a registration");
        assert_eq!(shard.live(), 0);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_drop_after_close_is_harmless() {
        // Closing the shard wakes the pending registration.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let mut sleeper = register(&shard, later(), &waker);
        let mut deferred = Deferred::default();
        shard.close(&mut deferred);
        run(&mut deferred);

        // Cancelling afterwards finds nothing to remove, and closure woke the
        // waker once and released the shard's clone.
        sleeper.cancel();
        assert_eq!(shard.live(), 0);
        assert_eq!(count.get(), 1);
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_budget_leaves_a_backlog_that_drains() {
        // Many more registrations than one budget, all due by `now`.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut sleepers: Vec<_> = (0..1000u64)
            .map(|index| register(&shard, deadline + index % 3, &waker))
            .collect();
        let now = deadline + RES;

        // Expire at one fixed time until the bound passes it.
        let mut passes = 0;
        loop {
            let mut deferred = Deferred::default();
            let bound = shard.expire(now, &mut deferred);
            passes += 1;
            assert!(deferred.wakes.len() <= BUDGET as usize);
            run(&mut deferred);

            // A backlog keeps the bound at or below now, so the owner serves
            // again before it parks.
            if bound > now {
                break;
            }
        }

        // Every registration fired once, within a few passes.
        assert_eq!(count.get(), 1000);
        assert!((4..=6).contains(&passes), "took {passes} passes");
        for sleeper in &mut sleepers {
            assert_eq!(poll_with(sleeper, &waker), Poll::Ready(Outcome::Fired));
        }
    }

    #[test]
    fn test_rescue_skips_a_held_or_closed_shard() {
        // An overdue registration on a shard whose lock this thread holds.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let deadline = later();
        let _sleeper = register(&shard, deadline, &waker);
        let held = shard.hold();

        // Rescue from another thread skips the shard instead of waiting.
        let rescued = thread::scope(|scope| {
            scope
                .spawn(|| shard.rescue(deadline + RES, &mut Deferred::default()))
                .join()
                .unwrap()
        });
        assert!(!rescued);

        // Once the lock is free, rescue fires the registration.
        drop(held);
        let mut deferred = Deferred::default();
        assert!(shard.rescue(deadline + RES, &mut deferred));
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(shard.published(), u64::MAX);

        // A closed shard is never rescued, even past a pending deadline.
        let _pending = register(&shard, deadline + 1_000_000, &waker);
        shard.close(&mut deferred);
        run(&mut deferred);
        assert!(!shard.rescue(deadline + 2_000_000, &mut deferred));
        assert!(deferred.is_empty());
    }

    #[test]
    fn test_rescue_selects_only_peers_overdue_by_the_threshold() {
        // One registration on each of three shards, all firing at `firing`.
        let threshold = RESCUE_THRESHOLD.as_nanos() as u64;
        let shards: Vec<_> = (0..3).map(|_| Arc::new(TimerShard::new())).collect();
        let (count, waker) = counter();
        let deadline = later();
        let firing = Wheel::<RES>::rounded(deadline);
        let _sleepers: Vec<_> = shards
            .iter()
            .map(|shard| register(shard, deadline, &waker))
            .collect();

        // Overdue by less than the threshold, nobody is rescued.
        let mut deferred = Deferred::default();
        rescue(&shards, 0, firing + threshold - 1, &mut deferred);
        assert!(deferred.is_empty());

        // At the threshold, every peer is, but never the caller's own shard.
        rescue(&shards, 0, firing + threshold, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 2);
        assert_eq!(shards[0].resident(), 1);
        assert_eq!(shards[1].resident(), 0);
        assert_eq!(shards[2].resident(), 0);
    }

    #[test]
    fn test_early_completion_is_bounded_by_the_turn_time() {
        // One registration well in the future.
        let shard = Arc::new(TimerShard::new());
        let (count, waker) = counter();
        let deadline = later();
        let mut sleeper = register(&shard, deadline, &waker);

        // A poll completes early once the worker's turn time reaches the
        // deadline. Reset the turn time so later tests on this thread see none.
        clock::set_turn(deadline - 1);
        assert!(poll_with(&mut sleeper, &waker).is_pending());
        clock::set_turn(deadline);
        assert_eq!(poll_with(&mut sleeper, &waker), Poll::Ready(Outcome::Fired));
        clock::set_turn(0);
        drop(sleeper);

        // The poll removed the registration without a wake.
        assert_eq!(shard.resident(), 0);
        assert_eq!(shard.live(), 0);
        let mut deferred = Deferred::default();
        shard.expire(deadline + RES, &mut deferred);
        assert!(deferred.is_empty());
        assert_eq!(count.get(), 0, "woke an early completion");
        assert_eq!(Arc::strong_count(&count), 2);
    }

    #[test]
    fn test_reused_slot_belongs_to_the_new_registration() {
        // A registration after a cancellation reuses its slot under a new
        // generation, and the old identifier no longer resolves.
        let shard = Arc::new(TimerShard::new());
        let deadline = later();
        let mut old = register(&shard, deadline, Waker::noop());
        let old_id = old.id;
        old.cancel();
        let (count, waker) = counter();
        let mut current = register(&shard, deadline + 1_000_000, &waker);
        assert_eq!(old_id.index, current.id.index);
        assert_ne!(old_id.generation, current.id.generation);
        assert!(!shard.holds(old_id));

        // The old deadline fires nothing, the new one at its own.
        let mut deferred = Deferred::default();
        shard.expire(deadline + RES, &mut deferred);
        assert!(deferred.is_empty());
        shard.expire(deadline + 1_000_000 + RES, &mut deferred);
        run(&mut deferred);
        assert_eq!(count.get(), 1);
        assert_eq!(poll_with(&mut current, &waker), Poll::Ready(Outcome::Fired));
    }

    /// A waker that fails if its clone, wake, or drop runs while its shard is locked.
    struct LockCheck {
        /// The shard whose lock must be free during every callback.
        shard: Arc<TimerShard>,
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

        /// Count a callback, failing if the shard is locked.
        fn check(&self) {
            assert!(
                self.shard.registrations.try_lock().is_some(),
                "waker callback under the shard lock"
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
    fn test_callbacks_never_run_under_the_shard_lock() {
        // Three checked wakers on one shard.
        let shard = Arc::new(TimerShard::new());
        let checks: Vec<_> = (0..3)
            .map(|_| {
                Arc::new(LockCheck {
                    shard: shard.clone(),
                    callbacks: AtomicUsize::new(0),
                })
            })
            .collect();
        let wakers: Vec<_> = checks.iter().map(LockCheck::waker).collect();
        let deadline = later();

        // Register, refresh (a clone and a displaced drop), expire and wake.
        let mut fired = register(&shard, deadline, &wakers[0]);
        assert!(poll_with(&mut fired, &wakers[1]).is_pending());
        let mut deferred = Deferred::default();
        shard.expire(deadline + RES, &mut deferred);
        run(&mut deferred);
        assert_eq!(
            poll_with(&mut fired, &wakers[1]),
            Poll::Ready(Outcome::Fired)
        );

        // Cancel a waiting registration, and close one.
        let mut cancelled = register(&shard, deadline, &wakers[2]);
        cancelled.cancel();
        let mut closed = register(&shard, deadline + 1_000_000, &wakers[2]);
        shard.close(&mut deferred);
        run(&mut deferred);
        assert_eq!(
            poll_with(&mut closed, &wakers[2]),
            Poll::Ready(Outcome::Closed)
        );

        // Every waker ran a callback, and the shard released all its clones.
        drop(wakers);
        for check in &checks {
            assert!(check.callbacks.load(Ordering::SeqCst) > 0);
            assert_eq!(Arc::strong_count(check), 1);
        }
    }

    #[test]
    fn test_expiry_races_foreign_polls() {
        let shard = Arc::new(TimerShard::new());
        for round in 0..300 {
            // A registration moves to a thread that changes its waker while
            // this one expires it.
            let deadline = later();
            let (_, first_waker) = counter();
            let sleeper = register(&shard, deadline, &first_waker);
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
            shard.expire(deadline + RES, &mut deferred);
            run(&mut deferred);
            poller.join().unwrap();
        }
        assert_eq!(shard.live(), 0);
    }

    #[test]
    fn test_drops_race_expiry() {
        let shard = Arc::new(TimerShard::new());
        for _ in 0..300 {
            // Eight registrations, whose only waker clones the shard holds.
            let deadline = later();
            let (count, waker) = counter();
            let sleepers: Vec<_> = (0..8).map(|_| register(&shard, deadline, &waker)).collect();
            drop(waker);

            // Cancel them on another thread while this one expires them.
            let dropper = thread::spawn(move || {
                for mut sleeper in sleepers {
                    sleeper.cancel();
                }
            });
            let mut deferred = Deferred::default();
            shard.expire(deadline + RES, &mut deferred);
            run(&mut deferred);
            dropper.join().unwrap();

            // Either way, every registration is gone and every clone released.
            assert_eq!(shard.live(), 0);
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
            let (shard, id) = registration(&sleep);

            // A replacement keeps the registration and defers destruction of
            // its previous waker until after the poll.
            let second = Arc::new(Reentrant::default());
            let second_waker = second.waker();
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            assert!(shard.waits_with(id, &second_waker));
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
            assert!(shard.waits_with(id, &second_waker));

            // Dropping removes the registration and defers destruction of
            // its waker.
            drop(sleep);
            assert!(!shard.holds(id));
            assert_eq!(second.drops.load(Ordering::Relaxed), 0);
            reschedule().await;
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
                let (shard, id) = registration(&sleep);
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
                assert!(!shard.holds(id));
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
            // Register, poll once on another thread, and drop the sleep.
            let mut sleep = Sleep::new(Duration::from_secs(60));
            assert!(poll!(&mut sleep).is_pending());
            let (shard, old) = registration(&sleep);
            let sleep = poll_on_foreign_thread(sleep, Waker::noop().clone());
            drop(sleep);

            // A replacement reuses the slot under a new generation.
            let mut replacement = Sleep::new(Duration::from_secs(60));
            assert!(poll!(&mut replacement).is_pending());
            let (_, current) = registration(&replacement);
            assert_eq!(old.index, current.index);
            assert_ne!(old.generation, current.generation);

            // After a worker turn, only the replacement is held, until it drops.
            reschedule().await;
            assert!(poll!(&mut replacement).is_pending());
            assert!(!shard.holds(old));
            assert!(shard.holds(current));
            drop(replacement);
            assert!(!shard.holds(current));
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
    fn test_exact_deadlines_share_one_key() {
        Runner::default().start(|context| async move {
            // A dedicated worker's shard is private, so nothing else registers.
            context
                .dedicated()
                .spawn(|_| async {
                    let deadline = Instant::now() + Duration::from_secs(60);
                    let mut first = Sleep::at(deadline);
                    let mut second = Sleep::at(deadline);
                    assert!(poll!(&mut first).is_pending());
                    assert!(poll!(&mut second).is_pending());

                    // Both share one wheel key, whose firing time the worker
                    // caches as its next bound.
                    let (shard, _) = registration(&first);
                    assert_eq!(shard.resident(), 2);
                    assert_eq!(shard.bound(), Wheel::<RES>::rounded(clock::nanos(deadline)));
                    let local = Local::current().unwrap();
                    assert_eq!(local.borrow().timers_next, shard.bound());
                })
                .await
                .unwrap();
        });
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
    fn test_busy_peer_rescues_a_stalled_owner() {
        let cfg = Config::default().with_worker_threads(2);
        let fired = Runner::new(cfg).start(|context| async move {
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

            // Register on worker zero, then stall it inside this poll.
            let (count, waker) = counter();
            let mut sleep = Sleep::new(Duration::from_millis(5));
            assert!(
                sleep
                    .poll_unpin(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let start = Instant::now();
            while count.get() == 0 && start.elapsed() < Duration::from_millis(300) {
                std::hint::spin_loop();
            }
            let fired = (count.get() > 0).then(|| start.elapsed());

            // Finish the sleep and the busy tasks.
            sleep.await;
            stop.store(true, Ordering::Release);
            for task in busy {
                task.await.unwrap();
            }
            fired
        });

        // The peer fired the sleep long before the stall ended.
        let fired = fired.expect("the busy peer did not rescue the stalled owner's sleep");
        assert!(
            fired < Duration::from_millis(100),
            "rescued after {fired:?}"
        );
    }

    #[test]
    fn test_polling_worker_completes_a_due_sleep_of_a_stalled_owner() {
        // One pool worker, so no peer can rescue its timers. A dedicated
        // worker polls the sleep every 200 us while the owner stalls.
        let cfg = Config::default().with_worker_threads(1);
        let late = Runner::new(cfg).start(|context| async move {
            let (sender, receiver) = mpsc::channel::<Sleep>();
            let done = Arc::new(OnceLock::new());
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
                            done.set(Instant::now()).unwrap();
                            return;
                        }
                        context.sleep(Duration::from_micros(200)).await;
                    }
                }
            });

            // Register on the pool worker, hand the sleep to the poller, and
            // stall well past the deadline.
            let deadline = Instant::now() + Duration::from_millis(5);
            let mut sleep = Sleep::at(deadline);
            assert!(poll!(&mut sleep).is_pending());
            sender.send(sleep).unwrap();
            let thaw = Instant::now() + Duration::from_millis(150);
            while Instant::now() < thaw {
                std::hint::spin_loop();
            }
            let completed = done.get().map(|at| at.saturating_duration_since(deadline));
            poller.await.unwrap();
            completed
        });

        // The poller completed the sleep soon after its deadline.
        let late = late.expect("the polling worker did not complete the sleep");
        assert!(
            late < Duration::from_millis(50),
            "completed {late:?} after the deadline"
        );
    }
}
