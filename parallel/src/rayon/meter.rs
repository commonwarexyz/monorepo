//! Accounting of the time threads spend executing a run.
//!
//! [`measure_with`] returns a run's busy time, the wall time its threads spend executing it. Busy
//! time includes time the operating system deschedules those threads. It excludes time spent
//! handing off a job, waiting for one, searching for work, sleeping, or running unrelated jobs, so
//! a run queued behind other jobs is not charged for the queue.
//!
//! Each thread has a context, the meter it charges or none, and charges the previous meter whenever
//! its context changes, so a thread with no context never reads the clock. A job its creator waits
//! for (a join, install, or broadcast) runs in the creator's context. A detached job runs in none.
//! The strategy's spawn measures its job and, when the awaiting run is on a pool worker with its
//! wait suspended, charges the job's busy time to that run through [`charge`] on receipt. A thread
//! outside the pool parks in its context and is charged for each park, which covers the jobs that
//! overlap it.

use std::{
    cell::Cell,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[cfg(test)]
mod test;

/// Runs `op` through [`measure_with`] on the system clock.
#[cfg(test)]
pub(crate) fn measure<R>(op: impl FnOnce() -> R) -> (R, Duration) {
    measure_with(Clock::Wall, op)
}

/// Runs `op` as a measured run on `clock` and returns its result with the run's busy time. An
/// enclosing run is charged that busy time once `op` returns or unwinds.
pub(crate) fn measure_with<R>(clock: Clock, op: impl FnOnce() -> R) -> (R, Duration) {
    let meter = Meter {
        busy: AtomicU64::new(0),
        clock,
    };

    // The guard charges the enclosing context after `enter` restores it, even when `op` unwinds.
    let _charge_outer = ChargeOuter {
        inner: &meter,
        outer: Context::current(),
    };

    // SAFETY: this frame holds the meter for the whole call, so it outlives `enter`.
    let result = unsafe { Context(&meter).enter(op) };
    (result, meter.busy())
}

/// Charges `busy` to the calling thread's run, or to nothing outside a run. A run that awaits a
/// detached job with its wait suspended charges the job's busy time this way on receipt.
pub(crate) fn charge(busy: Duration) {
    CURRENT.with(|current| {
        // SAFETY: a thread's current context is none or points to a live meter, as described on
        // `Context`.
        if let Some(meter) = unsafe { current.get().meter.as_ref() } {
            meter.charge_nanos(nanos(busy));
        }
    });
}

/// The busy time of one run.
#[derive(Debug)]
struct Meter {
    /// The nanoseconds charged so far.
    //
    // Relaxed accesses suffice. A thread charges before setting the latch the run waits on, and
    // that latch orders the charge before the run reads its total.
    busy: AtomicU64,
    /// The clock the run's threads read.
    clock: Clock,
}

impl Meter {
    /// The busy time charged so far.
    fn busy(&self) -> Duration {
        Duration::from_nanos(self.busy.load(Ordering::Relaxed))
    }

    /// Adds `nanos` to this meter's busy time.
    fn charge_nanos(&self, nanos: u64) {
        self.busy.fetch_add(nanos, Ordering::Relaxed);
    }
}

/// The clock a run's busy time is read from.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Clock {
    /// The monotonic system clock.
    Wall,
    /// A clock tests advance explicitly, so busy time is exact.
    #[cfg(test)]
    Virtual(TestClock),
}

impl Clock {
    #[inline]
    fn now(&self) -> Instant {
        match self {
            Self::Wall => Instant::now(),
            #[cfg(test)]
            Self::Virtual(clock) => clock.now(),
        }
    }
}

/// A clock tests advance. [`TestClock::spin`] passes time for the calling thread alone, and
/// [`TestClock::elapse`] passes it for every thread.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct TestClock(std::sync::Arc<AtomicU64>);

#[cfg(test)]
impl PartialEq for TestClock {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(test)]
impl TestClock {
    /// Passes `duration` on the calling thread alone, so only its context is charged for it.
    pub(crate) fn spin(&self, duration: Duration) {
        SPUN.with(|spun| spun.set(spun.get() + nanos(duration)));
    }

    /// Passes `duration` for every thread, so every context on this clock is charged for it.
    pub(crate) fn elapse(&self, duration: Duration) {
        self.0.fetch_add(nanos(duration), Ordering::SeqCst);
    }

    fn now(&self) -> Instant {
        static ANCHOR: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let nanos = self.0.load(Ordering::SeqCst) + SPUN.with(Cell::get);
        *ANCHOR.get_or_init(Instant::now) + Duration::from_nanos(nanos)
    }
}

#[cfg(test)]
thread_local! {
    /// The nanoseconds the calling thread has spun on virtual clocks.
    static SPUN: Cell<u64> = const { Cell::new(0) };
}

/// A duration in nanoseconds, saturating at `u64::MAX`.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Charges a nested run's busy time to the enclosing context. It drops after [`measure_with`]
/// restores that context, so the nested meter holds every charge the run waited for.
struct ChargeOuter<'a> {
    /// The meter whose total is charged.
    inner: &'a Meter,
    /// The context the nested run was measured in.
    outer: Context,
}

impl Drop for ChargeOuter<'_> {
    fn drop(&mut self) {
        // SAFETY: `outer` is the calling thread's current context again, so it is none or points
        // to a live meter, as described on `Context`.
        if let Some(outer) = unsafe { self.outer.0.as_ref() } {
            outer.charge_nanos(self.inner.busy.load(Ordering::Relaxed));
        }
    }
}

/// The meter a thread charges, or none.
///
/// A thread's current context is none or points to a live meter. Each entry into a meter's
/// context ends before the meter can drop:
///
/// - [`measure_with`] holds the meter and restores the previous context before it returns or
///   unwinds.
/// - A stack job runs in its creator's context, and the creator waits on the job's latch.
/// - A suspension enters [`Context::NONE`] and restores a context whose scope encloses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Context(*const Meter);

impl Context {
    /// No context. Time spent in it is charged to no meter.
    const NONE: Self = Self(ptr::null());

    /// The calling thread's context.
    #[inline]
    pub(super) fn current() -> Self {
        Self(CURRENT.with(|current| current.get().meter))
    }

    /// Runs `op` in this context on the calling thread, then restores the thread's previous
    /// context, even if `op` unwinds. Entering the current context changes nothing.
    ///
    /// # Safety
    ///
    /// The context must be [`Self::NONE`] or point to a meter that outlives this call.
    #[inline]
    pub(super) unsafe fn enter<R>(self, op: impl FnOnce() -> R) -> R {
        let _restore = Restore(switch(self.0));
        op()
    }

    /// Runs `op` in [`Self::NONE`] and then restores the calling thread's context.
    #[inline]
    pub(super) fn suspend<R>(op: impl FnOnce() -> R) -> R {
        // SAFETY: the context is `NONE`.
        unsafe { Self::NONE.enter(op) }
    }
}

/// Restores a thread's previous context when dropped.
struct Restore(*const Meter);

impl Drop for Restore {
    #[inline]
    fn drop(&mut self) {
        switch(self.0);
    }
}

/// A thread's context and the instant from which its time is charged to it.
#[derive(Clone, Copy)]
struct Current {
    /// The meter the thread charges, or null for no context.
    meter: *const Meter,
    /// When the thread entered its meter's context, or `None` while it has no context.
    since: Option<Instant>,
}

thread_local! {
    /// The calling thread's context, initially none.
    static CURRENT: Cell<Current> = const {
        Cell::new(Current {
            meter: ptr::null(),
            since: None,
        })
    };
}

/// Makes `to` the calling thread's context and returns the previous one. A change charges the
/// previous meter for the time since it was entered.
#[inline]
fn switch(to: *const Meter) -> *const Meter {
    CURRENT.with(|current| {
        // Entering the current context keeps its meter charging from the instant it was entered.
        let previous = current.get();
        if previous.meter == to {
            return to;
        }

        // SAFETY: `previous` is still the thread's current context, so it is none or points to a
        // live meter, as described on `Context`.
        let previous_meter = unsafe { previous.meter.as_ref() };

        // SAFETY: `to` is none or points to a live meter, by the contract of `Context::enter`.
        let next_meter = unsafe { to.as_ref() };

        // The previous meter is charged up to the instant the next one starts from, so no time is
        // charged twice or lost between meters on one clock.
        let now = previous_meter.map(|meter| meter.clock.now());
        if let (Some(meter), Some(since), Some(now)) = (previous_meter, previous.since, now) {
            meter.charge_nanos(nanos(now.saturating_duration_since(since)));
        }
        let since = next_meter.map(|next| match (previous_meter, now) {
            (Some(previous), Some(now)) if previous.clock == next.clock => now,
            _ => next.clock.now(),
        });
        current.set(Current { meter: to, since });
        previous.meter
    })
}
