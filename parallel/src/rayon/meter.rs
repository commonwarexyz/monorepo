//! Accounting of the time threads spend executing a run.
//!
//! A [`Meter`] sums the busy time of one run: the wall time its threads spend executing the run.
//! It includes time the operating system deschedules those threads. It excludes time they spend
//! waiting for the pool, searching for work, sleeping, or running unrelated jobs, so a run queued
//! behind other jobs is not charged for the queue.
//!
//! Each thread has a context: the meter it currently charges, or none. Whenever the context
//! changes, the thread charges the previous meter for the time since entering it. Entering the
//! current context therefore costs only a pointer comparison, and a thread that stays without a
//! context never reads the clock.
//!
//! A job its creator waits for (a join, an install, or a broadcast) captures the creator's context
//! and executes in it, wherever it runs. A detached job can outlive the run that spawned it, so it
//! runs without a context, even when the run later waits for its result. A thread suspends its
//! context while it waits for a job, and the jobs it runs meanwhile enter their own.

use std::{
    cell::Cell,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[cfg(test)]
mod test;

/// The busy time of one run.
#[derive(Debug)]
pub(crate) struct Meter {
    /// Charged nanoseconds. Another thread charges this meter before setting the latch the run
    /// waits on, as [`Context`] describes, so the latch orders those charges before the run
    /// returns. Relaxed accesses therefore suffice for the caller to read the full sum.
    busy: AtomicU64,
}

impl Meter {
    /// A meter with no busy time charged.
    pub(crate) const fn new() -> Self {
        Self {
            busy: AtomicU64::new(0),
        }
    }

    /// Runs `op` on the calling thread in this meter's context and returns its result. A meter
    /// is measured once, since its whole total is charged to the enclosing context afterward.
    ///
    /// This meter is charged for the time the calling thread spends executing `op` and for the time
    /// other threads spend executing the jobs `op` waits for. It is not charged for the waits
    /// themselves or for unrelated jobs the calling thread runs meanwhile. Once `op` returns or
    /// unwinds, this meter's busy time is also charged to the calling thread's previous context, so
    /// an enclosing run's busy time includes its nested runs.
    pub(crate) fn measure<R>(&self, op: impl FnOnce() -> R) -> R {
        let outer = Context::current();
        assert!(!ptr::eq(outer.0, self), "a meter must not measure itself");
        let _charge_outer = ChargeOuter { inner: self, outer };
        // SAFETY: this meter is borrowed for the whole call, so it outlives `enter`.
        unsafe { Context(self).enter(op) }
    }

    /// The busy time charged so far.
    pub(crate) fn busy(&self) -> Duration {
        Duration::from_nanos(self.busy.load(Ordering::Relaxed))
    }

    fn charge_nanos(&self, nanos: u64) {
        self.busy.fetch_add(nanos, Ordering::Relaxed);
    }
}

/// Charges a nested meter's busy time to the context it was measured in. It drops after
/// [`Meter::measure`] restores that context, so the nested meter already holds every charge.
struct ChargeOuter<'a> {
    inner: &'a Meter,
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
/// A thread's current context always points to a live meter or to none. A thread enters a meter's
/// context only under the contract of [`Context::enter`], within a scope that ends before the
/// meter can be dropped:
///
/// - [`Meter::measure`] borrows the meter for its call and restores the previous context before
///   returning or unwinding.
/// - A stack job captures its creator's context and executes in it. The creator waits for the
///   job's latch before leaving the frame that holds the job, and the job restores the executing
///   thread's previous context before setting that latch.
/// - Suspending a context and running a detached job enter [`Context::NONE`], and restoring
///   returns to a context whose scope encloses the suspension.
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
    /// The context must be [`Self::NONE`] or point to a meter that outlives this call. The calling
    /// thread's current context qualifies, and so does the context a stack job captured from a
    /// creator that waits on the job's latch until this call returns.
    #[inline]
    pub(super) unsafe fn enter<R>(self, op: impl FnOnce() -> R) -> R {
        let _restore = Restore(switch(self.0));
        op()
    }

    /// Runs `op` in [`Self::NONE`], so its time is charged to no meter, and then restores the
    /// calling thread's context.
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
    meter: *const Meter,
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
        let previous = current.get();
        if previous.meter == to {
            return to;
        }
        let now = Instant::now();
        // SAFETY: a thread's current context points to a live meter or to none, since every
        // context is entered under `Context::enter`'s contract, and `previous` is current until
        // this switch replaces it.
        if let (Some(meter), Some(since)) = (unsafe { previous.meter.as_ref() }, previous.since) {
            let elapsed = now.saturating_duration_since(since).as_nanos();
            meter.charge_nanos(u64::try_from(elapsed).unwrap_or(u64::MAX));
        }
        current.set(Current {
            meter: to,
            since: Some(now),
        });
        previous.meter
    })
}
