//! Accounting of the time threads spend executing a run.
//!
//! [`measure`] sums the busy time of one run: the wall time its threads spend executing the run.
//! It includes time the operating system deschedules those threads. It excludes time they spend
//! handing a job to the pool, waiting for it, searching for work, sleeping, or running unrelated
//! jobs, so a run queued behind other jobs is not charged for the queue.
//!
//! Each thread has a context: the meter it currently charges, or none. Whenever the context
//! changes, the thread charges the previous meter for the time since entering it. Entering the
//! current context therefore costs only a pointer comparison, and a thread that stays without a
//! context never reads the clock.
//!
//! A job its creator waits for (a join, an install, or a broadcast) captures the creator's context
//! and executes in it, wherever it runs. A detached job can outlive the run that spawned it, so
//! it runs without a context. A spawner that wants a detached job's work charged to its run
//! captures a [`MeterHandle`], which keeps the meter alive, and enters it around that work before
//! delivering the result, so the charge is ordered before the run can observe the result. A
//! thread suspends its context while it hands off a job, waits for the pool, or yields, and the
//! jobs it runs meanwhile enter their own. A thread outside the pool that blocks in its context,
//! for example on a spawned job's result, stays charged while it waits.

use std::{
    cell::Cell,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
mod test;

/// Runs `op` on the calling thread as a measured run and returns its result with the run's busy
/// time. The run is charged for the time threads spend executing `op`, the joins, installs, and
/// broadcasts it waits for, and the work its [`MeterHandle`]s enter, but not for its waits. An
/// enclosing run is charged the whole busy time once `op` returns or unwinds.
pub(crate) fn measure<R>(op: impl FnOnce() -> R) -> (R, Duration) {
    // A handle may outlive this frame, so the meter is shared.
    let meter = Arc::new(Meter {
        busy: AtomicU64::new(0),
    });

    // The guard captures the enclosing context, and it charges that context only after `enter`
    // restores it, even when `op` unwinds.
    let _charge_outer = ChargeOuter {
        inner: &meter,
        outer: Context::current(),
    };

    // SAFETY: this frame holds the meter for the whole call, so it outlives `enter`.
    let result = unsafe { Context(Arc::as_ptr(&meter)).enter(op) };
    (result, meter.busy())
}

/// A shared handle to the meter of the run that was current when it was captured, or to none,
/// for work that may outlive the run. Entering the handle charges that run for the work.
#[derive(Clone, Debug)]
pub(crate) struct MeterHandle(Option<Arc<Meter>>);

impl MeterHandle {
    /// Captures the calling thread's context.
    pub(crate) fn capture() -> Self {
        let meter = Context::current().0;
        if meter.is_null() {
            return Self(None);
        }
        // SAFETY: a current context points to a live meter that `measure` allocated in an
        // `Arc` and still holds, so the pointer came from that `Arc` and the count can grow.
        Self(Some(unsafe {
            Arc::increment_strong_count(meter);
            Arc::from_raw(meter)
        }))
    }

    /// Runs `op` in the captured context and returns its result once the charge has landed.
    pub(crate) fn enter<R>(&self, op: impl FnOnce() -> R) -> R {
        let context = self
            .0
            .as_ref()
            .map_or(Context::NONE, |meter| Context(Arc::as_ptr(meter)));
        // SAFETY: this handle holds the meter until it returns, so the meter outlives `enter`.
        unsafe { context.enter(op) }
    }
}

/// The busy time of one run.
#[derive(Debug)]
struct Meter {
    /// The nanoseconds charged so far.
    //
    // Another thread charges this meter before setting the latch or sending the result the run
    // waits on, as described on `Context` and `MeterHandle`, so that hand-off orders the charge
    // before the run returns. Relaxed accesses therefore suffice for the caller to read every
    // charge it waited for. Work the run does not wait for may charge after the run read its
    // total.
    busy: AtomicU64,
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

/// Charges a nested run's busy time to the context it was measured in. It drops after [`measure`]
/// restores that context, so the nested meter already holds every charge.
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
/// A thread's current context always points to a live meter, one that [`measure`] allocated and
/// holds, or to none. A thread enters a meter's context only under the contract of
/// [`Context::enter`], within a scope that ends before the meter can be dropped:
///
/// - [`measure`] holds the meter for its call and restores the previous context before returning
///   or unwinding.
/// - A stack job captures its creator's context and executes in it. The creator waits for the
///   job's latch before leaving the frame that holds the job. A job that enters the context on a
///   thread that was in another leaves it, charging the meter, before setting that latch. A job
///   that runs on a thread already in its context charges nothing itself, and the activation that
///   put the thread there charges the meter before it sets its own latch or returns from
///   [`measure`].
/// - A [`MeterHandle`] holds the meter it captured and enters that context while it runs work.
/// - Suspending a context enters [`Context::NONE`], and restoring returns to a context whose scope
///   encloses the suspension.
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
    /// thread's current context qualifies, so does the context a stack job captured from a creator
    /// that waits on the job's latch until this call returns, and so does a meter the caller holds
    /// a [`MeterHandle`] to.
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
    /// The meter the thread charges, or null for no context.
    meter: *const Meter,
    /// When the thread entered its context, or `None` before its first switch.
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

        // The previous meter is charged up to the instant `to` starts from, so no time is charged
        // twice or lost between them.
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
