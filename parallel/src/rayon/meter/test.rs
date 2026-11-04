use super::{Context, Meter};
use crate::rayon::{ThreadPoolBuilder, Yield, join, spin, timed_spin};
use commonware_utils::NZUsize;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::{Duration, Instant},
};

const MS: Duration = Duration::from_millis(1);

/// Runs `op` in `meter`'s context and returns its wall time.
fn timed(meter: &Meter, op: impl FnOnce()) -> Duration {
    let start = Instant::now();
    meter.measure(op);
    start.elapsed()
}

/// The calling thread is charged for its time in the context, never for more than the wall time,
/// and for nothing once it has left.
#[test]
fn charges_the_calling_thread_until_it_leaves() {
    // Spin for 2ms in the context.
    let meter = Meter::new();
    let wall = timed(&meter, || spin(2 * MS));

    // The charge covers the spin and stays within the wall time.
    let busy = meter.busy();
    assert!(
        busy >= 2 * MS && busy <= wall,
        "busy time {busy:?} must cover the 2ms spin and stay within the wall {wall:?}"
    );

    // The thread left the context, so later time is not charged.
    assert_eq!(Context::current(), Context::NONE);
    spin(MS);
    assert_eq!(meter.busy(), busy);
}

/// Entering the context that is already current leaves it current throughout, so both spins are
/// charged.
#[test]
fn entering_the_current_context_keeps_charging() {
    // Re-enter the current context around one spin, then spin again after it returns.
    let meter = Meter::new();
    let wall = timed(&meter, || {
        let context = Context::current();
        assert_ne!(context, Context::NONE);
        // SAFETY: `context` is the calling thread's current context.
        unsafe { context.enter(|| spin(MS)) };
        assert_eq!(Context::current(), context);
        spin(MS);
    });

    // Both spins are charged, and the charge stays within the wall time.
    let busy = meter.busy();
    assert!(
        busy >= 2 * MS && busy <= wall,
        "busy time {busy:?} must cover both 1ms spins and stay within the wall {wall:?}"
    );
}

/// The 50ms spent suspended is not charged, and the spins on either side of it are.
#[test]
fn suspension_charges_nothing_and_resumes() {
    // Spin for 1ms on each side of a 50ms suspension.
    let meter = Meter::new();
    let wall = timed(&meter, || {
        spin(MS);
        Context::suspend(|| {
            assert_eq!(Context::current(), Context::NONE);
            spin(50 * MS);
        });
        spin(MS);
    });

    // Only the two 1ms spins are charged.
    let busy = meter.busy();
    assert!(
        busy >= 2 * MS && busy <= wall - 50 * MS,
        "busy time {busy:?} must cover both spins and exclude the suspension, wall {wall:?}"
    );
}

/// A measured operation that unwinds still leaves the thread in its previous context.
#[test]
fn context_is_restored_when_op_unwinds() {
    // Unwind out of a measured operation.
    let meter = Meter::new();
    let result = catch_unwind(|| meter.measure(|| panic!("unwind")));

    // The panic reaches the caller, and the thread's context is none again.
    assert!(result.is_err());
    assert_eq!(Context::current(), Context::NONE);
}

/// The enclosing run includes a nested run's busy time once, and one thread's busy time never
/// exceeds its wall time.
#[test]
fn nested_meters_charge_the_enclosing_run_once() {
    // Spin for 1ms on each side of a nested meter that measures a 2ms spin.
    let (outer, inner) = (Meter::new(), Meter::new());
    let wall = timed(&outer, || {
        spin(MS);
        inner.measure(|| spin(2 * MS));
        spin(MS);
    });

    // The outer charge adds the nested charge to its own 2ms, and counting the nested charge
    // twice would exceed the wall time.
    let (outer, inner) = (outer.busy(), inner.busy());
    assert!(
        inner >= 2 * MS,
        "inner busy time {inner:?} must cover the 2ms spin"
    );
    assert!(
        outer >= inner + 2 * MS && outer <= wall,
        "outer busy time {outer:?} must add inner {inner:?} to 2ms and stay within wall {wall:?}"
    );
}

/// A nested run that unwinds after 2ms still charges its busy time to the enclosing run.
#[test]
fn unwinding_nested_meter_charges_the_enclosing_run() {
    // A nested meter spins for 2ms and then unwinds inside the outer context.
    let (outer, inner) = (Meter::new(), Meter::new());
    outer.measure(|| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            inner.measure(|| {
                spin(2 * MS);
                panic!("unwind");
            })
        }));
        assert!(result.is_err());
    });

    // The outer charge still includes the nested charge.
    let (outer, inner) = (outer.busy(), inner.busy());
    assert!(
        inner >= 2 * MS && outer >= inner,
        "inner busy time {inner:?} must cover the 2ms spin and outer {outer:?} must include it"
    );
}

/// An install from outside the pool charges the worker that runs it. The caller's context is
/// suspended while it waits, so the busy time exceeds the wall time only by the hand-off.
#[test]
fn installs_charge_the_worker_but_not_the_wait() {
    // Install a 20ms spin from outside the pool.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || pool.install(|| spin(20 * MS)));

    // The worker's spin is charged, and the caller's wait adds nothing beyond the hand-off.
    let busy = meter.busy();
    assert!(
        busy >= 20 * MS && busy < wall + 10 * MS,
        "busy time {busy:?} must cover the 20ms spin and stay under the wall {wall:?} plus 10ms"
    );
}

/// A broadcast from outside the pool charges the worker that runs it, and the caller's blocked
/// wait on the broadcast's latch is not charged.
#[test]
fn broadcasts_charge_the_worker_but_not_the_wait() {
    // Broadcast a 20ms spin to the only worker from outside the pool.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.broadcast(|_| spin(20 * MS));
    });

    // The worker's spin is charged, and the caller's wait adds nothing beyond the hand-off.
    let busy = meter.busy();
    assert!(
        busy >= 20 * MS && busy < wall + 10 * MS,
        "busy time {busy:?} must cover the 20ms spin and stay under the wall {wall:?} plus 10ms"
    );
}

/// A join charges both sides for the time their threads spend in them. When the long side is
/// stolen, the worker that finishes the short side waits for it uncharged, so the busy time
/// exceeds the sum of both sides by at most the hand-off overhead.
#[test]
fn joins_charge_both_sides_but_not_the_wait() {
    // Join a 5ms side with a 40ms side on two workers, timing each side on its own thread.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let meter = Meter::new();
    let mut sides = Duration::ZERO;
    let wall = timed(&meter, || {
        let (short, long) = pool.install(|| join(|| timed_spin(5 * MS), || timed_spin(40 * MS)));
        sides = short + long;
    });

    // Both sides are charged, and the wait for the long side is not.
    let busy = meter.busy();
    assert!(
        busy >= 45 * MS && busy < sides + 15 * MS,
        "busy time {busy:?} must cover both sides {sides:?} and exclude the wait, wall {wall:?}"
    );
}

/// On a worker, a nested meter measures a 30ms spin and the worker then spins for 1ms more. The
/// enclosing run includes the nested busy time once, plus that 1ms, and no charged wait.
#[test]
fn nested_meters_on_workers_charge_the_enclosing_run_once() {
    // On a worker, measure a nested 30ms spin and then spin for 1ms in the installed run.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let (outer, inner) = (Meter::new(), Meter::new());
    let wall = timed(&outer, || {
        pool.install(|| {
            inner.measure(|| spin(30 * MS));
            spin(MS);
        });
    });

    // The outer charge adds the nested charge to the 1ms, and the caller's wait adds nothing
    // beyond the hand-off.
    let (outer, inner) = (outer.busy(), inner.busy());
    assert!(
        inner >= 30 * MS,
        "inner busy time {inner:?} must cover the 30ms spin"
    );
    assert!(
        outer >= inner + MS && outer < wall + 10 * MS,
        "outer busy time {outer:?} must add inner {inner:?} to 1ms, within wall {wall:?} plus 10ms"
    );
}

/// On a pool with one worker, a spawned job runs when the worker yields inside the measured
/// install. A detached job is not part of the run, so its 50ms charges nothing.
#[test]
fn spawned_jobs_charge_nothing() {
    // Spawn a 50ms job from a measured install, and yield so the only worker runs it.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.install(|| {
            pool.spawn(|| spin(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });

    // The spawned job's 50ms is not charged.
    let busy = meter.busy();
    assert!(
        busy < wall - 40 * MS,
        "busy time {busy:?} must exclude the spawned job, wall {wall:?}"
    );
}

/// A spawned broadcast run by the yielding worker is detached like a spawned job, so its 50ms
/// charges nothing to the measured install.
#[test]
fn spawned_broadcasts_charge_nothing() {
    // Spawn a 50ms broadcast from a measured install, and yield so the only worker runs it.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.install(|| {
            pool.spawn_broadcast(|_| spin(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });

    // The spawned broadcast's 50ms is not charged.
    let busy = meter.busy();
    assert!(
        busy < wall - 40 * MS,
        "busy time {busy:?} must exclude the spawned broadcast, wall {wall:?}"
    );
}

/// Enters and restores contexts through a measured install from outside the pool, a join whose
/// sides may run on either worker, a nested meter on a worker, and a nested meter that unwinds, so
/// Miri can check each access to a context's meter.
#[commonware_macros::test_group("miri")]
#[test]
fn contexts_are_scoped_to_their_runs() {
    // The install runs in the outer context on a worker, and either join side may run on either
    // worker.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let (outer, inner, unwound) = (Meter::new(), Meter::new(), Meter::new());
    outer.measure(|| {
        assert_eq!(Context::current(), Context(&outer));
        pool.install(|| {
            assert_eq!(Context::current(), Context(&outer));
            join(
                || inner.measure(|| spin(Duration::from_micros(1))),
                || spin(Duration::from_micros(1)),
            );

            // A nested meter that unwinds on a worker restores the outer context.
            let result = catch_unwind(AssertUnwindSafe(|| unwound.measure(|| panic!("unwind"))));
            assert!(result.is_err());
            assert_eq!(Context::current(), Context(&outer));
        });
        assert_eq!(Context::current(), Context(&outer));
    });

    // The caller leaves every context, and the outer meter includes both nested charges once.
    assert_eq!(Context::current(), Context::NONE);
    assert!(inner.busy() > Duration::ZERO && outer.busy() >= inner.busy() + unwound.busy());
}
