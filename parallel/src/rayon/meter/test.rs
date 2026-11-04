use super::{Context, Meter};
use crate::rayon::{ThreadPoolBuilder, Yield, join, spin};
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
    let meter = Meter::new();
    let wall = timed(&meter, || spin(2 * MS));
    let busy = meter.busy();
    assert!(
        busy >= 2 * MS && busy <= wall,
        "busy {busy:?}, wall {wall:?}"
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
    let meter = Meter::new();
    let wall = timed(&meter, || {
        let context = Context::current();
        assert_ne!(context, Context::NONE);
        // SAFETY: `context` is the calling thread's current context.
        unsafe { context.enter(|| spin(MS)) };
        assert_eq!(Context::current(), context);
        spin(MS);
    });
    let busy = meter.busy();
    assert!(
        busy >= 2 * MS && busy <= wall,
        "busy {busy:?}, wall {wall:?}"
    );
}

/// The 50ms spent suspended is not charged, and the spins on either side of it are.
#[test]
fn suspension_charges_nothing_and_resumes() {
    let meter = Meter::new();
    let wall = timed(&meter, || {
        spin(MS);
        Context::suspend(|| {
            assert_eq!(Context::current(), Context::NONE);
            spin(50 * MS);
        });
        spin(MS);
    });
    let busy = meter.busy();
    assert!(
        busy >= 2 * MS && busy <= wall - 50 * MS,
        "busy {busy:?}, wall {wall:?}"
    );
}

/// A measured operation that unwinds still leaves the thread in its previous context.
#[test]
fn context_is_restored_when_op_unwinds() {
    let meter = Meter::new();
    let result = catch_unwind(|| meter.measure(|| panic!("unwind")));
    assert!(result.is_err());
    assert_eq!(Context::current(), Context::NONE);
}

/// The enclosing run includes a nested run's busy time once, and one thread's busy time never
/// exceeds its wall time.
#[test]
fn nested_meters_charge_the_enclosing_run_once() {
    let (outer, inner) = (Meter::new(), Meter::new());
    let wall = timed(&outer, || {
        spin(MS);
        inner.measure(|| spin(2 * MS));
        spin(MS);
    });
    let (outer, inner) = (outer.busy(), inner.busy());
    assert!(inner >= 2 * MS, "inner {inner:?}");
    assert!(
        outer >= inner + 2 * MS && outer <= wall,
        "outer {outer:?}, wall {wall:?}"
    );
}

/// A nested run that unwinds after 2ms still charges its busy time to the enclosing run.
#[test]
fn unwinding_nested_meter_charges_the_enclosing_run() {
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
    let (outer, inner) = (outer.busy(), inner.busy());
    assert!(
        inner >= 2 * MS && outer >= inner,
        "outer {outer:?}, inner {inner:?}"
    );
}

/// An install from outside the pool charges the worker that runs it. The caller's context is
/// suspended while it waits, so the busy time exceeds the wall time only by the hand-off.
#[test]
fn installs_charge_the_worker_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || pool.install(|| spin(20 * MS)));
    let busy = meter.busy();
    assert!(
        busy >= 20 * MS && busy < wall + 10 * MS,
        "busy {busy:?}, wall {wall:?}"
    );
}

/// A broadcast from outside the pool charges the worker that runs it, and the caller's blocked
/// wait on the broadcast's latch is not charged.
#[test]
fn broadcasts_charge_the_worker_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.broadcast(|_| spin(20 * MS));
    });
    let busy = meter.busy();
    assert!(
        busy >= 20 * MS && busy < wall + 10 * MS,
        "busy {busy:?}, wall {wall:?}"
    );
}

/// A join charges both sides. When the long side is stolen, the worker that finishes the short
/// side waits for it uncharged, so the busy time exceeds the wall time by at most the short side
/// plus hand-off overhead.
#[test]
fn joins_charge_both_sides_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.install(|| join(|| spin(5 * MS), || spin(40 * MS)));
    });
    let busy = meter.busy();
    assert!(
        busy >= 45 * MS && busy < wall + 15 * MS,
        "busy {busy:?}, wall {wall:?}"
    );
}

/// On a worker, a nested meter measures a 30ms spin and the worker then spins for 1ms more. The
/// enclosing run includes the nested busy time once, plus that 1ms, and no charged wait.
#[test]
fn nested_meters_on_workers_charge_the_enclosing_run_once() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let (outer, inner) = (Meter::new(), Meter::new());
    let wall = timed(&outer, || {
        pool.install(|| {
            inner.measure(|| spin(30 * MS));
            spin(MS);
        });
    });
    let (outer, inner) = (outer.busy(), inner.busy());
    assert!(inner >= 30 * MS, "inner {inner:?}");
    assert!(
        outer >= inner + MS && outer < wall + 10 * MS,
        "outer {outer:?}, wall {wall:?}"
    );
}

/// On a pool with one worker, a spawned job runs when the worker yields inside the measured
/// install. A detached job is not part of the run, so its 50ms charges nothing.
#[test]
fn spawned_jobs_charge_nothing() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.install(|| {
            pool.spawn(|| spin(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });
    let busy = meter.busy();
    assert!(busy < wall - 40 * MS, "busy {busy:?}, wall {wall:?}");
}

/// A spawned broadcast run by the yielding worker is detached like a spawned job, so its 50ms
/// charges nothing to the measured install.
#[test]
fn spawned_broadcasts_charge_nothing() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let meter = Meter::new();
    let wall = timed(&meter, || {
        pool.install(|| {
            pool.spawn_broadcast(|_| spin(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });
    let busy = meter.busy();
    assert!(busy < wall - 40 * MS, "busy {busy:?}, wall {wall:?}");
}

/// Enters and restores contexts through a measured install from outside the pool, a join whose
/// sides may run on either worker, a nested meter on a worker, and a nested meter that unwinds, so
/// Miri can check each access to a context's meter.
#[commonware_macros::test_group("miri")]
#[test]
fn contexts_are_scoped_to_their_runs() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let (outer, inner) = (Meter::new(), Meter::new());
    outer.measure(|| {
        assert_eq!(Context::current(), Context(&outer));
        pool.install(|| {
            assert_eq!(Context::current(), Context(&outer));
            join(
                || inner.measure(|| spin(Duration::from_micros(1))),
                || spin(Duration::from_micros(1)),
            );
            let result = catch_unwind(AssertUnwindSafe(|| inner.measure(|| panic!("unwind"))));
            assert!(result.is_err());
            assert_eq!(Context::current(), Context(&outer));
        });
        assert_eq!(Context::current(), Context(&outer));
    });
    assert_eq!(Context::current(), Context::NONE);
    assert!(inner.busy() > Duration::ZERO && outer.busy() >= inner.busy());
}
