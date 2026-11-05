use super::{Context, charge, measure};
use crate::rayon::{ThreadPoolBuilder, Yield, join, spin, timed_spin};
use commonware_utils::NZUsize;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::{Duration, Instant},
};

const MS: Duration = Duration::from_millis(1);

/// Measures `op` and returns the run's busy time and its wall time.
fn timed(op: impl FnOnce()) -> (Duration, Duration) {
    let start = Instant::now();
    let ((), busy) = measure(op);
    (busy, start.elapsed())
}

/// A run charges the calling thread's time up to the wall time and leaves its context on return.
#[test]
fn charges_the_calling_thread_until_it_leaves() {
    // Spin for 2ms in a measured run.
    let (busy, wall) = timed(|| spin(2 * MS));
    assert!(
        busy >= 2 * MS && busy <= wall,
        "busy time {busy:?} must cover the 2ms spin and stay within the wall {wall:?}"
    );

    // The thread left the context.
    assert_eq!(Context::current(), Context::NONE);
}

/// Re-entering the current context keeps it current, so spins inside and after it are charged.
#[test]
fn entering_the_current_context_keeps_charging() {
    // Re-enter the current context around one spin, then spin again after it returns.
    let (busy, wall) = timed(|| {
        let context = Context::current();
        assert_ne!(context, Context::NONE);
        // SAFETY: `context` is the calling thread's current context.
        unsafe { context.enter(|| spin(MS)) };
        assert_eq!(Context::current(), context);
        spin(MS);
    });

    // Both spins are charged, and the charge stays within the wall time.
    assert!(
        busy >= 2 * MS && busy <= wall,
        "busy time {busy:?} must cover both 1ms spins and stay within the wall {wall:?}"
    );
}

/// The 50ms spent suspended is not charged, and the spins on either side of it are.
#[test]
fn suspension_charges_nothing_and_resumes() {
    // Spin for 1ms on each side of a 50ms suspension.
    let (busy, wall) = timed(|| {
        spin(MS);
        Context::suspend(|| {
            assert_eq!(Context::current(), Context::NONE);
            spin(50 * MS);
        });
        spin(MS);
    });

    // Only the two 1ms spins are charged.
    assert!(
        busy >= 2 * MS && busy <= wall - 50 * MS,
        "busy time {busy:?} must cover both spins and exclude the suspension, wall {wall:?}"
    );
}

/// A measured run that unwinds still leaves the thread in its previous context.
#[test]
fn context_is_restored_when_op_unwinds() {
    // Unwind out of a measured run.
    let result = catch_unwind(|| measure(|| panic!("unwind")));

    // The panic reaches the caller, and the thread's context is none again.
    assert!(result.is_err());
    assert_eq!(Context::current(), Context::NONE);
}

/// The enclosing run includes a nested run's busy time once, and one thread's busy time never
/// exceeds its wall time.
#[test]
fn nested_runs_charge_the_enclosing_run_once() {
    // Spin for 1ms on each side of a nested run that measures a 2ms spin.
    let mut inner = Duration::ZERO;
    let (outer, wall) = timed(|| {
        spin(MS);
        inner = measure(|| spin(2 * MS)).1;
        spin(MS);
    });

    // The outer run adds the nested charge once to its own 2ms, within the wall time.
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
fn unwinding_nested_run_charges_the_enclosing_run() {
    // A nested run spins for 2ms and then unwinds inside the outer run.
    let ((), outer) = measure(|| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            measure(|| {
                spin(2 * MS);
                panic!("unwind");
            })
        }));
        assert!(result.is_err());
    });

    // The outer charge includes the nested spin.
    assert!(
        outer >= 2 * MS,
        "outer busy time {outer:?} must include the nested 2ms spin"
    );
}

/// An install from outside the pool charges the worker's 20ms spin but not the caller's wait, so
/// busy time stays within the wall time, with slack for clock skew between threads.
#[test]
fn installs_charge_the_worker_but_not_the_wait() {
    // Install a 20ms spin from outside the pool.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let (busy, wall) = timed(|| pool.install(|| spin(20 * MS)));

    // The worker's spin is charged, and the caller's wait adds nothing.
    assert!(
        busy >= 20 * MS && busy < wall + 10 * MS,
        "busy time {busy:?} must cover the 20ms spin and stay under the wall {wall:?} plus 10ms"
    );
}

/// A broadcast from outside the pool charges the worker's 20ms spin but not the caller's wait.
#[test]
fn broadcasts_charge_the_worker_but_not_the_wait() {
    // Broadcast a 20ms spin to the only worker from outside the pool.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let (busy, wall) = timed(|| {
        pool.broadcast(|_| spin(20 * MS));
    });

    // The worker's spin is charged, and the caller's wait adds nothing.
    assert!(
        busy >= 20 * MS && busy < wall + 10 * MS,
        "busy time {busy:?} must cover the 20ms spin and stay under the wall {wall:?} plus 10ms"
    );
}

/// A join charges both sides but not the worker that finishes the short side and waits for the
/// long one.
#[test]
fn joins_charge_both_sides_but_not_the_wait() {
    // Join a 5ms side with a 40ms side on two workers, timing each side on its own thread.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let mut sides = Duration::ZERO;
    let (busy, wall) = timed(|| {
        let (short, long) = pool.install(|| join(|| timed_spin(5 * MS), || timed_spin(40 * MS)));
        sides = short + long;
    });

    // Both sides are charged, and the wait for the long side is not.
    assert!(
        busy >= 45 * MS && busy < sides + 15 * MS,
        "busy time {busy:?} must cover both sides {sides:?} and exclude the wait, wall {wall:?}"
    );
}

/// A nested run on a worker charges its busy time to the enclosing run once, and the caller's
/// wait adds nothing.
#[test]
fn nested_runs_on_workers_charge_the_enclosing_run_once() {
    // On a worker, measure a nested 30ms spin and then spin for 1ms in the installed run.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let start = Instant::now();
    let (inner, outer) = measure(|| {
        pool.install(|| {
            let ((), inner) = measure(|| spin(30 * MS));
            spin(MS);
            inner
        })
    });
    let wall = start.elapsed();

    // The outer run adds the nested charge to the 1ms spin, and the wait adds nothing.
    assert!(
        inner >= 30 * MS,
        "inner busy time {inner:?} must cover the 30ms spin"
    );
    assert!(
        outer >= inner + MS && outer < wall + 10 * MS,
        "outer busy time {outer:?} must add inner {inner:?} to 1ms, within wall {wall:?} plus 10ms"
    );
}

/// A spawned job that the worker runs while yielding inside a measured install charges nothing to
/// the install.
#[test]
fn spawned_jobs_charge_nothing() {
    // Spawn a 50ms job from a measured install, and yield so the only worker runs it.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let (busy, wall) = timed(|| {
        pool.install(|| {
            pool.spawn(|| spin(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });

    // The spawned job's 50ms is not charged.
    assert!(
        busy < wall - 40 * MS,
        "busy time {busy:?} must exclude the spawned job, wall {wall:?}"
    );
}

/// A spawned broadcast that the worker runs while yielding charges nothing to the install.
#[test]
fn spawned_broadcasts_charge_nothing() {
    // Spawn a 50ms broadcast from a measured install, and yield so the only worker runs it.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let (busy, wall) = timed(|| {
        pool.install(|| {
            pool.spawn_broadcast(|_| spin(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });

    // The spawned broadcast's 50ms is not charged.
    assert!(
        busy < wall - 40 * MS,
        "busy time {busy:?} must exclude the spawned broadcast, wall {wall:?}"
    );
}

/// A charge lands on the calling thread's run, and a charge outside any run lands nowhere.
#[test]
fn charges_land_on_the_current_run() {
    // Charge 20ms inside a run that spins for 1ms, and 20ms more outside any run.
    charge(20 * MS);
    let (busy, wall) = timed(|| {
        spin(MS);
        charge(20 * MS);
    });

    // The run holds its spin plus the charge, and nothing from the charge outside it.
    assert!(
        busy >= 21 * MS && busy <= wall + 20 * MS,
        "busy time {busy:?} must add the 20ms charge to the 1ms spin, wall {wall:?}"
    );
}

/// A thread that blocks in its context is charged for the wait, so a run suspends its context
/// around a wait it does not want charged.
#[test]
fn blocked_threads_are_charged_for_the_wait() {
    // Spawn a 20ms job and block on its result on the test thread, in its context.
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let (busy, wall) = timed(|| {
        let (sender, receiver) = std::sync::mpsc::channel();
        pool.spawn(move || {
            spin(20 * MS);
            sender.send(()).unwrap();
        });
        receiver.recv().unwrap();
    });

    // The blocked wait covers the job once.
    assert!(
        busy >= 20 * MS && busy <= wall,
        "busy time {busy:?} must cover the blocked wait and stay within the wall {wall:?}"
    );
}

/// A worker that yields on empty queues searches in no context, so a measured install that keeps
/// yielding is charged only for its time between yields. A descheduled attempt is retried. The
/// oracle assumes a clock read costs less than an idle search.
#[test]
fn idle_yields_charge_nothing() {
    const ITERATIONS: usize = 20_000;
    let pool = ThreadPoolBuilder::new(NZUsize!(8)).build().unwrap();
    for _ in 0..10 {
        // Yield on empty queues inside a measured install, timing every yield.
        let start = Instant::now();
        let (mut yields, busy) = measure(|| {
            pool.install(|| {
                let mut yields = Vec::with_capacity(ITERATIONS);
                for _ in 0..ITERATIONS {
                    let begun = Instant::now();
                    assert_eq!(pool.yield_now(), Some(Yield::Idle));
                    yields.push(begun.elapsed());
                }
                yields
            })
        });
        let wall = start.elapsed();

        // An outlier yield or excess wall time means the thread was descheduled, so retry.
        yields.sort_unstable();
        let median = yields[ITERATIONS / 2].max(Duration::from_nanos(100));
        let total: Duration = yields.iter().sum();
        if yields[ITERATIONS - 1] > 50 * median || wall > total + total / 2 {
            continue;
        }

        // The yields are not charged, so the busy time leaves out most of their total; a charged
        // search would bring it up to the wall time.
        assert!(
            busy + total / 2 < wall,
            "busy time {busy:?} must exclude the {total:?} spent in idle searches, wall {wall:?}"
        );
        return;
    }
    panic!("some attempt must run without a deschedule in ten tries");
}

/// Contexts restore across an install, a join with a nested run, and a nested run that unwinds on
/// a worker, under Miri's checks of the raw context pointers.
#[commonware_macros::test_group("miri")]
#[test]
fn contexts_are_scoped_to_their_runs() {
    // Each step sees the outer context, compared by address since raw pointers are not `Send`.
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let address = || Context::current().0.addr();
    let (inner, outer) = measure(|| {
        let outer = address();
        assert_ne!(outer, Context::NONE.0.addr());
        let inner = pool.install(|| {
            assert_eq!(address(), outer);
            let (inner, ()) = join(
                || measure(|| spin(Duration::from_micros(1))).1,
                || spin(Duration::from_micros(1)),
            );

            // A nested run that unwinds on a worker restores the outer context.
            let result = catch_unwind(AssertUnwindSafe(|| measure(|| panic!("unwind"))));
            assert!(result.is_err());
            assert_eq!(address(), outer);
            inner
        });
        assert_eq!(address(), outer);
        inner
    });

    // The caller leaves every context, and the outer run includes the nested charge.
    assert_eq!(Context::current(), Context::NONE);
    assert!(inner > Duration::ZERO && outer >= inner);
}
