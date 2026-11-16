use super::{
    Clock, Context, Parked, TestClock, charge, is_parked, measure, measure_with, unparked,
};
use crate::rayon::{Placement, ThreadPool, ThreadPoolBuilder, Yield, join, spin};
use commonware_utils::NZUsize;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MS: Duration = Duration::from_millis(1);

/// Measures `op` on a fresh virtual clock and returns the run's busy time.
fn measured(op: impl FnOnce(&TestClock)) -> Duration {
    let clock = TestClock::default();
    measure_with(Clock::Virtual(clock.clone()), || op(&clock)).1
}

/// Blocks until at least `count` workers of `pool` sleep. A sleeping worker waits with its context
/// suspended, so virtual time that passes afterwards is not charged to it.
fn wait_until_asleep(pool: &ThreadPool, count: usize) {
    let start = Instant::now();
    while pool.sleeping_workers() < count {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{count} workers must sleep within 10s"
        );
        std::hint::spin_loop();
    }
}

/// A run charges the calling thread's spins and leaves its context on return.
#[test]
fn charges_the_calling_thread_until_it_leaves() {
    let busy = measured(|clock| clock.spin(2 * MS));
    assert_eq!(busy, 2 * MS);
    assert_eq!(Context::current(), Context::NONE);
}

/// Re-entering the current context keeps it current, so spins inside and after it are charged.
#[test]
fn entering_the_current_context_keeps_charging() {
    let busy = measured(|clock| {
        let context = Context::current();
        assert_ne!(context, Context::NONE);
        // SAFETY: `context` is the calling thread's current context.
        unsafe { context.enter(|| clock.spin(MS)) };
        assert_eq!(Context::current(), context);
        clock.spin(MS);
    });
    assert_eq!(busy, 2 * MS);
}

/// Time that passes while the thread is suspended is not charged, and the spins on either side
/// of the suspension are.
#[test]
fn suspension_charges_nothing_and_resumes() {
    let busy = measured(|clock| {
        clock.spin(MS);
        Context::suspend(|| {
            assert_eq!(Context::current(), Context::NONE);
            clock.elapse(50 * MS);
        });
        clock.spin(MS);
    });
    assert_eq!(busy, 2 * MS);
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

/// The enclosing run includes a nested run's busy time once, besides its own spins.
#[test]
fn nested_runs_charge_the_enclosing_run_once() {
    let mut inner = Duration::ZERO;
    let outer = measured(|clock| {
        clock.spin(MS);
        inner = measure_with(Clock::Virtual(clock.clone()), || clock.spin(2 * MS)).1;
        clock.spin(MS);
    });
    assert_eq!(inner, 2 * MS);
    assert_eq!(outer, 4 * MS);
}

/// A nested run that unwinds after 2ms still charges its busy time to the enclosing run.
#[test]
fn unwinding_nested_run_charges_the_enclosing_run() {
    let outer = measured(|clock| {
        let result = catch_unwind(AssertUnwindSafe(|| {
            measure_with(Clock::Virtual(clock.clone()), || {
                clock.spin(2 * MS);
                panic!("unwind");
            })
        }));
        assert!(result.is_err());
    });
    assert_eq!(outer, 2 * MS);
}

/// An install from outside the pool charges the 20ms that pass on the worker but not the caller's
/// hand-off and wait. The caller suspends its context before the job can run.
#[test]
fn installs_charge_the_worker_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let busy = measured(|clock| pool.install(|| clock.elapse(20 * MS)));
    assert_eq!(busy, 20 * MS);
}

/// An install placed on another group from a worker charges the 20ms that pass on that group's
/// worker but not the installing worker's hand-off and wait.
#[test]
fn cross_group_installs_charge_the_worker_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2))
        .group_width(1)
        .build()
        .unwrap();
    let busy = measured(|clock| {
        pool.install_in(Placement::Local(0), || {
            pool.install_in(Placement::Local(1), || clock.elapse(20 * MS))
        })
    });
    assert_eq!(busy, 20 * MS);
}

/// A broadcast from outside the pool charges the 20ms that pass on the worker but not the
/// caller's wait.
#[test]
fn broadcasts_charge_the_worker_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let busy = measured(|clock| {
        pool.broadcast(|_| clock.elapse(20 * MS));
    });
    assert_eq!(busy, 20 * MS);
}

/// A join whose second side runs inline charges both sides' spins.
#[test]
fn inline_joins_charge_both_sides() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let busy = measured(|clock| {
        pool.install(|| join(|| clock.spin(5 * MS), || clock.spin(40 * MS)));
    });
    assert_eq!(busy, 45 * MS);
}

/// A join whose second side is stolen charges the 40ms that pass on the thief but not the joining
/// worker's wait. The joining worker sleeps before the 40ms pass.
#[test]
fn joins_charge_the_stolen_side_but_not_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let stolen = AtomicBool::new(false);
    let busy = measured(|clock| {
        pool.install(|| {
            join(
                // The first side returns once the second is stolen, so the joiner has to wait.
                || {
                    let start = Instant::now();
                    while !stolen.load(Ordering::Acquire) {
                        assert!(
                            start.elapsed() < Duration::from_secs(10),
                            "the second side must be stolen within 10s"
                        );
                        std::hint::spin_loop();
                    }
                },
                || {
                    stolen.store(true, Ordering::Release);
                    wait_until_asleep(&pool, 1);
                    clock.elapse(40 * MS);
                },
            );
        });
    });
    assert_eq!(busy, 40 * MS);
}

/// A nested run on a worker charges its busy time to the enclosing run once, and the caller's
/// wait adds nothing.
#[test]
fn nested_runs_on_workers_charge_the_enclosing_run_once() {
    let pool = ThreadPoolBuilder::new(NZUsize!(2)).build().unwrap();
    let mut inner = Duration::ZERO;
    let outer = measured(|clock| {
        inner = pool.install(|| {
            let inner = measure_with(Clock::Virtual(clock.clone()), || clock.elapse(30 * MS)).1;
            clock.spin(MS);
            inner
        });
    });
    assert_eq!(inner, 30 * MS);
    assert_eq!(outer, 31 * MS);
}

/// A spawned job that the worker runs while yielding inside a measured install charges nothing
/// to the install.
#[test]
fn spawned_jobs_charge_nothing() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let busy = measured(|clock| {
        pool.install(|| {
            let clock = clock.clone();
            pool.spawn(move || clock.elapse(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });
    assert_eq!(busy, Duration::ZERO);
}

/// A spawned broadcast that the worker runs while yielding charges nothing to the install.
#[test]
fn spawned_broadcasts_charge_nothing() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let busy = measured(|clock| {
        pool.install(|| {
            let clock = clock.clone();
            pool.spawn_broadcast(move |_| clock.elapse(50 * MS));
            assert_eq!(pool.yield_now(), Some(Yield::Executed));
        });
    });
    assert_eq!(busy, Duration::ZERO);
}

/// A charge lands on the calling thread's run, and a charge outside any run lands nowhere.
#[test]
fn charges_land_on_the_current_run() {
    charge(20 * MS);
    let busy = measured(|clock| {
        clock.spin(MS);
        charge(20 * MS);
    });
    assert_eq!(busy, 21 * MS);
}

/// A thread that blocks in its context is charged for the 20ms that pass meanwhile, so a run
/// suspends its context around a wait it does not want charged.
#[test]
fn blocked_threads_are_charged_for_the_wait() {
    let pool = ThreadPoolBuilder::new(NZUsize!(1)).build().unwrap();
    let busy = measured(|clock| {
        let (sender, receiver) = std::sync::mpsc::channel();
        let clock = clock.clone();
        pool.spawn(move || {
            clock.elapse(20 * MS);
            sender.send(()).unwrap();
        });
        receiver.recv().unwrap();
    });
    assert_eq!(busy, 20 * MS);
}

/// Time that passes while the context is parked is not charged, and spins on either side are.
#[commonware_macros::test_group("miri")]
#[test]
fn parked_contexts_charge_nothing_until_resumed() {
    let busy = measured(|clock| {
        clock.spin(MS);
        {
            let _parked = Parked::new();
            assert!(is_parked());
            clock.elapse(50 * MS);
            clock.spin(MS);
        }
        assert!(!is_parked());
        clock.spin(MS);
    });
    assert_eq!(busy, 2 * MS);
}

/// A parked context stays current: a charge lands on it, and a nested run returns to it parked.
#[commonware_macros::test_group("miri")]
#[test]
fn parked_contexts_receive_charges_and_nested_runs() {
    let mut inner = Duration::ZERO;
    let outer = measured(|clock| {
        let _parked = Parked::new();
        charge(20 * MS);
        inner = measure_with(Clock::Virtual(clock.clone()), || clock.spin(2 * MS)).1;
        assert!(is_parked());
        clock.elapse(50 * MS);
    });
    assert_eq!(inner, 2 * MS);
    assert_eq!(outer, 22 * MS);
}

/// Work a parked thread does through `unparked` is charged, and the context is parked again after.
#[commonware_macros::test_group("miri")]
#[test]
fn unparked_work_on_a_parked_context_is_charged() {
    let busy = measured(|clock| {
        let _parked = Parked::new();
        unparked(|| {
            assert!(!is_parked());
            clock.spin(5 * MS);
        });
        assert!(is_parked());
        clock.elapse(50 * MS);
    });
    assert_eq!(busy, 5 * MS);
}

/// Parking a thread with no context, or one already parked, changes nothing.
#[commonware_macros::test_group("miri")]
#[test]
fn parking_nests_and_ignores_no_context() {
    {
        let _parked = Parked::new();
        assert!(!is_parked());
    }
    let busy = measured(|clock| {
        let _outer = Parked::new();
        {
            let _inner = Parked::new();
            clock.elapse(10 * MS);
        }
        assert!(is_parked());
        clock.elapse(10 * MS);
    });
    assert_eq!(busy, Duration::ZERO);
}

/// A worker that yields on empty queues searches in no context. The searches dominate a loop of
/// yields, so the worker is charged for less than half of the loop's wall time. A deschedule inside
/// a charged interval can inflate one attempt, so a failed attempt is retried.
#[test]
fn idle_yields_charge_nothing() {
    // Each idle search scans the other workers' deques, so a wide pool makes it dwarf the charged
    // interval between yields.
    const ITERATIONS: usize = 10_000;
    let pool = ThreadPoolBuilder::new(NZUsize!(32)).build().unwrap();
    let mut attempts = Vec::new();
    for _ in 0..10 {
        // Yield on empty queues inside a measured install, timing the loop on the worker.
        let (wall, busy) = measure(|| {
            pool.install(|| {
                let start = Instant::now();
                for _ in 0..ITERATIONS {
                    assert_eq!(pool.yield_now(), Some(Yield::Idle));
                }
                start.elapsed()
            })
        });

        // A charged search would bring the busy time up to the wall time on every attempt.
        if busy < wall / 2 {
            return;
        }
        attempts.push((busy, wall));
    }
    panic!("busy time must exclude the idle searches in one of ten attempts: {attempts:?}");
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
