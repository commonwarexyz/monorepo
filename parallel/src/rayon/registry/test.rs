//! Tests for the groups of a pool's workers and the placement of jobs among them.

use super::Placement;
use crate::rayon::{
    ThreadPool, ThreadPoolBuilder, Yield, join, placement_width, thread_pool::Worker, yield_now,
};
use commonware_utils::{TestRng, sync::Mutex};
use rand::RngExt as _;
use std::{
    any::Any,
    collections::HashSet,
    ops::Range,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

/// A pool of `threads` workers in groups of `width`.
fn pool(threads: usize, width: usize) -> ThreadPool {
    ThreadPoolBuilder::new()
        .num_threads(threads)
        .group_width(width)
        .build()
        .unwrap()
}

/// Runs `scenario` on its own thread and fails if it does not finish in time, so a scenario
/// that deadlocks fails the test rather than hanging it.
fn within<R: Send + 'static>(scenario: impl FnOnce() -> R + Send + 'static) -> R {
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let _ = tx.send(scenario());
    });
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic::resume_unwind(handle.join().unwrap_err())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("the scenario deadlocked"),
    }
}

/// Waits until `done` holds, failing after a bound.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting until {what}"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

/// Waits until every worker of `pool` is registered as asleep.
fn wait_until_asleep(pool: &ThreadPool) {
    wait_until("every worker sleeps", || {
        pool.sleeping_workers() == pool.current_num_threads()
    });
}

/// Busy-waits for `duration`, so a job holds its worker without sleeping.
fn spin(duration: Duration) {
    let start = Instant::now();
    while start.elapsed() < duration {
        std::hint::spin_loop();
    }
}

/// Runs `leaf` on every index of `range` through a tree of joins.
fn tree(range: Range<usize>, leaf: &(impl Fn(usize) + Sync)) {
    if range.len() <= 1 {
        if !range.is_empty() {
            leaf(range.start);
        }
        return;
    }
    let mid = range.start + range.len() / 2;
    join(
        || tree(range.start..mid, leaf),
        || tree(mid..range.end, leaf),
    );
}

/// The message of a panic raised with a string literal.
fn message(payload: Box<dyn Any + Send>) -> Option<&'static str> {
    payload.downcast_ref::<&'static str>().copied()
}

/// The placement of the job the calling thread runs, if it is a worker of `pool`.
fn placement(pool: &ThreadPool) -> Option<Placement> {
    pool.current_worker().map(|worker| worker.placement)
}

/// Workers form consecutive groups of the configured width, the last one narrower, and a pool
/// built without a width, or with a width that is zero or too wide, is one group.
#[test]
fn workers_form_consecutive_groups() {
    let pool = pool(7, 3);
    assert_eq!(pool.group_widths(), [3, 3, 1]);
    let mut seen: Vec<_> = (0..3)
        .flat_map(|group| {
            pool.broadcast_in(group, || {
                pool.current_worker()
                    .map(|worker| (worker.index, worker.group))
            })
        })
        .collect();
    seen.sort_unstable();
    let expected: Vec<_> = (0..7).map(|index| Some((index, index / 3))).collect();
    assert_eq!(seen, expected);
    assert_eq!(pool.current_worker(), None);

    for width in [0, 4, 9] {
        assert_eq!(self::pool(4, width).group_widths(), [4]);
    }
    let default = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    assert_eq!(default.group_widths(), [4]);
}

/// A worker reports the width of the placement of the job it runs: its group's under a local
/// placement, the last group narrower, and the whole pool's under a wide one.
#[test]
fn a_worker_reports_the_width_of_its_placement() {
    let pool = pool(5, 2);
    let width = |placement| {
        pool.install_in(placement, || {
            let worker = pool.current_worker().unwrap();
            assert_eq!(worker.width, placement_width());
            worker.width
        })
    };

    // A local placement spans its group, and the last group has the one worker left over
    assert_eq!(width(Placement::Local(0)), 2);
    assert_eq!(width(Placement::Local(2)), 1);

    // A wide placement spans every worker, whichever group it names
    assert_eq!(width(Placement::Wide { near: 2 }), 5);
}

/// An install runs its operation under the placement it names, a job the operation spawns under
/// its worker's placement runs under that placement, and the placement in force before the install
/// is restored when it returns.
#[test]
fn installs_place_their_operation_and_restore_the_previous_placement() {
    let pool = Arc::new(pool(4, 2));
    assert!(matches!(
        pool.install_in(Placement::Wide { near: 0 }, || placement(&pool)),
        Some(Placement::Wide { .. })
    ));
    let observed = pool.install_in(Placement::Local(1), || {
        let local = placement(&pool);
        let wide = pool.install_in(Placement::Wide { near: 0 }, || placement(&pool));
        let restored = placement(&pool);
        let (tx, rx) = mpsc::channel();
        let spawner = Arc::clone(&pool);
        pool.spawn_in(restored.unwrap(), move || {
            tx.send(placement(&spawner)).unwrap();
        });
        let spawned = loop {
            if let Ok(placement) = rx.try_recv() {
                break placement;
            }
            yield_now();
        };
        (local, wide, restored, spawned)
    });
    assert_eq!(
        observed,
        (
            Some(Placement::Local(1)),
            Some(Placement::Wide { near: 1 }),
            Some(Placement::Local(1)),
            Some(Placement::Local(1)),
        )
    );
}

/// A worker's placement is restored when an operation it installed under another placement
/// panics.
#[test]
fn a_panicking_install_restores_the_previous_placement() {
    let pool = pool(4, 2);
    let after = pool.install_in(Placement::Local(1), || {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            pool.install_in(Placement::Wide { near: 0 }, || panic!("wide"))
        }));
        assert_eq!(result.map_err(message), Err(Some("wide")));
        placement(&pool)
    });
    assert_eq!(after, Some(Placement::Local(1)));
}

/// Join runs its second closure under the placement it was pushed under, whether the joining
/// worker pops it after its first closure returns or takes it while it waits inside a nested
/// install of the other placement.
#[test]
fn join_runs_its_second_closure_under_the_placement_it_was_pushed_under() {
    // Groups of one worker, so a pushed local job runs only on the worker that pushed it.
    let pool = pool(2, 1);
    let (_, popped) = pool.install_in(Placement::Local(0), || {
        join(
            || pool.install_in(Placement::Wide { near: 0 }, || placement(&pool)),
            || placement(&pool),
        )
    });
    assert_eq!(popped, Some(Placement::Local(0)));

    // The first closure joins on the whole pool, where the other group's worker steals the
    // nested second closure. That closure holds the nested join open until the outer second
    // closure has run, so the joining worker must take the outer one from its local deque while
    // it waits inside the wide install.
    let stolen = AtomicBool::new(false);
    let outer_ran = AtomicBool::new(false);
    let (_, taken) = pool.install_in(Placement::Local(0), || {
        join(
            || {
                pool.install_in(Placement::Wide { near: 0 }, || {
                    join(
                        || wait_until("the other group steals", || stolen.load(Ordering::SeqCst)),
                        || {
                            stolen.store(true, Ordering::SeqCst);
                            wait_until("the outer second closure runs", || {
                                outer_ran.load(Ordering::SeqCst)
                            });
                        },
                    )
                })
            },
            || {
                let observed = pool
                    .current_worker()
                    .map(|worker| (worker.placement, worker.index));
                outer_ran.store(true, Ordering::SeqCst);
                observed
            },
        )
    });
    assert_eq!(taken, Some((Placement::Local(0), 0)));
}

/// Every job of a tree installed on a group runs on that group's workers, while every group
/// runs such a tree and jobs placed on the whole pool keep the workers searching.
#[test]
fn local_jobs_run_only_on_their_group() {
    const GROUPS: usize = 4;
    const LEAVES: usize = 10_000;
    let pool = pool(2 * GROUPS, 2);
    let stop = AtomicBool::new(false);
    let strays = AtomicUsize::new(0);
    let leaves = AtomicUsize::new(0);
    thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                pool.install_in(Placement::Wide { near: 0 }, || {
                    tree(0..256, &|_| spin(Duration::from_micros(5)));
                });
            }
        });
        let trees: Vec<_> = (0..GROUPS)
            .map(|group| {
                let (pool, strays, leaves) = (&pool, &strays, &leaves);
                scope.spawn(move || {
                    pool.install_in(Placement::Local(group), || {
                        tree(0..LEAVES, &|_| {
                            spin(Duration::from_micros(1));
                            let worker = pool
                                .current_worker()
                                .map(|worker| (worker.group, worker.placement));
                            if worker != Some((group, Placement::Local(group))) {
                                strays.fetch_add(1, Ordering::Relaxed);
                            }
                            leaves.fetch_add(1, Ordering::Relaxed);
                        });
                    });
                })
            })
            .collect();
        for handle in trees {
            handle.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
    });
    assert_eq!(leaves.into_inner(), GROUPS * LEAVES);
    assert_eq!(strays.into_inner(), 0, "local jobs ran outside their group");
}

/// A tree of jobs installed on the whole pool of an idle pool spreads over every group.
#[test]
fn wide_jobs_spread_over_every_group() {
    let pool = pool(8, 2);
    wait_until_asleep(&pool);
    let seen = Mutex::new(HashSet::new());
    pool.install_in(Placement::Wide { near: 0 }, || {
        tree(0..64, &|_| {
            thread::sleep(Duration::from_millis(2));
            seen.lock()
                .insert(pool.current_worker().map(|worker| worker.group));
        });
    });
    let groups: HashSet<_> = (0..4).map(Some).collect();
    assert_eq!(seen.into_inner(), groups);
}

/// A job placed on a group whose workers all sleep wakes one of them and runs promptly, and no
/// worker of another group wakes for it.
#[test]
fn a_local_job_wakes_only_its_group() {
    let pool = pool(8, 2);
    wait_until_asleep(&pool);
    let before = pool.wakeups();
    let (tx, rx) = mpsc::channel();
    let started = Instant::now();
    pool.spawn_in(Placement::Local(3), move || tx.send(()).unwrap());
    rx.recv_timeout(Duration::from_secs(5))
        .expect("a sleeping group must wake for its job");
    let elapsed = started.elapsed();
    let after = pool.wakeups();
    assert_eq!(
        before[..6],
        after[..6],
        "another group woke for a local job"
    );
    assert!(after[6..].iter().sum::<usize>() > before[6..].iter().sum::<usize>());
    assert!(elapsed < Duration::from_secs(1), "woke after {elapsed:?}");
}

/// A job placed on the whole pool of a sleeping pool is offered to the group it names first, so
/// that group wakes for it and runs it, and no group before it in index order wakes.
#[test]
fn a_wide_job_wakes_its_near_group_first() {
    let pool = Arc::new(pool(6, 2));
    wait_until_asleep(&pool);
    let before = pool.wakeups();
    let (tx, rx) = mpsc::channel();
    let runner = Arc::clone(&pool);
    pool.spawn_in(Placement::Wide { near: 2 }, move || {
        tx.send(runner.current_worker().map(|worker| worker.group))
            .unwrap()
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(Some(2)));
    let after = pool.wakeups();
    assert_eq!(before[..4], after[..4], "a farther group woke first");
}

/// A worker running a job placed on the whole pool, which installs on its own group and joins
/// there, helps the group-mate that took its second closure. The mate blocks until its own
/// nested second closure starts, which only the waiting worker can take. The waiting worker
/// waits under its group's placement here.
#[test]
fn a_wide_job_waiting_on_its_groups_local_job_helps_its_mate() {
    let pool = Arc::new(pool(4, 2));
    within(move || {
        pool.install_in(Placement::Wide { near: 0 }, || {
            let group = pool.current_worker().unwrap().group;
            pool.install_in(Placement::Local(group), || {
                let mate_started = AtomicBool::new(false);
                let nested_started = AtomicBool::new(false);
                join(
                    || {
                        wait_until("the mate takes the second closure", || {
                            mate_started.load(Ordering::SeqCst)
                        })
                    },
                    || {
                        mate_started.store(true, Ordering::SeqCst);
                        join(
                            || {
                                wait_until("the waiting worker takes the nested closure", || {
                                    nested_started.load(Ordering::SeqCst)
                                })
                            },
                            || nested_started.store(true, Ordering::SeqCst),
                        )
                    },
                );
            });
        });
    });
}

/// A worker running a local job that waits on a child placed on the whole pool, which a worker
/// of another group stole, runs the work the thief waits on. The waiting worker waits under the
/// whole pool's placement here.
#[test]
fn a_local_job_waiting_on_a_stolen_wide_child_helps_the_thief() {
    // Groups of one worker, so only the waiting worker can take what the thief waits on.
    let pool = Arc::new(pool(2, 1));
    within(move || {
        pool.install_in(Placement::Local(0), || {
            pool.install_in(Placement::Wide { near: 0 }, || {
                let thief_started = AtomicBool::new(false);
                let nested_started = AtomicBool::new(false);
                join(
                    || {
                        wait_until("the other group steals", || {
                            thief_started.load(Ordering::SeqCst)
                        })
                    },
                    || {
                        thief_started.store(true, Ordering::SeqCst);
                        join(
                            || {
                                wait_until("the waiting worker takes the nested closure", || {
                                    nested_started.load(Ordering::SeqCst)
                                })
                            },
                            || nested_started.store(true, Ordering::SeqCst),
                        )
                    },
                );
            });
        });
    });
}

/// Joins under `outer` on a pool of two workers in one group. The other worker steals the second
/// closure and joins again under `inner`, then blocks until its own nested second closure starts,
/// which only the worker waiting under `outer` can take. Returns the worker the nested closure ran
/// on, as it saw itself there, and the waiting worker.
fn help_across_placements(outer: Placement, inner: Placement) -> (Option<Worker>, Option<Worker>) {
    let pool = Arc::new(pool(2, 2));
    within(move || {
        pool.install_in(outer, || {
            let taken = AtomicBool::new(false);
            let nested_started = AtomicBool::new(false);
            let ((), nested) = join(
                || {
                    wait_until("the peer takes the second closure", || {
                        taken.load(Ordering::SeqCst)
                    })
                },
                || {
                    taken.store(true, Ordering::SeqCst);
                    pool.install_in(inner, || {
                        join(
                            || {
                                wait_until("the waiting worker takes the nested closure", || {
                                    nested_started.load(Ordering::SeqCst)
                                })
                            },
                            || {
                                nested_started.store(true, Ordering::SeqCst);
                                pool.current_worker()
                            },
                        )
                        .1
                    })
                },
            );
            (nested, pool.current_worker())
        })
    })
}

/// A worker waiting under the whole pool's placement takes a group-mate's local job that the
/// mate waits on, since its search does not depend on its placement.
#[test]
fn a_worker_waiting_under_wide_takes_a_mates_local_job() {
    let (nested, waiter) = help_across_placements(Placement::Wide { near: 0 }, Placement::Local(0));
    assert_eq!(
        nested.map(|worker| worker.placement),
        Some(Placement::Local(0))
    );
    assert_eq!(
        nested.map(|worker| worker.index),
        waiter.map(|worker| worker.index)
    );
}

/// A worker waiting under its group's placement takes a group-mate's wide job that the mate
/// waits on, since its search does not depend on its placement.
#[test]
fn a_worker_waiting_under_local_takes_a_mates_wide_job() {
    let (nested, waiter) = help_across_placements(Placement::Local(0), Placement::Wide { near: 0 });
    assert_eq!(
        nested.map(|worker| worker.placement),
        Some(Placement::Wide { near: 0 })
    );
    assert_eq!(
        nested.map(|worker| worker.index),
        waiter.map(|worker| worker.index)
    );
}

/// A small deterministic generator for the shape of a random job tree.
const fn mix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// What a random job tree counts: jobs still detached, and jobs that ran under the wrong
/// placement.
#[derive(Default)]
struct Counts {
    pending: AtomicUsize,
    strays: AtomicUsize,
}

/// Runs one node of a random job tree, checking that it runs under `expected`, and submits its
/// children with placements and kinds drawn from `seed`.
fn node(pool: &Arc<ThreadPool>, counts: &Arc<Counts>, expected: Placement, seed: u64, depth: u32) {
    let current = placement(pool).expect("a node runs on a worker");
    let as_expected = match expected {
        Placement::Local(_) => current == expected,
        Placement::Wide { .. } => matches!(current, Placement::Wide { .. }),
    };
    if !as_expected {
        counts.strays.fetch_add(1, Ordering::Relaxed);
    }
    let roll = mix(seed);
    if depth == 0 {
        spin(Duration::from_micros(roll % 20));
        return;
    }
    let groups = pool.group_widths().len();
    let choice = usize::try_from(roll >> 40).unwrap() % (groups + 1);
    let placement = if choice == groups {
        Placement::Wide {
            near: usize::try_from(roll >> 20).unwrap() % groups,
        }
    } else {
        Placement::Local(choice)
    };
    let (left, right) = (mix(seed ^ 1), mix(seed ^ 2));
    match roll % 4 {
        0 => {
            join(
                || node(pool, counts, current, left, depth - 1),
                || node(pool, counts, current, right, depth - 1),
            );
        }
        1 => pool.install_in(placement, || node(pool, counts, placement, left, depth - 1)),
        kind => {
            // A spawn runs under the placement it names: the one drawn above, or the worker's own.
            let spawned = if kind == 2 { placement } else { current };
            counts.pending.fetch_add(1, Ordering::SeqCst);
            let (job_pool, job_counts) = (Arc::clone(pool), Arc::clone(counts));
            pool.spawn_in(spawned, move || {
                node(&job_pool, &job_counts, spawned, left, depth - 1);
                job_counts.pending.fetch_sub(1, Ordering::SeqCst);
            });
            node(pool, counts, current, right, depth - 1);
        }
    }
}

/// Random mixes of joins, installs, and spawns placed on groups and on the whole pool, made from
/// workers and from outside the pool, all complete, every job runs under its placement, and the
/// pool's workers stop once the last job ran after the pool was dropped.
#[test]
fn random_placements_all_complete() {
    for round in 0..20u64 {
        let pool = Arc::new(pool(6, 2));
        let registry = Arc::clone(pool.registry());
        let counts = Arc::new(Counts::default());
        let mut rng = TestRng::new(round);
        let roots: Vec<(Placement, u64)> = (0..8)
            .map(|_| {
                let placement = match rng.random_range(0..4usize) {
                    3 => Placement::Wide {
                        near: rng.random_range(0..3),
                    },
                    group => Placement::Local(group),
                };
                (placement, rng.random_range(0..u64::MAX))
            })
            .collect();
        thread::scope(|scope| {
            for &(placement, seed) in &roots {
                let (pool, counts) = (&pool, &counts);
                scope.spawn(move || {
                    if seed % 2 == 0 {
                        pool.install_in(placement, || node(pool, counts, placement, seed, 6));
                    } else {
                        counts.pending.fetch_add(1, Ordering::SeqCst);
                        let (job_pool, job_counts) = (Arc::clone(pool), Arc::clone(counts));
                        pool.spawn_in(placement, move || {
                            node(&job_pool, &job_counts, placement, seed, 6);
                            job_counts.pending.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                });
            }
        });
        drop(pool);
        wait_until("every detached job ran", || {
            counts.pending.load(Ordering::SeqCst) == 0
        });
        registry.wait_until_stopped();
        assert_eq!(counts.strays.load(Ordering::SeqCst), 0, "round {round}");
    }
}

/// A thread taken over as a pool's first worker runs its own code under the whole pool's
/// placement, installs on its own group inline and on other groups through their workers, and
/// is the only worker that takes the jobs placed on its group of one.
#[test]
fn a_taken_over_thread_keeps_its_groups_jobs() {
    let pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(3)
            .group_width(1)
            .use_current_thread()
            .build()
            .unwrap(),
    );
    assert_eq!(pool.current_worker().map(|worker| worker.group), Some(0));
    assert_eq!(placement(&pool), Some(Placement::Wide { near: 0 }));
    assert_eq!(
        pool.install_in(Placement::Local(0), || placement(&pool)),
        Some(Placement::Local(0))
    );
    assert_eq!(
        pool.install_in(Placement::Local(2), || {
            pool.current_worker().map(|worker| worker.group)
        }),
        Some(2)
    );

    // Jobs placed on the taken-over thread's group wait for it, whoever places them.
    let ran = Arc::new(AtomicUsize::new(0));
    let job = |ran: &Arc<AtomicUsize>| {
        let ran = Arc::clone(ran);
        move || {
            ran.fetch_add(1, Ordering::SeqCst);
        }
    };
    pool.spawn_in(Placement::Local(0), job(&ran));
    thread::scope(|scope| {
        scope.spawn(|| pool.spawn_in(Placement::Local(0), job(&ran)));
    });
    thread::sleep(Duration::from_millis(50));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(yield_now(), Some(Yield::Executed));
    assert_eq!(yield_now(), Some(Yield::Executed));
    assert_eq!(ran.load(Ordering::SeqCst), 2);

    // A job it places on the whole pool is taken by the other workers.
    pool.spawn_in(Placement::Wide { near: 0 }, job(&ran));
    wait_until("another worker takes the wide job", || {
        ran.load(Ordering::SeqCst) == 3
    });
}

/// Jobs still queued for a group or for the whole pool when the pool is dropped all run before
/// the workers stop.
#[test]
fn dropping_a_pool_runs_the_jobs_queued_on_its_groups() {
    let ran = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let registry;
    {
        let pool = pool(4, 2);
        registry = Arc::clone(pool.registry());

        // Hold every worker, so the jobs below stay queued.
        let (held_tx, held_rx) = mpsc::channel();
        for group in [0, 0, 1, 1] {
            let (held_tx, release) = (held_tx.clone(), Arc::clone(&release));
            pool.spawn_in(Placement::Local(group), move || {
                held_tx.send(()).unwrap();
                while !release.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
            });
        }
        for _ in 0..4 {
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        for placement in [
            Placement::Local(0),
            Placement::Local(1),
            Placement::Wide { near: 1 },
        ] {
            for _ in 0..10 {
                let ran = Arc::clone(&ran);
                pool.spawn_in(placement, move || {
                    ran.fetch_add(1, Ordering::SeqCst);
                });
            }
        }
    }
    release.store(true, Ordering::SeqCst);
    registry.wait_until_stopped();
    assert_eq!(ran.load(Ordering::SeqCst), 30);
}

/// A panic in an operation installed under either placement reaches the installing thread, from
/// outside the pool, from a worker that runs the operation itself, and from a worker of another
/// group.
#[test]
fn installs_propagate_panics_under_either_placement() {
    let pool = pool(4, 2);
    for placement in [Placement::Local(1), Placement::Wide { near: 1 }] {
        let outside = panic::catch_unwind(AssertUnwindSafe(|| {
            pool.install_in(placement, || panic!("placed"))
        }));
        assert_eq!(outside.map_err(message), Err(Some("placed")));
    }
    let from_worker = pool.install_in(Placement::Local(0), || {
        [
            Placement::Local(0),
            Placement::Wide { near: 0 },
            Placement::Local(1),
        ]
        .map(|placement| {
            panic::catch_unwind(AssertUnwindSafe(|| {
                pool.install_in(placement, || panic!("nested"))
            }))
            .map_err(message)
        })
    });
    assert_eq!(from_worker, [Err(Some("nested")); 3]);
}

/// Installs that cross between two groups of one worker each and back complete. Each waiting
/// worker takes the install placed back on its group from its group's injector, since no other
/// worker may.
#[test]
fn installs_across_groups_of_one_pool_and_back_complete() {
    let pool = Arc::new(pool(2, 1));
    let ran = within(move || {
        pool.install_in(Placement::Local(0), || {
            pool.install_in(Placement::Local(1), || {
                let there = pool
                    .current_worker()
                    .map(|worker| (worker.group, worker.index));
                let back = pool.install_in(Placement::Local(0), || {
                    pool.current_worker()
                        .map(|worker| (worker.group, worker.index))
                });
                (there, back)
            })
        })
    });
    assert_eq!(ran, (Some((1, 1)), Some((0, 0))));
}

/// A worker of another pool that installs on a group gets the operation run by that group, and
/// keeps running its own pool's jobs while it waits. The operation here installs back on the
/// caller's pool, whose only worker is the waiting caller.
#[test]
fn a_foreign_worker_installs_on_a_group() {
    let caller = Arc::new(pool(1, 1));
    let target = Arc::new(pool(4, 2));
    let result = within(move || {
        caller.install_in(Placement::Wide { near: 0 }, || {
            target.install_in(Placement::Local(1), || {
                let back = caller.install_in(Placement::Wide { near: 0 }, || {
                    caller.current_worker().map(|worker| worker.index)
                });
                (
                    target.current_worker().map(|worker| worker.group),
                    caller.current_worker(),
                    back,
                )
            })
        })
    });
    assert_eq!(result, (Some(1), None, Some(0)));
}

/// A broadcast on a group runs once on each of its workers, under the group's placement.
#[test]
fn group_broadcasts_reach_only_their_group() {
    let pool = Arc::new(pool(5, 2));
    let mut seen = pool.broadcast_in(1, || {
        pool.current_worker()
            .map(|worker| (worker.index, worker.placement))
    });
    seen.sort_unstable_by_key(|worker| worker.map(|(index, _)| index));
    assert_eq!(
        seen,
        [
            Some((2, Placement::Local(1))),
            Some((3, Placement::Local(1)))
        ]
    );

    let ran = Arc::new(Mutex::new(Vec::new()));
    let (runner, record) = (Arc::clone(&pool), Arc::clone(&ran));
    pool.spawn_broadcast_in(2, move || {
        record.lock().push(
            runner
                .current_worker()
                .map(|worker| (worker.index, worker.group)),
        );
    });
    wait_until("the broadcast runs", || !ran.lock().is_empty());
    thread::sleep(Duration::from_millis(20));
    assert_eq!(*ran.lock(), [Some((4, 2))]);
}

/// A job spawned from a thread outside the pool runs under the placement the spawn names: on the
/// workers of the group it names, or on any worker under the whole pool's placement.
#[test]
fn a_spawn_from_outside_the_pool_runs_under_the_placement_it_names() {
    let pool = Arc::new(pool(4, 2));
    let ran = Arc::new(Mutex::new(Vec::new()));
    let record = || {
        let (pool, ran) = (Arc::clone(&pool), Arc::clone(&ran));
        move || {
            ran.lock().push(
                pool.current_worker()
                    .map(|worker| (worker.placement, worker.group)),
            );
        }
    };

    for _ in 0..8 {
        pool.spawn_in(Placement::Local(1), record());
    }
    wait_until("the spawns on group 1 run", || ran.lock().len() == 8);
    assert_eq!(*ran.lock(), vec![Some((Placement::Local(1), 1)); 8]);

    ran.lock().clear();
    for _ in 0..8 {
        pool.spawn_in(Placement::Wide { near: 1 }, record());
        pool.spawn_in(Placement::Wide { near: 0 }, record());
    }
    wait_until("the spawns on the whole pool run", || {
        ran.lock().len() == 16
    });
    let placements: Vec<_> = ran
        .lock()
        .iter()
        .map(|worker| worker.map(|(placement, _)| placement))
        .collect();
    assert!(
        placements
            .iter()
            .all(|placement| matches!(placement, Some(Placement::Wide { .. }))),
        "{placements:?}"
    );
}

/// A worker that spawns under the placement of the job it runs pushes the jobs onto its own
/// deque, as it pushes the second closures of its joins, so a worker with no one to steal them
/// runs them last in, first out, under either placement.
#[test]
fn a_spawn_under_the_workers_placement_pushes_onto_its_deque() {
    let pool = pool(1, 1);
    for placement in [Placement::Local(0), Placement::Wide { near: 0 }] {
        // Spawn from the only worker under the placement of the job it runs
        let (tx, rx) = mpsc::channel();
        pool.install_in(placement, || {
            let own = pool.current_worker().unwrap().placement;
            for i in 0..10 {
                let tx = tx.clone();
                pool.spawn_in(own, move || tx.send(i).unwrap());
            }
        });
        drop(tx);

        // The worker pops its deque from the end it pushed to
        let order: Vec<_> = rx.iter().collect();
        assert_eq!(order, (0..10).rev().collect::<Vec<_>>(), "{placement:?}");
    }
}
