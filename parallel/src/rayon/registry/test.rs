//! Tests for the groups of a pool's workers and the placement of jobs among them.

use super::Placement;
use crate::rayon::{
    ThreadPool, ThreadPoolBuilder, WorkerPosition, Yield, join, placement_width,
    sleep::with_sleep_notification, spin, thread_pool::Worker, yield_now,
};
use commonware_utils::{NZUsize, TestRng, Widen, sync::Mutex};
use rand::RngExt as _;
use std::{
    any::Any,
    cell::RefCell,
    collections::HashSet,
    ops::Range,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

/// A pool of `threads` workers in groups of `width`.
fn pool(threads: usize, width: usize) -> ThreadPool {
    ThreadPoolBuilder::new(NZUsize!(threads))
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
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("the scenario must finish within 30 seconds")
        }
    }
}

/// Waits up to ten seconds for `done` to hold.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "condition must hold within 10 seconds: {what}"
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

/// Workers form consecutive groups of the configured width, with a narrower last group when
/// needed. A pool built without a width, or with a width of 0 or at least the thread count, is one
/// group.
#[test]
fn workers_form_consecutive_groups() {
    // Seven workers in groups of three form groups of 3, 3, and 1, and worker i is in group i / 3.
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

    // A width of 0, a width of at least the thread count, and no width each form one group.
    for width in [0, 4, 9] {
        assert_eq!(self::pool(4, width).group_widths(), [4]);
    }
    let default = ThreadPoolBuilder::new(NZUsize!(4)).build().unwrap();
    assert_eq!(default.group_widths(), [4]);
}

/// The thread name closure and the start handler receive each worker's index, group, and offset
/// in its group, with the last group narrower when the width does not divide the thread count.
#[test]
fn thread_names_see_worker_positions() {
    let named = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(Mutex::new(Vec::new()));
    let (name_seen, start_seen) = (Arc::clone(&named), Arc::clone(&started));
    let pool = ThreadPoolBuilder::new(NZUsize!(5))
        .group_width(2)
        .thread_name(move |worker| {
            name_seen.lock().push(worker);
            format!("g{}-{}", worker.group, worker.offset)
        })
        .start_handler(move |worker| start_seen.lock().push(worker))
        .build()
        .unwrap();
    let names = pool.broadcast(|_| thread::current().name().map(str::to_owned));
    let expected: Vec<_> = (0..5)
        .map(|index| WorkerPosition {
            index,
            group: index / 2,
            offset: index % 2,
        })
        .collect();
    for positions in [&named, &started] {
        let mut positions = positions.lock().clone();
        positions.sort_by_key(|worker| worker.index);
        assert_eq!(positions, expected);
    }
    assert_eq!(
        names,
        ["g0-0", "g0-1", "g1-0", "g1-1", "g2-0"].map(|name| Some(name.to_owned()))
    );
}

/// A worker reports its group's width under a Local placement, including a narrower last
/// group. Under a Wide placement, it reports the whole pool's width.
#[commonware_macros::test_group("miri")]
#[test]
fn workers_report_placement_width() {
    let pool = pool(5, 2);
    let width = |placement| {
        pool.install_in(placement, || {
            let worker = pool.current_worker().unwrap();
            assert_eq!(worker.width, placement_width());
            worker.width
        })
    };

    // A Local placement spans its group, and the last group has the one worker left over.
    assert_eq!(width(Placement::Local(0)), 2);
    assert_eq!(width(Placement::Local(2)), 1);

    // A Wide placement spans every worker, whichever group it names.
    assert_eq!(width(Placement::Wide { near: 2 }), 5);
}

/// An install runs its operation under the requested placement and restores the previous
/// placement on return. A job spawned with the worker's current placement runs under that
/// placement too.
#[commonware_macros::test_group("miri")]
#[test]
fn install_restores_previous_placement() {
    let pool = Arc::new(pool(4, 2));

    // A Wide install from outside the pool runs its operation under a Wide placement.
    assert!(matches!(
        pool.install_in(Placement::Wide { near: 0 }, || placement(&pool)),
        Some(Placement::Wide { .. })
    ));

    // A nested Wide install must restore the outer Local placement before that placement is
    // passed to a spawned job.
    let observed = pool.install_in(Placement::Local(1), || {
        let local = placement(&pool);
        let wide = pool.install_in(Placement::Wide { near: 0 }, || placement(&pool));
        let restored = placement(&pool);
        let (tx, rx) = mpsc::channel();
        let spawner = Arc::clone(&pool);
        pool.spawn_in(restored.unwrap(), move || {
            tx.send(placement(&spawner)).unwrap();
        });

        // Yield rather than block, so the spawned job can run on this worker if no other worker
        // takes it.
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
#[commonware_macros::test_group("miri")]
#[test]
fn install_panic_restores_previous_placement() {
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
#[commonware_macros::test_group("miri")]
#[test]
fn join_retains_queued_closure_placement() {
    // Groups of one worker, so a pushed Local job runs only on the worker that pushed it.
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
    // closure has run, so the joining worker must take the outer one from its Local deque while
    // it waits inside the Wide install.
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
fn local_jobs_stay_on_group() {
    const GROUPS: usize = 4;
    const LEAVES: usize = 10_000;
    let pool = pool(2 * GROUPS, 2);
    let stop = AtomicBool::new(false);
    let strays = AtomicUsize::new(0);
    let leaves = AtomicUsize::new(0);
    thread::scope(|scope| {
        // Keep the whole pool searching with trees placed on the whole pool.
        scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                pool.install_in(Placement::Wide { near: 0 }, || {
                    tree(0..256, &|_| spin(Duration::from_micros(5)));
                });
            }
        });

        // A tree per group, each leaf checking that it runs on a worker of its group under the
        // Local placement.
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

    // Every leaf ran, and none on another group.
    assert_eq!(leaves.into_inner(), GROUPS * LEAVES);
    assert_eq!(
        strays.into_inner(),
        0,
        "local jobs must run only on their group"
    );
}

/// On an idle pool, a tree of jobs installed on the whole pool spreads over every group.
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
fn local_jobs_wake_only_own_group() {
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
        "no other group may wake for a local job"
    );
    assert!(after[6..].iter().sum::<usize>() > before[6..].iter().sum::<usize>());
    assert!(
        elapsed < Duration::from_secs(1),
        "the group must wake within a second, woke after {elapsed:?}"
    );
}

/// While every worker sleeps, a job placed on the whole pool is offered to the group it names
/// first, so that group wakes for it and runs it, and no group before it in index order wakes.
#[test]
fn wide_jobs_wake_near_group_first() {
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
    assert_eq!(
        before[..4],
        after[..4],
        "groups before the near group must remain asleep"
    );
}

/// A worker running a Wide job installs a Local job on its own group and joins there. Its
/// group-mate takes the second closure and blocks until a nested closure starts. Only the
/// waiting worker can take that nested closure, and it helps under its group's Local placement.
#[test]
fn wide_jobs_help_local_children() {
    let pool = Arc::new(pool(4, 2));
    within(move || {
        pool.install_in(Placement::Wide { near: 0 }, || {
            // From the Wide job, install on the worker's own group and join there.
            let group = pool.current_worker().unwrap().group;
            pool.install_in(Placement::Local(group), || {
                let mate_started = AtomicBool::new(false);
                let nested_started = AtomicBool::new(false);

                // The first closure waits for the mate, so the mate must take the second.
                join(
                    || {
                        wait_until("the mate takes the second closure", || {
                            mate_started.load(Ordering::SeqCst)
                        })
                    },
                    || {
                        mate_started.store(true, Ordering::SeqCst);

                        // The mate's join needs the waiting worker to take the nested closure.
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

/// A worker running a Local job installs a Wide job and joins there. A worker of another group
/// steals the second closure and blocks until a nested closure starts. The waiting worker helps
/// by running that nested closure under the Wide placement.
#[test]
fn local_jobs_help_stolen_wide_children() {
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
/// closure and joins again under `inner`, then blocks until its nested second closure starts. Only
/// the worker waiting under `outer` can take it.
///
/// Checks that helping executes the closure once and restores the waiting worker's outer placement.
/// Returns the worker's state during the nested closure and after the outer join.
fn help_across_placements(outer: Placement, inner: Placement) -> (Option<Worker>, Option<Worker>) {
    // Sharing a group lets the waiting worker help under either Local or Wide placement.
    let pool = Arc::new(pool(2, 2));
    within(move || {
        pool.install_in(outer, || {
            // Keep the waiter in the outer join until its peer takes the second closure.
            let taken = AtomicBool::new(false);
            let nested_started = AtomicBool::new(false);
            let nested_runs = AtomicUsize::new(0);
            let ((), nested) = join(
                || {
                    wait_until("the peer takes the second closure", || {
                        taken.load(Ordering::SeqCst)
                    })
                },
                || {
                    // The thief holds its inner join open until the waiter starts the
                    // nested closure, so neither worker can finish without that help.
                    taken.store(true, Ordering::SeqCst);
                    pool.install_in(inner, || {
                        join(
                            || {
                                wait_until("the waiting worker takes the nested closure", || {
                                    nested_started.load(Ordering::SeqCst)
                                })
                            },
                            || {
                                // Observe the helped job's placement before the outer one is
                                // restored.
                                nested_runs.fetch_add(1, Ordering::SeqCst);
                                nested_started.store(true, Ordering::SeqCst);
                                pool.current_worker()
                            },
                        )
                        .1
                    })
                },
            );

            // Both joins have finished, so the helper must have restored the outer placement.
            assert_eq!(nested_runs.load(Ordering::SeqCst), 1);
            assert_eq!(placement(&pool), Some(outer));
            (nested, pool.current_worker())
        })
    })
}

/// A worker waiting under the whole pool's placement takes a group-mate's Local job that the
/// mate waits on, since its search does not depend on its placement.
#[commonware_macros::test_group("miri")]
#[test]
fn wide_waiters_take_local_jobs() {
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

/// A worker waiting under its group's placement takes a group-mate's Wide job that the mate
/// waits on, since its search does not depend on its placement.
#[commonware_macros::test_group("miri")]
#[test]
fn local_waiters_take_wide_jobs() {
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
    // Count a stray when the node runs outside its expected placement. A Wide node may run near
    // any group.
    let current = placement(pool).expect("a node must run on a worker");
    let as_expected = match expected {
        Placement::Local(_) => current == expected,
        Placement::Wide { .. } => matches!(current, Placement::Wide { .. }),
    };
    if !as_expected {
        counts.strays.fetch_add(1, Ordering::Relaxed);
    }

    // A leaf spins briefly. An inner node draws a placement for its install or spawn, either one
    // group or the whole pool.
    let roll = mix(seed);
    if depth == 0 {
        spin(Duration::from_micros(roll % 20));
        return;
    }
    let groups = pool.group_widths().len();
    let choice = usize::try_from(roll >> 40).unwrap() % (groups + 1);
    let placement = if choice == groups {
        Placement::Wide {
            near: usize::try_from((roll >> 20) % u64::try_from(groups).unwrap()).unwrap(),
        }
    } else {
        Placement::Local(choice)
    };

    // A join runs both children under the node's own placement, an install runs one child under
    // the drawn placement, and a spawn detaches one child and runs the other in place.
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

/// Random mixes of joins, installs, and spawns from workers and outside threads must all
/// complete under their requested placements. After the pool is dropped, its workers must
/// finish the remaining jobs and stop.
#[test]
fn random_placements_complete() {
    for round in 0..20u64 {
        let pool = Arc::new(pool(6, 2));
        let registry = Arc::clone(pool.registry());
        let counts = Arc::new(Counts::default());
        let mut rng = TestRng::new(round);

        // Eight random roots, each a Local or Wide placement with a seed for its job tree.
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

        // Start each root from its own thread, installing even seeds and spawning odd seeds.
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

        // Release the test's handle to the pool. Its workers must still run every detached job and
        // then stop.
        drop(pool);
        wait_until("every detached job ran", || {
            counts.pending.load(Ordering::SeqCst) == 0
        });
        registry.wait_until_stopped();
        assert_eq!(
            counts.strays.load(Ordering::SeqCst),
            0,
            "every job must run under its requested placement in round {round}"
        );
    }
}

/// A thread registered as a pool's first worker starts under a Wide placement. It runs installs
/// on its own group inline and queues installs on other groups for their workers. No other
/// worker can take jobs placed on this thread's group of one.
#[test]
fn taken_over_thread_keeps_local_jobs() {
    // The taken-over thread starts under a Wide placement and runs each install on the group it
    // names.
    let pool = Arc::new(
        ThreadPoolBuilder::new(NZUsize!(3))
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
#[commonware_macros::test_group("miri")]
#[test]
fn pool_drop_runs_queued_jobs() {
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

    // Dropping the pool leaves all 30 jobs queued behind the held workers. Once released, the
    // workers must run every one before they stop.
    release.store(true, Ordering::SeqCst);
    registry.wait_until_stopped();
    assert_eq!(ran.load(Ordering::SeqCst), 30);
}

/// A panic in an operation installed under either placement reaches the installing thread, from
/// outside the pool, from a worker that runs the operation itself, and from a worker of another
/// group.
#[test]
fn install_propagates_panics_across_placements() {
    let pool = pool(4, 2);

    // An install from outside the pool, under either placement.
    for placement in [Placement::Local(1), Placement::Wide { near: 1 }] {
        let outside = panic::catch_unwind(AssertUnwindSafe(|| {
            pool.install_in(placement, || panic!("placed"))
        }));
        assert_eq!(outside.map_err(message), Err(Some("placed")));
    }

    // Installs from a worker of group 0: two it runs itself and one it sends to group 1.
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
#[commonware_macros::test_group("miri")]
#[test]
fn install_crosses_groups_and_returns() {
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
fn install_crosses_pools_and_returns() {
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
#[commonware_macros::test_group("miri")]
#[test]
fn broadcast_reaches_only_selected_group() {
    let pool = Arc::new(pool(5, 2));

    // A blocking broadcast on group 1 runs once on each of its two workers.
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

    // A detached broadcast on the narrower last group runs on its only worker.
    let ran = Arc::new(Mutex::new(Vec::new()));
    let (runner, record) = (Arc::clone(&pool), Arc::clone(&ran));
    pool.spawn_broadcast_in(2, move || {
        record.lock().push(
            runner
                .current_worker()
                .map(|worker| (worker.index, worker.placement)),
        );
    });

    // Per-worker broadcast order makes this wait for the selected callback and every no-op.
    pool.broadcast(|_| ());
    assert_eq!(*ran.lock(), [Some((4, Placement::Local(2)))]);
}

/// A job spawned from a thread outside the pool runs under the placement the spawn names: on the
/// workers of the group it names, or on any worker under the whole pool's placement.
#[test]
fn spawn_external_jobs_honor_placement() {
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

    // Jobs placed on group 1 run on its workers under its Local placement.
    for _ in 0..8 {
        pool.spawn_in(Placement::Local(1), record());
    }
    wait_until("the spawns on group 1 run", || ran.lock().len() == 8);
    assert_eq!(*ran.lock(), vec![Some((Placement::Local(1), 1)); 8]);

    // Jobs placed on the whole pool, near either group, run under a Wide placement.
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

/// With no deque work, injected jobs run in submission order across placements.
#[test]
fn spawn_external_jobs_keep_submission_order() {
    within(|| {
        let local = Placement::Local(0);
        let wide = Placement::Wide { near: 0 };
        let pool = pool(1, 1);
        for placements in [
            [
                local, local, local, local, local, local, local, local, local, wide,
            ],
            [wide, wide, wide, wide, wide, wide, wide, wide, wide, local],
            [
                local, wide, wide, local, local, local, wide, wide, wide, local,
            ],
        ] {
            let order = Arc::new(Mutex::new(Vec::new()));

            // Hold the only worker until every job below is queued.
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            pool.spawn_in(Placement::Local(0), move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            started_rx.recv().unwrap();
            for (index, placement) in placements.into_iter().enumerate() {
                let order = Arc::clone(&order);
                pool.spawn_in(placement, move || order.lock().push(index));
            }
            release_tx.send(()).unwrap();

            // Once released, the worker runs the jobs in the order they were queued.
            wait_until("every queued job runs", || {
                order.lock().len() == placements.len()
            });
            assert_eq!(*order.lock(), (0..placements.len()).collect::<Vec<_>>());
        }
    });
}

/// A group's incoming work follows submission order without waiting for another group's jobs.
#[test]
fn spawn_external_jobs_skip_foreign_groups() {
    within(|| {
        let pool = Arc::new(pool(2, 1));

        // Hold the only worker of each group until its release.
        let mut releases = Vec::new();
        for group in 0..2 {
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            pool.spawn_in(Placement::Local(group), move || {
                started_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
            started_rx.recv().unwrap();
            releases.push(release_tx);
        }

        // Queue jobs that alternate between the two groups and the whole pool.
        let order = Arc::new(Mutex::new(Vec::new()));
        for (index, placement) in [
            Placement::Local(1),
            Placement::Local(0),
            Placement::Wide { near: 1 },
            Placement::Local(1),
            Placement::Wide { near: 0 },
            Placement::Local(0),
        ]
        .into_iter()
        .enumerate()
        {
            let order = Arc::clone(&order);
            let runner = Arc::clone(&pool);
            pool.spawn_in(placement, move || {
                order
                    .lock()
                    .push((index, runner.current_worker().unwrap().group));
            });
        }

        // Only group 0 can run while the older jobs on group 1 remain queued.
        releases.remove(0).send(()).unwrap();
        wait_until("group 0's eligible jobs run", || order.lock().len() == 4);
        assert_eq!(*order.lock(), [(1, 0), (2, 0), (4, 0), (5, 0)]);

        // Once released, group 1 runs its own jobs in submission order.
        drop(releases);
        wait_until("group 1's jobs run", || order.lock().len() == 6);
        assert_eq!(order.lock()[4..], [(0, 1), (3, 1)]);
    });
}

/// Each worker admits an external producer's jobs in order, across both incoming queues.
#[test]
fn spawn_contended_producers_keep_submission_order() {
    within(|| {
        const JOBS: usize = 1000;
        let pool = Arc::new(pool(4, 2));

        // One producer alone, then four producers racing.
        for producers in [1, 4] {
            let order = Arc::new(Mutex::new(vec![Vec::new(); 4]));
            thread::scope(|scope| {
                // Each producer spawns jobs with random placements, and each job records which
                // worker ran it.
                for producer in 0..producers {
                    let pool = &pool;
                    let order = &order;
                    scope.spawn(move || {
                        let mut rng = TestRng::new(Widen::widen(producer));
                        for index in 0..JOBS {
                            let placement = match rng.random_range(0..4) {
                                0 => Placement::Local(0),
                                1 => Placement::Local(1),
                                near => Placement::Wide { near: near - 2 },
                            };
                            let runner = Arc::clone(pool);
                            let order = Arc::clone(order);
                            pool.spawn_in(placement, move || {
                                let worker = runner.current_worker().unwrap();
                                order.lock()[worker.index].push((producer, index));
                            });
                        }
                    });
                }
            });
            wait_until("every producer's jobs run", || {
                order.lock().iter().map(Vec::len).sum::<usize>() == producers * JOBS
            });

            // On each worker, every producer's jobs ran in the order it spawned them.
            for jobs in order.lock().iter() {
                let mut last = vec![None; producers];
                for &(producer, index) in jobs {
                    assert!(
                        last[producer].is_none_or(|previous| previous < index),
                        "producer {producer} ran job {index} after {:?}",
                        last[producer]
                    );
                    last[producer] = Some(index);
                }
            }
        }
    });
}

/// Queues a job on the whole pool from a thread taken over with `use_current_thread`, outside any
/// job, so it stays on that thread's own Wide deque while the thread runs its own code. Threads
/// outside the pool then place `injected` jobs on the group and, when `wide` is set, as many on the
/// whole pool.
///
/// Returns the position at which the other worker ran the taken-over thread's job and the labels of
/// every job in the order they ran.
fn wide_deque_order(group_width: usize, injected: usize, wide: bool) -> (usize, Vec<&'static str>) {
    within(move || {
        // The taken-over thread stays in test code while the other worker runs queued work.
        let pool = Arc::new(
            ThreadPoolBuilder::new(NZUsize!(2))
                .group_width(group_width)
                .use_current_thread()
                .build()
                .unwrap(),
        );
        let group = 1 / group_width;
        let order = Arc::new(Mutex::new(Vec::new()));
        let from_outside = |submit: Box<dyn FnOnce(&ThreadPool) + Send>| {
            let pool = Arc::clone(&pool);
            thread::spawn(move || submit(&pool)).join().unwrap();
        };

        // Hold the other worker with a job from the group's injector until every job below is
        // queued.
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        from_outside(Box::new(move |pool| {
            pool.spawn_in(Placement::Local(group), move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        }));
        started_rx.recv().unwrap();

        // Queue the taken-over thread's job on its Wide deque, then inject jobs from outside.
        {
            let order = Arc::clone(&order);
            pool.spawn(move || order.lock().push("taken over"));
        }
        {
            let order = Arc::clone(&order);
            from_outside(Box::new(move |pool| {
                for _ in 0..injected {
                    let local = Arc::clone(&order);
                    pool.spawn_in(Placement::Local(group), move || local.lock().push("local"));
                    if wide {
                        let order = Arc::clone(&order);
                        pool.spawn_in(Placement::Wide { near: group }, move || {
                            order.lock().push("wide");
                        });
                    }
                }
            }));
        }
        release_tx.send(()).unwrap();

        // Report where the taken-over thread's job ran among all the queued jobs.
        let total = injected * (1 + usize::from(wide)) + 1;
        wait_until("every queued job runs", || order.lock().len() == total);
        let order = order.lock().clone();
        let position = order
            .iter()
            .position(|label| *label == "taken over")
            .unwrap();
        (position, order)
    })
}

/// A thread taken over with `use_current_thread` that queues a job on the whole pool outside any
/// job keeps it on its own Wide deque while it runs its own code. Another worker steals it before
/// taking jobs injected on the group.
#[test]
fn wide_deque_jobs_precede_local_injections() {
    const LOCAL: usize = 8;
    for width in [1, 2] {
        let (position, order) = wide_deque_order(width, LOCAL, false);
        assert_eq!(
            position, 0,
            "the wide deque job must precede group injections: {order:?}"
        );
    }
}

/// A Wide deque job precedes injected jobs while both the group and Wide injectors have work.
#[test]
fn wide_deque_jobs_precede_mixed_injections() {
    const INJECTED: usize = 8;
    for width in [1, 2] {
        let (position, order) = wide_deque_order(width, INJECTED, true);
        assert_eq!(
            position, 0,
            "the wide deque job must precede injections: {order:?}"
        );
    }
}

/// A worker that spawns under the placement of the job it runs pushes the jobs onto its own
/// deque, as it pushes the second closures of its joins, so a worker with no one to steal them
/// runs them last in, first out, under either placement.
#[test]
fn spawn_current_placement_uses_worker_deque() {
    let pool = pool(1, 1);
    for placement in [Placement::Local(0), Placement::Wide { near: 0 }] {
        // Spawn from the only worker under the placement of the job it runs.
        let (tx, rx) = mpsc::channel();
        pool.install_in(placement, || {
            let own = pool.current_worker().unwrap().placement;
            for i in 0..10 {
                let tx = tx.clone();
                pool.spawn_in(own, move || tx.send(i).unwrap());
            }
        });
        drop(tx);

        // The worker pops its deque from the end it pushed to.
        let order: Vec<_> = rx.iter().collect();
        assert_eq!(order, (0..10).rev().collect::<Vec<_>>(), "{placement:?}");
    }
}

/// Publishing Wide work continues past a group whose workers are all occupied.
#[test]
fn wide_work_wakes_past_busy_group() {
    within(|| {
        // Exercise injection from this thread and a push onto a worker's Wide deque, each with
        // the same occupied group.
        let woke = [WideSource::Injector, WideSource::Deque].map(|source| {
            let pool = Arc::new(pool(4, 2));
            let (held_tx, held_rx) = mpsc::channel();
            let (post_tx, post_rx) = mpsc::channel();
            let (posted_tx, posted_rx) = mpsc::channel();
            let (ran_tx, ran_rx) = mpsc::channel();
            let mut releases = Vec::new();

            // The first worker of group 0 publishes to its own Wide deque when asked. Its reply
            // confirms that publication and wake routing have finished before sampling.
            let runner = Arc::clone(&pool);
            let (release_tx, release_rx) = mpsc::channel::<()>();
            releases.push(release_tx);
            let held = held_tx.clone();
            let ran = ran_tx.clone();
            pool.spawn_in(Placement::Local(0), move || {
                held.send(()).unwrap();
                if source == WideSource::Deque {
                    post_rx.recv().unwrap();
                    runner.spawn_in(Placement::Wide { near: 0 }, move || {
                        ran.send(()).unwrap();
                    });
                    posted_tx.send(()).unwrap();
                }
                let _ = release_rx.recv();
            });

            // Occupy the other worker of group 0 until after group 1's wake count is sampled.
            let (release_tx, release_rx) = mpsc::channel::<()>();
            releases.push(release_tx);
            pool.spawn_in(Placement::Local(0), move || {
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });

            // Both callbacks broadcast to group 1 enter before either waits, so starting one
            // cannot wake the other after it reports sleeping. Their installs stay queued on
            // group 0, whose workers are held.
            for _ in 0..2 {
                held_rx.recv().unwrap();
            }
            let entered = Arc::new(Barrier::new(3));
            let (sleep_tx, sleep_rx) = mpsc::channel();
            let (waiting_pool, waiting_entered) = (Arc::clone(&pool), Arc::clone(&entered));
            pool.spawn_broadcast_in(1, move || {
                waiting_entered.wait();
                with_sleep_notification(sleep_tx.clone(), || {
                    waiting_pool.install_in(Placement::Local(0), || ());
                });
            });
            entered.wait();
            for _ in 0..2 {
                sleep_rx.recv().unwrap();
            }
            let before: usize = pool.wakeups()[2..].iter().sum();

            // Publish while group 0 is occupied. When the worker publishes from its own thread,
            // wait for its reply.
            if source == WideSource::Injector {
                pool.spawn_in(Placement::Wide { near: 0 }, move || {
                    ran_tx.send(()).unwrap();
                });
            } else {
                post_tx.send(()).unwrap();
                posted_rx.recv().unwrap();
            }

            // Sample before releasing either worker of group 0, so their later idle transitions
            // cannot supply the wakeup being checked. Then let all jobs finish.
            let after: usize = pool.wakeups()[2..].iter().sum();
            drop(releases);
            ran_rx.recv().unwrap();
            after > before
        });
        assert_eq!(
            woke,
            [true, true],
            "wide publication must wake the sleeping group"
        );
    });
}

/// A point in a worker's idle loop where a test can hold the worker while it still counts as
/// idle: before each search, after a search finds a job, or after the latch it waits on is set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WakePoint {
    BeforeSearch,
    Found,
    Resumed,
}

/// Spins its thread until released, keeping a held worker busy without entering the pool's sleep
/// protocol. It gives up after ten seconds and records the expiry, so a missed release fails the
/// test rather than hanging it.
#[derive(Default)]
struct CpuHold {
    released: AtomicBool,
    expired: AtomicBool,
}

impl CpuHold {
    /// Spins until released or expired, calling `tick` on every iteration.
    fn wait(&self, mut tick: impl FnMut()) {
        let start = Instant::now();
        while !self.released.load(Ordering::SeqCst) {
            tick();
            if start.elapsed() >= Duration::from_secs(10) {
                self.expired.store(true, Ordering::SeqCst);
                break;
            }
            std::hint::spin_loop();
        }
    }
}

/// Holds the first worker that reaches `point` after the gate is armed. Arming is consumed by
/// that worker, so the gate holds at most one worker per arming.
struct WakeGate {
    point: WakePoint,
    armed: AtomicBool,
    entered: AtomicBool,
    hold: CpuHold,
}

thread_local! {
    /// The gate the calling worker checks at each wake point, if it was given one.
    static WAKE_GATE: RefCell<Option<Arc<WakeGate>>> = const { RefCell::new(None) };
}

impl WakeGate {
    /// A gate for `point` that is not yet armed.
    fn new(point: WakePoint) -> Arc<Self> {
        Arc::new(Self {
            point,
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            hold: CpuHold::default(),
        })
    }

    /// Gives every worker of group 1 the same new gate for `point`.
    fn install(pool: &ThreadPool, point: WakePoint) -> Arc<Self> {
        let gate = Self::new(point);
        pool.broadcast_in(1, || {
            WAKE_GATE.with_borrow_mut(|slot| *slot = Some(Arc::clone(&gate)));
        });
        gate
    }
}

/// Holds the calling worker at `point` when its gate is armed for that point, and reports the
/// hold through the gate's `entered` flag.
pub(super) fn at_wake_point(point: WakePoint) {
    WAKE_GATE.with_borrow(|slot| {
        if let Some(gate) = slot
            && gate.point == point
            && gate.armed.swap(false, Ordering::SeqCst)
        {
            gate.entered.store(true, Ordering::SeqCst);
            gate.hold.wait(|| {});
        }
    });
}

/// Waits up to a second for the Wide job to set `wide`, and reports whether it did.
fn observe_wide_job(wide: &AtomicBool) -> bool {
    let start = Instant::now();
    while !wide.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(1) {
        thread::sleep(Duration::from_millis(1));
    }
    wide.load(Ordering::SeqCst)
}

/// Where a scenario queues its Wide job: in the Wide injector from a thread outside the pool, in
/// a worker's Wide deque, or nowhere, as a control.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WideSource {
    Injector,
    Deque,
    None,
}

/// Holds a worker of group 1 at `point` as it leaves the idle loop for a job placed `taken`, and
/// queues a Wide job from `source` near group 1 while every other awake worker is busy. The held
/// worker counts as idle coverage for the Wide job, so its exit must wake group 2 to run it before
/// any busy worker is released. Without a Wide job, a Local exit must not wake group 2. A resumed
/// wait always takes a Local job.
fn check_wide_handoff(point: WakePoint, source: WideSource, taken: Placement) {
    // Give group 1's workers a gate for `point` and let the whole pool fall asleep.
    let pool = Arc::new(pool(6, 2));
    let gate = WakeGate::install(&pool, point);
    wait_until_asleep(&pool);
    let before_wakes = pool.wakeups();
    let busy = Arc::new(CpuHold::default());
    let started = Arc::new(AtomicUsize::new(0));
    let resumed = Arc::new(AtomicBool::new(false));
    let wide = Arc::new(AtomicBool::new(false));
    let post = Arc::new(AtomicBool::new(false));
    let posted = Arc::new(AtomicBool::new(false));

    // This worker can publish Wide work while its group-mate is leaving the idle loop.
    {
        let (busy, started, runner, wide, post, posted) = (
            Arc::clone(&busy),
            Arc::clone(&started),
            Arc::clone(&pool),
            Arc::clone(&wide),
            Arc::clone(&post),
            Arc::clone(&posted),
        );
        pool.spawn_in(Placement::Local(1), move || {
            started.fetch_add(1, Ordering::SeqCst);
            busy.wait(|| {
                if post.swap(false, Ordering::SeqCst) {
                    let wide = Arc::clone(&wide);
                    runner.spawn_in(Placement::Wide { near: 1 }, move || {
                        wide.store(true, Ordering::SeqCst);
                    });
                    posted.store(true, Ordering::SeqCst);
                }
            });
        });
    }

    // Occupy group 0 so its workers cannot take the Wide job. A resumed wait first needs one of
    // them free to run the waiting parent's child.
    let occupy_group_zero = || {
        let (busy, started) = (Arc::clone(&busy), Arc::clone(&started));
        pool.spawn_in(Placement::Local(0), move || {
            started.fetch_add(1, Ordering::SeqCst);
            busy.wait(|| {});
        });
    };
    occupy_group_zero();
    let initial_busy = if point == WakePoint::Resumed { 2 } else { 3 };
    if initial_busy == 3 {
        occupy_group_zero();
    }
    wait_until("initial local jobs run", || {
        started.load(Ordering::SeqCst) == initial_busy
            && pool.sleeping_workers() == 6 - initial_busy
    });

    // Bring group 1's other worker to the armed wake point with Local work, still counted idle.
    if point == WakePoint::Resumed {
        // The parent waits in an install on group 0 and sleeps. Releasing the child sets the
        // parent's latch, and the gate holds the parent as it resumes. The child's worker then
        // takes a job that occupies group 0 again.
        let child = Arc::new(CpuHold::default());
        let child_started = Arc::new(AtomicBool::new(false));
        let (runner, busy, resumed, child, child_started) = (
            Arc::clone(&pool),
            Arc::clone(&busy),
            Arc::clone(&resumed),
            Arc::clone(&child),
            Arc::clone(&child_started),
        );
        let (release_child, saw_child) = (Arc::clone(&child), Arc::clone(&child_started));
        pool.spawn_in(Placement::Local(1), move || {
            runner.install_in(Placement::Local(0), || {
                child_started.store(true, Ordering::SeqCst);
                child.wait(|| {});
            });
            resumed.store(true, Ordering::SeqCst);
            busy.wait(|| {});
        });
        wait_until("the parent sleeps waiting for its child", || {
            saw_child.load(Ordering::SeqCst) && pool.sleeping_workers() == 3
        });
        gate.armed.store(true, Ordering::SeqCst);
        release_child.released.store(true, Ordering::SeqCst);
        wait_until("the parent leaves its latch wait", || {
            gate.entered.load(Ordering::SeqCst)
        });
        assert!(!release_child.expired.load(Ordering::SeqCst));
        occupy_group_zero();
        wait_until("both group-zero workers run local jobs", || {
            started.load(Ordering::SeqCst) == 3
        });
    } else {
        // A sleeping worker of group 1 wakes for the job, and the gate holds it after it finds the
        // job.
        gate.armed.store(true, Ordering::SeqCst);
        let (busy, resumed) = (Arc::clone(&busy), Arc::clone(&resumed));
        pool.spawn_in(taken, move || {
            resumed.store(true, Ordering::SeqCst);
            busy.wait(|| {});
        });
        wait_until("a worker takes the job", || {
            gate.entered.load(Ordering::SeqCst)
        });
    }

    // Queue the Wide job near group 1, so group 1 is offered it first and its held worker counts
    // as idle coverage.
    match source {
        WideSource::Injector => {
            let wide = Arc::clone(&wide);
            pool.spawn_in(Placement::Wide { near: 1 }, move || {
                wide.store(true, Ordering::SeqCst);
            });
        }
        WideSource::Deque => {
            post.store(true, Ordering::SeqCst);
            wait_until("wide work is pushed", || posted.load(Ordering::SeqCst));
        }
        WideSource::None => {}
    }

    // Release the held worker, and check whether group 2 runs the Wide job before any busy worker
    // could take it.
    gate.hold.released.store(true, Ordering::SeqCst);
    wait_until("the held worker runs its job", || {
        resumed.load(Ordering::SeqCst)
    });
    let ran_before_release = source != WideSource::None && observe_wide_job(&wide);
    let after_wakes = pool.wakeups();

    // Release the busy workers and let the pool settle before checking the outcome.
    busy.released.store(true, Ordering::SeqCst);
    if source != WideSource::None {
        wait_until("wide work completes", || wide.load(Ordering::SeqCst));
    }
    wait_until_asleep(&pool);
    assert!(!busy.expired.load(Ordering::SeqCst));
    assert!(!gate.hold.expired.load(Ordering::SeqCst));
    if source == WideSource::None {
        assert_eq!(&before_wakes[4..], &after_wakes[4..]);
    } else {
        assert!(ran_before_release, "wide work must use the sleeping group");
    }
}

/// A worker that leaves the idle loop for Local work, after finding a job or after its wait
/// resumes, passes queued Wide work on to a sleeping group, whether the job sits in the injector
/// or in a worker's deque. With no Wide work queued, it wakes no other group.
#[test]
fn wide_work_survives_local_idle_exit() {
    within(|| {
        for point in [WakePoint::Found, WakePoint::Resumed] {
            for source in [WideSource::Injector, WideSource::Deque, WideSource::None] {
                check_wide_handoff(point, source, Placement::Local(1));
            }
        }
    });
}

/// A worker that leaves the idle loop for Wide work passes other queued Wide work on to a sleeping
/// group, whether that work sits in the injector or in a worker's deque.
#[test]
fn wide_work_survives_wide_idle_exit() {
    within(|| {
        for source in [WideSource::Injector, WideSource::Deque] {
            check_wide_handoff(WakePoint::Found, source, Placement::Wide { near: 1 });
        }
    });
}

/// Workers waking for Local jobs can cover a Wide publication while still counted idle. The
/// first to leave idle must forward it even when another idle worker has selected Local work.
#[test]
fn wide_work_survives_concurrent_local_wakes() {
    within(|| {
        // Gate group 1's first worker before its search and its second after it finds a job.
        let pool = Arc::new(pool(6, 2));
        let gates = [
            WakeGate::new(WakePoint::BeforeSearch),
            WakeGate::new(WakePoint::Found),
        ];
        pool.broadcast_in(1, || {
            let offset = pool.registry().current_thread().unwrap().index() - 2;
            WAKE_GATE.with_borrow_mut(|slot| *slot = Some(Arc::clone(&gates[offset])));
        });
        wait_until_asleep(&pool);

        // Occupy group 0, so only the sleepers of groups 1 and 2 can take the Wide job.
        let busy = Arc::new(CpuHold::default());
        let started = Arc::new(AtomicUsize::new(0));
        let wide = Arc::new(AtomicBool::new(false));
        let occupy = |group| {
            let (busy, started) = (Arc::clone(&busy), Arc::clone(&started));
            pool.spawn_in(Placement::Local(group), move || {
                started.fetch_add(1, Ordering::SeqCst);
                busy.wait(|| {});
            });
        };
        occupy(0);
        occupy(0);
        wait_until("group zero is busy and the others sleep", || {
            started.load(Ordering::SeqCst) == 2 && pool.sleeping_workers() == 4
        });
        let before_wakes = pool.wakeups();

        // Wake both workers for Local jobs. Hold the first before it searches and the second
        // after it selects a Local job, while both are still counted idle.
        for gate in &gates {
            gate.armed.store(true, Ordering::SeqCst);
        }
        occupy(1);
        wait_until("a woken worker is about to search", || {
            gates[0].entered.load(Ordering::SeqCst)
        });
        occupy(1);
        wait_until("the second worker has selected local work", || {
            gates[1].entered.load(Ordering::SeqCst)
        });

        // The already-awake workers cover this publication without waking group 2. Both
        // Local jobs arrived first, so the first worker must select the remaining Local job.
        {
            let wide = Arc::clone(&wide);
            pool.spawn_in(Placement::Wide { near: 1 }, move || {
                wide.store(true, Ordering::SeqCst);
            });
        }
        assert_eq!(&pool.wakeups()[4..], &before_wakes[4..]);

        // The other worker has selected Local work, although it is still counted idle, so the
        // first worker's exit must wake group 2 for the Wide job before the second is released.
        gates[0].hold.released.store(true, Ordering::SeqCst);
        wait_until("the first woken worker runs local work", || {
            started.load(Ordering::SeqCst) == 3
        });
        let ran_before_release = observe_wide_job(&wide);

        // Release every held worker and let the pool settle before checking the outcome.
        gates[1].hold.released.store(true, Ordering::SeqCst);
        wait_until("both woken workers run local jobs", || {
            started.load(Ordering::SeqCst) == 4
        });
        busy.released.store(true, Ordering::SeqCst);
        wait_until("wide work completes", || wide.load(Ordering::SeqCst));
        wait_until_asleep(&pool);
        assert!(!busy.expired.load(Ordering::SeqCst));
        for gate in &gates {
            assert!(!gate.hold.expired.load(Ordering::SeqCst));
        }
        assert!(ran_before_release, "wide work must use the sleeping group");
    });
}
