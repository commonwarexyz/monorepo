//! Unit tests for the Parked strategy: equivalence with Sequential, exact-once ownership
//! under panics and errors, nesting, overflow, and concurrent submitters.

use super::*;
use crate::Rayon;
use std::sync::{
    Arc as StdArc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

/// A drop-counting token: increments its counter exactly once when dropped.
#[derive(Debug)]
struct Tok(StdArc<AtomicUsize>);

impl Tok {
    fn new(counter: &StdArc<AtomicUsize>) -> Self {
        Self(StdArc::clone(counter))
    }
}

impl Drop for Tok {
    fn drop(&mut self) {
        self.0.fetch_add(1, AtomicOrdering::SeqCst);
    }
}

fn parked(workers: usize) -> Parked {
    // Miri interprets every worker thread; two are enough to exercise the concurrent
    // protocol paths without hour-long runs.
    let workers = if cfg!(miri) { workers.min(2) } else { workers };
    Parked::new(NonZeroUsize::new(workers).unwrap())
}

// Miri executes these tests with real threads under its interpreter; keep sizes small
// there so the exact-once and protocol checks stay fast.
const N: usize = if cfg!(miri) { 48 } else { 512 };

#[test]
fn test_map_collect_vec_matches_sequential() {
    let strategy = parked(4);
    let expected = Sequential.map_collect_vec(0..N as u64, |i| i * 3 + 1);
    // `manual()` forces the parallel arm; the policy-driven call must agree too.
    assert_eq!(
        strategy
            .manual()
            .map_collect_vec(0..N as u64, |i| i * 3 + 1),
        expected
    );
    assert_eq!(
        strategy.map_collect_vec(0..N as u64, |i| i * 3 + 1),
        expected
    );
}

#[test]
fn test_try_map_collect_vec_ok_and_err() {
    let strategy = parked(4);
    let ok: Result<Vec<u64>, ()> = strategy
        .manual()
        .try_map_collect_vec(0..N as u64, |i| Ok(i + 7));
    assert_eq!(
        ok.unwrap(),
        (0..N as u64).map(|i| i + 7).collect::<Vec<_>>()
    );

    let err: Result<Vec<u64>, u64> = strategy.manual().try_map_collect_vec(0..N as u64, |i| {
        if i == N as u64 / 2 { Err(i) } else { Ok(i) }
    });
    assert_eq!(err.unwrap_err(), N as u64 / 2);
}

#[test]
fn test_map_init_collect_vec_matches_sequential() {
    let strategy = parked(4);
    let init = || Vec::<u8>::new();
    let map = |buf: &mut Vec<u8>, i: u64| {
        buf.clear();
        buf.extend_from_slice(&i.to_be_bytes());
        buf.iter().map(|&b| b as u64).sum::<u64>()
    };
    let expected = Sequential.map_init_collect_vec(0..N as u64, init, map);
    assert_eq!(
        strategy
            .manual()
            .map_init_collect_vec(0..N as u64, init, map),
        expected
    );
    assert_eq!(
        strategy
            .manual()
            .map_init_collect_vec_with_multiplier(0..N as u64, 32, init, map),
        expected
    );
}

#[test]
fn test_fold_init_matches_sequential() {
    let strategy = parked(4);
    let expected = Sequential.fold_init(
        0..N as u64,
        || 0u64,
        || 0u64,
        |acc, salt, i| acc + i + *salt,
        |a, b| a + b,
    );
    let got = strategy.manual().fold_init(
        0..N as u64,
        || 0u64,
        || 0u64,
        |acc, salt, i| acc + i + *salt,
        |a, b| a + b,
    );
    assert_eq!(got, expected);
}

#[test]
fn test_try_fold_ok_and_err() {
    let strategy = parked(4);
    let ok: Result<u64, ()> =
        strategy
            .manual()
            .try_fold(0..N as u64, || 0u64, |acc, i| Ok(acc + i), |a, b| a + b);
    assert_eq!(ok.unwrap(), (N as u64 - 1) * N as u64 / 2);

    let err: Result<u64, &'static str> = strategy.manual().try_fold(
        0..N as u64,
        || 0u64,
        |acc, i| {
            if i == N as u64 / 3 {
                Err("boom")
            } else {
                Ok(acc + i)
            }
        },
        |a, b| a + b,
    );
    assert_eq!(err.unwrap_err(), "boom");
}

#[test]
fn test_fold_init_order_matches_sequential_non_commutative() {
    // reduce_op is associative but NOT commutative (Vec concatenation): partials must be
    // reduced in input-segment order, matching Sequential and Rayon.
    let strategy = parked(4);
    let expected = Sequential.fold_init(
        0..N as u64,
        || (),
        Vec::new,
        |mut acc, _, x| {
            acc.push(x);
            acc
        },
        |mut a, b| {
            a.extend(b);
            a
        },
    );
    for _ in 0..50 {
        let got = strategy.manual().fold_init(
            0..N as u64,
            || (),
            Vec::new,
            |mut acc, _, x| {
                acc.push(x);
                acc
            },
            |mut a, b| {
                a.extend(b);
                a
            },
        );
        assert_eq!(got, expected);
    }
}

#[test]
fn test_map_partition_collect_vec() {
    let strategy = parked(4);
    let op = |i: u64| {
        if i % 2 == 0 {
            (i, Some(i * 10))
        } else {
            (i, None)
        }
    };
    let expected = Sequential.map_partition_collect_vec(0..N as u64, op);
    assert_eq!(
        strategy.manual().map_partition_collect_vec(0..N as u64, op),
        expected
    );
}

#[test]
fn test_run_and_try_run_exactly_once() {
    let strategy = parked(4);
    let serial_calls = AtomicUsize::new(0);
    let parallel_calls = AtomicUsize::new(0);
    // Manual forces the parallel closure; exactly one closure runs, exactly once.
    let out = strategy.manual().run(
        N,
        || {
            serial_calls.fetch_add(1, AtomicOrdering::SeqCst);
            1u8
        },
        || {
            parallel_calls.fetch_add(1, AtomicOrdering::SeqCst);
            2u8
        },
    );
    assert_eq!(out, 2);
    assert_eq!(serial_calls.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(parallel_calls.load(AtomicOrdering::SeqCst), 1);

    let out: Result<u8, ()> = strategy.manual().try_run(N, || Ok(1), || Ok(2));
    assert_eq!(out.unwrap(), 2);
}

#[test]
fn test_sort_by_and_join_and_spawn() {
    let strategy = parked(2);
    let mut data: Vec<u64> = (0..N as u64).rev().collect();
    strategy.sort_by(&mut data, |a, b| a.cmp(b));
    assert_eq!(data, (0..N as u64).collect::<Vec<_>>());

    let (a, b) = strategy.join(|| 1u8, || 2u8);
    assert_eq!((a, b), (1, 2));

    let result = futures::executor::block_on(strategy.spawn(1, |_| 42u8));
    assert_eq!(result, 42);
}

#[test]
fn test_single_worker_parallel_arm() {
    // One worker with planning parallelism 2: the caller and the lone worker share every
    // scoped job (the loom models run this exact configuration).
    let strategy =
        Parked::new(NonZeroUsize::new(1).unwrap()).with_parallelism(NonZeroUsize::new(2).unwrap());
    let out = strategy.manual().map_collect_vec(0..N as u64, |i| i * 5);
    assert_eq!(out, (0..N as u64).map(|i| i * 5).collect::<Vec<_>>());
}

#[test]
fn test_single_worker_pool() {
    let strategy = parked(1);
    // parallelism 1: both policy-driven and manual paths run serially, results identical.
    assert_eq!(
        strategy.map_collect_vec(0..N as u64, |i| i * 2),
        strategy.manual().map_collect_vec(0..N as u64, |i| i * 2),
    );
}

#[test]
fn test_with_parallelism_one_takes_serial_arm() {
    // Workers exist but planning parallelism is 1: manual (policy=None) must choose Serial.
    let strategy = parked(4).with_parallelism(NonZeroUsize::new(1).unwrap());
    assert_eq!(
        strategy.manual().run(N, || "serial", || "parallel"),
        "serial"
    );
    let out = strategy.manual().map_collect_vec(0..N as u64, |i| i + 1);
    assert_eq!(out, (1..=N as u64).collect::<Vec<_>>());
}

#[test]
fn test_with_parallelism_above_workers() {
    // Participant cap (8) exceeds workers + caller (3): budget clamps to pool.workers().
    let strategy = parked(2).with_parallelism(NonZeroUsize::new(8).unwrap());
    let expected = Sequential.map_collect_vec(0..N as u64, |i| i ^ 5);
    assert_eq!(
        strategy.manual().map_collect_vec(0..N as u64, |i| i ^ 5),
        expected
    );
}

#[test]
fn test_single_worker_spawn_executes_inline() {
    use futures::FutureExt;
    // A 1-worker pool executes spawn at submission; the future is already resolved.
    let strategy = parked(1);
    assert_eq!(strategy.spawn(1, |_| 7u8).now_or_never(), Some(7));
    assert_eq!(strategy.manual().spawn(1, |_| 8u8).now_or_never(), Some(8));
}

#[test]
fn test_map_err_drops_every_input_exactly_once() {
    let strategy = parked(4);
    let input_drops = StdArc::new(AtomicUsize::new(0));
    let outputs_created = StdArc::new(AtomicUsize::new(0));
    let output_drops = StdArc::new(AtomicUsize::new(0));

    let items: Vec<Tok> = (0..N).map(|_| Tok::new(&input_drops)).collect();
    let created = StdArc::clone(&outputs_created);
    let out_ctr = StdArc::clone(&output_drops);
    let calls = AtomicUsize::new(0);
    let result: Result<Vec<Tok>, &'static str> =
        strategy.manual().try_map_collect_vec(items, move |tok| {
            drop(tok);
            // Fail roughly mid-stream on one item; every executor keeps mapping until the
            // close propagates, so multiple errors may race (first must win).
            if calls.fetch_add(1, AtomicOrdering::SeqCst) == N / 2 {
                return Err("mid-stream failure");
            }
            created.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(Tok::new(&out_ctr))
        });
    assert_eq!(result.unwrap_err(), "mid-stream failure");

    // Every input dropped exactly once (consumed by map_op or cleaned up), and every
    // created output dropped exactly once by the failure cleanup.
    assert_eq!(input_drops.load(AtomicOrdering::SeqCst), N);
    assert_eq!(
        output_drops.load(AtomicOrdering::SeqCst),
        outputs_created.load(AtomicOrdering::SeqCst)
    );
}

#[test]
fn test_map_panic_drops_every_input_exactly_once() {
    let strategy = parked(4);
    let input_drops = StdArc::new(AtomicUsize::new(0));
    let outputs_created = StdArc::new(AtomicUsize::new(0));
    let output_drops = StdArc::new(AtomicUsize::new(0));

    let items: Vec<Tok> = (0..N).map(|_| Tok::new(&input_drops)).collect();
    let created = StdArc::clone(&outputs_created);
    let out_ctr = StdArc::clone(&output_drops);
    let calls = AtomicUsize::new(0);
    let manual = strategy.manual();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        manual.map_collect_vec(items, move |tok| {
            drop(tok);
            if calls.fetch_add(1, AtomicOrdering::SeqCst) == N / 2 {
                panic!("chunk panic");
            }
            created.fetch_add(1, AtomicOrdering::SeqCst);
            Tok::new(&out_ctr)
        })
    }));
    let payload = result.unwrap_err();
    assert_eq!(*payload.downcast_ref::<&str>().unwrap(), "chunk panic");

    assert_eq!(input_drops.load(AtomicOrdering::SeqCst), N);
    assert_eq!(
        output_drops.load(AtomicOrdering::SeqCst),
        outputs_created.load(AtomicOrdering::SeqCst)
    );
}

#[test]
fn test_init_panic_drops_every_input_exactly_once() {
    let strategy = parked(4);
    let input_drops = StdArc::new(AtomicUsize::new(0));
    let items: Vec<Tok> = (0..N).map(|_| Tok::new(&input_drops)).collect();
    let manual = strategy.manual();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        manual.map_init_collect_vec(items, || panic!("init panic"), |_state: &mut (), tok| tok)
    }));
    assert!(result.is_err());
    assert_eq!(input_drops.load(AtomicOrdering::SeqCst), N);
}

#[test]
fn test_fold_err_drops_every_input_exactly_once() {
    let strategy = parked(4);
    let input_drops = StdArc::new(AtomicUsize::new(0));
    let items: Vec<Tok> = (0..N).map(|_| Tok::new(&input_drops)).collect();
    let calls = AtomicUsize::new(0);
    let result: Result<u64, &'static str> = strategy.manual().try_fold(
        items,
        || 0u64,
        |acc, tok| {
            drop(tok);
            if calls.fetch_add(1, AtomicOrdering::SeqCst) == N / 3 {
                Err("fold failure")
            } else {
                Ok(acc + 1)
            }
        },
        |a, b| a + b,
    );
    assert_eq!(result.unwrap_err(), "fold failure");
    assert_eq!(input_drops.load(AtomicOrdering::SeqCst), N);
}

#[test]
fn test_nested_submission_and_overflow_inline() {
    // Nest one map inside another deeper than the slot table: inner levels overflow to
    // inline execution and must still complete correctly (submission never blocks).
    let strategy = parked(4);
    fn nested(strategy: &Parked, depth: usize) -> u64 {
        let manual = strategy.manual();
        manual
            .map_collect_vec(0..8u64, |i| {
                if depth == 0 {
                    i
                } else {
                    i + nested(strategy, depth - 1)
                }
            })
            .into_iter()
            .sum()
    }
    // Depth exceeds pool::SLOTS (4): the deepest submissions find the table full.
    let got = nested(&strategy, pool::SLOTS + 2);
    let want = {
        fn reference(depth: usize) -> u64 {
            (0..8u64)
                .map(|i| {
                    if depth == 0 {
                        i
                    } else {
                        i + reference(depth - 1)
                    }
                })
                .sum()
        }
        reference(pool::SLOTS + 2)
    };
    assert_eq!(got, want);
}

#[test]
fn test_concurrent_submitters() {
    let strategy = parked(4);
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let s = strategy.clone();
            std::thread::spawn(move || {
                let out = s
                    .manual()
                    .map_collect_vec(0..N as u64, move |i| i + t as u64);
                assert_eq!(out, (0..N as u64).map(|i| i + t as u64).collect::<Vec<_>>());
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_burst_train_smoke() {
    // Back-to-back small jobs (the merkleize per-level shape); correctness smoke only,
    // the timing gate lives in the bench suite.
    let strategy = parked(4);
    for _ in 0..200 {
        let out = strategy.manual().map_collect_vec(0..64u64, |i| i * 2);
        assert_eq!(out.len(), 64);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "constructs a rayon pool; rayon-core does not run under miri"
)]
fn test_matches_rayon_semantics_on_error_priority() {
    // Both strategies must return an error (not panic) when map errors race; the specific
    // error may differ (first-to-close wins), but the operation must not lose it.
    let parked = parked(4);
    let rayon = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();
    for strategy_result in [
        parked
            .manual()
            .try_map_collect_vec(0..N as u64, |i| if i % 97 == 0 { Err(i) } else { Ok(i) }),
        rayon
            .manual()
            .try_map_collect_vec(0..N as u64, |i| if i % 97 == 0 { Err(i) } else { Ok(i) }),
    ] {
        let e = strategy_result.unwrap_err();
        assert_eq!(e % 97, 0);
    }
}

#[test]
fn test_spawn_result_and_panic() {
    let strategy = parked(2);
    assert_eq!(futures::executor::block_on(strategy.spawn(1, |_| 7u8)), 7);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        futures::executor::block_on(strategy.spawn(1, |_| -> u8 { panic!("spawn boom") }))
    }));
    assert_eq!(
        *result.unwrap_err().downcast_ref::<&str>().unwrap(),
        "spawn boom"
    );
}

#[test]
fn test_detached_spawn_still_runs() {
    // Eager submission: dropping the returned future must not cancel the job.
    let strategy = parked(2);
    let (tx, rx) = std::sync::mpsc::channel();
    drop(strategy.manual().spawn(1, move |_| {
        tx.send(42u8).unwrap();
    }));
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap(),
        42
    );
}

#[test]
fn test_member_poller_executes_pending_spawn() {
    // Port of the Rayon member-poller contract: occupy every worker except the one running
    // the outer job, so the inner spawn can only complete if the outer job's block_on
    // (polling from a pool worker) helps by running queued work itself.
    let strategy = parked(2);
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let gate_rx = StdArc::new(std::sync::Mutex::new(gate_rx));

    // Occupy one worker with a job that blocks until the end of the test.
    let blocker = {
        let gate_rx = StdArc::clone(&gate_rx);
        strategy.manual().spawn(1, move |_| {
            let _ = gate_rx.lock().unwrap().recv();
        })
    };

    // The outer job runs on the remaining worker and block_on-polls an inner spawn: with
    // no free worker, only the member help path can execute it.
    let outer = strategy.manual().spawn(1, move |s| {
        futures::executor::block_on(s.spawn(1, |_| 99u8))
    });
    assert_eq!(futures::executor::block_on(outer), 99);

    gate_tx.send(()).unwrap();
    futures::executor::block_on(blocker);
}

#[test]
fn test_last_owner_dropped_inside_spawned_job() {
    // The spawned job holds the final Parked clone: its drop runs Owner::drop ON a pool
    // worker, which must detach (not self-join) and must not hang the pool.
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let strategy = parked(2);
        let fut = strategy.manual().spawn(1, move |s| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(s); // possibly the last owner by now
            tx.send(1u8).unwrap();
        });
        drop(fut);
        drop(strategy); // job's clone may become the last owner
    }
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap(),
        1
    );
}

#[test]
fn test_dropping_handles_never_cancels_queued_spawns() {
    // Every queued job holds an owner clone, so the pool cannot shut down while work is
    // pending: dropping every external handle must still let all 64 jobs run.
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let strategy = parked(2);
        for i in 0..64u8 {
            let tx = tx.clone();
            drop(strategy.manual().spawn(1, move |_| {
                tx.send(i).unwrap();
            }));
        }
    }
    drop(tx);
    let mut seen = 0;
    while rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok() {
        seen += 1;
    }
    assert_eq!(seen, 64);
}

#[test]
fn test_manual_spawn_hands_off_blocking_jobs() {
    // The block_strategy pattern: jobs that block on a channel must not execute inline on
    // the submitter (that would deadlock before the release below).
    let strategy = parked(2);
    let manual = strategy.manual();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = StdArc::new(std::sync::Mutex::new(release_rx));
    let futs: Vec<_> = (0..2)
        .map(|_| {
            let rx = StdArc::clone(&release_rx);
            manual.spawn(1, move |_| {
                let _ = rx.lock().unwrap().recv();
            })
        })
        .collect();
    // If either job had run inline, we would never reach here.
    release_tx.send(()).unwrap();
    release_tx.send(()).unwrap();
    for fut in futs {
        futures::executor::block_on(fut);
    }
}

#[test]
fn test_boundary_lengths_match_sequential() {
    // len 0 exercises scoped::run's early return after scoped_map's set_len(0);
    // len == MIN_CHUNK yields a zero wake budget (caller-only); MIN_CHUNK + 1 wakes one.
    let strategy = parked(4);
    for n in [
        0usize,
        1,
        scoped::MIN_CHUNK - 1,
        scoped::MIN_CHUNK,
        scoped::MIN_CHUNK + 1,
        3 * scoped::MIN_CHUNK + 1,
    ] {
        let expected = Sequential.map_collect_vec(0..n as u64, |i| i * 3 + 1);
        assert_eq!(
            strategy
                .manual()
                .map_collect_vec(0..n as u64, |i| i * 3 + 1),
            expected,
            "n={n}"
        );
        let sum: u64 = strategy
            .manual()
            .fold(0..n as u64, || 0u64, |a, i| a + i, |a, b| a + b);
        assert_eq!(sum, (0..n as u64).sum::<u64>(), "n={n}");
    }
}

// ---------------------------------------------------------------------------
// Increment C: parallel sort_by and join.
// ---------------------------------------------------------------------------

/// Deterministic splitmix64 stream for sort inputs.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// `(key, sequence)` pairs: comparing by key only makes stability observable via the
/// sequence numbers.
fn keyed_input(len: usize, key_range: u64, seed: u64) -> Vec<(u64, u32)> {
    let mut state = seed;
    (0..len)
        .map(|i| (splitmix(&mut state) % key_range, i as u32))
        .collect()
}

fn assert_sorts_like_std(strategy: &impl Strategy, mut input: Vec<(u64, u32)>) {
    let mut expected = input.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    strategy.sort_by(&mut input, |a, b| a.0.cmp(&b.0));
    // Full-tuple equality against the standard stable sort: any stability violation
    // shows up as reordered sequence numbers within an equal-key group.
    assert_eq!(input, expected);
}

#[test]
fn test_sort_by_matches_std_and_is_stable() {
    // Sizes hit: serial fallback (single run), several runs with a short tail, and an
    // odd run count whose merge rounds carry an unpaired run through.
    let sizes = if cfg!(miri) {
        vec![0, 1, 2, 3, sort::MIN_RUN, 3 * sort::MIN_RUN, 96, 27]
    } else {
        vec![
            0,
            1,
            2,
            3,
            sort::MIN_RUN,
            3 * sort::MIN_RUN,
            40_000,
            37_531,
            5_000,
        ]
    };
    let strategy = parked(4).manual();
    for (i, &len) in sizes.iter().enumerate() {
        // Heavy ties (small key range) and mostly-distinct keys.
        assert_sorts_like_std(&strategy, keyed_input(len, 4, 7 + i as u64));
        assert_sorts_like_std(&strategy, keyed_input(len, u64::MAX, 71 + i as u64));
        // Presorted and reversed inputs.
        let mut asc = keyed_input(len, 1 << 40, 137 + i as u64);
        asc.sort_by(|a, b| a.0.cmp(&b.0));
        assert_sorts_like_std(&strategy, asc.clone());
        asc.reverse();
        assert_sorts_like_std(&strategy, asc);
    }
}

#[test]
fn test_sort_by_all_equal_keys_keeps_order() {
    let len = if cfg!(miri) { 64 } else { 20_000 };
    let strategy = parked(4).manual();
    let mut items: Vec<(u64, u32)> = (0..len).map(|i| (42, i as u32)).collect();
    strategy.sort_by(&mut items, |a, b| a.0.cmp(&b.0));
    assert!(items.windows(2).all(|w| w[0].1 < w[1].1));
}

#[test]
fn test_sort_by_zst() {
    let strategy = parked(2).manual();
    let mut items = vec![(); if cfg!(miri) { 64 } else { 10_000 }];
    strategy.sort_by(&mut items, |_, _| CmpOrdering::Equal);
    assert_eq!(items.len(), if cfg!(miri) { 64 } else { 10_000 });
}

#[test]
fn test_sort_by_policied_matches_std_across_calls() {
    // The adaptive policy probes both paths over repeated calls; every call must sort
    // correctly regardless of which arm it lands on.
    let strategy = parked(4);
    let len = if cfg!(miri) { 48 } else { 8_192 };
    for round in 0..if cfg!(miri) { 4 } else { 30 } {
        assert_sorts_like_std(&strategy, keyed_input(len, 16, round as u64));
    }
}

#[test]
fn test_sort_by_panic_in_run_phase_preserves_elements() {
    // An always-panicking comparator dies inside the run-phase in-place sorts; the slice
    // must come back with every element exactly once.
    let strategy = parked(4).manual();
    let counter = StdArc::new(AtomicUsize::new(0));
    let len = 4 * sort::MIN_RUN;
    let mut items: Vec<(u64, Tok)> = (0..len as u64).map(|k| (k, Tok::new(&counter))).collect();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        strategy.sort_by(&mut items, |_, _| panic!("comparator poison"));
    }));
    assert!(result.is_err());
    assert_eq!(items.len(), len);
    assert_eq!(
        counter.load(AtomicOrdering::SeqCst),
        0,
        "no element dropped during unwind"
    );
    let keys: std::collections::BTreeSet<u64> = items.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys.len(), len, "every element still present exactly once");
    drop(items);
    assert_eq!(
        counter.load(AtomicOrdering::SeqCst),
        len,
        "each element dropped exactly once"
    );
}

#[test]
fn test_sort_by_panic_in_merge_phase_preserves_elements() {
    // Comparator that panics only for one specific cross-run pair: within-run ordering is
    // clean, so the run phase completes and the poison fires inside the first merge round
    // (covering the scratch-abandon unwind path).
    let strategy = parked(2).manual();
    let run = sort::MIN_RUN;
    let len = 4 * run;
    // Run 0 holds the even keys and run 1 the odd keys, both ascending, so their merge
    // alternates heads all the way down and is forced to compare the two largest keys
    // (the poison pair) right before the left run exhausts. Runs 2 and 3 are a plain
    // ascending tail with no poison. Within-run comparisons never mix the pair.
    let poison_a = 2 * (run as u64) - 2;
    let poison_b = 2 * (run as u64) - 1;
    let counter = StdArc::new(AtomicUsize::new(0));
    let mut keys: Vec<u64> = Vec::with_capacity(len);
    keys.extend((0..run as u64).map(|i| 2 * i));
    keys.extend((0..run as u64).map(|i| 2 * i + 1));
    keys.extend(2 * run as u64..len as u64);
    let mut items: Vec<(u64, Tok)> = keys.into_iter().map(|k| (k, Tok::new(&counter))).collect();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        strategy.sort_by(&mut items, |x, y| {
            let pair = (x.0.min(y.0), x.0.max(y.0));
            assert!(pair != (poison_a, poison_b), "merge poison");
            x.0.cmp(&y.0)
        });
    }));
    assert!(result.is_err());
    assert_eq!(items.len(), len);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 0);
    let keys: std::collections::BTreeSet<u64> = items.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys.len(), len);
    drop(items);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), len);
}

#[test]
fn test_join_returns_both() {
    let strategy = parked(2);
    let (ra, rb) = strategy.join(|| 40 + 2, || "side b".to_string());
    assert_eq!(ra, 42);
    assert_eq!(rb, "side b");
}

#[test]
fn test_join_serial_at_parallelism_one() {
    let strategy = parked(1);
    let caller = std::thread::current().id();
    let (ta, tb) = strategy.join(
        || std::thread::current().id(),
        || std::thread::current().id(),
    );
    assert_eq!(ta, caller);
    assert_eq!(tb, caller);
}

#[cfg(not(miri))]
#[test]
fn test_join_sides_overlap() {
    // Side a blocks until side b signals: only a genuinely concurrent b lets the join
    // complete (a fully serialized join would time out the recv and fail the test).
    let strategy = parked(2);
    let (tx, rx) = std::sync::mpsc::channel();
    let (ra, rb) = strategy.join(
        move || rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap(),
        move || tx.send(7usize).unwrap(),
    );
    assert_eq!(ra, 7);
    let () = rb;
}

#[test]
fn test_join_nested_overflow_inline() {
    // Nested joins occupy slots; deeper than SLOTS forces the inline overflow path,
    // which must still run both sides.
    fn nest(strategy: &Parked, depth: usize) -> usize {
        if depth == 0 {
            return 1;
        }
        let (l, r) = strategy.join(|| nest(strategy, depth - 1), || 1usize);
        l + r
    }
    let strategy = parked(2);
    assert_eq!(nest(&strategy, 6), 7);
}

#[test]
fn test_join_panic_propagates_and_drops_other_result() {
    let strategy = parked(2);
    let counter = StdArc::new(AtomicUsize::new(0));
    let token = Tok::new(&counter);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        strategy.join(|| panic!("join poison"), move || token)
    }));
    assert!(result.is_err());
    // Side b always runs (rayon parity); its produced token is dropped exactly once by
    // the unwinding join frame.
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 1);
}

/// Sorts `len` drop-counting elements with an arbitrary (possibly inconsistent)
/// comparator and asserts the memory-safety contract: whatever the order, every element
/// survives exactly once (std/rayon parity for non-total-order comparators).
fn assert_sort_multiset_safe<C>(len: usize, compare: C)
where
    C: Fn(&(u64, Tok), &(u64, Tok)) -> CmpOrdering + Send + Sync,
{
    let strategy = parked(2).manual();
    let counter = StdArc::new(AtomicUsize::new(0));
    let mut items: Vec<(u64, Tok)> = (0..len as u64).map(|k| (k, Tok::new(&counter))).collect();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        strategy.sort_by(&mut items, &compare);
    }));
    // The order (and whether it panicked) is unspecified for a garbage comparator; the
    // multiset must survive regardless.
    let _ = result;
    assert_eq!(items.len(), len);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 0);
    let keys: std::collections::BTreeSet<u64> = items.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys.len(), len, "elements lost or duplicated");
    drop(items);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), len);
}

#[test]
fn test_sort_by_constant_less_comparator_is_memory_safe() {
    assert_sort_multiset_safe(4 * sort::MIN_RUN, |_, _| CmpOrdering::Less);
}

#[test]
fn test_sort_by_constant_greater_comparator_is_memory_safe() {
    assert_sort_multiset_safe(4 * sort::MIN_RUN, |_, _| CmpOrdering::Greater);
}

#[test]
fn test_sort_by_stateful_flip_comparator_is_memory_safe() {
    let calls = StdArc::new(AtomicUsize::new(0));
    assert_sort_multiset_safe(4 * sort::MIN_RUN, move |x, y| {
        // Consistent early (the run phase sees a plausible order), then adversarial:
        // every third call inverts, breaking antisymmetry across unit boundaries.
        let n = calls.fetch_add(1, AtomicOrdering::Relaxed);
        if n % 3 == 0 {
            y.0.cmp(&x.0)
        } else {
            x.0.cmp(&y.0)
        }
    });
}

#[test]
fn test_sort_by_panic_in_slice_destination_round_restores_elements() {
    // Forces the poison into the SECOND merge round, whose destination is the slice
    // (round 0 writes scratch, then the buffers swap): exercises the restore branch that
    // copies the complete scratch image back before resuming. Construction: runs 0 and 1
    // hold the evens (interleaved mod 4), runs 2 and 3 the odds, so round 0 merges
    // parity-pure pairs and only round 1's evens-vs-odds merge can compare the poison
    // pair (the two global maxima), right at the tail of its final segment.
    let strategy = parked(2).manual();
    let run = sort::MIN_RUN;
    let len = 4 * run;
    let poison_a = 4 * (run as u64) - 2;
    let poison_b = 4 * (run as u64) - 1;
    let counter = StdArc::new(AtomicUsize::new(0));
    let mut keys: Vec<u64> = Vec::with_capacity(len);
    keys.extend((0..run as u64).map(|i| 4 * i));
    keys.extend((0..run as u64).map(|i| 4 * i + 2));
    keys.extend((0..run as u64).map(|i| 4 * i + 1));
    keys.extend((0..run as u64).map(|i| 4 * i + 3));
    let mut items: Vec<(u64, Tok)> = keys.into_iter().map(|k| (k, Tok::new(&counter))).collect();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        strategy.sort_by(&mut items, |x, y| {
            let pair = (x.0.min(y.0), x.0.max(y.0));
            assert!(pair != (poison_a, poison_b), "round-1 poison");
            x.0.cmp(&y.0)
        });
    }));
    assert!(result.is_err());
    assert_eq!(items.len(), len);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 0);
    let keys: std::collections::BTreeSet<u64> = items.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys.len(), len);
    drop(items);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), len);
}

#[test]
fn test_join_both_panic_side_a_wins() {
    // Rayon parity: when both sides panic, side a's payload is the one propagated. Side b
    // waits for a's start signal so both sides genuinely run when a worker is available;
    // if b is never claimed (degenerate scheduling), a's payload still wins trivially.
    let strategy = parked(2);
    let (tx, rx) = std::sync::mpsc::channel();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        strategy.join(
            move || {
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(20));
                panic!("boom-a")
            },
            move || {
                let _ = rx.recv_timeout(std::time::Duration::from_secs(10));
                panic!("boom-b")
            },
        )
    }));
    let payload = result.unwrap_err();
    assert_eq!(*payload.downcast_ref::<&str>().unwrap(), "boom-a");
}

#[test]
fn test_join_runs_b_even_when_a_panics() {
    // Rayon parity: both closures always execute; a's panic is propagated only after b
    // has run (or been waited out). Checked on the pooled path and the parallelism-1
    // inline path.
    for workers in [2usize, 1] {
        let strategy = parked(workers);
        let b_ran = StdArc::new(AtomicUsize::new(0));
        let b_flag = StdArc::clone(&b_ran);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            strategy.join(
                || panic!("boom-a"),
                move || {
                    b_flag.fetch_add(1, AtomicOrdering::SeqCst);
                },
            )
        }));
        let payload = result.unwrap_err();
        assert_eq!(*payload.downcast_ref::<&str>().unwrap(), "boom-a");
        assert_eq!(
            b_ran.load(AtomicOrdering::SeqCst),
            1,
            "side b must execute despite a's panic (workers={workers})"
        );
    }
}

#[test]
fn test_with_parallelism_huge_is_safe() {
    // Absurd planning parallelism must degrade gracefully (saturating chunk math), not
    // panic mid-claim after a job is published: a panic there would tear down the run's
    // stack frame behind a still-published slot.
    let strategy = parked(2).with_parallelism(NonZeroUsize::new(usize::MAX).unwrap());
    let (a, b) = strategy.join(|| 1u8, || 2u8);
    assert_eq!((a, b), (1, 2));
    let out = strategy.manual().map_collect_vec(0..N as u64, |i| i * 3);
    assert_eq!(out, (0..N as u64).map(|i| i * 3).collect::<Vec<_>>());
    let mut items: Vec<u64> = (0..(4 * sort::MIN_RUN) as u64).rev().collect();
    strategy.manual().sort_by(&mut items, |a, b| a.cmp(b));
    assert!(items.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn test_sort_by_presorted_shapes_match_std() {
    // The presorted early-exit and the ordered-pair fast path must produce exactly the
    // std stable result on sorted, nearly-sorted, descending, and sawtooth inputs (with
    // ties, so stability stays observable).
    let strategy = parked(4).manual();
    let len = 8 * sort::MIN_RUN;
    // Fully sorted with duplicate keys.
    let sorted: Vec<(u64, u32)> = (0..len).map(|i| ((i / 3) as u64, i as u32)).collect();
    assert_sorts_like_std(&strategy, sorted.clone());
    // Nearly sorted: one displaced element defeats the whole-slice exit but leaves most
    // pairs on the ordered-concatenation path.
    let mut nearly = sorted.clone();
    nearly.swap(1, len - 2);
    assert_sorts_like_std(&strategy, nearly);
    // Strictly descending.
    let mut desc = sorted.clone();
    desc.reverse();
    assert_sorts_like_std(&strategy, desc);
    // Sawtooth: ascending runs of exactly MIN_RUN, so run boundaries alternate ordered
    // and disordered.
    let saw: Vec<(u64, u32)> = (0..len)
        .map(|i| ((i % sort::MIN_RUN) as u64, i as u32))
        .collect();
    assert_sorts_like_std(&strategy, saw);
}
