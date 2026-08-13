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

    let err: Result<Vec<u64>, u64> = strategy
        .manual()
        .try_map_collect_vec(0..N as u64, |i| if i == 300 { Err(i) } else { Ok(i) });
    assert_eq!(err.unwrap_err(), 300);
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
        |acc, i| if i == 100 { Err("boom") } else { Ok(acc + i) },
        |a, b| a + b,
    );
    assert_eq!(err.unwrap_err(), "boom");
}

#[test]
fn test_map_partition_collect_vec() {
    let strategy = parked(4);
    let (evens, odds) = strategy
        .manual()
        .map_partition_collect_vec(0..N as u64, |i| {
            if i % 2 == 0 {
                (i, Some(i * 10))
            } else {
                (i, None)
            }
        });
    let mut evens = evens;
    let mut odds = odds;
    evens.sort_unstable();
    odds.sort_unstable();
    assert_eq!(
        evens,
        (0..N as u64)
            .filter(|i| i % 2 == 0)
            .map(|i| i * 10)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        odds,
        (0..N as u64).filter(|i| i % 2 == 1).collect::<Vec<_>>()
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

    let result = futures::executor::block_on(strategy.spawn(|_| 42u8));
    assert_eq!(result, 42);
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
fn test_smoke_map() {
    let strategy = parked(2);
    let out = strategy.manual().map_collect_vec(0..64u64, |i| i * 2);
    assert_eq!(out, (0..64u64).map(|i| i * 2).collect::<Vec<_>>());
}
