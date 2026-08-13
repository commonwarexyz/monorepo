//! Increment-A gate benches, run manually and judged as paired same-session A/Bs:
//!
//! ```text
//! cargo test -p commonware-parallel --release --lib parked::bench_tests -- --ignored --nocapture
//! ```
//!
//! - `gate_saturated_parity`: `map_init_collect_vec` throughput at saturation vs `Rayon`.
//! - `gate_fairness_long_short`: short-job latency while a long job monopolizes a slot.
//! - `gate_burst_train`: back-to-back small jobs at merkleize per-level sizes; this is the
//!   bench that sets `SEARCH_ROUNDS` (the Searching-window tunable) by measurement.

use super::*;
use crate::Rayon;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const WORKERS: usize = 8;

/// CPU-bound per-item work (~1us): a small keyed mixing loop the optimizer cannot elide.
fn work(seed: u64, rounds: u32) -> u64 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for _ in 0..rounds {
        x ^= x >> 33;
        x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        x ^= x >> 29;
    }
    x
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn time<R>(f: impl FnOnce() -> R) -> (Duration, R) {
    let start = Instant::now();
    let out = f();
    (start.elapsed(), out)
}

#[test]
#[ignore = "gate bench: run manually with --ignored --nocapture in release"]
fn gate_saturated_parity() {
    const N: usize = 100_000;
    const ROUNDS: u32 = 200;
    const ITERS: usize = 21;

    let parked = Parked::new(NonZeroUsize::new(WORKERS).unwrap());
    let rayon = Rayon::new(NonZeroUsize::new(WORKERS).unwrap()).unwrap();

    let mut results = Vec::new();
    for (name, run) in [
        (
            "parked",
            Box::new(|| {
                parked
                    .manual()
                    .map_init_collect_vec(0..N as u64, || (), |_, i| work(i, ROUNDS))
            }) as Box<dyn Fn() -> Vec<u64>>,
        ),
        (
            "rayon",
            Box::new(|| {
                rayon
                    .manual()
                    .map_init_collect_vec(0..N as u64, || (), |_, i| work(i, ROUNDS))
            }),
        ),
    ] {
        // Warmup, then timed iterations.
        for _ in 0..3 {
            black_box(run());
        }
        let samples: Vec<Duration> = (0..ITERS)
            .map(|_| {
                let (elapsed, out) = time(&run);
                black_box(out);
                elapsed
            })
            .collect();
        results.push((name, median(samples)));
    }
    for (name, med) in &results {
        println!("gate_saturated_parity/{name}: median {med:?} (n={N}, rounds={ROUNDS})");
    }
}

#[test]
#[ignore = "gate bench: run manually with --ignored --nocapture in release"]
fn gate_fairness_long_short() {
    const LONG_N: usize = 2_000_000;
    const SHORT_N: usize = 2_000;
    const ROUNDS: u32 = 40;
    const SHORT_JOBS: usize = 200;

    fn scenario<S: Strategy>(strategy: &S) -> (Duration, Duration) {
        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut latencies = Vec::with_capacity(SHORT_JOBS);
        std::thread::scope(|scope| {
            let long = scope.spawn({
                let strategy = strategy.clone();
                let stop = &stop;
                move || {
                    // Keep a long job continuously claimable until the short side finishes.
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        black_box(strategy.manual().map_init_collect_vec(
                            0..LONG_N as u64,
                            || (),
                            |_, i| work(i, 8),
                        ));
                    }
                }
            });
            for _ in 0..SHORT_JOBS {
                let (elapsed, out) = time(|| {
                    strategy.manual().map_init_collect_vec(
                        0..SHORT_N as u64,
                        || (),
                        |_, i| work(i, ROUNDS),
                    )
                });
                black_box(out);
                latencies.push(elapsed);
            }
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            long.join().unwrap();
        });
        latencies.sort_unstable();
        (
            latencies[latencies.len() / 2],
            latencies[latencies.len() * 99 / 100],
        )
    }

    let parked = Parked::new(NonZeroUsize::new(WORKERS).unwrap());
    let (p50, p99) = scenario(&parked);
    println!("gate_fairness_long_short/parked: short p50 {p50:?} p99 {p99:?}");
    drop(parked);

    let rayon = Rayon::new(NonZeroUsize::new(WORKERS).unwrap()).unwrap();
    let (p50, p99) = scenario(&rayon);
    println!("gate_fairness_long_short/rayon: short p50 {p50:?} p99 {p99:?}");
}

#[test]
#[ignore = "gate bench: run manually with --ignored --nocapture in release"]
fn gate_burst_train() {
    // Merkleize submits ~15 back-to-back per-level jobs per commit, halving in size.
    const LEVELS: [usize; 12] = [4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2];
    const ROUNDS: u32 = 60;
    const COMMITS: usize = 2_000;

    fn train<S: Strategy>(strategy: &S) -> Duration {
        // Warmup commits so pools reach steady state.
        for _ in 0..50 {
            for &n in &LEVELS {
                black_box(strategy.manual().map_init_collect_vec(
                    0..n as u64,
                    || (),
                    |_, i| work(i, ROUNDS),
                ));
            }
        }
        let (elapsed, _) = time(|| {
            for _ in 0..COMMITS {
                for &n in &LEVELS {
                    black_box(strategy.manual().map_init_collect_vec(
                        0..n as u64,
                        || (),
                        |_, i| work(i, ROUNDS),
                    ));
                }
            }
        });
        elapsed
    }

    let parked = Parked::new(NonZeroUsize::new(WORKERS).unwrap());
    let t = train(&parked);
    println!(
        "gate_burst_train/parked: {t:?} total, {:?}/commit (SEARCH_ROUNDS={})",
        t / COMMITS as u32,
        pool::SEARCH_ROUNDS,
    );
    drop(parked);

    let rayon = Rayon::new(NonZeroUsize::new(WORKERS).unwrap()).unwrap();
    let t = train(&rayon);
    println!(
        "gate_burst_train/rayon: {t:?} total, {:?}/commit",
        t / COMMITS as u32
    );

    let sequential = Sequential;
    let t = train(&sequential);
    println!(
        "gate_burst_train/serial: {t:?} total, {:?}/commit",
        t / COMMITS as u32
    );
}
