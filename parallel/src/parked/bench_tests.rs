//! Increment-A gate benches, run manually and judged as paired same-session A/Bs:
//!
//! ```text
//! cargo test -p commonware-parallel --release --lib parked::bench_tests -- --ignored --nocapture
//! ```
//!
//! - `gate_saturated_parity`: `map_init_collect_vec` throughput at saturation vs `Rayon`.
//! - `gate_fairness_long_short`: short-job latency while a long job monopolizes a slot.
//! - `gate_burst_train`: back-to-back small jobs in halving sizes; this is the bench that
//!   sets `SEARCH_ROUNDS` (the Searching-window tunable) and `MIN_CHUNK` by measurement.
//! - `gate_spawn_roundtrip`: hand-off + wake + completion latency of one spawned job with
//!   interleaved caller work.

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
fn gate_spawn_roundtrip() {
    // The merkleize offload shape: spawn one CPU job per commit and await it after doing
    // interleaved caller work. Measures hand-off + wake + completion latency beyond the
    // job's own wall.
    const JOB_ROUNDS: u32 = 40_000; // ~40us of work
    const CALLER_ROUNDS: u32 = 20_000; // caller overlaps ~20us before awaiting
    const ITERS: usize = 2_001;

    fn scenario<S: Strategy>(strategy: &S) -> Duration {
        // Warmup.
        for _ in 0..100 {
            let fut = strategy.manual().spawn(1, |_| work(1, JOB_ROUNDS));
            black_box(work(2, CALLER_ROUNDS));
            black_box(futures::executor::block_on(fut));
        }
        let samples: Vec<Duration> = (0..ITERS)
            .map(|_| {
                let (elapsed, out) = time(|| {
                    let fut = strategy.manual().spawn(1, |_| work(1, JOB_ROUNDS));
                    let caller = work(2, CALLER_ROUNDS);
                    (futures::executor::block_on(fut), caller)
                });
                black_box(out);
                elapsed
            })
            .collect();
        median(samples)
    }

    let parked = Parked::new(NonZeroUsize::new(WORKERS).unwrap());
    println!(
        "gate_spawn_roundtrip/parked: median {:?}",
        scenario(&parked)
    );
    drop(parked);
    let rayon = Rayon::new(NonZeroUsize::new(WORKERS).unwrap()).unwrap();
    println!("gate_spawn_roundtrip/rayon: median {:?}", scenario(&rayon));
    println!(
        "gate_spawn_roundtrip/inline-floor: job {:?} + caller {:?} serial",
        time(|| black_box(work(1, JOB_ROUNDS))).0,
        time(|| black_box(work(2, CALLER_ROUNDS))).0,
    );
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

#[test]
#[ignore = "gate bench: run manually with --ignored --nocapture in release"]
fn gate_sort() {
    // The constantinople-shaped cell: qmdb's apply path sorts ~32k-element diffs every
    // commit through `Strategy::sort_by`, and rayon's parallel sort is its entire
    // right-end win there. Compare raw parallel sorts (policy off) and the serial
    // baseline on identical data.
    const ITERS: usize = 21;

    let parked = Parked::new(NonZeroUsize::new(WORKERS).unwrap()).manual();
    let rayon = Rayon::new(NonZeroUsize::new(WORKERS).unwrap())
        .unwrap()
        .manual();

    for (n, presorted) in [(32_768usize, false), (262_144, false), (262_144, true)] {
        let mut seed = 0x5EEDu64;
        let mut next = move || {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z ^ (z >> 31)
        };
        let mut input: Vec<(u64, u64)> = (0..n as u64).map(|i| (next(), i)).collect();
        if presorted {
            input.sort_by(|a, b| a.0.cmp(&b.0));
        }

        let mut report = Vec::new();
        for (name, sorter) in [
            (
                "parked",
                Box::new(|items: &mut [(u64, u64)]| parked.sort_by(items, |a, b| a.0.cmp(&b.0)))
                    as Box<dyn Fn(&mut [(u64, u64)])>,
            ),
            (
                "rayon",
                Box::new(|items: &mut [(u64, u64)]| rayon.sort_by(items, |a, b| a.0.cmp(&b.0))),
            ),
            (
                "serial",
                Box::new(|items: &mut [(u64, u64)]| items.sort_by(|a, b| a.0.cmp(&b.0))),
            ),
        ] {
            let mut samples = Vec::with_capacity(ITERS);
            for _ in 0..ITERS {
                let mut items = input.clone();
                let (elapsed, ()) = time(|| sorter(black_box(&mut items)));
                samples.push(elapsed);
                black_box(items);
            }
            report.push((name, median(samples)));
        }
        println!("gate_sort n={n} presorted={presorted}:");
        for (name, med) in report {
            println!("  {name:>7}: {med:?} median");
        }
    }
}

#[test]
#[ignore = "gate bench: run manually with --ignored --nocapture in release"]
fn gate_gapped_train() {
    // The constantinople shape the other gates miss: sub-millisecond parallel phases
    // separated by SERIAL gaps longer than the fixed search window, so an unadaptive
    // parked pool parks between phases and pays a wake round-trip per phase per worker.
    // Sweeps the gap: the adaptive linger should track rayon at every gap at or under
    // LINGER_CAP, and decay back to parking (keeping the parked win) far above it.
    const ITERS: usize = 15;
    const WARMUP: usize = 5;
    const LEVELS: [usize; 6] = [32_768, 16_384, 8_192, 4_096, 2_048, 1_024];
    const ROUNDS: u32 = 40;

    fn busy_wait(gap: Duration) {
        let start = Instant::now();
        let mut x = 1u64;
        while start.elapsed() < gap {
            x = work(x, 8);
        }
        black_box(x);
    }

    let parked = Parked::new(NonZeroUsize::new(WORKERS).unwrap()).manual();
    let rayon = Rayon::new(NonZeroUsize::new(WORKERS).unwrap())
        .unwrap()
        .manual();

    for gap_us in [0u64, 100, 300, 600, 1_000, 5_000] {
        let gap = Duration::from_micros(gap_us);
        let mut report = Vec::new();
        for (name, run_iter) in [
            (
                "parked",
                Box::new(|| {
                    for level in LEVELS {
                        black_box(parked.map_collect_vec(0..level as u64, |i| work(i, ROUNDS)));
                        busy_wait(gap);
                    }
                }) as Box<dyn Fn()>,
            ),
            (
                "rayon",
                Box::new(|| {
                    for level in LEVELS {
                        black_box(rayon.map_collect_vec(0..level as u64, |i| work(i, ROUNDS)));
                        busy_wait(gap);
                    }
                }),
            ),
            (
                "serial",
                Box::new(|| {
                    for level in LEVELS {
                        black_box(
                            crate::Sequential.map_collect_vec(0..level as u64, |i| work(i, ROUNDS)),
                        );
                        busy_wait(gap);
                    }
                }),
            ),
        ] {
            for _ in 0..WARMUP {
                run_iter();
            }
            let mut samples = Vec::with_capacity(ITERS);
            for _ in 0..ITERS {
                let (elapsed, ()) = time(&run_iter);
                samples.push(elapsed);
            }
            report.push((name, median(samples)));
        }
        println!("gate_gapped_train gap={gap_us}us:");
        for (name, med) in report {
            println!("  {name:>7}: {med:?} median/iter");
        }
    }
}
