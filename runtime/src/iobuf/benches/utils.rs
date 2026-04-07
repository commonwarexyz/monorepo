//! Shared helpers for `iobuf` benchmarks.
//!
//! The benchmark modules in this directory share the same small set of
//! threading presets and the same timing harness:
//!
//! - [`Threading`] defines the single-threaded and multi-threaded benchmark
//!   shapes used by both suites.
//! - [`Pattern`] describes the multi-threaded synchronization style:
//!   - `Lockstep`: all workers enter the hot path together, maximizing
//!     contention.
//!   - `Staggered`: workers add a small variable spin delay between iterations
//!     to decorrelate access timing.
//! - [`measure`] runs the benchmark body under those presets, including the
//!   barrier synchronization used by the multi-threaded cases.
//!
//! Keeping these helpers in one place ensures that the `pool` and `freelist`
//! benchmarks use the same contention patterns and wall-clock measurement
//! rules.

use std::{
    hint::spin_loop,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

const MIN_BENCH_THREADS: usize = 2;
const MAX_BENCH_THREADS: usize = 8;

#[derive(Clone, Copy)]
pub enum Pattern {
    /// All workers enter the hot path together, maximizing contention.
    Lockstep,
    /// Workers add a small spin delay to decorrelate access timing.
    Staggered,
}

impl Pattern {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lockstep => "lockstep",
            Self::Staggered => "staggered",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Threading {
    Single,
    Multi { threads: usize, pattern: Pattern },
}

impl Threading {
    pub fn standard() -> [Self; 3] {
        let threads = std::thread::available_parallelism().map_or(MIN_BENCH_THREADS, |n| {
            n.get().clamp(MIN_BENCH_THREADS, MAX_BENCH_THREADS)
        });
        [
            Self::Single,
            Self::Multi {
                threads,
                pattern: Pattern::Lockstep,
            },
            Self::Multi {
                threads,
                pattern: Pattern::Staggered,
            },
        ]
    }

    pub const fn threads(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Multi { threads, .. } => threads,
        }
    }
}

/// Measure `iters` repetitions of `step`.
///
/// `setup` runs per-worker before timing starts and returns state passed to
/// each `step` invocation. For multi-threaded runs, all workers synchronize
/// via a barrier after setup so timing captures concurrent execution only.
pub fn measure<T>(
    iters: u64,
    threading: Threading,
    setup: impl Fn() -> T + Sync,
    step: impl Fn(&mut T) + Sync,
) -> Duration {
    let Threading::Multi { threads, pattern } = threading else {
        let mut state = setup();
        let start = Instant::now();
        for _ in 0..iters {
            step(&mut state);
        }
        return start.elapsed();
    };

    let start = thread::scope(|scope| {
        let ready = Arc::new(Barrier::new(threads + 1));
        let launch = Arc::new(Barrier::new(threads + 1));

        for thread_id in 0..threads {
            let ready = ready.clone();
            let launch = launch.clone();
            let setup = &setup;
            let step = &step;
            scope.spawn(move || {
                let mut state = setup();
                ready.wait();
                launch.wait();
                for iter in 0..iters {
                    step(&mut state);

                    if matches!(pattern, Pattern::Staggered) {
                        // Desynchronize threads so they don't all hit the
                        // allocator at once. This spreads access times apart
                        // without adding enough delay to dominate the
                        // measurement.
                        let spins = (iter as usize).wrapping_add(1).wrapping_mul(
                            thread_id
                                .wrapping_mul(MAX_BENCH_THREADS - 1)
                                .wrapping_add(1),
                        ) & 0xF;

                        for _ in 0..spins {
                            spin_loop();
                        }
                    }
                }
            });
        }

        ready.wait();
        let start = Instant::now();
        launch.wait();
        start
    });

    start.elapsed()
}
