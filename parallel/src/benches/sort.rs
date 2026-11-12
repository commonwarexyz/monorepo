//! Compare fixed serial sorts with strategy sorts on independently reset inputs.
//!
//! `adaptive_stable` learns only execution mode. `adaptive_unstable` may also learn the
//! algorithm. Neither is a forced parallel baseline. Run the same benchmark at the baseline
//! revision to compare with its execution-only unstable policy.
//!
//! `u64` and `key32` represent QMDB location and evicted-key sorts. `decision` sorts a wider
//! record by its key alone, carrying an inline value, next key, and location. These compare sort
//! costs without reproducing database access or the distribution of a particular replay.
//!
//! For an exact baseline, use `git archive <baseline-revision>` to populate a temporary workspace.
//! Copy the candidate's `parallel/Cargo.toml` and `parallel/src/benches` into it, leaving its
//! library sources unchanged. Run `cargo bench -p commonware-parallel --bench parallel --
//! '<filter>' --save-baseline execution_only` there, then the same command with
//! `--baseline execution_only` in the candidate workspace. Use separate `CARGO_TARGET_DIR`
//! directories so Cargo cannot reuse the other workspace's binary, and set `CRITERION_HOME`
//! to the same absolute directory for both runs. Cargo's workspace bench profile retains
//! overflow checks.

use commonware_parallel::{Rayon, Strategy, ThreadPool, rayon::ThreadPoolBuilder};
use commonware_utils::TestRng;
use criterion::{BatchSize, Criterion, criterion_group};
use rand::Rng;
use std::{cmp::Ordering, hint::black_box, num::NonZeroUsize, sync::Arc, time::Duration};

/// Seed execution choices before recording steady-state samples.
const TRAINING_CALLS: usize = 128;

#[derive(Clone, Copy)]
enum Mode {
    SerialStable,
    SerialUnstable,
    AdaptiveStable,
    AdaptiveUnstable,
}

impl Mode {
    const ALL: [Self; 4] = [
        Self::SerialStable,
        Self::SerialUnstable,
        Self::AdaptiveStable,
        Self::AdaptiveUnstable,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::SerialStable => "serial_stable",
            Self::SerialUnstable => "serial_unstable",
            Self::AdaptiveStable => "adaptive_stable",
            Self::AdaptiveUnstable => "adaptive_unstable",
        }
    }
}

#[derive(Clone, Copy)]
enum Shape {
    Random,
    Sorted,
    Reverse,
    Runs,
    ShortRuns,
    Duplicates,
}

impl Shape {
    const ALL: [Self; 6] = [
        Self::Random,
        Self::Sorted,
        Self::Reverse,
        Self::Runs,
        Self::ShortRuns,
        Self::Duplicates,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Sorted => "sorted",
            Self::Reverse => "reverse",
            Self::Runs => "runs",
            Self::ShortRuns => "short_runs",
            Self::Duplicates => "duplicates",
        }
    }
}

/// Training and measured calls share these call sites so they use the same policy entries.
fn run<T: Send>(
    mode: Mode,
    strategy: &Rayon,
    items: &mut [T],
    compare: impl Fn(&T, &T) -> Ordering + Copy + Send + Sync,
) {
    match mode {
        Mode::SerialStable => items.sort_by(compare),
        Mode::SerialUnstable => items.sort_unstable_by(compare),
        Mode::AdaptiveStable => strategy.sort_by(items, compare),
        Mode::AdaptiveUnstable => strategy.sort_unstable_by(items, compare),
    }
}

fn input<T: Clone>(
    len: usize,
    shape: Shape,
    make: impl Fn(&mut TestRng) -> T,
    compare: impl Fn(&T, &T) -> Ordering + Copy,
) -> Vec<T> {
    let mut rng = TestRng::new(42);
    let mut items: Vec<T> = match shape {
        Shape::Duplicates => {
            let choices: Vec<_> = (0..8).map(|_| make(&mut rng)).collect();
            (0..len)
                .map(|_| choices[(rng.next_u64() % 8) as usize].clone())
                .collect()
        }
        _ => (0..len).map(|_| make(&mut rng)).collect(),
    };
    match shape {
        Shape::Sorted => items.sort_unstable_by(compare),
        Shape::Reverse => items.sort_unstable_by(|a, b| compare(b, a)),
        Shape::Runs => items
            .chunks_mut(128)
            .for_each(|run| run.sort_unstable_by(compare)),
        Shape::ShortRuns => items
            .chunks_mut(16)
            .for_each(|run| run.sort_unstable_by(compare)),
        _ => {}
    }
    items
}

fn bench_type<T: Clone + Send>(
    c: &mut Criterion,
    pool: &ThreadPool,
    item: &str,
    make: impl Fn(&mut TestRng) -> T,
    compare: impl Fn(&T, &T) -> Ordering + Copy + Send + Sync,
) {
    for len in [16, 64, 128, 256, 512, 1024, 16384, 65536] {
        for shape in Shape::ALL {
            let mut source = None;
            for mode in Mode::ALL {
                // A separate policy keeps one input distribution's estimates out of another's.
                let mut strategy = None;
                let mut trained = false;
                c.bench_function(
                    &format!(
                        "{}/item={item} n={len} shape={} mode={} phase=steady threads=4",
                        module_path!(),
                        shape.name(),
                        mode.name(),
                    ),
                    |b| {
                        let source =
                            source.get_or_insert_with(|| input(len, shape, &make, compare));
                        let strategy =
                            strategy.get_or_insert_with(|| Rayon::with_pool(Arc::clone(pool)));
                        if !trained {
                            if matches!(mode, Mode::AdaptiveStable | Mode::AdaptiveUnstable) {
                                for _ in 0..TRAINING_CALLS {
                                    let mut items = source.clone();
                                    run(mode, strategy, &mut items, compare);
                                    black_box(items);
                                }
                            }
                            trained = true;
                        }
                        b.iter_batched_ref(
                            || source.clone(),
                            |items| {
                                run(mode, strategy, black_box(items), compare);
                                black_box(items.as_slice());
                            },
                            BatchSize::LargeInput,
                        );
                    },
                );
            }
        }
    }

    let len = 1024;
    let mut source = None;
    for mode in [Mode::AdaptiveStable, Mode::AdaptiveUnstable] {
        c.bench_function(
            &format!(
                "{}/item={item} n={len} shape=random mode={} phase=cold threads=4",
                module_path!(),
                mode.name(),
            ),
            |b| {
                let source =
                    source.get_or_insert_with(|| input(len, Shape::Random, &make, compare));
                // Pool and strategy construction are outside the timed first sort. The new
                // policy entry and initial dispatch remain inside it.
                b.iter_batched_ref(
                    || (Rayon::with_pool(Arc::clone(pool)), source.clone()),
                    |(strategy, items)| {
                        run(mode, strategy, black_box(items), compare);
                        black_box(items.as_slice());
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

fn bench_sort(c: &mut Criterion) {
    let pool = Arc::new(
        ThreadPoolBuilder::new(NonZeroUsize::new(4).unwrap())
            .build()
            .unwrap(),
    );
    bench_type(c, &pool, "u64", |rng| rng.next_u64(), Ord::cmp);
    bench_type(
        c,
        &pool,
        "loc_slot",
        |rng| (rng.next_u64(), rng.next_u64() as usize),
        Ord::cmp,
    );
    let key = |rng: &mut TestRng| {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    };
    bench_type(c, &pool, "key32", key, Ord::cmp);
    bench_type(
        c,
        &pool,
        "decision",
        |rng| (key(rng), key(rng), key(rng), rng.next_u64()),
        |a, b| a.0.cmp(&b.0),
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(500));
    targets = bench_sort,
}
