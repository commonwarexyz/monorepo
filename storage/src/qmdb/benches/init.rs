//! Benchmarks for QMDB startup initialization performance.
//!
//! These benchmarks have expensive setup (generating large random databases) and are separated
//! from the generation benchmarks so they can be filtered easily.

use crate::common::{
    make_fixed_value, make_var_value, populate_and_sync, with_fixed_value_db, with_var_value_db,
    FIXED_VALUE_VARIANTS, VAR_VALUE_VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Runner as _,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const ELEMENTS: [u64; 1] = [NUM_ELEMENTS];
        const OPERATIONS: [u64; 1] = [NUM_OPERATIONS];
    } else {
        const ELEMENTS: [u64; 2] = [NUM_ELEMENTS, NUM_ELEMENTS * 10];
        const OPERATIONS: [u64; 2] = [NUM_OPERATIONS, NUM_OPERATIONS * 10];
    }
}

fn bench_fixed_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in FIXED_VALUE_VARIANTS {
                // Setup: populate database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_fixed_value_db!(ctx, variant, |mut db| {
                        populate_and_sync(
                            &mut db,
                            elements,
                            operations,
                            COMMIT_FREQUENCY,
                            make_fixed_value,
                        )
                        .await;
                    });
                });

                // Benchmark: measure init time (excluding config construction)
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                let start = Instant::now();
                                with_fixed_value_db!(ctx, variant, |mut db| {
                                    assert_ne!(db.bounds().await.end, 0);
                                });
                                total += start.elapsed();
                            }
                            total
                        });
                    },
                );

                // Cleanup: destroy database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_fixed_value_db!(ctx, variant, |mut db| {
                        db.destroy().await.unwrap();
                    });
                });
            }
        }
    }
}

fn bench_var_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in VAR_VALUE_VARIANTS {
                // Setup: populate database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_var_value_db!(ctx, variant, |mut db| {
                        populate_and_sync(
                            &mut db,
                            elements,
                            operations,
                            COMMIT_FREQUENCY,
                            make_var_value,
                        )
                        .await;
                    });
                });

                // Benchmark: measure init time (excluding config construction)
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                let start = Instant::now();
                                with_var_value_db!(ctx, variant, |mut db| {
                                    assert_ne!(db.bounds().await.end, 0);
                                });
                                total += start.elapsed();
                            }
                            total
                        });
                    },
                );

                // Cleanup: destroy database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_var_value_db!(ctx, variant, |mut db| {
                        db.destroy().await.unwrap();
                    });
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_init, bench_var_value_init
}
