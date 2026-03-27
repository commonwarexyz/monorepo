//! Benchmarks for QMDB point lookups (`db.get(key)`).
//!
//! Pre-populates a database, then measures the time to perform random key lookups.

use crate::common::{
    make_fixed_value, make_var_value, populate_and_sync, seeded_keys, with_fixed_value_db,
    with_var_value_db, Digest, FIXED_VALUE_VARIANTS, VAR_VALUE_VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Runner as _,
};
use commonware_storage::qmdb::any::traits::DbAny;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::time::{Duration, Instant};

const NUM_OPERATIONS: u64 = 10_000;
const COMMIT_FREQUENCY: u32 = 1_000;
const NUM_READS: usize = 1_000;

async fn bench_gets<C: DbAny<Key = Digest>>(db: &C, keys: &[Digest]) -> Duration {
    let mut rng = StdRng::seed_from_u64(99);
    let sample: Vec<_> = keys.choose_multiple(&mut rng, NUM_READS).collect();
    let start = Instant::now();
    for key in &sample {
        let _ = db.get(key).await.unwrap();
    }
    start.elapsed()
}

fn bench_fixed_value_get(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in [10_000u64, 100_000] {
        let keys = seeded_keys(elements);
        for variant in FIXED_VALUE_VARIANTS {
            // Setup: populate database
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                with_fixed_value_db!(ctx, variant, |mut db| {
                    populate_and_sync(
                        &mut db,
                        elements,
                        NUM_OPERATIONS,
                        COMMIT_FREQUENCY,
                        make_fixed_value,
                    )
                    .await;
                });
            });

            // Benchmark: measure get time on freshly-opened instance
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!(
                    "{}/variant={} elements={elements} reads={NUM_READS}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    let keys = keys.clone();
                    b.to_async(&runner).iter_custom(|iters| {
                        let keys = keys.clone();
                        async move {
                            let ctx = context::get::<Context>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += with_fixed_value_db!(ctx, variant, |mut db| {
                                    bench_gets(&db, &keys).await
                                });
                            }
                            total
                        }
                    });
                },
            );

            // Cleanup
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                with_fixed_value_db!(ctx, variant, |mut db| {
                    db.destroy().await.unwrap();
                });
            });
        }
    }
}

fn bench_var_value_get(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in [10_000u64, 100_000] {
        let keys = seeded_keys(elements);
        for variant in VAR_VALUE_VARIANTS {
            // Setup: populate database
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                with_var_value_db!(ctx, variant, |mut db| {
                    populate_and_sync(
                        &mut db,
                        elements,
                        NUM_OPERATIONS,
                        COMMIT_FREQUENCY,
                        make_var_value,
                    )
                    .await;
                });
            });

            // Benchmark: measure get time on freshly-opened instance
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!(
                    "{}/variant={} elements={elements} reads={NUM_READS}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    let keys = keys.clone();
                    b.to_async(&runner).iter_custom(|iters| {
                        let keys = keys.clone();
                        async move {
                            let ctx = context::get::<Context>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += with_var_value_db!(ctx, variant, |mut db| {
                                    bench_gets(&db, &keys).await
                                });
                            }
                            total
                        }
                    });
                },
            );

            // Cleanup
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                with_var_value_db!(ctx, variant, |mut db| {
                    db.destroy().await.unwrap();
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_get, bench_var_value_get
}
