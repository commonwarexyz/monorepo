//! Benchmarks for QMDB database generation (write-heavy workloads).
//!
//! Measures the time to seed a database and perform random updates/deletes across all keyed
//! variants (fixed-value, variable-value) and the keyless variant.

use crate::common::{
    gen_random_kv, keyless_cfg, make_fixed_value, make_var_value, with_fixed_value_db,
    with_var_value_db, Digest, KeylessMmbDb, KeylessMmrDb, FIXED_VALUE_VARIANTS,
    VAR_VALUE_VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::qmdb::any::traits::DbAny;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;

/// Benchmark a populated database: generate data, prune, sync. Returns elapsed time (excluding
/// destroy).
async fn bench_db<F: commonware_storage::merkle::Family, C: DbAny<F, Key = Digest>>(
    mut db: C,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
    make_value: impl Fn(&mut StdRng) -> C::Value,
) -> Duration {
    let start = Instant::now();
    gen_random_kv(
        &mut db,
        elements,
        operations,
        Some(commit_frequency),
        make_value,
    )
    .await;
    db.prune(db.inactivity_floor_loc().await).await.unwrap();
    db.sync().await.unwrap();
    let elapsed = start.elapsed();
    db.destroy().await.unwrap();
    elapsed
}

fn bench_fixed_value_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in FIXED_VALUE_VARIANTS {
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let commit_freq = (operations / COMMITS_PER_ITERATION) as u32;
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += with_fixed_value_db!(ctx, variant, |mut db| {
                                    bench_db(
                                        db,
                                        elements,
                                        operations,
                                        commit_freq,
                                        make_fixed_value,
                                    )
                                    .await
                                });
                            }
                            total
                        });
                    },
                );
            }
        }
    }
}

fn bench_var_value_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VAR_VALUE_VARIANTS {
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let commit_freq = (operations / COMMITS_PER_ITERATION) as u32;
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += with_var_value_db!(ctx, variant, |mut db| {
                                    bench_db(db, elements, operations, commit_freq, make_var_value)
                                        .await
                                });
                            }
                            total
                        });
                    },
                );
            }
        }
    }
}

const KEYLESS_OPS: u64 = 10_000;
const KEYLESS_COMMIT_FREQ: u32 = 25;

macro_rules! bench_keyless_one {
    ($ctx:expr, $operations:expr, $DbType:ty) => {{
        let start = Instant::now();
        let cfg = keyless_cfg(&$ctx);
        let mut db = <$DbType>::init($ctx.clone(), cfg).await.unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let mut batch = db.new_batch();
        for _ in 0u64..$operations {
            let v = make_var_value(&mut rng);
            batch = batch.append(v);
            if rng.next_u32() % KEYLESS_COMMIT_FREQ == 0 {
                let finalized = batch.merkleize(None).finalize();
                db.apply_batch(finalized).await.unwrap();
                batch = db.new_batch();
            }
        }
        let finalized = batch.merkleize(None).finalize();
        db.apply_batch(finalized).await.unwrap();
        db.sync().await.unwrap();
        let elapsed = start.elapsed();
        db.destroy().await.unwrap();
        elapsed
    }};
}

fn bench_keyless_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for operations in [KEYLESS_OPS, KEYLESS_OPS * 2] {
        for (name, is_mmb) in [("mmr", false), ("mmb", true)] {
            c.bench_function(
                &format!("{}/family={name} operations={operations}", module_path!()),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += if is_mmb {
                                bench_keyless_one!(ctx, operations, KeylessMmbDb)
                            } else {
                                bench_keyless_one!(ctx, operations, KeylessMmrDb)
                            };
                        }
                        total
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_generate, bench_var_value_generate, bench_keyless_generate
}
