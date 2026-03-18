//! Benchmarks for QMDB database generation (write-heavy workloads).
//!
//! Measures the time to seed a database and perform random updates/deletes across all keyed
//! variants (fixed-value, variable-value) and the keyless variant.

use crate::common::{
    gen_random_kv, keyless_cfg, make_fixed_value, make_variable_value, with_fixed_db,
    with_variable_db, Digest, KeylessDb, FIXED_VARIANTS, VARIABLE_VARIANTS,
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
async fn bench_db<C: DbAny<Key = Digest>>(
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

fn bench_fixed_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in FIXED_VARIANTS {
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
                                total += with_fixed_db!(ctx, variant, |mut db| {
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

fn bench_variable_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VARIABLE_VARIANTS {
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
                                total += with_variable_db!(ctx, variant, |mut db| {
                                    bench_db(
                                        db,
                                        elements,
                                        operations,
                                        commit_freq,
                                        make_variable_value,
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

const KEYLESS_OPS: u64 = 10_000;
const KEYLESS_COMMIT_FREQ: u32 = 25;

fn bench_keyless_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for operations in [KEYLESS_OPS, KEYLESS_OPS * 2] {
        c.bench_function(
            &format!("{}/operations={operations}", module_path!()),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();

                        let cfg = keyless_cfg(&ctx);
                        let mut db = KeylessDb::init(ctx.clone(), cfg).await.unwrap();
                        let mut rng = StdRng::seed_from_u64(42);
                        let mut batch = db.new_batch();
                        for _ in 0u64..operations {
                            let v = make_variable_value(&mut rng);
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

                        total += start.elapsed();
                        db.destroy().await.unwrap();
                    }
                    total
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_generate, bench_variable_generate, bench_keyless_generate
}
