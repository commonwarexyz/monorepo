//! Benchmarks for QMDB database generation (write-heavy workloads).
//!
//! Measures the time to seed a database and perform random updates/deletes across all keyed
//! variants (fixed-value, variable-value) and the keyless variant.

use crate::common::{
    gen_random_kv, make_fixed_value, make_var_value, open_keyless_db, with_fixed_value_db,
    with_var_value_db, Digest, FIXED_VALUE_VARIANTS, VAR_VALUE_VARIANTS,
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
async fn bench_db<C: DbAny<commonware_storage::merkle::mmr::Family, Key = Digest>>(
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
    db.prune(db.sync_boundary().await).await.unwrap();
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

fn bench_keyless_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for operations in [KEYLESS_OPS, KEYLESS_OPS * 2] {
        c.bench_function(
            &format!("{}/variant=keyless operations={operations}", module_path!()),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();

                        let mut db = open_keyless_db(ctx.clone()).await;
                        let mut rng = StdRng::seed_from_u64(42);
                        let mut batch = db.new_batch();
                        for _ in 0u64..operations {
                            let v = make_var_value(&mut rng);
                            batch = batch.append(v);
                            if rng.next_u32() % KEYLESS_COMMIT_FREQ == 0 {
                                let merkleized =
                                    batch.merkleize(&db, None, db.inactivity_floor_loc());
                                db.apply_batch(merkleized).await.unwrap();
                                batch = db.new_batch();
                            }
                        }
                        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
                        db.apply_batch(merkleized).await.unwrap();
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
    targets = bench_fixed_value_generate, bench_var_value_generate, bench_keyless_generate
}
