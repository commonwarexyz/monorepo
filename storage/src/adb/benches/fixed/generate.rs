//! Benchmark each ADB variant on the generation of a large randomly generated database with
//! fixed-size values.

use crate::fixed::{
    gen_random_kv, get_ordered_any, get_ordered_current, get_store, get_unordered_any,
    get_unordered_current, get_variable_any, Variant, VARIANTS,
};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{adb::store::Db, translator::EightCap};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;

/// Benchmark the generation of a large randomly generated [Db].
fn bench_fixed_generate(c: &mut Criterion) {
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VARIANTS {
                let runner = tokio::Runner::new(Config::default().clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={} operations={}",
                        module_path!(),
                        variant.name(),
                        elements,
                        operations,
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let mut total_elapsed = Duration::ZERO;
                            for _ in 0..iters {
                                let commit_frequency = (operations / COMMITS_PER_ITERATION) as u32;
                                match variant {
                                    Variant::AnyUnordered => {
                                        let db = get_unordered_any(ctx.clone()).await;
                                        total_elapsed +=
                                            test_db(db, elements, operations, commit_frequency)
                                                .await
                                                .unwrap();
                                    }
                                    Variant::AnyOrdered => {
                                        let db = get_ordered_any(ctx.clone()).await;
                                        total_elapsed +=
                                            test_db(db, elements, operations, commit_frequency)
                                                .await
                                                .unwrap();
                                    }
                                    Variant::Store => {
                                        let db = get_store(ctx.clone()).await;
                                        total_elapsed +=
                                            test_db(db, elements, operations, commit_frequency)
                                                .await
                                                .unwrap();
                                    }
                                    Variant::Variable => {
                                        let db = get_variable_any(ctx.clone()).await;
                                        total_elapsed +=
                                            test_db(db, elements, operations, commit_frequency)
                                                .await
                                                .unwrap();
                                    }
                                    Variant::CurrentUnordered => {
                                        let db = get_unordered_current(ctx.clone()).await;
                                        total_elapsed +=
                                            test_db(db, elements, operations, commit_frequency)
                                                .await
                                                .unwrap();
                                    }
                                    Variant::CurrentOrdered => {
                                        let db = get_ordered_current(ctx.clone()).await;
                                        total_elapsed +=
                                            test_db(db, elements, operations, commit_frequency)
                                                .await
                                                .unwrap();
                                    }
                                }
                            }
                            total_elapsed
                        });
                    },
                );
            }
        }
    }
}

async fn test_db<
    A: Db<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, EightCap>,
>(
    db: A,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
) -> Result<Duration, commonware_storage::adb::Error> {
    let start = Instant::now();
    let mut db = gen_random_kv(db, elements, operations, Some(commit_frequency)).await;
    db.sync().await?;
    db.prune(db.inactivity_floor_loc()).await?;
    let res = start.elapsed();
    db.destroy().await?; // don't time destroy

    Ok(res)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_generate
}
