//! Benchmark the generation of a large database with values of varying sizes for each (a)db variant
//! that supports variable-size values.

use crate::variable::{
    gen_random_kv, gen_random_kv_batcher, get_any, get_store, Variant, VARIANTS,
};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{
    adb::store::{batcher::Batcher, Db},
    translator::EightCap,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;

/// Benchmark the generation of a large randomly generated any db.
fn bench_variable_generate(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VARIANTS {
                for use_batcher in [false, true] {
                    c.bench_function(
                        &format!(
                            "{}/variant={} batched={} elements={} operations={}",
                            module_path!(),
                            variant.name(),
                            use_batcher,
                            elements,
                            operations,
                        ),
                        |b| {
                            b.to_async(&runner).iter_custom(|iters| async move {
                                let ctx = context::get::<Context>();
                                let mut total_elapsed = Duration::ZERO;
                                for _ in 0..iters {
                                    let commit_frequency =
                                        (operations / COMMITS_PER_ITERATION) as u32;
                                    match variant {
                                        Variant::Store => {
                                            let db = get_store(ctx.clone()).await;
                                            total_elapsed += test_db(
                                                db,
                                                use_batcher,
                                                elements,
                                                operations,
                                                commit_frequency,
                                            )
                                            .await
                                            .unwrap();
                                        }
                                        Variant::Any => {
                                            let db = get_any(ctx.clone()).await;
                                            total_elapsed += test_db(
                                                db,
                                                use_batcher,
                                                elements,
                                                operations,
                                                commit_frequency,
                                            )
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
}

async fn test_db<A: Db<Context, <Sha256 as Hasher>::Digest, Vec<u8>, EightCap>>(
    mut db: A,
    use_batcher: bool,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
) -> Result<Duration, commonware_storage::adb::Error> {
    let start = Instant::now();

    if use_batcher {
        let mut batched_db = Batcher::new(db);
        gen_random_kv_batcher(&mut batched_db, elements, operations, commit_frequency).await;
        db = batched_db.take().await?;
        db.sync().await.unwrap();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
    } else {
        db = gen_random_kv(db, elements, operations, commit_frequency).await;
    };
    let elapsed = start.elapsed();

    db.destroy().await.unwrap(); // don't time destroy

    Ok(elapsed)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_generate
}
