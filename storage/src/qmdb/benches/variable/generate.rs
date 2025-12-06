//! Benchmark the generation of a large database with values of varying sizes for each (a)db variant
//! that supports variable-size values.

use crate::variable::{
    gen_random_kv, gen_random_kv_batched, get_any, get_store, Variant, VARIANTS,
};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{
    qmdb::{
        store::{Batchable, LogStorePrunable},
        Error,
    },
    store::{StoreDeletable, StorePersistable},
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;

/// Benchmark the generation of a large randomly generated any db.
fn bench_variable_generate(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VARIANTS {
                for use_batch in [false, true] {
                    c.bench_function(
                        &format!(
                            "{}/variant={} batched={} elements={} operations={}",
                            module_path!(),
                            variant.name(),
                            use_batch,
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
                                    let elapsed = match variant {
                                        Variant::Store => {
                                            let db = get_store(ctx.clone()).await;
                                            test_db(
                                                db,
                                                use_batch,
                                                elements,
                                                operations,
                                                commit_frequency,
                                            )
                                            .await
                                            .unwrap()
                                        }
                                        Variant::Any => {
                                            let db = get_any(ctx.clone()).await;
                                            test_db(
                                                db,
                                                use_batch,
                                                elements,
                                                operations,
                                                commit_frequency,
                                            )
                                            .await
                                            .unwrap()
                                        }
                                    };
                                    total_elapsed += elapsed;
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

async fn test_db<A>(
    db: A,
    use_batch: bool,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
) -> Result<Duration, Error>
where
    A: StorePersistable<Key = <Sha256 as Hasher>::Digest, Value = Vec<u8>>
        + Batchable
        + StoreDeletable
        + LogStorePrunable,
{
    let start = Instant::now();
    let db = if use_batch {
        gen_random_kv_batched(db, elements, operations, commit_frequency).await
    } else {
        gen_random_kv(db, elements, operations, commit_frequency).await
    };
    let elapsed = start.elapsed();
    db.destroy().await?;
    Ok(elapsed)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_generate
}
