//! Benchmark the generation of a large database with values of varying sizes for each (a)db variant
//! that supports variable-size values.

use crate::variable::{
    gen_random_kv, gen_random_kv_batched, get_any_ordered, get_any_unordered, Digest, Variant,
    VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::qmdb::{
    any::states::{CleanAny, MutableAny, UnmerkleizedDurableAny},
    store::LogStore,
    Error,
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
                                        Variant::AnyUnordered => {
                                            let db = get_any_unordered(ctx.clone()).await;
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
                                        Variant::AnyOrdered => {
                                            let db = get_any_ordered(ctx.clone()).await;
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

/// Test the database generation and cleanup.
///
/// Takes a clean database, converts to mutable, generates data, then prunes and destroys.
async fn test_db<C>(
    db: C,
    use_batch: bool,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
) -> Result<Duration, Error>
where
    C: CleanAny<Key = Digest>,
    C::Mutable: MutableAny<Key = Digest> + LogStore<Value = Vec<u8>>,
    <C::Mutable as MutableAny>::Durable:
        UnmerkleizedDurableAny<Mutable = C::Mutable, Merkleized = C>,
{
    let start = Instant::now();

    // Convert clean → mutable
    let mutable = db.into_mutable();

    // Generate random operations, returns in durable state
    let durable = if use_batch {
        gen_random_kv_batched(mutable, elements, operations, commit_frequency).await
    } else {
        gen_random_kv(mutable, elements, operations, commit_frequency).await
    };

    // Convert durable → provable (clean) for pruning
    let mut clean = durable.into_merkleized().await?;
    clean.prune(clean.inactivity_floor_loc()).await?;
    clean.sync().await?;

    let elapsed = start.elapsed();
    clean.destroy().await?; // don't time destroy

    Ok(elapsed)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_generate
}
