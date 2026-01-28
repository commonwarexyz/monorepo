//! Benchmark each QMDB variant on the generation of a large randomly generated database with
//! fixed-size values.

use crate::fixed::{
    gen_random_kv, gen_random_kv_batched, get_any_ordered_fixed, get_any_ordered_variable,
    get_any_unordered_fixed, get_any_unordered_variable, get_current_ordered_fixed,
    get_current_ordered_variable, get_current_unordered_fixed, get_current_unordered_variable,
    Digest, Variant, VARIANTS,
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

/// Benchmark the generation of a large randomly generated database.
fn bench_fixed_generate(c: &mut Criterion) {
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for variant in VARIANTS {
                for use_batch in [false, true] {
                    let runner = tokio::Runner::new(Config::default().clone());
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
                                    let duration = match variant {
                                        Variant::AnyUnorderedFixed => {
                                            let db = get_any_unordered_fixed(ctx.clone()).await;
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
                                        Variant::AnyOrderedFixed => {
                                            let db = get_any_ordered_fixed(ctx.clone()).await;
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
                                        Variant::AnyUnorderedVariable => {
                                            let db = get_any_unordered_variable(ctx.clone()).await;
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
                                        Variant::AnyOrderedVariable => {
                                            let db = get_any_ordered_variable(ctx.clone()).await;
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
                                        Variant::CurrentUnorderedFixed => {
                                            let db = get_current_unordered_fixed(ctx.clone()).await;
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
                                        Variant::CurrentOrderedFixed => {
                                            let db = get_current_ordered_fixed(ctx.clone()).await;
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
                                        Variant::CurrentUnorderedVariable => {
                                            let db =
                                                get_current_unordered_variable(ctx.clone()).await;
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
                                        Variant::CurrentOrderedVariable => {
                                            let db =
                                                get_current_ordered_variable(ctx.clone()).await;
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
                                    total_elapsed += duration;
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
    C::Mutable: MutableAny<Key = Digest> + LogStore<Value = Digest>,
    <C::Mutable as MutableAny>::Durable:
        UnmerkleizedDurableAny<Mutable = C::Mutable, Merkleized = C>,
{
    let start = Instant::now();

    // Convert clean → mutable
    let mutable = db.into_mutable();

    // Generate random operations, returns in durable state
    let durable = if use_batch {
        gen_random_kv_batched(mutable, elements, operations, Some(commit_frequency)).await
    } else {
        gen_random_kv(mutable, elements, operations, Some(commit_frequency)).await
    };

    // Convert durable → provable (clean) for pruning
    let mut clean = durable.into_merkleized().await?;
    clean.prune(clean.inactivity_floor_loc()).await?;
    clean.sync().await?;

    let res = start.elapsed();
    clean.destroy().await?; // don't time destroy

    Ok(res)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_generate
}
