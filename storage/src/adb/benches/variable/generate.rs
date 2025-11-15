//! Benchmark the generation of a large database with values of varying sizes for each (a)db variant
//! that supports variable-size values.

use crate::variable::{gen_random_kv, get_any, get_store, Variant, VARIANTS};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::adb::store::Db as _;
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
                                let start = Instant::now();
                                let commit_frequency = (operations / COMMITS_PER_ITERATION) as u32;
                                match variant {
                                    Variant::Store => {
                                        let db = get_store(ctx.clone()).await;
                                        let db = gen_random_kv(
                                            db,
                                            elements,
                                            operations,
                                            commit_frequency,
                                        )
                                        .await;
                                        total_elapsed += start.elapsed();
                                        db.destroy().await.unwrap(); // don't time destroy
                                    }
                                    Variant::Any => {
                                        let db = get_any(ctx.clone()).await;
                                        let db = gen_random_kv(
                                            db,
                                            elements,
                                            operations,
                                            commit_frequency,
                                        )
                                        .await;
                                        total_elapsed += start.elapsed();
                                        db.destroy().await.unwrap(); // don't time destroy
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_generate
}
