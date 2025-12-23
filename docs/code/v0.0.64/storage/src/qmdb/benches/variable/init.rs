//! Benchmark the initialization performance of each QMDB variant on a large randomly generated
//! database with variable-sized values.

use crate::variable::{
    gen_random_kv, get_any_ordered, get_any_unordered, get_store, Variant, VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Runner},
    Runner as _,
};
use criterion::{criterion_group, Criterion};
use std::time::Instant;

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const ELEMENTS: [u64; 1] = [NUM_ELEMENTS];
        const OPERATIONS: [u64; 1] = [NUM_OPERATIONS];
    } else {
        const ELEMENTS: [u64; 2] = [NUM_ELEMENTS, NUM_ELEMENTS * 10];
        const OPERATIONS: [u64; 2] = [NUM_OPERATIONS, NUM_OPERATIONS * 10];
    }
}

/// Benchmark the initialization of a large randomly generated any db.
fn bench_variable_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in VARIANTS {
                let runner = Runner::new(cfg.clone());
                runner.start(|ctx| async move {
                    match variant {
                        Variant::Store => {
                            let db = get_store(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, COMMIT_FREQUENCY).await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::AnyUnordered => {
                            let db = get_any_unordered(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, COMMIT_FREQUENCY).await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::AnyOrdered => {
                            let db = get_any_ordered(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, COMMIT_FREQUENCY).await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                    }
                });
                let runner = tokio::Runner::new(cfg.clone());

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
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let start = Instant::now();
                            for _ in 0..iters {
                                match variant {
                                    Variant::Store => {
                                        let db = get_store(ctx.clone()).await;
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::AnyUnordered => {
                                        let db = get_any_unordered(ctx.clone()).await;
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::AnyOrdered => {
                                        let db = get_any_ordered(ctx.clone()).await;
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                }
                            }

                            start.elapsed()
                        });
                    },
                );

                let runner = Runner::new(cfg.clone());
                runner.start(|ctx| async move {
                    // Clean up the databases after the benchmark.
                    match variant {
                        Variant::Store => {
                            let db = get_store(ctx).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::AnyUnordered => {
                            let db = get_any_unordered(ctx).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::AnyOrdered => {
                            let db = get_any_ordered(ctx).await;
                            db.destroy().await.unwrap();
                        }
                    }
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_init
}
