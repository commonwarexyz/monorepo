//! Benchmark the startup initialization performance of each QMDB variant on a large randomly
//! generated database with fixed-size values.

use crate::fixed::{
    any_cfg, current_cfg, gen_random_kv, get_any_ordered_fixed, get_any_ordered_variable,
    get_any_unordered_fixed, get_any_unordered_variable, get_current_ordered_fixed,
    get_current_unordered_fixed, get_store, store_cfg, variable_any_cfg, OAnyDb, OCurrentDb,
    OVAnyDb, StoreDb, UAnyDb, UCurrentDb, UVAnyDb, Variant, THREADS, VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Runner},
    Runner as _,
};
use commonware_storage::qmdb::{
    any::AnyExt,
    store::{LogStore, LogStorePrunable},
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
fn bench_fixed_init(c: &mut Criterion) {
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
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::AnyUnorderedFixed => {
                            let db = get_any_unordered_fixed(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::AnyOrderedFixed => {
                            let db = get_any_ordered_fixed(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::CurrentUnorderedFixed => {
                            let db = get_current_unordered_fixed(ctx.clone()).await;
                            let db = AnyExt::new(db);
                            let mut db =
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::CurrentOrderedFixed => {
                            let db = get_current_ordered_fixed(ctx.clone()).await;
                            let db = AnyExt::new(db);
                            let mut db =
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::AnyUnorderedVariable => {
                            let db = get_any_unordered_variable(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                        Variant::AnyOrderedVariable => {
                            let db = get_any_ordered_variable(ctx.clone()).await;
                            let mut db =
                                gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY))
                                    .await;
                            db.prune(db.inactivity_floor_loc()).await.unwrap();
                            db.close().await.unwrap();
                        }
                    }
                });
                let runner = tokio::Runner::new(cfg.clone());

                c.bench_function(
                    &format!(
                        "{}/variant={}, elements={} operations={}",
                        module_path!(),
                        variant.name(),
                        elements,
                        operations,
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let pool =
                                commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();
                            let any_cfg = any_cfg(pool.clone());
                            let current_cfg = current_cfg(pool.clone());
                            let variable_any_cfg = variable_any_cfg(pool);
                            let store_cfg = store_cfg();
                            let start = Instant::now();
                            for _ in 0..iters {
                                match variant {
                                    Variant::Store => {
                                        let db = StoreDb::init(ctx.clone(), store_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::AnyUnorderedFixed => {
                                        let db = UAnyDb::init(ctx.clone(), any_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::AnyOrderedFixed => {
                                        let db = OAnyDb::init(ctx.clone(), any_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::CurrentUnorderedFixed => {
                                        let db = UCurrentDb::init(ctx.clone(), current_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::CurrentOrderedFixed => {
                                        let db = OCurrentDb::init(ctx.clone(), current_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::AnyUnorderedVariable => {
                                        let db =
                                            UVAnyDb::init(ctx.clone(), variable_any_cfg.clone())
                                                .await
                                                .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                        db.close().await.unwrap();
                                    }
                                    Variant::AnyOrderedVariable => {
                                        let db =
                                            OVAnyDb::init(ctx.clone(), variable_any_cfg.clone())
                                                .await
                                                .unwrap();
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
                    // Clean up the database after the benchmark.
                    match variant {
                        Variant::Store => {
                            let db = get_store(ctx.clone()).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::AnyUnorderedFixed => {
                            let db = get_any_unordered_fixed(ctx.clone()).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::AnyOrderedFixed => {
                            let db = get_any_ordered_fixed(ctx.clone()).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::CurrentUnorderedFixed => {
                            let db = get_current_unordered_fixed(ctx.clone()).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::CurrentOrderedFixed => {
                            let db = get_current_ordered_fixed(ctx.clone()).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::AnyUnorderedVariable => {
                            let db = get_any_unordered_variable(ctx.clone()).await;
                            db.destroy().await.unwrap();
                        }
                        Variant::AnyOrderedVariable => {
                            let db = get_any_ordered_variable(ctx.clone()).await;
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
    targets = bench_fixed_init
}
