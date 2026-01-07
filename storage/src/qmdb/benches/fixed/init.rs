//! Benchmark the startup initialization performance of each QMDB variant on a large randomly
//! generated database with fixed-size values.

use crate::fixed::{
    any_cfg, current_cfg, gen_random_kv, get_any_ordered_fixed, get_any_ordered_variable,
    get_any_unordered_fixed, get_any_unordered_variable, get_current_ordered_fixed,
    get_current_unordered_fixed, variable_any_cfg, Digest, OCurrentDb, OFixedDb, OVAnyDb,
    UCurrentDb, UFixedDb, UVAnyDb, Variant, THREADS, VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Runner},
    RayonPoolSpawner, Runner as _,
};
use commonware_storage::qmdb::{
    any::states::{CleanAny, MutableAny, UnmerkleizedDurableAny},
    store::LogStore,
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

/// Helper function to setup a database with random data, prune, and close it.
async fn setup_db<C>(db: C, elements: u64, operations: u64)
where
    C: CleanAny<Key = Digest>,
    C::Mutable: MutableAny<Key = Digest> + LogStore<Value = Digest>,
    <C::Mutable as MutableAny>::Durable:
        UnmerkleizedDurableAny<Mutable = C::Mutable, Merkleized = C>,
{
    let mutable = db.into_mutable();
    let durable = gen_random_kv(mutable, elements, operations, Some(COMMIT_FREQUENCY)).await;
    let mut clean = durable.into_merkleized().await.unwrap();
    clean.prune(clean.inactivity_floor_loc()).await.unwrap();
    clean.sync().await.unwrap();
    drop(clean);
}

/// Benchmark the initialization of a large randomly generated any db.
fn bench_fixed_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in VARIANTS {
                // Setup phase: create and populate the database
                let runner = Runner::new(cfg.clone());
                runner.start(|ctx| async move {
                    match variant {
                        Variant::AnyUnorderedFixed => {
                            let db = get_any_unordered_fixed(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                        Variant::AnyOrderedFixed => {
                            let db = get_any_ordered_fixed(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                        Variant::CurrentUnorderedFixed => {
                            let db = get_current_unordered_fixed(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                        Variant::CurrentOrderedFixed => {
                            let db = get_current_ordered_fixed(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                        Variant::AnyUnorderedVariable => {
                            let db = get_any_unordered_variable(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                        Variant::AnyOrderedVariable => {
                            let db = get_any_ordered_variable(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                    }
                });

                // Benchmark phase: measure initialization time
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
                            let pool = ctx.create_pool(THREADS).unwrap();
                            let any_cfg = any_cfg(pool.clone());
                            let current_cfg = current_cfg(pool.clone());
                            let variable_any_cfg = variable_any_cfg(pool);
                            let start = Instant::now();
                            for _ in 0..iters {
                                match variant {
                                    Variant::AnyUnorderedFixed => {
                                        let db = UFixedDb::init(ctx.clone(), any_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                    Variant::AnyOrderedFixed => {
                                        let db = OFixedDb::init(ctx.clone(), any_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                    Variant::CurrentUnorderedFixed => {
                                        let db = UCurrentDb::init(ctx.clone(), current_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                    Variant::CurrentOrderedFixed => {
                                        let db = OCurrentDb::init(ctx.clone(), current_cfg.clone())
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                    Variant::AnyUnorderedVariable => {
                                        let db =
                                            UVAnyDb::init(ctx.clone(), variable_any_cfg.clone())
                                                .await
                                                .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                    Variant::AnyOrderedVariable => {
                                        let db =
                                            OVAnyDb::init(ctx.clone(), variable_any_cfg.clone())
                                                .await
                                                .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                }
                            }
                            start.elapsed()
                        });
                    },
                );

                // Cleanup phase: destroy the database
                let runner = Runner::new(cfg.clone());
                runner.start(|ctx| async move {
                    match variant {
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
