//! Benchmark the initialization performance of each QMDB variant on a large randomly generated
//! database with variable-sized values.

use crate::variable::{
    any_cfg, gen_random_kv, get_any_ordered, get_any_unordered, Digest, OVariableDb, UVariableDb,
    Variant, THREADS, VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Runner},
    Runner as _,
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
    C::Mutable: MutableAny<Key = Digest> + LogStore<Value = Vec<u8>>,
    <C::Mutable as MutableAny>::Durable:
        UnmerkleizedDurableAny<Mutable = C::Mutable, Merkleized = C>,
{
    let mutable = db.into_mutable();
    let durable = gen_random_kv(mutable, elements, operations, COMMIT_FREQUENCY).await;
    let mut clean = durable.into_merkleized().await.unwrap();
    clean.prune(clean.inactivity_floor_loc()).await.unwrap();
    clean.sync().await.unwrap();
    drop(clean);
}

/// Benchmark the initialization of a large randomly generated any db.
fn bench_variable_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in VARIANTS {
                // Setup phase: create and populate the database
                let runner = Runner::new(cfg.clone());
                runner.start(|ctx| async move {
                    match variant {
                        Variant::AnyUnordered => {
                            let db = get_any_unordered(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                        Variant::AnyOrdered => {
                            let db = get_any_ordered(ctx.clone()).await;
                            setup_db(db, elements, operations).await;
                        }
                    }
                });

                // Benchmark phase: measure initialization time
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
                                    Variant::AnyUnordered => {
                                        let pool =
                                            commonware_runtime::create_pool(ctx.clone(), THREADS)
                                                .unwrap();
                                        let db = UVariableDb::init(ctx.clone(), any_cfg(pool))
                                            .await
                                            .unwrap();
                                        assert_ne!(db.op_count(), 0);
                                    }
                                    Variant::AnyOrdered => {
                                        let pool =
                                            commonware_runtime::create_pool(ctx.clone(), THREADS)
                                                .unwrap();
                                        let db = OVariableDb::init(ctx.clone(), any_cfg(pool))
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
