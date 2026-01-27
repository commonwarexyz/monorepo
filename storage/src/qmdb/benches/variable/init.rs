//! Benchmark the initialization performance of each QMDB variant on a large randomly generated
//! database with variable-sized values.

use crate::variable::{
    any_cfg, current_cfg, gen_random_kv, get_any_ordered_par, get_any_unordered_par,
    get_current_ordered_par, get_current_unordered_par, Digest, OVCurrentDbPar, OVCurrentDbSeq,
    OVariableDbPar, OVariableDbSeq, UVCurrentDbPar, UVCurrentDbSeq, UVariableDbPar, UVariableDbSeq,
    Variant, THREADS, VARIANTS,
};
use commonware_parallel::{Rayon, Sequential};
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

#[derive(Debug, Clone, Copy)]
enum Parallelism {
    Sequential,
    Parallel,
}

impl Parallelism {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Parallel => "parallel",
        }
    }
}

const PARALLELISMS: [Parallelism; 2] = [Parallelism::Sequential, Parallelism::Parallel];

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
            for parallelism in PARALLELISMS {
                for variant in VARIANTS {
                    // Setup phase: create and populate the database (use parallel for faster setup)
                    let runner = Runner::new(cfg.clone());
                    runner.start(|ctx| async move {
                        match variant {
                            Variant::AnyUnordered => {
                                let db = get_any_unordered_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::AnyOrdered => {
                                let db = get_any_ordered_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::CurrentUnordered => {
                                let db = get_current_unordered_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::CurrentOrdered => {
                                let db = get_current_ordered_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                        }
                    });

                    // Benchmark phase: measure initialization time
                    let runner = tokio::Runner::new(cfg.clone());
                    c.bench_function(
                        &format!(
                            "{}/variant={} parallelism={} elements={} operations={}",
                            module_path!(),
                            variant.name(),
                            parallelism.name(),
                            elements,
                            operations,
                        ),
                        |b| {
                            b.to_async(&runner).iter_custom(|iters| async move {
                                let ctx = context::get::<commonware_runtime::tokio::Context>();
                                let start = Instant::now();
                                for _ in 0..iters {
                                    match (variant, parallelism) {
                                        (Variant::AnyUnordered, Parallelism::Sequential) => {
                                            let db = UVariableDbSeq::init(
                                                ctx.clone(),
                                                any_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyUnordered, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = UVariableDbPar::init(
                                                ctx.clone(),
                                                any_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyOrdered, Parallelism::Sequential) => {
                                            let db = OVariableDbSeq::init(
                                                ctx.clone(),
                                                any_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyOrdered, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = OVariableDbPar::init(
                                                ctx.clone(),
                                                any_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentUnordered, Parallelism::Sequential) => {
                                            let db = UVCurrentDbSeq::init(
                                                ctx.clone(),
                                                current_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentUnordered, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = UVCurrentDbPar::init(
                                                ctx.clone(),
                                                current_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentOrdered, Parallelism::Sequential) => {
                                            let db = OVCurrentDbSeq::init(
                                                ctx.clone(),
                                                current_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentOrdered, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = OVCurrentDbPar::init(
                                                ctx.clone(),
                                                current_cfg(Rayon::with_pool(pool)),
                                            )
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

                    // Cleanup phase: destroy the database (use parallel for faster cleanup)
                    let runner = Runner::new(cfg.clone());
                    runner.start(|ctx| async move {
                        match variant {
                            Variant::AnyUnordered => {
                                let db = get_any_unordered_par(ctx).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::AnyOrdered => {
                                let db = get_any_ordered_par(ctx).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::CurrentUnordered => {
                                let db = get_current_unordered_par(ctx).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::CurrentOrdered => {
                                let db = get_current_ordered_par(ctx).await;
                                db.destroy().await.unwrap();
                            }
                        }
                    });
                }
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_variable_init
}
