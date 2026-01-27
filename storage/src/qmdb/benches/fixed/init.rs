//! Benchmark the startup initialization performance of each QMDB variant on a large randomly
//! generated database with fixed-size values.

use crate::fixed::{
    any_cfg, current_cfg, gen_random_kv, get_any_ordered_fixed_par, get_any_ordered_variable_par,
    get_any_unordered_fixed_par, get_any_unordered_variable_par, get_current_ordered_fixed_par,
    get_current_ordered_variable_par, get_current_unordered_fixed_par,
    get_current_unordered_variable_par, variable_any_cfg, variable_current_cfg, Digest,
    OCurrentDbPar, OCurrentDbSeq, OFixedDbPar, OFixedDbSeq, OVAnyDbPar, OVAnyDbSeq, OVCurrentDbPar,
    OVCurrentDbSeq, UCurrentDbPar, UCurrentDbSeq, UFixedDbPar, UFixedDbSeq, UVAnyDbPar, UVAnyDbSeq,
    UVCurrentDbPar, UVCurrentDbSeq, Variant, THREADS, VARIANTS,
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
            for parallelism in PARALLELISMS {
                for variant in VARIANTS {
                    // Setup phase: create and populate the database (use parallel for faster setup)
                    let runner = Runner::new(cfg.clone());
                    runner.start(|ctx| async move {
                        match variant {
                            Variant::AnyUnorderedFixed => {
                                let db = get_any_unordered_fixed_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::AnyOrderedFixed => {
                                let db = get_any_ordered_fixed_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::CurrentUnorderedFixed => {
                                let db = get_current_unordered_fixed_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::CurrentOrderedFixed => {
                                let db = get_current_ordered_fixed_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::AnyUnorderedVariable => {
                                let db = get_any_unordered_variable_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::AnyOrderedVariable => {
                                let db = get_any_ordered_variable_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::CurrentUnorderedVariable => {
                                let db = get_current_unordered_variable_par(ctx.clone()).await;
                                setup_db(db, elements, operations).await;
                            }
                            Variant::CurrentOrderedVariable => {
                                let db = get_current_ordered_variable_par(ctx.clone()).await;
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
                                        (Variant::AnyUnorderedFixed, Parallelism::Sequential) => {
                                            let db =
                                                UFixedDbSeq::init(ctx.clone(), any_cfg(Sequential))
                                                    .await
                                                    .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyUnorderedFixed, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = UFixedDbPar::init(
                                                ctx.clone(),
                                                any_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyOrderedFixed, Parallelism::Sequential) => {
                                            let db =
                                                OFixedDbSeq::init(ctx.clone(), any_cfg(Sequential))
                                                    .await
                                                    .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyOrderedFixed, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = OFixedDbPar::init(
                                                ctx.clone(),
                                                any_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (
                                            Variant::CurrentUnorderedFixed,
                                            Parallelism::Sequential,
                                        ) => {
                                            let db = UCurrentDbSeq::init(
                                                ctx.clone(),
                                                current_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentUnorderedFixed, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = UCurrentDbPar::init(
                                                ctx.clone(),
                                                current_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentOrderedFixed, Parallelism::Sequential) => {
                                            let db = OCurrentDbSeq::init(
                                                ctx.clone(),
                                                current_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::CurrentOrderedFixed, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = OCurrentDbPar::init(
                                                ctx.clone(),
                                                current_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (
                                            Variant::AnyUnorderedVariable,
                                            Parallelism::Sequential,
                                        ) => {
                                            let db = UVAnyDbSeq::init(
                                                ctx.clone(),
                                                variable_any_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyUnorderedVariable, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = UVAnyDbPar::init(
                                                ctx.clone(),
                                                variable_any_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyOrderedVariable, Parallelism::Sequential) => {
                                            let db = OVAnyDbSeq::init(
                                                ctx.clone(),
                                                variable_any_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (Variant::AnyOrderedVariable, Parallelism::Parallel) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = OVAnyDbPar::init(
                                                ctx.clone(),
                                                variable_any_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (
                                            Variant::CurrentUnorderedVariable,
                                            Parallelism::Sequential,
                                        ) => {
                                            let db = UVCurrentDbSeq::init(
                                                ctx.clone(),
                                                variable_current_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (
                                            Variant::CurrentUnorderedVariable,
                                            Parallelism::Parallel,
                                        ) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = UVCurrentDbPar::init(
                                                ctx.clone(),
                                                variable_current_cfg(Rayon::with_pool(pool)),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (
                                            Variant::CurrentOrderedVariable,
                                            Parallelism::Sequential,
                                        ) => {
                                            let db = OVCurrentDbSeq::init(
                                                ctx.clone(),
                                                variable_current_cfg(Sequential),
                                            )
                                            .await
                                            .unwrap();
                                            assert_ne!(db.op_count(), 0);
                                        }
                                        (
                                            Variant::CurrentOrderedVariable,
                                            Parallelism::Parallel,
                                        ) => {
                                            let pool = ctx.create_pool(THREADS).unwrap();
                                            let db = OVCurrentDbPar::init(
                                                ctx.clone(),
                                                variable_current_cfg(Rayon::with_pool(pool)),
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
                            Variant::AnyUnorderedFixed => {
                                let db = get_any_unordered_fixed_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::AnyOrderedFixed => {
                                let db = get_any_ordered_fixed_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::CurrentUnorderedFixed => {
                                let db = get_current_unordered_fixed_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::CurrentOrderedFixed => {
                                let db = get_current_ordered_fixed_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::AnyUnorderedVariable => {
                                let db = get_any_unordered_variable_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::AnyOrderedVariable => {
                                let db = get_any_ordered_variable_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::CurrentUnorderedVariable => {
                                let db = get_current_unordered_variable_par(ctx.clone()).await;
                                db.destroy().await.unwrap();
                            }
                            Variant::CurrentOrderedVariable => {
                                let db = get_current_ordered_variable_par(ctx.clone()).await;
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
    targets = bench_fixed_init
}
