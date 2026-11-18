//! Benchmarks for QMDB startup initialization performance.
//!
//! These benchmarks have expensive setup (generating large random databases) that runs lazily
//! inside `bench_function` so criterion's name filter can skip them entirely.

use crate::common::{
    Digest, StoreDb, define_fixed_variants, define_vec_variants, gen_random_kv,
    gen_store_random_kv, make_fixed_value, make_var_value, open_store_db, store_cfg,
};
use commonware_bench::Inputs;
use commonware_macros::boxed;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{merkle::Family, qmdb::any::traits::DbAny};
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;

fn cases() -> &'static [(u64, u64)] {
    match Inputs::current() {
        Inputs::Smoke => &[(1_000, 10_000)],
        Inputs::Standard => &[(NUM_ELEMENTS, NUM_OPERATIONS)],
        Inputs::Full => &[
            (NUM_ELEMENTS, NUM_OPERATIONS),
            (NUM_ELEMENTS * 3, NUM_OPERATIONS * 3),
        ],
    }
}

/// Populate, prune, and sync a database (used in setup phase).
#[boxed]
async fn populate_and_sync<F: Family, C: DbAny<Family = F, Key = Digest>>(
    db: C,
    elements: u64,
    operations: u64,
    make_value: impl Fn(&mut TestRng) -> C::Value,
) -> C {
    let db = gen_random_kv::<F, _>(
        db,
        elements,
        operations,
        Some(COMMIT_FREQUENCY),
        None, // seed_batch
        None, // prune_frequency
        None, // key_zipf_exponent (uniform churn)
        None, // keyspace (all keys seeded)
        make_value,
    )
    .await;
    let boundary = db.sync_boundary();
    let db = db.prune(boundary).await.unwrap();
    db.sync().await.unwrap()
}

define_fixed_variants! {
    enum FixedVariant;
    const FIXED_VARIANTS;
    dispatch dispatch_fixed;
    timed_dispatch dispatch_fixed_timed_init;
}

fn bench_fixed_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for &(elements, operations) in cases() {
        for &variant in FIXED_VARIANTS {
            // Populated lazily on the first matched sample.
            let mut initialized = false;
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!(
                    "{}/variant={} elements={elements}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    // Setup: populate database (once, on first matched sample).
                    if !initialized {
                        commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                            |ctx| async move {
                                dispatch_fixed!(ctx, variant, |db| {
                                    populate_and_sync(db, elements, operations, make_fixed_value)
                                        .await;
                                });
                            },
                        );
                        initialized = true;
                    }

                    // Benchmark: measure init time.
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<Context>();
                        dispatch_fixed_timed_init!(ctx, variant, iters, |db| {
                            assert_ne!(db.bounds().end, 0);
                        })
                    });
                },
            );

            // Cleanup: destroy database.
            if initialized {
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    dispatch_fixed!(ctx, variant, |db| {
                        db.destroy().await.unwrap();
                    });
                });
            }
        }
    }
}

define_vec_variants! {
    enum VarVariant;
    const VEC_VARIANTS;
    dispatch dispatch_var;
    timed_dispatch dispatch_var_timed_init;
}

fn bench_var_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for &(elements, operations) in cases() {
        for &variant in VEC_VARIANTS {
            // Populated lazily on the first matched sample.
            let mut initialized = false;
            let runner = tokio::Runner::new(cfg.clone());
            c.bench_function(
                &format!(
                    "{}/variant={} elements={elements}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    // Setup: populate database (once, on first matched sample).
                    if !initialized {
                        commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                            |ctx| async move {
                                dispatch_var!(ctx, variant, |db| {
                                    populate_and_sync(db, elements, operations, make_var_value)
                                        .await;
                                });
                            },
                        );
                        initialized = true;
                    }

                    // Benchmark: measure init time.
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<Context>();
                        dispatch_var_timed_init!(ctx, variant, iters, |db| {
                            assert_ne!(db.bounds().end, 0);
                        })
                    });
                },
            );

            // Cleanup: destroy database.
            if initialized {
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    dispatch_var!(ctx, variant, |db| {
                        db.destroy().await.unwrap();
                    });
                });
            }
        }
    }
}

/// Benchmark reopening a populated unauthenticated store.
fn bench_store_init(c: &mut Criterion) {
    let cfg = Config::default();
    for &(elements, operations) in cases() {
        // Populated lazily on the first matched sample.
        let mut initialized = false;
        let runner = tokio::Runner::new(cfg.clone());
        c.bench_function(
            &format!(
                "{}/variant=store::variable elements={elements}",
                module_path!(),
            ),
            |b| {
                // Populate the database once, on the first matched sample.
                if !initialized {
                    commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                        let db = open_store_db(ctx.child("storage")).await;
                        let db = gen_store_random_kv(
                            db,
                            elements,
                            operations,
                            COMMIT_FREQUENCY,
                            make_var_value,
                        )
                        .await;
                        let floor = db.inactivity_floor();
                        let db = db.prune(floor).await.unwrap();
                        db.sync().await.unwrap();
                    });
                    initialized = true;
                }

                // Measure init time.
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<Context>();
                    let cfg = store_cfg(&ctx);
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let db = StoreDb::init(ctx.child("storage"), cfg.clone(), None)
                            .await
                            .unwrap();
                        assert_ne!(db.bounds().end, 0);
                    }
                    start.elapsed()
                });
            },
        );

        // Destroy the populated database.
        if initialized {
            commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                open_store_db(ctx.child("storage"))
                    .await
                    .destroy()
                    .await
                    .unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_init, bench_var_value_init, bench_store_init
}
