//! Benchmarks for QMDB startup initialization performance.
//!
//! These benchmarks have expensive setup (generating large random databases) that runs lazily
//! inside `bench_function` so criterion's name filter can skip them entirely.

use crate::common::{
    define_fixed_variants, define_vec_variants, gen_random_kv, make_fixed_value, make_var_value,
    Digest,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Runner as _,
};
use commonware_storage::{merkle::Family, qmdb::any::traits::DbAny};
use criterion::{criterion_group, Criterion};

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

/// Populate, prune, and sync a database (used in setup phase).
async fn populate_and_sync<F: Family, C: DbAny<F, Key = Digest>>(
    db: &mut C,
    elements: u64,
    operations: u64,
    make_value: impl Fn(&mut rand::rngs::StdRng) -> C::Value,
) {
    gen_random_kv::<F, _>(db, elements, operations, Some(COMMIT_FREQUENCY), make_value).await;
    db.prune(db.sync_boundary().await).await.unwrap();
    db.sync().await.unwrap();
}

// -- Fixed-value variants (16 = 8 db shapes x 2 merkle families) --

define_fixed_variants! {
    enum FixedVariant;
    const FIXED_VARIANTS;
    dispatch dispatch_fixed;
    timed_dispatch dispatch_fixed_timed_init;
}

fn bench_fixed_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for &variant in FIXED_VARIANTS {
                let mut initialized = false;
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        // Setup: populate database (once, on first sample).
                        if !initialized {
                            commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                                |ctx| async move {
                                    dispatch_fixed!(ctx, variant, |db| {
                                        populate_and_sync(
                                            &mut db,
                                            elements,
                                            operations,
                                            make_fixed_value,
                                        )
                                        .await;
                                    });
                                },
                            );
                            initialized = true;
                        }

                        // Benchmark: measure init time.
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            dispatch_fixed_timed_init!(ctx, variant, iters, |db| {
                                assert_ne!(db.bounds().await.end, 0);
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
}

// -- Variable-value variants (8 = 4 db shapes x 2 merkle families) --

define_vec_variants! {
    enum VarVariant;
    const VEC_VARIANTS;
    dispatch dispatch_var;
    timed_dispatch dispatch_var_timed_init;
}

fn bench_var_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for &variant in VEC_VARIANTS {
                let mut initialized = false;
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        // Setup: populate database (once, on first sample).
                        if !initialized {
                            commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                                |ctx| async move {
                                    dispatch_var!(ctx, variant, |db| {
                                        populate_and_sync(
                                            &mut db,
                                            elements,
                                            operations,
                                            make_var_value,
                                        )
                                        .await;
                                    });
                                },
                            );
                            initialized = true;
                        }

                        // Benchmark: measure init time.
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            dispatch_var_timed_init!(ctx, variant, iters, |db| {
                                assert_ne!(db.bounds().await.end, 0);
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
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_init, bench_var_value_init
}
