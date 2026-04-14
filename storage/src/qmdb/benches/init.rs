//! Benchmarks for QMDB startup initialization performance.
//!
//! These benchmarks have expensive setup (generating large random databases) and are separated
//! from the generation benchmarks so they can be filtered easily.

use crate::common::{
    any_fix_cfg, any_var_digest_cfg, any_var_vec_cfg, cur_fix_cfg, cur_var_digest_cfg,
    cur_var_vec_cfg, gen_random_kv, make_fixed_value, make_var_value, with_fixed_value_db,
    with_fixed_value_db_cfg, with_var_value_db, with_var_value_db_cfg, Digest,
    FIXED_VALUE_VARIANTS, PAGE_CACHE_SIZE, PAGE_SIZE, VAR_VALUE_VARIANTS,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    Metrics, Runner as _,
};
use commonware_storage::qmdb::any::traits::DbAny;
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

/// Populate, prune, and sync a database (used in setup phase).
async fn populate_and_sync<C: DbAny<commonware_storage::merkle::mmr::Family, Key = Digest>>(
    db: &mut C,
    elements: u64,
    operations: u64,
    make_value: impl Fn(&mut rand::rngs::StdRng) -> C::Value,
) {
    gen_random_kv(db, elements, operations, Some(COMMIT_FREQUENCY), make_value).await;
    db.prune(db.inactivity_floor_loc().await).await.unwrap();
    db.sync().await.unwrap();
}

fn bench_fixed_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in FIXED_VALUE_VARIANTS {
                // Setup: populate database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_fixed_value_db!(ctx, variant, |mut db| {
                        populate_and_sync(&mut db, elements, operations, make_fixed_value).await;
                    });
                });

                // Benchmark: measure init time
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let pc = CacheRef::from_pooler(
                                ctx.with_label("cache"),
                                PAGE_SIZE,
                                PAGE_CACHE_SIZE,
                            );
                            let af = any_fix_cfg(&ctx, pc.clone());
                            let cf = cur_fix_cfg(&ctx, pc.clone());
                            let av = any_var_digest_cfg(&ctx, pc.clone());
                            let cv = cur_var_digest_cfg(&ctx, pc);
                            let start = Instant::now();
                            for _ in 0..iters {
                                with_fixed_value_db_cfg!(ctx, variant, af, cf, av, cv, |mut db| {
                                    assert_ne!(db.bounds().await.end, 0);
                                });
                            }
                            start.elapsed()
                        });
                    },
                );

                // Cleanup: destroy database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_fixed_value_db!(ctx, variant, |mut db| {
                        db.destroy().await.unwrap();
                    });
                });
            }
        }
    }
}

fn bench_var_value_init(c: &mut Criterion) {
    let cfg = Config::default();
    for elements in ELEMENTS {
        for operations in OPERATIONS {
            for variant in VAR_VALUE_VARIANTS {
                // Setup: populate database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_var_value_db!(ctx, variant, |mut db| {
                        populate_and_sync(&mut db, elements, operations, make_var_value).await;
                    });
                });

                // Benchmark: measure init time
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let pc = CacheRef::from_pooler(
                                ctx.with_label("cache"),
                                PAGE_SIZE,
                                PAGE_CACHE_SIZE,
                            );
                            let av = any_var_vec_cfg(&ctx, pc.clone());
                            let cv = cur_var_vec_cfg(&ctx, pc);
                            let start = Instant::now();
                            for _ in 0..iters {
                                with_var_value_db_cfg!(ctx, variant, av, cv, |mut db| {
                                    assert_ne!(db.bounds().await.end, 0);
                                });
                            }
                            start.elapsed()
                        });
                    },
                );

                // Cleanup: destroy database
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_var_value_db!(ctx, variant, |mut db| {
                        db.destroy().await.unwrap();
                    });
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_init, bench_var_value_init
}
