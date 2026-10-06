//! Benchmarks for QMDB startup initialization performance.
//!
//! These benchmarks have expensive setup (generating large random databases) that runs lazily
//! inside `bench_function` so criterion's name filter can skip them entirely.
//!
//! `prune=floor` cases prune to the inactivity floor before reopening, and `prune=none` cases
//! reopen every operation ever written. The keyless cases never prune.

use crate::common::{
    Digest, define_fixed_variants, define_vec_variants, gen_random_kv, make_fixed_value,
    make_var_value, open_keyless_db,
};
use commonware_macros::boxed;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{
    merkle::{Family, mmb, mmr},
    qmdb::any::traits::DbAny,
};
use commonware_utils::{NZUsize, TestRng};
use core::num::NonZeroUsize;
use criterion::{Criterion, criterion_group};
use rand::Rng;
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 100_000;
const NUM_OPERATIONS: u64 = 1_000_000;
const COMMIT_FREQUENCY: u32 = 10_000;

/// Init-time `(location -> key)` cache sizes to compare: `None` disables the cache (the no-cache
/// baseline), and a reasonably sized cache that covers the bench's working set.
const CACHE_SIZES: [Option<NonZeroUsize>; 2] = [None, Some(NZUsize!(1 << 18))];

/// Whether setup prunes to the inactivity floor before the timed reopen.
const PRUNE: [bool; 2] = [true, false];

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const CASES: [(u64, u64); 1] = [(NUM_ELEMENTS, NUM_OPERATIONS)];
    } else {
        const CASES: [(u64, u64); 2] = [
            (NUM_ELEMENTS, NUM_OPERATIONS),
            (NUM_ELEMENTS * 3, NUM_OPERATIONS * 3),
        ];
    }
}

/// Populate, optionally prune, and sync a database (used in setup phase).
#[boxed]
async fn populate_and_sync<F: Family, C: DbAny<F, Key = Digest>>(
    db: C,
    elements: u64,
    operations: u64,
    prune: bool,
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
    let db = if prune {
        let boundary = db.sync_boundary();
        db.prune(boundary).await.unwrap()
    } else {
        db
    };
    db.sync().await.unwrap()
}

/// Append `operations` variable-size values to a keyless database, committing periodically.
#[boxed]
async fn populate_keyless<F: Family>(ctx: Context, operations: u64) {
    let mut db = open_keyless_db::<F>(ctx.child("storage")).await;
    let mut rng = TestRng::new(42);
    let mut batch = db.new_batch();
    for _ in 0..operations {
        batch = batch.append(make_var_value(&mut rng));
        if rng.next_u32().is_multiple_of(COMMIT_FREQUENCY) {
            let merkleized = batch
                .merkleize(&db, None, db.inactivity_floor_loc())
                .await
                .unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            db = db.commit().await.unwrap();
            batch = db.new_batch();
        }
    }
    let merkleized = batch
        .merkleize(&db, None, db.inactivity_floor_loc())
        .await
        .unwrap();
    let (db, _) = db.apply_batch(merkleized).await.unwrap();
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
    for (elements, operations) in CASES {
        for prune in PRUNE {
            for &variant in FIXED_VARIANTS {
                // Populated lazily on the first sample of the first matched cache size, then reused by
                // every cache size for this variant (all read the same on-disk database).
                let mut initialized = false;
                for &cache_size in &CACHE_SIZES {
                    let cache = cache_size.map_or(0, NonZeroUsize::get);
                    let runner = tokio::Runner::new(cfg.clone());
                    c.bench_function(
                        &format!(
                            "{}/variant={} cache={cache} elements={elements} prune={}",
                            module_path!(),
                            variant.name(),
                            if prune { "floor" } else { "none" },
                        ),
                        |b| {
                            // Setup: populate database (once, on first matched sample).
                            if !initialized {
                                commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                                    |ctx| async move {
                                        dispatch_fixed!(ctx, variant, |db| {
                                            populate_and_sync(
                                                db,
                                                elements,
                                                operations,
                                                prune,
                                                make_fixed_value,
                                            )
                                            .await;
                                        });
                                    },
                                );
                                initialized = true;
                            }

                            // Benchmark: measure init time at this cache size.
                            b.to_async(&runner).iter_custom(move |iters| async move {
                                let ctx = context::get::<Context>();
                                dispatch_fixed_timed_init!(ctx, variant, iters, cache_size, |db| {
                                    assert_ne!(db.bounds().end, 0);
                                })
                            });
                        },
                    );
                }

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
    for (elements, operations) in CASES {
        for prune in PRUNE {
            for &variant in VEC_VARIANTS {
                // Populated lazily on the first sample of the first matched cache size, then reused by
                // every cache size for this variant (all read the same on-disk database).
                let mut initialized = false;
                for &cache_size in &CACHE_SIZES {
                    let cache = cache_size.map_or(0, NonZeroUsize::get);
                    let runner = tokio::Runner::new(cfg.clone());
                    c.bench_function(
                        &format!(
                            "{}/variant={} cache={cache} elements={elements} prune={}",
                            module_path!(),
                            variant.name(),
                            if prune { "floor" } else { "none" },
                        ),
                        |b| {
                            // Setup: populate database (once, on first matched sample).
                            if !initialized {
                                commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                                    |ctx| async move {
                                        dispatch_var!(ctx, variant, |db| {
                                            populate_and_sync(
                                                db,
                                                elements,
                                                operations,
                                                prune,
                                                make_var_value,
                                            )
                                            .await;
                                        });
                                    },
                                );
                                initialized = true;
                            }

                            // Benchmark: measure init time at this cache size.
                            b.to_async(&runner).iter_custom(move |iters| async move {
                                let ctx = context::get::<Context>();
                                dispatch_var_timed_init!(ctx, variant, iters, cache_size, |db| {
                                    assert_ne!(db.bounds().end, 0);
                                })
                            });
                        },
                    );
                }

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

// -- Keyless variants --

/// Reopen a keyless database `iters` times, returning the total time.
async fn keyless_init<F: Family>(ctx: Context, iters: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        let db = open_keyless_db::<F>(ctx.child("storage")).await;
        assert_ne!(db.bounds().end, 0);
    }
    start.elapsed()
}

fn bench_keyless_family<F: Family>(c: &mut Criterion, variant: &str) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg.clone());
    let mut initialized = false;
    c.bench_function(
        &format!(
            "{}/variant={variant} operations={NUM_OPERATIONS}",
            module_path!()
        ),
        |b| {
            // Setup: populate database (once, on first matched sample).
            if !initialized {
                commonware_runtime::tokio::Runner::new(cfg.clone())
                    .start(|ctx| populate_keyless::<F>(ctx, NUM_OPERATIONS));
                initialized = true;
            }

            b.to_async(&runner)
                .iter_custom(|iters| keyless_init::<F>(context::get::<Context>(), iters));
        },
    );

    // Cleanup: destroy database.
    if initialized {
        commonware_runtime::tokio::Runner::new(cfg).start(|ctx| async move {
            let db = open_keyless_db::<F>(ctx.child("storage")).await;
            db.destroy().await.unwrap();
        });
    }
}

fn bench_keyless_init(c: &mut Criterion) {
    bench_keyless_family::<mmr::Family>(c, "keyless::mmr");
    bench_keyless_family::<mmb::Family>(c, "keyless::mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_init, bench_var_value_init, bench_keyless_init
}
