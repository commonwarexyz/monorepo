//! Benchmarks for QMDB database generation (write-heavy workloads).
//!
//! Measures the time to seed a database and perform random updates/deletes across all keyed
//! variants (fixed-value, variable-value) and the keyless variant.

use crate::common::{
    define_fixed_variants, define_vec_variants, gen_random_kv, make_fixed_value, make_var_value,
    open_keyless_db, Digest,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{
    merkle::{mmb, mmr, Family},
    qmdb::any::traits::DbAny,
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;

/// Benchmark a populated database: generate data, prune, sync. Returns elapsed time (excluding
/// destroy).
async fn bench_db<F: Family, C: DbAny<F, Key = Digest>>(
    mut db: C,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
    make_value: impl Fn(&mut StdRng) -> C::Value,
) -> Duration {
    let start = Instant::now();
    gen_random_kv::<F, _>(
        &mut db,
        elements,
        operations,
        Some(commit_frequency),
        make_value,
    )
    .await;
    db.prune(db.sync_boundary().await).await.unwrap();
    db.sync().await.unwrap();
    let elapsed = start.elapsed();
    db.destroy().await.unwrap();
    elapsed
}

// -- Fixed-value variants (16 = 8 db shapes x 2 merkle families) --

define_fixed_variants! {
    enum FixedVariant;
    const FIXED_VARIANTS;
    dispatch dispatch_fixed;
    timed_dispatch dispatch_fixed_timed_init;
}

fn bench_fixed_value_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for &variant in FIXED_VARIANTS {
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let commit_freq = (operations / COMMITS_PER_ITERATION) as u32;
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += dispatch_fixed!(ctx.clone(), variant, |db| {
                                    bench_db(
                                        db,
                                        elements,
                                        operations,
                                        commit_freq,
                                        make_fixed_value,
                                    )
                                    .await
                                });
                            }
                            total
                        });
                    },
                );
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

fn bench_var_value_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for elements in [NUM_ELEMENTS, NUM_ELEMENTS * 10] {
        for operations in [NUM_OPERATIONS, NUM_OPERATIONS * 10] {
            for &variant in VEC_VARIANTS {
                c.bench_function(
                    &format!(
                        "{}/variant={} elements={elements} operations={operations}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            let commit_freq = (operations / COMMITS_PER_ITERATION) as u32;
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                total += dispatch_var!(ctx.clone(), variant, |db| {
                                    bench_db(db, elements, operations, commit_freq, make_var_value)
                                        .await
                                });
                            }
                            total
                        });
                    },
                );
            }
        }
    }
}

// -- Keyless variants --

const KEYLESS_OPS: u64 = 10_000;
const KEYLESS_COMMIT_FREQ: u32 = 25;

macro_rules! keyless_variants {
    (
        $(
            $entry:ident {
                name: $name:literal,
                init: |$ctx:ident| $init:expr,
            }
        )+
    ) => {
        #[derive(Debug, Clone, Copy)]
        enum KeylessVariant {
            $($entry),+
        }

        impl KeylessVariant {
            const fn name(self) -> &'static str {
                match self {
                    $(Self::$entry => $name),+
                }
            }
        }

        const KEYLESS_VARIANTS: &[KeylessVariant] = &[$(KeylessVariant::$entry),+];

        macro_rules! dispatch_keyless {
            ($ctx_expr:expr, $variant_expr:expr, |$db_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        KeylessVariant::$entry => {
                            let $ctx = $ctx_expr;
                            let mut $db_name = $init.await;
                            $body
                        }
                    )+
                }
            };
        }
    };
}

keyless_variants! {
    Mmr {
        name: "keyless::mmr",
        init: |ctx| open_keyless_db::<mmr::Family>(ctx.clone()),
    }
    Mmb {
        name: "keyless::mmb",
        init: |ctx| open_keyless_db::<mmb::Family>(ctx.clone()),
    }
}

fn bench_keyless_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for operations in [KEYLESS_OPS, KEYLESS_OPS * 2] {
        for &variant in KEYLESS_VARIANTS {
            c.bench_function(
                &format!(
                    "{}/variant={} operations={operations}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            dispatch_keyless!(ctx.clone(), variant, |db| {
                                let mut rng = StdRng::seed_from_u64(42);
                                let mut batch = db.new_batch();
                                for _ in 0u64..operations {
                                    let v = make_var_value(&mut rng);
                                    batch = batch.append(v);
                                    if rng.next_u32() % KEYLESS_COMMIT_FREQ == 0 {
                                        let merkleized =
                                            batch.merkleize(&db, None, db.inactivity_floor_loc());
                                        db.apply_batch(merkleized).await.unwrap();
                                        batch = db.new_batch();
                                    }
                                }
                                let merkleized =
                                    batch.merkleize(&db, None, db.inactivity_floor_loc());
                                db.apply_batch(merkleized).await.unwrap();
                                db.sync().await.unwrap();

                                total += start.elapsed();
                                db.destroy().await.unwrap();
                            });
                        }
                        total
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_value_generate, bench_var_value_generate, bench_keyless_generate
}
