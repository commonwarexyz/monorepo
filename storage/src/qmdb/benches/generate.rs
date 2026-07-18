//! Benchmarks for QMDB database generation (write-heavy workloads).
//!
//! Measures the time to seed a database and perform random updates/deletes across all keyed
//! variants (fixed-value, variable-value) and the keyless variant.

use crate::common::{
    define_fixed_variants, define_vec_variants, gen_random_kv, make_fixed_value, make_var_value,
    open_keyless_db, Digest, DELETE_FREQUENCY,
};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_macros::boxed;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Spawner as _, Supervisor as _,
};
use commonware_storage::{
    merkle::{mmb, mmr, Family},
    qmdb::any::traits::{DbAny, UnmerkleizedBatch as _},
};
use commonware_utils::TestRng;
use criterion::{criterion_group, Criterion};
use rand::Rng;
use std::time::{Duration, Instant};

const NUM_ELEMENTS: u64 = 1_000;
const NUM_OPERATIONS: u64 = 10_000;
const COMMITS_PER_ITERATION: u64 = 100;
const CASES: [(u64, u64); 1] = [(NUM_ELEMENTS, NUM_OPERATIONS)];

/// Benchmark a populated database: generate data, prune, sync. Returns elapsed time (excluding
/// destroy).
#[boxed]
async fn bench_db<F: Family, C: DbAny<F, Key = Digest>>(
    mut db: C,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
    make_value: impl Fn(&mut TestRng) -> C::Value,
) -> Duration {
    let start = Instant::now();
    gen_random_kv::<F, _>(
        &mut db,
        elements,
        operations,
        Some(commit_frequency),
        None, // seed_batch
        None, // prune_frequency
        None, // key_zipf_exponent (uniform churn)
        None, // keyspace (all keys seeded)
        make_value,
    )
    .await;
    db.prune(db.sync_boundary()).await.unwrap();
    db.sync().await.unwrap();
    let elapsed = start.elapsed();
    db.destroy().await.unwrap();
    elapsed
}

/// [`bench_db`] with OVERLAPPED periodic syncs: each periodic commit starts
/// its sync (`DbAny::start_sync`) and hands the handle to a spawned waiter
/// that drives it while the main task merkleizes and applies the next chunk,
/// bounded at one in-flight sync (the glue actor's pipeline shape). The
/// operation stream is identical to [`bench_db`]'s (same seeded RNG), so the
/// two measure the same work with sequential vs overlapped durability.
#[boxed]
async fn bench_db_overlapped<F: Family, C: DbAny<F, Key = Digest>>(
    ctx: Context,
    mut db: C,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
    make_value: impl Fn(&mut TestRng) -> C::Value,
) -> Duration {
    let start = Instant::now();
    let mut rng = TestRng::new(42);

    // Seed phase: one batch, blocking sync (matching `gen_random_kv` with
    // `seed_batch: None`).
    let mut batch = db.new_batch();
    for i in 0u64..elements {
        let key = Sha256::hash(&i.to_be_bytes());
        batch = batch.write(key, Some(make_value(&mut rng)));
    }
    let merkleized = batch.merkleize(&db, None).await.unwrap();
    db.apply_batch(merkleized).await.unwrap();
    db.sync().await.unwrap();

    // Operations phase: periodic commits start their sync instead of
    // blocking on it. A spawned waiter polls the handle (driving the
    // backend's commit) concurrently with the next chunk's merkleize+apply;
    // the next commit joins it first, so at most one sync is in flight.
    let mut inflight: Option<commonware_runtime::Handle<()>> = None;
    let mut batch = db.new_batch();
    for _ in 0u64..operations {
        let idx = rng.next_u64() % elements;
        let rand_key = Sha256::hash(&idx.to_be_bytes());
        if rng.next_u32().is_multiple_of(DELETE_FREQUENCY) {
            batch = batch.write(rand_key, None);
            continue;
        }
        batch = batch.write(rand_key, Some(make_value(&mut rng)));
        if rng.next_u32().is_multiple_of(commit_frequency) {
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            if let Some(previous) = inflight.take() {
                previous.await.unwrap();
            }
            let sync = db.start_sync().await.unwrap();
            inflight = Some(
                ctx.child("sync_waiter")
                    .spawn(move |_| async move { sync.await.unwrap() }),
            );
            batch = db.new_batch();
        }
    }
    let merkleized = batch.merkleize(&db, None).await.unwrap();
    db.apply_batch(merkleized).await.unwrap();
    if let Some(previous) = inflight.take() {
        previous.await.unwrap();
    }

    db.prune(db.sync_boundary()).await.unwrap();
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
    for (elements, operations) in CASES {
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
                            total += dispatch_fixed!(ctx.child("storage"), variant, |db| {
                                bench_db(db, elements, operations, commit_freq, make_fixed_value)
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

fn bench_fixed_value_generate_overlapped(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for (elements, operations) in CASES {
        for &variant in FIXED_VARIANTS {
            c.bench_function(
                &format!(
                    "{}/variant={} sync=overlapped elements={elements} operations={operations}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let commit_freq = (operations / COMMITS_PER_ITERATION) as u32;
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += dispatch_fixed!(ctx.child("storage"), variant, |db| {
                                bench_db_overlapped(
                                    ctx.child("driver"),
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

// -- Variable-value variants (8 = 4 db shapes x 2 merkle families) --

define_vec_variants! {
    enum VarVariant;
    const VEC_VARIANTS;
    dispatch dispatch_var;
    timed_dispatch dispatch_var_timed_init;
}

fn bench_var_value_generate(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for (elements, operations) in CASES {
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
                            total += dispatch_var!(ctx.child("storage"), variant, |db| {
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
        init: |ctx| open_keyless_db::<mmr::Family>(ctx.child("storage")),
    }
    Mmb {
        name: "keyless::mmb",
        init: |ctx| open_keyless_db::<mmb::Family>(ctx.child("storage")),
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
                            dispatch_keyless!(ctx.child("storage"), variant, |db| {
                                let mut rng = TestRng::new(42);
                                let mut batch = db.new_batch();
                                for _ in 0u64..operations {
                                    let v = make_var_value(&mut rng);
                                    batch = batch.append(v);
                                    if rng.next_u32().is_multiple_of(KEYLESS_COMMIT_FREQ) {
                                        let merkleized = batch
                                            .merkleize(&db, None, db.inactivity_floor_loc())
                                            .await;
                                        db.apply_batch(merkleized).await.unwrap();
                                        batch = db.new_batch();
                                    }
                                }
                                let merkleized =
                                    batch.merkleize(&db, None, db.inactivity_floor_loc()).await;
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
    targets = bench_fixed_value_generate, bench_fixed_value_generate_overlapped,
        bench_var_value_generate, bench_keyless_generate
}
