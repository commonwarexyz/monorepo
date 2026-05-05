//! Benchmarks for speculative batch merkleization.
//!
//! Each iteration creates a speculative batch (10% random updates, sampled with replacement),
//! merkleizes it, and reads the root. The per-iteration `write_random_updates` + `merkleize` +
//! `root()` is timed; one-time setup (seed, churn batches, sync) is not.
//!
//! - [`bench_merkleize`]: timing on a freshly seeded DB (no prior overwrites).
//! - [`bench_merkleize_churned`]: timing after overwrite batches have accumulated inactive
//!   update operations above the inactivity floor — the workload the floor-raise bitmap-skip
//!   optimizes for.

use crate::common::{seed_db, write_random_updates, Digest, CHUNK_SIZE, WRITE_BUFFER_SIZE};
use commonware_cryptography::Sha256;
use commonware_parallel::Rayon;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    BufferPooler, Supervisor as _, ThreadPooler,
};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{self, full},
    qmdb::any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

// -- Type aliases --

type AnyUFix = commonware_storage::qmdb::any::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyUVar = commonware_storage::qmdb::any::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyUFixMmb = commonware_storage::qmdb::any::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyUVarMmb = commonware_storage::qmdb::any::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type CurUFix32 = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurUVar32 = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurUFix32Mmb = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurUVar32Mmb = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;

const LARGE_CHUNK_SIZE: usize = 256;

type CurUFix256 = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
type CurUVar256 = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
type CurUFix256Mmb = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
type CurUVar256Mmb = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;

// Ordered variants.
type AnyOFix = commonware_storage::qmdb::any::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyOVar = commonware_storage::qmdb::any::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyOFixMmb = commonware_storage::qmdb::any::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyOVarMmb = commonware_storage::qmdb::any::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type CurOFix32 = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurOVar32 = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurOFix32Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurOVar32Mmb = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurOFix256 = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
type CurOVar256 = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
type CurOFix256Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
type CurOVar256Mmb = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;

// -- Config --

// Use huge blobs to avoid iteration times being affected by multiple fsyncs from crossing blob
// boundaries.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const THREADS: NonZeroUsize = NZUsize!(8);
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
// Very large so all state is in memory.
const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(131_072);
// Very small so most reads miss the cache.
const SMALL_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(32);
const PARTITION: &str = "bench-merkleize";

fn merkle_cfg(ctx: &(impl BufferPooler + ThreadPooler), pc: CacheRef) -> full::Config<Rayon> {
    full::Config {
        journal_partition: format!("journal-{PARTITION}"),
        metadata_partition: format!("metadata-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        strategy: ctx.create_strategy(THREADS).unwrap(),
        page_cache: pc,
    }
}

fn fix_log_cfg(pc: CacheRef) -> FConfig {
    FConfig {
        partition: format!("log-journal-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        page_cache: pc,
        write_buffer: WRITE_BUFFER_SIZE,
    }
}

fn var_log_cfg(pc: CacheRef) -> VConfig<((), ())> {
    VConfig {
        partition: format!("log-journal-{PARTITION}"),
        items_per_section: ITEMS_PER_BLOB,
        compression: None,
        codec_config: ((), ()),
        page_cache: pc,
        write_buffer: WRITE_BUFFER_SIZE,
    }
}

// -- DB constructors (eliminates repeated config boilerplate in match arms) --

fn any_fix_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
    cache_size: NonZeroUsize,
) -> commonware_storage::qmdb::any::FixedConfig<EightCap, Rayon> {
    let pc = CacheRef::from_pooler(ctx, PAGE_SIZE, cache_size);
    commonware_storage::qmdb::any::FixedConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: fix_log_cfg(pc),
        translator: EightCap,
    }
}

fn any_var_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
    cache_size: NonZeroUsize,
) -> commonware_storage::qmdb::any::VariableConfig<EightCap, ((), ()), Rayon> {
    let pc = CacheRef::from_pooler(ctx, PAGE_SIZE, cache_size);
    commonware_storage::qmdb::any::VariableConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: var_log_cfg(pc),
        translator: EightCap,
    }
}

fn cur_fix_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
    cache_size: NonZeroUsize,
) -> commonware_storage::qmdb::current::FixedConfig<EightCap, Rayon> {
    let pc = CacheRef::from_pooler(ctx, PAGE_SIZE, cache_size);
    commonware_storage::qmdb::current::FixedConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: fix_log_cfg(pc),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
    }
}

fn cur_var_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
    cache_size: NonZeroUsize,
) -> commonware_storage::qmdb::current::VariableConfig<EightCap, ((), ()), Rayon> {
    let pc = CacheRef::from_pooler(ctx, PAGE_SIZE, cache_size);
    commonware_storage::qmdb::current::VariableConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: var_log_cfg(pc),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
    }
}

// -- Benchmark helpers --

/// Single-batch benchmark: create batch, write updates, merkleize, read root.
///
/// If `seed_sync` is `true`, the seed database is fully synced before running the benchmark. A
/// value of `false` will exercise the DB in a state where lookups during merkleize may be satisfied
/// by the `Append` wrapper's tip buffer, which may be more reflective of a real application that
/// calls only `commit()` for durability.
async fn run_bench<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    mut db: C,
    num_keys: u64,
    iters: u64,
    seed_sync: bool,
) -> Duration {
    seed_db(&mut db, num_keys).await;
    if seed_sync {
        db.sync().await.unwrap();
    }
    let num_updates = num_keys / 10;
    let mut rng = StdRng::seed_from_u64(99);
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let batch = write_random_updates(db.new_batch(), num_updates, num_keys, &mut rng);
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        black_box(merkleized.root());
        total += start.elapsed();
    }
    db.destroy().await.unwrap();
    total
}

/// Apply overwrite batches before timing merkleization.
///
/// This leaves inactive update operations above the inactivity floor, matching
/// the workload optimized by bitmap-backed floor raising.
async fn run_churned_bench<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    mut db: C,
    num_keys: u64,
    churn_batches: u64,
    iters: u64,
) -> Duration {
    seed_db(&mut db, num_keys).await;
    let num_updates = num_keys / 10;
    let mut rng = StdRng::seed_from_u64(99);

    for _ in 0..churn_batches {
        let batch = write_random_updates(db.new_batch(), num_updates, num_keys, &mut rng);
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
    }
    db.commit().await.unwrap();
    db.sync().await.unwrap();

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let batch = write_random_updates(db.new_batch(), num_updates, num_keys, &mut rng);
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        black_box(merkleized.root());
        total += start.elapsed();
    }
    db.destroy().await.unwrap();
    total
}

/// Chained benchmark: merkleize a parent (not timed), then create a child from
/// the parent, write updates, merkleize the child, and read its root (timed).
///
/// `fork_child` bridges the gap between the generic trait and the concrete
/// `MerkleizedBatch::new_batch` method.
async fn run_chained_bench<
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    Fn: std::ops::Fn(&C::Merkleized) -> C::Batch,
>(
    mut db: C,
    num_keys: u64,
    iters: u64,
    seed_sync: bool,
    fork_child: Fn,
) -> Duration {
    seed_db(&mut db, num_keys).await;
    if seed_sync {
        db.sync().await.unwrap();
    }
    let num_updates = num_keys / 10;
    let mut rng = StdRng::seed_from_u64(99);
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        // Build and merkleize parent (not timed).
        let parent_batch = write_random_updates(db.new_batch(), num_updates, num_keys, &mut rng);
        let parent = parent_batch.merkleize(&db, None).await.unwrap();

        // Build and merkleize child (timed).
        let start = Instant::now();
        let child_batch =
            write_random_updates(fork_child(&parent), num_updates, num_keys, &mut rng);
        let child = child_batch.merkleize(&db, None).await.unwrap();
        black_box(child.root());
        total += start.elapsed();
    }
    db.destroy().await.unwrap();
    total
}

// -- Variant dispatch --

macro_rules! variants {
    (
        $(
            $entry:ident {
                name: $name:literal,
                init: |$ctx:ident, $cache:ident| $init:expr,
            }
        )+
    ) => {
        #[derive(Debug, Clone, Copy)]
        enum Variant {
            $($entry),+
        }

        impl Variant {
            const fn name(self) -> &'static str {
                match self {
                    $(Self::$entry => $name),+
                }
            }

            /// Whether this is an `any::*` variant (vs `current::*`).
            fn is_any(&self) -> bool {
                self.name().starts_with("any::")
            }
        }

        const VARIANTS: &[Variant] = &[
            $(Variant::$entry),+
        ];

        /// Dispatch a variant to its concrete DB type, initialize it with the given page-cache
        /// size, and run `$body` with the resulting `db` in scope.
        macro_rules! dispatch_variant {
            ($ctx_expr:expr, $variant_expr:expr, $cache_size:expr, |$db_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        Variant::$entry => {
                            let $ctx = $ctx_expr;
                            let $cache = $cache_size;
                            let $db_name = $init.await.unwrap();
                            $body
                        }
                    )+
                }
            };
        }
    };
}

variants! {
    AnyFixed {
        name: "any::unordered::fixed::mmr",
        init: |ctx, cache_size| AnyUFix::init(ctx.child("storage"), any_fix_cfg(&ctx, cache_size)),
    }
    AnyVariable {
        name: "any::unordered::variable::mmr",
        init: |ctx, cache_size| AnyUVar::init(ctx.child("storage"), any_var_cfg(&ctx, cache_size)),
    }
    AnyFixedMmb {
        name: "any::unordered::fixed::mmb",
        init: |ctx, cache_size| AnyUFixMmb::init(ctx.child("storage"), any_fix_cfg(&ctx, cache_size)),
    }
    AnyVariableMmb {
        name: "any::unordered::variable::mmb",
        init: |ctx, cache_size| AnyUVarMmb::init(ctx.child("storage"), any_var_cfg(&ctx, cache_size)),
    }
    AnyOrderedFixed {
        name: "any::ordered::fixed::mmr",
        init: |ctx, cache_size| AnyOFix::init(ctx.child("storage"), any_fix_cfg(&ctx, cache_size)),
    }
    AnyOrderedVariable {
        name: "any::ordered::variable::mmr",
        init: |ctx, cache_size| AnyOVar::init(ctx.child("storage"), any_var_cfg(&ctx, cache_size)),
    }
    AnyOrderedFixedMmb {
        name: "any::ordered::fixed::mmb",
        init: |ctx, cache_size| AnyOFixMmb::init(ctx.child("storage"), any_fix_cfg(&ctx, cache_size)),
    }
    AnyOrderedVariableMmb {
        name: "any::ordered::variable::mmb",
        init: |ctx, cache_size| AnyOVarMmb::init(ctx.child("storage"), any_var_cfg(&ctx, cache_size)),
    }
    CurrentFixed32 {
        name: "current::unordered::fixed::mmr chunk=32",
        init: |ctx, cache_size| CurUFix32::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentVariable32 {
        name: "current::unordered::variable::mmr chunk=32",
        init: |ctx, cache_size| CurUVar32::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentFixed32Mmb {
        name: "current::unordered::fixed::mmb chunk=32",
        init: |ctx, cache_size| CurUFix32Mmb::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentVariable32Mmb {
        name: "current::unordered::variable::mmb chunk=32",
        init: |ctx, cache_size| CurUVar32Mmb::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentFixed256 {
        name: "current::unordered::fixed::mmr chunk=256",
        init: |ctx, cache_size| CurUFix256::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentVariable256 {
        name: "current::unordered::variable::mmr chunk=256",
        init: |ctx, cache_size| CurUVar256::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentFixed256Mmb {
        name: "current::unordered::fixed::mmb chunk=256",
        init: |ctx, cache_size| CurUFix256Mmb::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentVariable256Mmb {
        name: "current::unordered::variable::mmb chunk=256",
        init: |ctx, cache_size| CurUVar256Mmb::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentOrderedFixed32 {
        name: "current::ordered::fixed::mmr chunk=32",
        init: |ctx, cache_size| CurOFix32::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentOrderedVariable32 {
        name: "current::ordered::variable::mmr chunk=32",
        init: |ctx, cache_size| CurOVar32::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentOrderedFixed32Mmb {
        name: "current::ordered::fixed::mmb chunk=32",
        init: |ctx, cache_size| CurOFix32Mmb::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentOrderedVariable32Mmb {
        name: "current::ordered::variable::mmb chunk=32",
        init: |ctx, cache_size| CurOVar32Mmb::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentOrderedFixed256 {
        name: "current::ordered::fixed::mmr chunk=256",
        init: |ctx, cache_size| CurOFix256::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentOrderedVariable256 {
        name: "current::ordered::variable::mmr chunk=256",
        init: |ctx, cache_size| CurOVar256::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
    CurrentOrderedFixed256Mmb {
        name: "current::ordered::fixed::mmb chunk=256",
        init: |ctx, cache_size| CurOFix256Mmb::init(ctx.child("storage"), cur_fix_cfg(&ctx, cache_size)),
    }
    CurrentOrderedVariable256Mmb {
        name: "current::ordered::variable::mmb chunk=256",
        init: |ctx, cache_size| CurOVar256Mmb::init(ctx.child("storage"), cur_var_cfg(&ctx, cache_size)),
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const NUM_KEYS: [u64; 1] = [10_000];
    } else {
        const NUM_KEYS: [u64; 3] = [10_000, 100_000, 1_000_000];
    }
}

fn bench_merkleize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for chained in [false, true] {
        for seed_sync in [false, true] {
            for num_keys in NUM_KEYS {
                for &variant in VARIANTS {
                    c.bench_function(
                        &format!(
                            "{}/variant={} keys={num_keys} ch={chained} sync={seed_sync}",
                            module_path!(),
                            variant.name(),
                        ),
                        |b| {
                            b.to_async(&runner).iter_custom(|iters| async move {
                                let ctx = context::get::<Context>();
                                dispatch_variant!(ctx, variant, LARGE_PAGE_CACHE_SIZE, |db| {
                                    if chained {
                                        run_chained_bench(db, num_keys, iters, seed_sync, |p| {
                                            p.new_batch()
                                        })
                                        .await
                                    } else {
                                        run_bench(db, num_keys, iters, seed_sync).await
                                    }
                                })
                            });
                        },
                    );
                }
            }
        }
    }
}

/// Overwrite batches applied before timing the churned benchmark.
const CHURN_BATCHES: u64 = 50;

/// Time merkleization after repeatedly overwriting existing keys.
///
/// The overwrite batches create inactive log entries that floor raising must
/// scan past. The smaller cache makes unnecessary reads of those entries show
/// up in the benchmark.
fn bench_merkleize_churned(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    let cache_pages = SMALL_PAGE_CACHE_SIZE.get();
    for num_keys in NUM_KEYS {
        // `current::*` already used a bitmap; only `any::*` exercises the new scan path.
        for variant in VARIANTS.iter().copied().filter(Variant::is_any) {
            c.bench_function(
                &format!(
                    "{}/variant={} keys={num_keys} churn={CHURN_BATCHES} cache_pages={cache_pages}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        dispatch_variant!(ctx, variant, SMALL_PAGE_CACHE_SIZE, |db| {
                            run_churned_bench(db, num_keys, CHURN_BATCHES, iters).await
                        })
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_merkleize, bench_merkleize_churned
}
