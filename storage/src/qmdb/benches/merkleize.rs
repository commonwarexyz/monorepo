//! Benchmarks for speculative batch merkleization.
//!
//! Measures the time required to create a speculative batch (applying random updates equal to 10%
//! of the total key count, sampled with replacement), merkleize it, and compute its root. The
//! database is initialized with N unique keys having random digests as values. Database
//! initialization time is not included in the benchmark. The page cache is large enough to hold the
//! entire active key set to eliminate disk access delays from affecting the results.

use crate::common::{make_fixed_value, Digest, CHUNK_SIZE, WRITE_BUFFER_SIZE};
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::ThreadPool;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    Metrics as _, ThreadPooler,
};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{self, journaled},
    qmdb::any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
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
>;
type AnyUVar = commonware_storage::qmdb::any::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type AnyUFixMmb = commonware_storage::qmdb::any::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type AnyUVarMmb = commonware_storage::qmdb::any::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type CurUFix32 = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurUVar32 = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurUFix32Mmb = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurUVar32Mmb = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
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
>;
type CurUVar256 = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;
type CurUFix256Mmb = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;
type CurUVar256Mmb = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;

// Ordered variants.
type AnyOFix = commonware_storage::qmdb::any::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type AnyOVar = commonware_storage::qmdb::any::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type AnyOFixMmb = commonware_storage::qmdb::any::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type AnyOVarMmb = commonware_storage::qmdb::any::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
>;
type CurOFix32 = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurOVar32 = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurOFix32Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurOVar32Mmb = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurOFix256 = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;
type CurOVar256 = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;
type CurOFix256Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;
type CurOVar256Mmb = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
>;

// -- Config --

// Use huge blobs to avoid iteration times being affected by multiple fsyncs from crossing blob
// boundaries.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const THREADS: NonZeroUsize = NZUsize!(8);
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(131_072);
const PARTITION: &str = "bench-merkleize";

fn merkle_cfg(thread_pool: ThreadPool, page_cache: CacheRef) -> journaled::Config {
    journaled::Config {
        journal_partition: format!("journal-{PARTITION}"),
        metadata_partition: format!("metadata-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        thread_pool: Some(thread_pool),
        page_cache,
    }
}

fn fix_log_cfg(page_cache: CacheRef) -> FConfig {
    FConfig {
        partition: format!("log-journal-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        page_cache,
        write_buffer: WRITE_BUFFER_SIZE,
    }
}

fn var_log_cfg(page_cache: CacheRef) -> VConfig<((), ())> {
    VConfig {
        partition: format!("log-journal-{PARTITION}"),
        items_per_section: ITEMS_PER_BLOB,
        compression: None,
        codec_config: ((), ()),
        page_cache,
        write_buffer: WRITE_BUFFER_SIZE,
    }
}

fn any_fix_cfg(
    thread_pool: ThreadPool,
    page_cache: CacheRef,
) -> commonware_storage::qmdb::any::FixedConfig<EightCap> {
    commonware_storage::qmdb::any::FixedConfig {
        merkle_config: merkle_cfg(thread_pool, page_cache.clone()),
        journal_config: fix_log_cfg(page_cache),
        translator: EightCap,
    }
}

fn any_var_cfg(
    thread_pool: ThreadPool,
    page_cache: CacheRef,
) -> commonware_storage::qmdb::any::VariableConfig<EightCap, ((), ())> {
    commonware_storage::qmdb::any::VariableConfig {
        merkle_config: merkle_cfg(thread_pool, page_cache.clone()),
        journal_config: var_log_cfg(page_cache),
        translator: EightCap,
    }
}

fn cur_fix_cfg(
    thread_pool: ThreadPool,
    page_cache: CacheRef,
) -> commonware_storage::qmdb::current::FixedConfig<EightCap> {
    commonware_storage::qmdb::current::FixedConfig {
        merkle_config: merkle_cfg(thread_pool, page_cache.clone()),
        journal_config: fix_log_cfg(page_cache),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
    }
}

fn cur_var_cfg(
    thread_pool: ThreadPool,
    page_cache: CacheRef,
) -> commonware_storage::qmdb::current::VariableConfig<EightCap, ((), ())> {
    commonware_storage::qmdb::current::VariableConfig {
        merkle_config: merkle_cfg(thread_pool, page_cache.clone()),
        journal_config: var_log_cfg(page_cache),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
    }
}

// -- Benchmark helpers --

/// Pre-populate the database with `num_keys` unique keys, commit, and sync.
async fn seed_db<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    db: &mut C,
    num_keys: u64,
) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.new_batch();
    for i in 0u64..num_keys {
        let k = Sha256::hash(&i.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(&mut rng)));
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    db.apply_batch(merkleized).await.unwrap();
    db.commit().await.unwrap();
    db.sync().await.unwrap();
}

/// Write `num_updates` random key updates into a batch.
fn write_random_updates<
    B: commonware_storage::qmdb::any::traits::UnmerkleizedBatch<Db, K = Digest, V = Digest>,
    Db: ?Sized,
>(
    mut batch: B,
    num_updates: u64,
    num_keys: u64,
    rng: &mut StdRng,
) -> B {
    for _ in 0..num_updates {
        let idx = rng.next_u64() % num_keys;
        let k = Sha256::hash(&idx.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(rng)));
    }
    batch
}

/// Single-batch benchmark: create batch, write updates, merkleize, read root.
async fn run_bench<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    mut db: C,
    num_keys: u64,
    iters: u64,
) -> Duration {
    seed_db(&mut db, num_keys).await;
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
    fork_child: Fn,
) -> Duration {
    seed_db(&mut db, num_keys).await;
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
                init: |$ctx:ident, $tp:ident, $pc:ident| $init:expr,
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
        }

        const VARIANTS: &[Variant] = &[
            $(Variant::$entry),+
        ];

        /// Dispatch a variant to its concrete DB type and config, then execute `$body` with `db`
        /// bound.
        macro_rules! dispatch_variant {
            ($ctx_expr:expr, $variant_expr:expr, |$db_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        Variant::$entry => {
                            let $ctx = $ctx_expr;
                            let $pc = CacheRef::from_pooler($ctx.with_label("cache"), PAGE_SIZE, LARGE_PAGE_CACHE_SIZE);
                            let $tp = $ctx.create_thread_pool(THREADS).unwrap();
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
        init: |ctx, thread_pool, page_cache| AnyUFix::init(ctx.clone(), any_fix_cfg(thread_pool, page_cache)),
    }
    AnyVariable {
        name: "any::unordered::variable::mmr",
        init: |ctx, thread_pool, page_cache| AnyUVar::init(ctx.clone(), any_var_cfg(thread_pool, page_cache)),
    }
    AnyFixedMmb {
        name: "any::unordered::fixed::mmb",
        init: |ctx, thread_pool, page_cache|AnyUFixMmb::init(ctx.clone(), any_fix_cfg(thread_pool, page_cache)),
    }
    AnyVariableMmb {
        name: "any::unordered::variable::mmb",
        init: |ctx, thread_pool, page_cache|AnyUVarMmb::init(ctx.clone(), any_var_cfg(thread_pool, page_cache)),
    }
    AnyOrderedFixed {
        name: "any::ordered::fixed::mmr",
        init: |ctx, thread_pool, page_cache|AnyOFix::init(ctx.clone(), any_fix_cfg(thread_pool, page_cache)),
    }
    AnyOrderedVariable {
        name: "any::ordered::variable::mmr",
        init: |ctx, thread_pool, page_cache|AnyOVar::init(ctx.clone(), any_var_cfg(thread_pool, page_cache)),
    }
    AnyOrderedFixedMmb {
        name: "any::ordered::fixed::mmb",
        init: |ctx, thread_pool, page_cache|AnyOFixMmb::init(ctx.clone(), any_fix_cfg(thread_pool, page_cache)),
    }
    AnyOrderedVariableMmb {
        name: "any::ordered::variable::mmb",
        init: |ctx, thread_pool, page_cache|AnyOVarMmb::init(ctx.clone(), any_var_cfg(thread_pool, page_cache)),
    }
    CurrentFixed32 {
        name: "current::unordered::fixed::mmr chunk=32",
        init: |ctx, thread_pool, page_cache|CurUFix32::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentVariable32 {
        name: "current::unordered::variable::mmr chunk=32",
        init: |ctx, thread_pool, page_cache|CurUVar32::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentFixed32Mmb {
        name: "current::unordered::fixed::mmb chunk=32",
        init: |ctx, thread_pool, page_cache|CurUFix32Mmb::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentVariable32Mmb {
        name: "current::unordered::variable::mmb chunk=32",
        init: |ctx, thread_pool, page_cache|CurUVar32Mmb::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentFixed256 {
        name: "current::unordered::fixed::mmr chunk=256",
        init: |ctx, thread_pool, page_cache|CurUFix256::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentVariable256 {
        name: "current::unordered::variable::mmr chunk=256",
        init: |ctx, thread_pool, page_cache|CurUVar256::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentFixed256Mmb {
        name: "current::unordered::fixed::mmb chunk=256",
        init: |ctx, thread_pool, page_cache|CurUFix256Mmb::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentVariable256Mmb {
        name: "current::unordered::variable::mmb chunk=256",
        init: |ctx, thread_pool, page_cache|CurUVar256Mmb::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedFixed32 {
        name: "current::ordered::fixed::mmr chunk=32",
        init: |ctx, thread_pool, page_cache|CurOFix32::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedVariable32 {
        name: "current::ordered::variable::mmr chunk=32",
        init: |ctx, thread_pool, page_cache|CurOVar32::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedFixed32Mmb {
        name: "current::ordered::fixed::mmb chunk=32",
        init: |ctx, thread_pool, page_cache|CurOFix32Mmb::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedVariable32Mmb {
        name: "current::ordered::variable::mmb chunk=32",
        init: |ctx, thread_pool, page_cache|CurOVar32Mmb::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedFixed256 {
        name: "current::ordered::fixed::mmr chunk=256",
        init: |ctx, thread_pool, page_cache|CurOFix256::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedVariable256 {
        name: "current::ordered::variable::mmr chunk=256",
        init: |ctx, thread_pool, page_cache|CurOVar256::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedFixed256Mmb {
        name: "current::ordered::fixed::mmb chunk=256",
        init: |ctx, thread_pool, page_cache|CurOFix256Mmb::init(ctx.clone(), cur_fix_cfg(thread_pool, page_cache)),
    }
    CurrentOrderedVariable256Mmb {
        name: "current::ordered::variable::mmb chunk=256",
        init: |ctx, thread_pool, page_cache|CurOVar256Mmb::init(ctx.clone(), cur_var_cfg(thread_pool, page_cache)),
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
        for num_keys in NUM_KEYS {
            for &variant in VARIANTS {
                c.bench_function(
                    &format!(
                        "{}/variant={} num_keys={num_keys} chained={chained}",
                        module_path!(),
                        variant.name(),
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<Context>();
                            dispatch_variant!(ctx, variant, |db| {
                                if chained {
                                    run_chained_bench(db, num_keys, iters, |p| p.new_batch()).await
                                } else {
                                    run_bench(db, num_keys, iters).await
                                }
                            })
                        });
                    },
                );
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_merkleize
}
