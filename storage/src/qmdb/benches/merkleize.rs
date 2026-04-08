//! Benchmarks for speculative batch merkleization.
//!
//! Measures the time required to create a speculative batch (applying random updates equal to 10%
//! of the total key count, sampled with replacement), merkleize it, and compute its root. The
//! database is initialized with N unique keys having random digests as values. Database
//! initialization time is not included in the benchmark. The page cache is large enough to hold the
//! entire active key set to eliminate disk access delays from affecting the results.

use crate::common::{make_fixed_value, Digest, CHUNK_SIZE, WRITE_BUFFER_SIZE};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    BufferPooler, ThreadPooler,
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

// -- Config --

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(100_000);
const THREADS: NonZeroUsize = NZUsize!(8);
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(131_072);
const PARTITION: &str = "bench-merkleize";

fn merkle_cfg(ctx: &(impl BufferPooler + ThreadPooler), pc: CacheRef) -> journaled::Config {
    journaled::Config {
        journal_partition: format!("journal-{PARTITION}"),
        metadata_partition: format!("metadata-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
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

fn pc(ctx: &impl BufferPooler) -> CacheRef {
    CacheRef::from_pooler(ctx, PAGE_SIZE, LARGE_PAGE_CACHE_SIZE)
}

// -- DB constructors (eliminates repeated config boilerplate in match arms) --

fn any_fix_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> commonware_storage::qmdb::any::FixedConfig<EightCap> {
    let pc = pc(ctx);
    commonware_storage::qmdb::any::FixedConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: fix_log_cfg(pc),
        translator: EightCap,
    }
}

fn any_var_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> commonware_storage::qmdb::any::VariableConfig<EightCap, ((), ())> {
    let pc = pc(ctx);
    commonware_storage::qmdb::any::VariableConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: var_log_cfg(pc),
        translator: EightCap,
    }
}

fn cur_fix_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> commonware_storage::qmdb::current::FixedConfig<EightCap> {
    let pc = pc(ctx);
    commonware_storage::qmdb::current::FixedConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: fix_log_cfg(pc),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
    }
}

fn cur_var_cfg(
    ctx: &(impl BufferPooler + ThreadPooler),
) -> commonware_storage::qmdb::current::VariableConfig<EightCap, ((), ())> {
    let pc = pc(ctx);
    commonware_storage::qmdb::current::VariableConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: var_log_cfg(pc),
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

#[derive(Debug, Clone, Copy)]
enum Variant {
    AnyFixed,
    AnyVariable,
    AnyFixedMmb,
    AnyVariableMmb,
    CurrentFixed32,
    CurrentVariable32,
    CurrentFixed32Mmb,
    CurrentVariable32Mmb,
    CurrentFixed256,
    CurrentVariable256,
    CurrentFixed256Mmb,
    CurrentVariable256Mmb,
}

impl Variant {
    const fn name(self) -> &'static str {
        match self {
            Self::AnyFixed => "any::unordered::fixed::mmr",
            Self::AnyVariable => "any::unordered::variable::mmr",
            Self::AnyFixedMmb => "any::unordered::fixed::mmb",
            Self::AnyVariableMmb => "any::unordered::variable::mmb",
            Self::CurrentFixed32 => "current::unordered::fixed::mmr chunk=32",
            Self::CurrentVariable32 => "current::unordered::variable::mmr chunk=32",
            Self::CurrentFixed32Mmb => "current::unordered::fixed::mmb chunk=32",
            Self::CurrentVariable32Mmb => "current::unordered::variable::mmb chunk=32",
            Self::CurrentFixed256 => "current::unordered::fixed::mmr chunk=256",
            Self::CurrentVariable256 => "current::unordered::variable::mmr chunk=256",
            Self::CurrentFixed256Mmb => "current::unordered::fixed::mmb chunk=256",
            Self::CurrentVariable256Mmb => "current::unordered::variable::mmb chunk=256",
        }
    }
}

const VARIANTS: [Variant; 12] = [
    Variant::AnyFixed,
    Variant::AnyVariable,
    Variant::AnyFixedMmb,
    Variant::AnyVariableMmb,
    Variant::CurrentFixed32,
    Variant::CurrentVariable32,
    Variant::CurrentFixed32Mmb,
    Variant::CurrentVariable32Mmb,
    Variant::CurrentFixed256,
    Variant::CurrentVariable256,
    Variant::CurrentFixed256Mmb,
    Variant::CurrentVariable256Mmb,
];

/// Dispatch a variant to its concrete DB type and config, then execute `$body` with `db` bound.
macro_rules! dispatch_variant {
    ($ctx:expr, $variant:expr, |$db:ident| $body:expr) => {
        match $variant {
            Variant::AnyFixed => {
                let $db = AnyUFix::init($ctx.clone(), any_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::AnyVariable => {
                let $db = AnyUVar::init($ctx.clone(), any_var_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::AnyFixedMmb => {
                let $db = AnyUFixMmb::init($ctx.clone(), any_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::AnyVariableMmb => {
                let $db = AnyUVarMmb::init($ctx.clone(), any_var_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentFixed32 => {
                let $db = CurUFix32::init($ctx.clone(), cur_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentVariable32 => {
                let $db = CurUVar32::init($ctx.clone(), cur_var_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentFixed32Mmb => {
                let $db = CurUFix32Mmb::init($ctx.clone(), cur_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentVariable32Mmb => {
                let $db = CurUVar32Mmb::init($ctx.clone(), cur_var_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentFixed256 => {
                let $db = CurUFix256::init($ctx.clone(), cur_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentVariable256 => {
                let $db = CurUVar256::init($ctx.clone(), cur_var_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentFixed256Mmb => {
                let $db = CurUFix256Mmb::init($ctx.clone(), cur_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
            Variant::CurrentVariable256Mmb => {
                let $db = CurUVar256Mmb::init($ctx.clone(), cur_var_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }
        }
    };
}

fn bench_merkleize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for num_keys in [10_000u64, 100_000, 1_000_000] {
        for variant in VARIANTS {
            c.bench_function(
                &format!(
                    "{}/variant={} num_keys={num_keys}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        dispatch_variant!(ctx, variant, |db| {
                            run_bench(db, num_keys, iters).await
                        })
                    });
                },
            );
        }
    }
}

fn bench_chained_merkleize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for num_keys in [10_000u64, 100_000, 1_000_000] {
        for variant in VARIANTS {
            c.bench_function(
                &format!(
                    "{}/chained variant={} num_keys={num_keys}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        dispatch_variant!(ctx, variant, |db| {
                            run_chained_bench(db, num_keys, iters, |p| p.new_batch()).await
                        })
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_merkleize, bench_chained_merkleize
}
