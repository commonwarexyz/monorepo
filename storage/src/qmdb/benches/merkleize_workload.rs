//! Shared QMDB merkleize benchmark workloads.

use crate::common::{seed_db, write_random_updates, Digest, CHUNK_SIZE, WRITE_BUFFER_SIZE};
use commonware_cryptography::Sha256;
use commonware_parallel::Rayon;
use commonware_runtime::{buffer::paged::CacheRef, tokio::Context, BufferPooler, ThreadPooler};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{self, full},
    qmdb::any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

pub type AnyUFix = commonware_storage::qmdb::any::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type AnyUVar = commonware_storage::qmdb::any::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type AnyUFixMmb = commonware_storage::qmdb::any::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type AnyUVarMmb = commonware_storage::qmdb::any::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type CurUFix32 = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurUVar32 = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurUFix32Mmb = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurUVar32Mmb = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;

pub const LARGE_CHUNK_SIZE: usize = 256;

pub type CurUFix256 = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
pub type CurUVar256 = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
pub type CurUFix256Mmb = commonware_storage::qmdb::current::unordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
pub type CurUVar256Mmb = commonware_storage::qmdb::current::unordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;

pub type AnyOFix = commonware_storage::qmdb::any::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type AnyOVar = commonware_storage::qmdb::any::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type AnyOFixMmb = commonware_storage::qmdb::any::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type AnyOVarMmb = commonware_storage::qmdb::any::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
pub type CurOFix32 = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurOVar32 = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurOFix32Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurOVar32Mmb = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
pub type CurOFix256 = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
pub type CurOVar256 = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
pub type CurOFix256Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;
pub type CurOVar256Mmb = commonware_storage::qmdb::current::ordered::variable::Db<
    commonware_storage::merkle::mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    LARGE_CHUNK_SIZE,
    Rayon,
>;

pub const TRACKED_NUM_KEYS: u64 = 10_000;

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        pub const NUM_KEYS: &[u64] = &[TRACKED_NUM_KEYS];
        pub const SYNC_NUM_KEYS: &[u64] = NUM_KEYS;
        pub const CHURNED_NUM_KEYS: &[u64] = NUM_KEYS;
    } else {
        pub const NUM_KEYS: &[u64] = &[TRACKED_NUM_KEYS, 100_000, 1_000_000];
        pub const SYNC_NUM_KEYS: &[u64] = &[TRACKED_NUM_KEYS, 100_000];
        pub const CHURNED_NUM_KEYS: &[u64] = &[TRACKED_NUM_KEYS, 100_000];
    }
}

pub const CHURN_BATCHES: u64 = 50;
pub const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16_384);
pub const SMALL_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(32);

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const THREADS: NonZeroUsize = NZUsize!(8);
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
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

pub fn any_fix_cfg(
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

pub fn any_var_cfg(
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

pub fn cur_fix_cfg(
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

pub fn cur_var_cfg(
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
        pub enum Variant {
            $($entry),+
        }

        impl Variant {
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$entry => $name),+
                }
            }

            pub fn is_any(&self) -> bool {
                self.name().starts_with("any::")
            }
        }

        pub const VARIANTS: &[Variant] = &[
            $(Variant::$entry),+
        ];

        macro_rules! dispatch_variant {
            ($ctx_expr:expr, $variant_expr:expr, $cache_size:expr, |$db_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        $crate::merkleize_workload::Variant::$entry => {
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

pub async fn prepare_db<F, C>(db: &mut C, num_keys: u64, seed_sync: bool)
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
{
    seed_db(db, num_keys).await;
    if seed_sync {
        db.sync().await.unwrap();
    }
}

pub async fn run_bench_once<F, C>(db: &C, num_keys: u64, rng: &mut StdRng) -> C::Merkleized
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
{
    let num_updates = num_keys / 10;
    let batch = write_random_updates(db.new_batch(), num_updates, num_keys, rng);
    batch.merkleize(db, None).await.unwrap()
}

pub async fn run_chained_bench_once<F, C, Fork>(
    db: &C,
    parent: &C::Merkleized,
    num_keys: u64,
    rng: &mut StdRng,
    fork_child: &Fork,
) -> C::Merkleized
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    Fork: Fn(&C::Merkleized) -> C::Batch,
{
    let num_updates = num_keys / 10;
    let batch = write_random_updates(fork_child(parent), num_updates, num_keys, rng);
    batch.merkleize(db, None).await.unwrap()
}

/// Single-batch benchmark: create batch, write updates, merkleize, read root.
///
/// If `seed_sync` is `true`, the seed database is fully synced before running the benchmark. A
/// value of `false` will exercise the DB in a state where lookups during merkleize may be satisfied
/// by the `Append` wrapper's tip buffer, which may be more reflective of a real application that
/// calls only `commit()` for durability.
pub async fn run_bench<F, C>(mut db: C, num_keys: u64, iters: u64, seed_sync: bool) -> Duration
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
{
    prepare_db::<F, _>(&mut db, num_keys, seed_sync).await;
    let mut rng = StdRng::seed_from_u64(99);
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let merkleized = run_bench_once::<F, _>(&db, num_keys, &mut rng).await;
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
pub async fn run_churned_bench<F, C>(
    mut db: C,
    num_keys: u64,
    churn_batches: u64,
    iters: u64,
) -> Duration
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
{
    seed_db(&mut db, num_keys).await;
    let mut rng = StdRng::seed_from_u64(99);

    for _ in 0..churn_batches {
        let merkleized = run_bench_once::<F, _>(&db, num_keys, &mut rng).await;
        db.apply_batch(merkleized).await.unwrap();
    }
    db.commit().await.unwrap();
    db.sync().await.unwrap();

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let start = Instant::now();
        let merkleized = run_bench_once::<F, _>(&db, num_keys, &mut rng).await;
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
pub async fn run_chained_bench<F, C, Fork>(
    mut db: C,
    num_keys: u64,
    iters: u64,
    seed_sync: bool,
    fork_child: Fork,
) -> Duration
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    Fork: Fn(&C::Merkleized) -> C::Batch,
{
    prepare_db::<F, _>(&mut db, num_keys, seed_sync).await;
    let mut rng = StdRng::seed_from_u64(99);
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let parent = run_bench_once::<F, _>(&db, num_keys, &mut rng).await;

        let start = Instant::now();
        let child =
            run_chained_bench_once::<F, _, _>(&db, &parent, num_keys, &mut rng, &fork_child).await;
        black_box(child.root());
        total += start.elapsed();
    }
    db.destroy().await.unwrap();
    total
}
