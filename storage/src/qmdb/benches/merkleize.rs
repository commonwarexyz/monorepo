//! Benchmarks for speculative batch merkleization.
//!
//! Measures the time required to create a speculative batch (applying random updates equal to 10%
//! of the total key count, sampled with replacement), merkleize it, and compute its root. The
//! database is initialized with N unique keys having random digests as values. Database
//! initialization time is not included in the benchmark. The page cache is large enough to hold the
//! entire active key set to eliminate disk access delays from affecting the results.

use crate::common::{seed_db, write_random_updates, Digest, CHUNK_SIZE, WRITE_BUFFER_SIZE};
use commonware_cryptography::Sha256;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    BufferPooler, ThreadPooler,
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

fn merkle_cfg(ctx: &(impl BufferPooler + ThreadPooler), pc: CacheRef) -> full::Config {
    full::Config {
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
        split_root: true,
        root_bagging:
            <commonware_storage::mmr::Family as commonware_storage::qmdb::RootSpec>::root_spec(0)
                .bagging(),
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
        split_root: true,
        root_bagging:
            <commonware_storage::mmr::Family as commonware_storage::qmdb::RootSpec>::root_spec(0)
                .bagging(),
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
                init: |$ctx:ident| $init:expr,
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
        init: |ctx| AnyUFix::init(ctx.clone(), any_fix_cfg(&ctx)),
    }
    AnyVariable {
        name: "any::unordered::variable::mmr",
        init: |ctx| AnyUVar::init(ctx.clone(), any_var_cfg(&ctx)),
    }
    AnyFixedMmb {
        name: "any::unordered::fixed::mmb",
        init: |ctx| AnyUFixMmb::init(ctx.clone(), any_fix_cfg(&ctx)),
    }
    AnyVariableMmb {
        name: "any::unordered::variable::mmb",
        init: |ctx| AnyUVarMmb::init(ctx.clone(), any_var_cfg(&ctx)),
    }
    AnyOrderedFixed {
        name: "any::ordered::fixed::mmr",
        init: |ctx| AnyOFix::init(ctx.clone(), any_fix_cfg(&ctx)),
    }
    AnyOrderedVariable {
        name: "any::ordered::variable::mmr",
        init: |ctx| AnyOVar::init(ctx.clone(), any_var_cfg(&ctx)),
    }
    AnyOrderedFixedMmb {
        name: "any::ordered::fixed::mmb",
        init: |ctx| AnyOFixMmb::init(ctx.clone(), any_fix_cfg(&ctx)),
    }
    AnyOrderedVariableMmb {
        name: "any::ordered::variable::mmb",
        init: |ctx| AnyOVarMmb::init(ctx.clone(), any_var_cfg(&ctx)),
    }
    CurrentFixed32 {
        name: "current::unordered::fixed::mmr chunk=32",
        init: |ctx| CurUFix32::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentVariable32 {
        name: "current::unordered::variable::mmr chunk=32",
        init: |ctx| CurUVar32::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentFixed32Mmb {
        name: "current::unordered::fixed::mmb chunk=32",
        init: |ctx| CurUFix32Mmb::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentVariable32Mmb {
        name: "current::unordered::variable::mmb chunk=32",
        init: |ctx| CurUVar32Mmb::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentFixed256 {
        name: "current::unordered::fixed::mmr chunk=256",
        init: |ctx| CurUFix256::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentVariable256 {
        name: "current::unordered::variable::mmr chunk=256",
        init: |ctx| CurUVar256::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentFixed256Mmb {
        name: "current::unordered::fixed::mmb chunk=256",
        init: |ctx| CurUFix256Mmb::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentVariable256Mmb {
        name: "current::unordered::variable::mmb chunk=256",
        init: |ctx| CurUVar256Mmb::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentOrderedFixed32 {
        name: "current::ordered::fixed::mmr chunk=32",
        init: |ctx| CurOFix32::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentOrderedVariable32 {
        name: "current::ordered::variable::mmr chunk=32",
        init: |ctx| CurOVar32::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentOrderedFixed32Mmb {
        name: "current::ordered::fixed::mmb chunk=32",
        init: |ctx| CurOFix32Mmb::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentOrderedVariable32Mmb {
        name: "current::ordered::variable::mmb chunk=32",
        init: |ctx| CurOVar32Mmb::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentOrderedFixed256 {
        name: "current::ordered::fixed::mmr chunk=256",
        init: |ctx| CurOFix256::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentOrderedVariable256 {
        name: "current::ordered::variable::mmr chunk=256",
        init: |ctx| CurOVar256::init(ctx.clone(), cur_var_cfg(&ctx)),
    }
    CurrentOrderedFixed256Mmb {
        name: "current::ordered::fixed::mmb chunk=256",
        init: |ctx| CurOFix256Mmb::init(ctx.clone(), cur_fix_cfg(&ctx)),
    }
    CurrentOrderedVariable256Mmb {
        name: "current::ordered::variable::mmb chunk=256",
        init: |ctx| CurOVar256Mmb::init(ctx.clone(), cur_var_cfg(&ctx)),
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
                                dispatch_variant!(ctx, variant, |db| {
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_merkleize
}
