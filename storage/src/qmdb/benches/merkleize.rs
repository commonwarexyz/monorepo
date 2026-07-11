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
use commonware_bench::{Benchmark, Metric, Workload};
use commonware_cryptography::Sha256;
use commonware_macros::boxed;
use commonware_parallel::Rayon;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    BufferPooler, Metrics as _, Strategizer, Supervisor as _,
};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{self, full},
    qmdb::any::traits::{DbAny, MerkleizedBatch, UnmerkleizedBatch as _},
    translator::EightCap,
};
use commonware_utils::{NZUsize, TestRng, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use std::{
    hint::black_box,
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

// -- Type aliases --

pub(crate) type AnyUFix = commonware_storage::qmdb::any::unordered::fixed::Db<
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
pub(crate) type CurOFix256Mmb = commonware_storage::qmdb::current::ordered::fixed::Db<
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

// Use huge blobs to avoid iteration times being affected by blob boundary crossings.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const THREADS: NonZeroUsize = NZUsize!(8);
pub(crate) const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
// Large enough such that most reads hit the cache.
pub(crate) const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16_384);
// Very small so most reads miss the cache.
const SMALL_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(32);
const PARTITION: &str = "bench-merkleize";

fn merkle_cfg(ctx: &(impl BufferPooler + Strategizer), pc: CacheRef) -> full::Config<Rayon> {
    full::Config {
        journal_partition: format!("journal-{PARTITION}"),
        metadata_partition: format!("metadata-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        strategy: ctx.strategy(THREADS),
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

pub(crate) fn any_fix_cfg_with_cache(
    ctx: &(impl BufferPooler + Strategizer),
    pc: CacheRef,
) -> commonware_storage::qmdb::any::FixedConfig<EightCap, Rayon> {
    commonware_storage::qmdb::any::FixedConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: fix_log_cfg(pc),
        translator: EightCap,
        init_cache_size: crate::common::INIT_CACHE_SIZE,
    }
}

fn any_var_cfg_with_cache(
    ctx: &(impl BufferPooler + Strategizer),
    pc: CacheRef,
) -> commonware_storage::qmdb::any::VariableConfig<EightCap, ((), ()), Rayon> {
    commonware_storage::qmdb::any::VariableConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: var_log_cfg(pc),
        translator: EightCap,
        init_cache_size: crate::common::INIT_CACHE_SIZE,
    }
}

pub(crate) fn cur_fix_cfg_with_cache(
    ctx: &(impl BufferPooler + Strategizer),
    pc: CacheRef,
) -> commonware_storage::qmdb::current::FixedConfig<EightCap, Rayon> {
    commonware_storage::qmdb::current::FixedConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: fix_log_cfg(pc),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
        init_cache_size: crate::common::INIT_CACHE_SIZE,
    }
}

fn cur_var_cfg_with_cache(
    ctx: &(impl BufferPooler + Strategizer),
    pc: CacheRef,
) -> commonware_storage::qmdb::current::VariableConfig<EightCap, ((), ()), Rayon> {
    commonware_storage::qmdb::current::VariableConfig {
        merkle_config: merkle_cfg(ctx, pc.clone()),
        journal_config: var_log_cfg(pc),
        grafted_metadata_partition: format!("grafted-metadata-{PARTITION}"),
        translator: EightCap,
        init_cache_size: crate::common::INIT_CACHE_SIZE,
    }
}

// -- Benchmark helpers --

/// Apply overwrite batches before timing merkleization.
///
/// This leaves inactive update operations above the inactivity floor, matching
/// the workload optimized by bitmap-backed floor raising.
#[boxed]
async fn run_churned_bench<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    mut db: C,
    num_keys: u64,
    churn_batches: u64,
    iters: u64,
) -> Duration {
    seed_db(&mut db, num_keys).await;
    let num_updates = num_keys / 10;
    let mut rng = TestRng::new(99);

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

#[derive(Clone, Copy, Debug)]
pub(crate) struct BenchOptions {
    pub(crate) variant: Variant,
    pub(crate) num_keys: u64,
    pub(crate) chained: bool,
    pub(crate) seed_sync: bool,
    pub(crate) clear_cache: bool,
}

impl BenchOptions {
    pub(crate) fn benchmark(self) -> Benchmark {
        Benchmark::new("qmdb::merkleize")
            .with_param("v", self.variant.name())
            .with_param("k", self.num_keys)
            .with_param("ch", self.chained)
            .with_param("s", self.seed_sync)
            .with_param("cc", self.clear_cache)
    }
}

pub(crate) struct MerkleizeWorkload<F, C>
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
{
    context: Context,
    db: Option<C>,
    page_cache: CacheRef,
    options: BenchOptions,
    new_child: fn(&C::Merkleized) -> C::Batch,
    rng: TestRng,
    parent: Option<C::Merkleized>,
    start_metrics: BlobMetrics,
    _family: PhantomData<F>,
}

impl<F, C> MerkleizeWorkload<F, C>
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
{
    pub(crate) fn new(
        context: Context,
        db: C,
        page_cache: CacheRef,
        options: BenchOptions,
        new_child: fn(&C::Merkleized) -> C::Batch,
    ) -> Self {
        Self {
            context,
            db: Some(db),
            page_cache,
            options,
            new_child,
            rng: TestRng::new(99),
            parent: None,
            start_metrics: BlobMetrics::default(),
            _family: PhantomData,
        }
    }
}

impl<F, C> Workload for MerkleizeWorkload<F, C>
where
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    C::Merkleized: MerkleizedBatch<Digest = Digest>,
{
    type Output = Digest;

    async fn setup(&mut self) {
        let Some(db) = self.db.as_mut() else {
            panic!("database must be present during setup");
        };
        seed_db(db, self.options.num_keys).await;
        if self.options.seed_sync {
            db.sync().await.unwrap();
        }
        if self.options.clear_cache {
            self.page_cache.clear();
        }
        self.start_metrics = BlobMetrics::from_context(&self.context);
    }

    async fn before_iter(&mut self) {
        if !self.options.chained {
            return;
        }
        let Some(db) = self.db.as_ref() else {
            panic!("database must be present before iteration");
        };
        let num_updates = self.options.num_keys / 10;
        let batch = write_random_updates(
            db.new_batch(),
            num_updates,
            self.options.num_keys,
            &mut self.rng,
        );
        self.parent = Some(batch.merkleize(db, None).await.unwrap());
    }

    async fn iter(&mut self) -> Self::Output {
        let Some(db) = self.db.as_ref() else {
            panic!("database must be present during iteration");
        };
        let num_updates = self.options.num_keys / 10;
        let batch = if self.options.chained {
            let Some(parent) = self.parent.as_ref() else {
                panic!("parent must be prepared before chained iteration");
            };
            write_random_updates(
                (self.new_child)(parent),
                num_updates,
                self.options.num_keys,
                &mut self.rng,
            )
        } else {
            write_random_updates(
                db.new_batch(),
                num_updates,
                self.options.num_keys,
                &mut self.rng,
            )
        };
        let merkleized = batch.merkleize(db, None).await.unwrap();
        merkleized.root()
    }

    async fn teardown(&mut self) {
        let Some(db) = self.db.take() else {
            return;
        };
        db.destroy().await.unwrap();
    }

    fn metrics(&self) -> Vec<Metric> {
        BlobMetrics::from_context(&self.context)
            .delta(self.start_metrics)
            .to_vec()
    }
}

#[derive(Clone, Copy, Default)]
struct BlobMetrics {
    reads: u64,
}

impl BlobMetrics {
    fn from_context(context: &Context) -> Self {
        let encoded = context.encode();
        Self {
            reads: metric_value(&encoded, "runtime_storage_reads_total"),
        }
    }

    fn delta(self, start: Self) -> [Metric; 1] {
        [Metric::new(
            "blob_reads",
            self.reads.saturating_sub(start.reads),
        )]
    }
}

fn metric_value(encoded: &str, name: &str) -> u64 {
    for line in encoded.lines() {
        if !line.starts_with(name) {
            continue;
        }
        let Some(value) = line.split_whitespace().nth(1) else {
            continue;
        };
        return value.parse().unwrap_or(0);
    }
    0
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
        pub(crate) enum Variant {
            $($entry),+
        }

        impl Variant {
            pub(crate) const fn name(self) -> &'static str {
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
            ($ctx_expr:expr, $variant_expr:expr, $cache_size:expr, |$db_name:ident, $pc_name:ident| $body:expr) => {
                match $variant_expr {
                    $(
                        Variant::$entry => {
                            let $ctx = &$ctx_expr;
                            let $pc_name = CacheRef::from_pooler($ctx, PAGE_SIZE, $cache_size);
                            let $cache = $pc_name.clone();
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
        init: |ctx, page_cache| AnyUFix::init(ctx.child("storage"), any_fix_cfg_with_cache(ctx, page_cache)),
    }
    AnyVariable {
        name: "any::unordered::variable::mmr",
        init: |ctx, page_cache| AnyUVar::init(ctx.child("storage"), any_var_cfg_with_cache(ctx, page_cache)),
    }
    AnyFixedMmb {
        name: "any::unordered::fixed::mmb",
        init: |ctx, page_cache| AnyUFixMmb::init(ctx.child("storage"), any_fix_cfg_with_cache(ctx, page_cache)),
    }
    AnyVariableMmb {
        name: "any::unordered::variable::mmb",
        init: |ctx, page_cache| AnyUVarMmb::init(ctx.child("storage"), any_var_cfg_with_cache(ctx, page_cache)),
    }
    AnyOrderedFixed {
        name: "any::ordered::fixed::mmr",
        init: |ctx, page_cache| AnyOFix::init(ctx.child("storage"), any_fix_cfg_with_cache(ctx, page_cache)),
    }
    AnyOrderedVariable {
        name: "any::ordered::variable::mmr",
        init: |ctx, page_cache| AnyOVar::init(ctx.child("storage"), any_var_cfg_with_cache(ctx, page_cache)),
    }
    AnyOrderedFixedMmb {
        name: "any::ordered::fixed::mmb",
        init: |ctx, page_cache| AnyOFixMmb::init(ctx.child("storage"), any_fix_cfg_with_cache(ctx, page_cache)),
    }
    AnyOrderedVariableMmb {
        name: "any::ordered::variable::mmb",
        init: |ctx, page_cache| AnyOVarMmb::init(ctx.child("storage"), any_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentFixed32 {
        name: "current::unordered::fixed::mmr chunk=32",
        init: |ctx, page_cache| CurUFix32::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentVariable32 {
        name: "current::unordered::variable::mmr chunk=32",
        init: |ctx, page_cache| CurUVar32::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentFixed32Mmb {
        name: "current::unordered::fixed::mmb chunk=32",
        init: |ctx, page_cache| CurUFix32Mmb::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentVariable32Mmb {
        name: "current::unordered::variable::mmb chunk=32",
        init: |ctx, page_cache| CurUVar32Mmb::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentFixed256 {
        name: "current::unordered::fixed::mmr chunk=256",
        init: |ctx, page_cache| CurUFix256::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentVariable256 {
        name: "current::unordered::variable::mmr chunk=256",
        init: |ctx, page_cache| CurUVar256::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentFixed256Mmb {
        name: "current::unordered::fixed::mmb chunk=256",
        init: |ctx, page_cache| CurUFix256Mmb::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentVariable256Mmb {
        name: "current::unordered::variable::mmb chunk=256",
        init: |ctx, page_cache| CurUVar256Mmb::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedFixed32 {
        name: "current::ordered::fixed::mmr chunk=32",
        init: |ctx, page_cache| CurOFix32::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedVariable32 {
        name: "current::ordered::variable::mmr chunk=32",
        init: |ctx, page_cache| CurOVar32::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedFixed32Mmb {
        name: "current::ordered::fixed::mmb chunk=32",
        init: |ctx, page_cache| CurOFix32Mmb::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedVariable32Mmb {
        name: "current::ordered::variable::mmb chunk=32",
        init: |ctx, page_cache| CurOVar32Mmb::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedFixed256 {
        name: "current::ordered::fixed::mmr chunk=256",
        init: |ctx, page_cache| CurOFix256::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedVariable256 {
        name: "current::ordered::variable::mmr chunk=256",
        init: |ctx, page_cache| CurOVar256::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedFixed256Mmb {
        name: "current::ordered::fixed::mmb chunk=256",
        init: |ctx, page_cache| CurOFix256Mmb::init(ctx.child("storage"), cur_fix_cfg_with_cache(ctx, page_cache)),
    }
    CurrentOrderedVariable256Mmb {
        name: "current::ordered::variable::mmb chunk=256",
        init: |ctx, page_cache| CurOVar256Mmb::init(ctx.child("storage"), cur_var_cfg_with_cache(ctx, page_cache)),
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(full_bench))] {
        const NUM_KEYS: &[u64] = &[10_000];
        const SYNC_NUM_KEYS: &[u64] = NUM_KEYS;
        const CHURNED_NUM_KEYS: &[u64] = NUM_KEYS;
    } else {
        const NUM_KEYS: &[u64] = &[10_000, 100_000, 1_000_000];
        const SYNC_NUM_KEYS: &[u64] = &[10_000, 100_000];
        const CHURNED_NUM_KEYS: &[u64] = &[10_000, 100_000];
    }
}

const fn main_num_keys(seed_sync: bool) -> &'static [u64] {
    if seed_sync {
        SYNC_NUM_KEYS
    } else {
        NUM_KEYS
    }
}

fn bench_merkleize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for chained in [false, true] {
        for seed_sync in [false, true] {
            let clear_cache_options: &[bool] = if !chained && seed_sync {
                &[false, true]
            } else {
                &[false]
            };
            for &clear_cache in clear_cache_options {
                for &num_keys in main_num_keys(seed_sync) {
                    for &variant in VARIANTS {
                        let options = BenchOptions {
                            variant,
                            num_keys,
                            chained,
                            seed_sync,
                            clear_cache,
                        };
                        let benchmark = options.benchmark();
                        let name = benchmark.name().to_string();
                        c.bench_function(&name, |b| {
                            b.to_async(&runner).iter_custom(|iters| {
                                let benchmark = benchmark.clone();
                                async move {
                                    let ctx = context::get::<Context>();
                                    dispatch_variant!(
                                        ctx,
                                        variant,
                                        LARGE_PAGE_CACHE_SIZE,
                                        |db, page_cache| {
                                            Box::pin(benchmark.criterion(
                                                MerkleizeWorkload::new(
                                                    ctx.child("metrics"),
                                                    db,
                                                    page_cache,
                                                    options,
                                                    |parent| parent.new_batch(),
                                                ),
                                                iters,
                                            ))
                                            .await
                                        }
                                    )
                                }
                            });
                        });
                    }
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
    for &num_keys in CHURNED_NUM_KEYS {
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
                        dispatch_variant!(ctx, variant, SMALL_PAGE_CACHE_SIZE, |db, _page_cache| {
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
    config = Criterion::default().sample_size(10);
    targets = bench_merkleize, bench_merkleize_churned
}
