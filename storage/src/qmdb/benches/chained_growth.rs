//! Benchmark for chained-growth merkleization against Current QMDB variants.
//!
//! Setup (untimed): seed `NUM_KEYS` keys, then grow a chain of `PREBUILT_CHAIN` batches applying
//! each parent while the child is still alive.
//!
//! Timed: do `batches` more merkleize + apply iterations on top of the pre-built chain, with a
//! single random update per batch so each overlay covers a tiny fraction of chunks.

use crate::common::{seed_db, write_random_updates, Digest, WRITE_BUFFER_SIZE};
use commonware_cryptography::Sha256;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    BufferPooler, ThreadPooler,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{self, full, mmb::Family as Mmb},
    qmdb::{
        any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
        current::{ordered::fixed::Db as OCFixed, unordered::fixed::Db as UCFixed},
    },
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

// -- Config (mirrors merkleize bench) --

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const THREADS: NonZeroUsize = NZUsize!(8);
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(131_072);
const PARTITION: &str = "bench-chained-growth";

const SMALL_CHUNK_SIZE: usize = 32;
const LARGE_CHUNK_SIZE: usize = 256;

type CurUFix32Mmb = UCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, SMALL_CHUNK_SIZE>;
type CurOFix32Mmb = OCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, SMALL_CHUNK_SIZE>;
type CurUFix256Mmb = UCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, LARGE_CHUNK_SIZE>;
type CurOFix256Mmb = OCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, LARGE_CHUNK_SIZE>;

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

fn pc(ctx: &impl BufferPooler) -> CacheRef {
    CacheRef::from_pooler(ctx, PAGE_SIZE, LARGE_PAGE_CACHE_SIZE)
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

/// Number of pre-populated keys in the seeded database.
const NUM_KEYS: u64 = 1_000_000;

/// Random updates per batch. One update means each batch's chunk overlay covers ~1 / num_chunks
/// of the bitmap, forcing chain reads to walk deep before finding a matching layer.
const UPDATES_PER_BATCH: u64 = 1;

/// Number of batches grown during the untimed seed phase, producing a Db::status chain of this
/// depth that subsequent reads must walk through.
const PREBUILT_CHAIN: u64 = 10_000;

/// Number of additional batches to grow during the timed region.
const GROW_COUNTS: [u64; 1] = [100];

#[derive(Debug, Clone, Copy)]
enum CurrentVariant {
    UnorderedFixed32,
    OrderedFixed32,
    UnorderedFixed256,
    OrderedFixed256,
}

impl CurrentVariant {
    const fn name(self) -> &'static str {
        match self {
            Self::UnorderedFixed32 => "current::unordered::fixed::mmb chunk=32",
            Self::OrderedFixed32 => "current::ordered::fixed::mmb chunk=32",
            Self::UnorderedFixed256 => "current::unordered::fixed::mmb chunk=256",
            Self::OrderedFixed256 => "current::ordered::fixed::mmb chunk=256",
        }
    }
}

const CURRENT_VARIANTS: [CurrentVariant; 4] = [
    CurrentVariant::UnorderedFixed32,
    CurrentVariant::OrderedFixed32,
    CurrentVariant::UnorderedFixed256,
    CurrentVariant::OrderedFixed256,
];

/// Construct a Current database for `$variant`, bind it as `$db`, and execute `$body`.
macro_rules! with_current_db {
    ($ctx:expr, $variant:expr, |mut $db:ident| $body:expr) => {{
        macro_rules! init_db {
            ($DbType:ty) => {{
                #[allow(unused_mut)]
                let mut $db = <$DbType>::init($ctx.clone(), cur_fix_cfg(&$ctx))
                    .await
                    .unwrap();
                $body
            }};
        }
        match $variant {
            CurrentVariant::UnorderedFixed32 => init_db!(CurUFix32Mmb),
            CurrentVariant::OrderedFixed32 => init_db!(CurOFix32Mmb),
            CurrentVariant::UnorderedFixed256 => init_db!(CurUFix256Mmb),
            CurrentVariant::OrderedFixed256 => init_db!(CurOFix256Mmb),
        }
    }};
}

/// Run a chained-growth sequence with a pre-built deep chain.
///
/// `fork_child` bridges the generic trait and the concrete `new_batch` method on a merkleized
/// batch.
async fn run_chained_growth<
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    Fork: Fn(&C::Merkleized) -> C::Batch,
>(
    mut db: C,
    grow: u64,
    fork_child: Fork,
) -> Duration {
    seed_db(&mut db, NUM_KEYS).await;
    let mut rng = StdRng::seed_from_u64(99);

    // Pre-build a deep chain (untimed).
    let initial = write_random_updates(db.new_batch(), UPDATES_PER_BATCH, NUM_KEYS, &mut rng);
    let mut parent = initial.merkleize(&db, None).await.unwrap();
    for _ in 0..PREBUILT_CHAIN {
        let child_batch =
            write_random_updates(fork_child(&parent), UPDATES_PER_BATCH, NUM_KEYS, &mut rng);
        let child = child_batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(parent).await.unwrap();
        parent = child;
    }

    // Flush buffered data so the timed region doesn't inherit setup fsync cost.
    db.commit().await.unwrap();
    db.sync().await.unwrap();

    // Timed: grow more batches on top of the pre-built chain.
    let start = Instant::now();
    for _ in 0..grow {
        let child_batch =
            write_random_updates(fork_child(&parent), UPDATES_PER_BATCH, NUM_KEYS, &mut rng);
        let child = child_batch.merkleize(&db, None).await.unwrap();
        black_box(child.root());
        db.apply_batch(parent).await.unwrap();
        parent = child;
    }
    db.apply_batch(parent).await.unwrap();
    let total = start.elapsed();

    db.destroy().await.unwrap();
    total
}

fn bench_chained_growth(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for batches in GROW_COUNTS {
        for &variant in &CURRENT_VARIANTS {
            c.bench_function(
                &format!(
                    "{}/variant={} batches={batches}",
                    module_path!(),
                    variant.name()
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            with_current_db!(ctx.clone(), variant, |mut db| {
                                total += run_chained_growth(db, batches, |p| p.new_batch()).await;
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
    targets = bench_chained_growth
}
