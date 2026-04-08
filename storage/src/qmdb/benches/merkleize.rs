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
    merkle::mmr::journaled::Config as MmrConfig,
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
type CurUFix = commonware_storage::qmdb::current::unordered::fixed::Db<
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type CurUVar = commonware_storage::qmdb::current::unordered::variable::Db<
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(100_000);
const THREADS: NonZeroUsize = NZUsize!(8);

/// Configure a large (512MB) page cache that can hold all active keys in RAM.
const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const LARGE_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(131_072);
const PARTITION: &str = "bench-merkleize";

fn mmr_cfg(ctx: &(impl BufferPooler + ThreadPooler), page_cache: CacheRef) -> MmrConfig {
    MmrConfig {
        journal_partition: format!("journal-{PARTITION}"),
        metadata_partition: format!("metadata-{PARTITION}"),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER_SIZE,
        thread_pool: Some(ctx.create_thread_pool(THREADS).unwrap()),
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

fn large_page_cache(ctx: &impl BufferPooler) -> CacheRef {
    CacheRef::from_pooler(ctx, PAGE_SIZE, LARGE_PAGE_CACHE_SIZE)
}

/// Pre-populate the database with `num_keys` unique keys, commit, and sync.
async fn seed_db<
    C: DbAny<commonware_storage::merkle::mmr::Family, Key = Digest, Value = Digest>,
>(
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

/// Create a speculative batch by applying random updates equal to 10% of the key count
/// (sampled with replacement), then merkleize & retrieve its root.
/// Returns elapsed time for the batch+merkleize+root cycle.
async fn bench_speculative_merkleize<
    C: DbAny<commonware_storage::merkle::mmr::Family, Key = Digest, Value = Digest>,
>(
    db: &C,
    num_keys: u64,
) -> Duration {
    let mut rng = StdRng::seed_from_u64(99);
    let num_updates = num_keys / 10;

    let start = Instant::now();

    let mut batch = db.new_batch();
    for _ in 0..num_updates {
        let idx = rng.next_u64() % num_keys;
        let k = Sha256::hash(&idx.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(&mut rng)));
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    black_box(merkleized.root());

    start.elapsed()
}

/// Run the benchmark for a concrete DB type.
async fn run_bench<
    C: DbAny<commonware_storage::merkle::mmr::Family, Key = Digest, Value = Digest>,
>(
    mut db: C,
    num_keys: u64,
    iters: u64,
) -> Duration {
    seed_db(&mut db, num_keys).await;
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        total += bench_speculative_merkleize(&db, num_keys).await;
    }
    db.destroy().await.unwrap();
    total
}

#[derive(Debug, Clone, Copy)]
enum Variant {
    AnyFixed,
    AnyVariable,
    CurrentFixed,
    CurrentVariable,
}

impl Variant {
    const fn name(self) -> &'static str {
        match self {
            Self::AnyFixed => "any::unordered::fixed",
            Self::AnyVariable => "any::unordered::variable",
            Self::CurrentFixed => "current::unordered::fixed",
            Self::CurrentVariable => "current::unordered::variable",
        }
    }
}

const VARIANTS: [Variant; 4] = [
    Variant::AnyFixed,
    Variant::AnyVariable,
    Variant::CurrentFixed,
    Variant::CurrentVariable,
];

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
                        let pc = large_page_cache(&ctx);
                        match variant {
                            Variant::AnyFixed => {
                                let cfg = commonware_storage::qmdb::any::FixedConfig {
                                    merkle_config: mmr_cfg(&ctx, pc.clone()),
                                    journal_config: fix_log_cfg(pc),
                                    translator: EightCap,
                                };
                                let db = AnyUFix::init(ctx, cfg).await.unwrap();
                                run_bench(db, num_keys, iters).await
                            }
                            Variant::AnyVariable => {
                                let cfg = commonware_storage::qmdb::any::VariableConfig {
                                    merkle_config: mmr_cfg(&ctx, pc.clone()),
                                    journal_config: var_log_cfg(pc),
                                    translator: EightCap,
                                };
                                let db = AnyUVar::init(ctx, cfg).await.unwrap();
                                run_bench(db, num_keys, iters).await
                            }
                            Variant::CurrentFixed => {
                                let cfg = commonware_storage::qmdb::current::FixedConfig {
                                    mmr_config: mmr_cfg(&ctx, pc.clone()),
                                    journal_config: fix_log_cfg(pc),
                                    grafted_mmr_metadata_partition: format!(
                                        "grafted-mmr-metadata-{PARTITION}"
                                    ),
                                    translator: EightCap,
                                };
                                let db = CurUFix::init(ctx, cfg).await.unwrap();
                                run_bench(db, num_keys, iters).await
                            }
                            Variant::CurrentVariable => {
                                let cfg = commonware_storage::qmdb::current::VariableConfig {
                                    mmr_config: mmr_cfg(&ctx, pc.clone()),
                                    journal_config: var_log_cfg(pc),
                                    grafted_mmr_metadata_partition: format!(
                                        "grafted-mmr-metadata-{PARTITION}"
                                    ),
                                    translator: EightCap,
                                };
                                let db = CurUVar::init(ctx, cfg).await.unwrap();
                                run_bench(db, num_keys, iters).await
                            }
                        }
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_merkleize
}
