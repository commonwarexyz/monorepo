//! Benchmarks of QMDB variants on variable-sized values.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, tokio::Context, BufferPooler, ThreadPooler};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    mmr::journaled::Config as MmrConfig,
    qmdb::{
        any::{
            ordered::variable::Db as OVariable,
            traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            unordered::variable::Db as UVariable,
            VariableConfig as AConfig,
        },
        current::{
            ordered::variable::Db as OVCurrent, unordered::variable::Db as UVCurrent,
            VariableConfig as CConfig,
        },
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

pub mod generate;
pub mod init;

pub type Digest = <Sha256 as Hasher>::Digest;

#[derive(Debug, Clone, Copy)]
enum Variant {
    AnyUnordered,
    AnyOrdered,
    CurrentUnordered,
    CurrentOrdered,
}

impl Variant {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AnyUnordered => "any-unordered",
            Self::AnyOrdered => "any-ordered",
            Self::CurrentUnordered => "current-unordered",
            Self::CurrentOrdered => "current-ordered",
        }
    }
}

const VARIANTS: [Variant; 4] = [
    Variant::AnyUnordered,
    Variant::AnyOrdered,
    Variant::CurrentUnordered,
    Variant::CurrentOrdered,
];

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "any-variable-bench-partition";

/// Chunk size for the current QMDB bitmap - must be a power of 2 (as assumed in
/// current::grafting_height()) and a multiple of digest size.
const CHUNK_SIZE: usize = 32;

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores.
const THREADS: NonZeroUsize = NZUsize!(8);

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroU16 = NZU16!(16384);

/// The number of pages to cache in the page cache.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Default delete frequency (1/10th of the updates will be deletes).
const DELETE_FREQUENCY: u32 = 10;

/// Default write buffer size.
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Db type aliases for Any databases.
type UVariableDb = UVariable<Context, Digest, Vec<u8>, Sha256, EightCap>;
type OVariableDb = OVariable<Context, Digest, Vec<u8>, Sha256, EightCap>;

/// Db type aliases for Current databases.
type UVCurrentDb = UVCurrent<Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;
type OVCurrentDb = OVCurrent<Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;

fn any_cfg(
    context: &(impl BufferPooler + ThreadPooler),
) -> AConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
    AConfig::<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
        mmr: MmrConfig {
            journal_partition: format!("journal-{PARTITION_SUFFIX}"),
            metadata_partition: format!("metadata-{PARTITION_SUFFIX}"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER_SIZE,
            thread_pool: Some(context.create_thread_pool(THREADS).unwrap()),
            page_cache: page_cache.clone(),
        },
        log: VConfig {
            partition: format!("log-journal-{PARTITION_SUFFIX}"),
            items_per_section: ITEMS_PER_BLOB,
            compression: None,
            codec_config: ((), ((0..=10000).into(), ())),
            page_cache,
            write_buffer: WRITE_BUFFER_SIZE,
        },
        translator: EightCap,
    }
}

async fn get_any_unordered(ctx: Context) -> UVariableDb {
    let any_cfg = any_cfg(&ctx);
    UVariableDb::init(ctx, any_cfg).await.unwrap()
}

async fn get_any_ordered(ctx: Context) -> OVariableDb {
    let any_cfg = any_cfg(&ctx);
    OVariableDb::init(ctx, any_cfg).await.unwrap()
}

fn current_cfg(
    context: &(impl BufferPooler + ThreadPooler),
) -> CConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
    let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
    CConfig::<EightCap, ((), (commonware_codec::RangeCfg<usize>, ()))> {
        mmr: MmrConfig {
            journal_partition: format!("journal-{PARTITION_SUFFIX}"),
            metadata_partition: format!("metadata-{PARTITION_SUFFIX}"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER_SIZE,
            thread_pool: Some(context.create_thread_pool(THREADS).unwrap()),
            page_cache: page_cache.clone(),
        },
        log: VConfig {
            partition: format!("log-journal-{PARTITION_SUFFIX}"),
            items_per_section: ITEMS_PER_BLOB,
            compression: None,
            codec_config: ((), ((0..=10000).into(), ())),
            page_cache,
            write_buffer: WRITE_BUFFER_SIZE,
        },
        grafted_mmr_metadata_partition: format!("grafted-mmr-metadata-{PARTITION_SUFFIX}"),
        translator: EightCap,
    }
}

async fn get_current_unordered(ctx: Context) -> UVCurrentDb {
    let current_cfg = current_cfg(&ctx);
    UVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

async fn get_current_ordered(ctx: Context) -> OVCurrentDb {
    let current_cfg = current_cfg(&ctx);
    OVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

/// Generate a large db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `commit_frequency` operations.
async fn gen_random_kv<M>(db: &mut M, num_elements: u64, num_operations: u64, commit_frequency: u32)
where
    M: DbAny<Key = Digest, Value = Vec<u8>>,
{
    let mut rng = StdRng::seed_from_u64(42);

    // Seed the db with `num_elements` entries.
    {
        let mut batch = db.new_batch();
        for i in 0u64..num_elements {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
            batch = batch.write(k, Some(v));
        }
        let finalized = batch.merkleize(None).await.unwrap().finalize();
        db.apply_batch(finalized).await.unwrap();
    }

    // Perform `num_operations` random updates/deletes, committing periodically.
    {
        let mut batch = db.new_batch();
        for _ in 0u64..num_operations {
            let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % DELETE_FREQUENCY == 0 {
                batch = batch.write(rand_key, None);
                continue;
            }
            let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
            batch = batch.write(rand_key, Some(v));
            if rng.next_u32() % commit_frequency == 0 {
                let finalized = batch.merkleize(None).await.unwrap().finalize();
                db.apply_batch(finalized).await.unwrap();
                batch = db.new_batch();
            }
        }
        let finalized = batch.merkleize(None).await.unwrap().finalize();
        db.apply_batch(finalized).await.unwrap();
    }
}
