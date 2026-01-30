//! Benchmarks of QMDB variants on variable-sized values.

use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, tokio::Context, RayonPoolSpawner};
use commonware_storage::{
    kv::{Deletable as _, Updatable as _},
    qmdb::{
        any::{
            ordered::variable::Db as OVariable,
            states::{MutableAny, UnmerkleizedDurableAny},
            unordered::variable::Db as UVariable,
            VariableConfig as AConfig,
        },
        current::{
            ordered::variable::Db as OVCurrent, unordered::variable::Db as UVCurrent,
            VariableConfig as CConfig,
        },
        store::LogStore,
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
            Self::AnyUnordered => "any_unordered",
            Self::AnyOrdered => "any_ordered",
            Self::CurrentUnordered => "current_unordered",
            Self::CurrentOrdered => "current_ordered",
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
const PARTITION_SUFFIX: &str = "any_variable_bench_partition";

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

/// Clean (Merkleized, Durable) db type aliases for Any databases.
type UVariableDb = UVariable<Context, Digest, Vec<u8>, Sha256, EightCap>;
type OVariableDb = OVariable<Context, Digest, Vec<u8>, Sha256, EightCap>;

/// Clean (Merkleized, Durable) db type aliases for Current databases.
type UVCurrentDb = UVCurrent<Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;
type OVCurrentDb = OVCurrent<Context, Digest, Vec<u8>, Sha256, EightCap, CHUNK_SIZE>;

fn any_cfg(pool: ThreadPool) -> AConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    AConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(pool),
        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

async fn get_any_unordered(ctx: Context) -> UVariableDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    UVariableDb::init(ctx, any_cfg).await.unwrap()
}

async fn get_any_ordered(ctx: Context) -> OVariableDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    OVariableDb::init(ctx, any_cfg).await.unwrap()
}

fn current_cfg(pool: ThreadPool) -> CConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    CConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        bitmap_metadata_partition: format!("bitmap_metadata_{PARTITION_SUFFIX}"),
        translator: EightCap,
        thread_pool: Some(pool),
        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

async fn get_current_unordered(ctx: Context) -> UVCurrentDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let current_cfg = current_cfg(pool);
    UVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

async fn get_current_ordered(ctx: Context) -> OVCurrentDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let current_cfg = current_cfg(pool);
    OVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

/// Generate a large db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `commit_frequency` operations.
///
/// Takes a mutable database and returns it in durable state after final commit.
async fn gen_random_kv<M>(
    mut db: M,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: u32,
) -> M::Durable
where
    M: MutableAny<Key = Digest> + LogStore<Value = Vec<u8>>,
    M::Durable: UnmerkleizedDurableAny<Mutable = M>,
{
    // Insert a random value for every possible element into the db.
    let mut rng = StdRng::seed_from_u64(42);
    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
        assert!(db.update(k, v).await.is_ok());
    }

    // Randomly update / delete them + randomly commit.
    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            assert!(db.delete(rand_key).await.is_ok());
            continue;
        }
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
        assert!(db.update(rand_key, v).await.is_ok());
        if rng.next_u32() % commit_frequency == 0 {
            let (durable, _) = db.commit(None).await.unwrap();
            db = durable.into_mutable();
        }
    }
    let (durable, _) = db.commit(None).await.unwrap();
    durable
}

async fn gen_random_kv_batched<M>(
    mut db: M,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: u32,
) -> M::Durable
where
    M: MutableAny<Key = Digest> + LogStore<Value = Vec<u8>>,
    M::Durable: UnmerkleizedDurableAny<Mutable = M>,
{
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.start_batch();

    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
        assert!(batch.update(k, v).await.is_ok());
    }
    let iter = batch.into_iter();
    assert!(db.write_batch(iter).await.is_ok());
    batch = db.start_batch();

    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            assert!(batch.delete(rand_key).await.is_ok());
            continue;
        }
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
        assert!(batch.update(rand_key, v).await.is_ok());
        if rng.next_u32() % commit_frequency == 0 {
            assert!(db.write_batch(batch.into_iter()).await.is_ok());
            let (durable, _) = db.commit(None).await.unwrap();
            db = durable.into_mutable();
            batch = db.start_batch();
        }
    }

    assert!(db.write_batch(batch.into_iter()).await.is_ok());
    let (durable, _) = db.commit(None).await.expect("commit shouldn't fail");
    durable
}
