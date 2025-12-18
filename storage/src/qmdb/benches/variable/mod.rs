//! Benchmarks of QMDB variants on variable-sized values.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::PoolRef, create_pool, tokio::Context, ThreadPool};
use commonware_storage::{
    qmdb::{
        any::{
            ordered::variable::Db as OVariable, unordered::variable::Db as UVariable,
            VariableConfig as AConfig,
        },
        store::{Batchable, Config as SConfig, LogStorePrunable, Store},
    },
    store::StoreDeletable,
    translator::EightCap,
    Persistable,
};
use commonware_utils::{NZUsize, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod generate;
pub mod init;

pub type Digest = <Sha256 as Hasher>::Digest;

#[derive(Debug, Clone, Copy)]
enum Variant {
    Store,
    AnyUnordered,
    AnyOrdered,
}

impl Variant {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::AnyUnordered => "any_unordered",
            Self::AnyOrdered => "any_ordered",
        }
    }
}

const VARIANTS: [Variant; 3] = [Variant::Store, Variant::AnyUnordered, Variant::AnyOrdered];

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "any_variable_bench_partition";

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores.
const THREADS: usize = 8;

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Default delete frequency (1/10th of the updates will be deletes).
const DELETE_FREQUENCY: u32 = 10;

/// Default write buffer size.
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

type StoreDb = Store<Context, <Sha256 as Hasher>::Digest, Vec<u8>, EightCap>;
type UVariableDb = UVariable<Context, <Sha256 as Hasher>::Digest, Vec<u8>, Sha256, EightCap>;
type OVariableDb = OVariable<Context, <Sha256 as Hasher>::Digest, Vec<u8>, Sha256, EightCap>;

fn store_cfg() -> SConfig<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
    SConfig::<EightCap, (commonware_codec::RangeCfg<usize>, ())> {
        log_partition: format!("journal_{PARTITION_SUFFIX}"),
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: ITEMS_PER_BLOB,
        translator: EightCap,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

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
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

async fn get_store(ctx: Context) -> StoreDb {
    let store_cfg = store_cfg();
    Store::init(ctx, store_cfg).await.unwrap()
}

async fn get_any_unordered(ctx: Context) -> UVariableDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    UVariable::init(ctx, any_cfg).await.unwrap()
}

async fn get_any_ordered(ctx: Context) -> OVariableDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    OVariable::init(ctx, any_cfg).await.unwrap()
}

/// Generate a large db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `commit_frequency` operations.
async fn gen_random_kv<A>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: u32,
) -> A
where
    A: Persistable + StoreDeletable<Key = Digest, Value = Vec<u8>> + LogStorePrunable,
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
            assert!(db.commit().await.is_ok());
        }
    }
    assert!(db.commit().await.is_ok());
    assert!(db.prune(db.inactivity_floor_loc()).await.is_ok());

    db
}

async fn gen_random_kv_batched<A>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: u32,
) -> A
where
    A: Persistable + Batchable<Key = Digest, Value = Vec<u8>> + LogStorePrunable<Value = Vec<u8>>,
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
            let iter = batch.into_iter();
            assert!(db.write_batch(iter).await.is_ok());
            assert!(db.commit().await.is_ok());
            batch = db.start_batch();
        }
    }

    let iter = batch.into_iter();
    assert!(db.write_batch(iter).await.is_ok());
    assert!(db.commit().await.is_ok());
    assert!(db.prune(db.inactivity_floor_loc()).await.is_ok());

    db
}
