//! Benchmarks of ADB variants on fixed-size values.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::PoolRef, create_pool, tokio::Context, ThreadPool};
use commonware_storage::{
    adb::{
        any::{
            fixed::{ordered::Any as OAny, unordered::Any as UAny, Config as AConfig},
            variable::{Any as VariableAny, Config as VariableAnyConfig},
        },
        current::{
            ordered::Current as OCurrent, unordered::Current as UCurrent, Config as CConfig,
        },
        store::{Batchable, Config as SConfig, Db, Store},
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod generate;
pub mod init;

#[derive(Debug, Clone, Copy)]
enum Variant {
    Store,
    AnyUnordered,
    AnyOrdered,
    Variable, // unordered
    CurrentUnordered,
    CurrentOrdered,
}

impl Variant {
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Store => "store",
            Variant::AnyUnordered => "any::fixed::unordered",
            Variant::AnyOrdered => "any::fixed::ordered",
            Variant::Variable => "any::variable",
            Variant::CurrentUnordered => "current::unordered",
            Variant::CurrentOrdered => "current::ordered",
        }
    }
}

const VARIANTS: [Variant; 6] = [
    Variant::Store,
    Variant::AnyUnordered,
    Variant::AnyOrdered,
    Variant::Variable,
    Variant::CurrentUnordered,
    Variant::CurrentOrdered,
];

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "any_fixed_bench_partition";

/// Chunk size for the current ADB bitmap - must be a power of 2 (as assumed in
/// current::grafting_height()) and a multiple of digest size.
const CHUNK_SIZE: usize = 32;

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

type UAnyDb =
    UAny<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, Sha256, EightCap>;
type OAnyDb =
    OAny<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, Sha256, EightCap>;
type UCurrentDb = UCurrent<
    Context,
    <Sha256 as Hasher>::Digest,
    <Sha256 as Hasher>::Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type OCurrentDb = OCurrent<
    Context,
    <Sha256 as Hasher>::Digest,
    <Sha256 as Hasher>::Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
>;
type StoreDb = Store<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, EightCap>;
type VariableAnyDb =
    VariableAny<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, Sha256, EightCap>;

/// Configuration for any ADB.
fn any_cfg(pool: ThreadPool) -> AConfig<EightCap> {
    AConfig::<EightCap> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Configuration for current ADB.
fn current_cfg(pool: ThreadPool) -> CConfig<EightCap> {
    CConfig::<EightCap> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        bitmap_metadata_partition: format!("bitmap_metadata_{PARTITION_SUFFIX}"),
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn store_cfg() -> SConfig<EightCap, ()> {
    SConfig::<EightCap, ()> {
        log_partition: format!("journal_{PARTITION_SUFFIX}"),
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        log_codec_config: (),
        log_items_per_section: ITEMS_PER_BLOB,
        translator: EightCap,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn variable_any_cfg(pool: ThreadPool) -> VariableAnyConfig<EightCap, ()> {
    VariableAnyConfig::<EightCap, ()> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: (),
        log_items_per_section: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Get an unordered any ADB instance.
async fn get_unordered_any(ctx: Context) -> UAnyDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    UAny::<_, _, _, Sha256, EightCap>::init(ctx, any_cfg)
        .await
        .unwrap()
}

/// Get an ordered any ADB instance.
async fn get_ordered_any(ctx: Context) -> OAnyDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    OAny::<_, _, _, Sha256, EightCap>::init(ctx, any_cfg)
        .await
        .unwrap()
}

/// Get an unordered current ADB instance.
async fn get_unordered_current(ctx: Context) -> UCurrentDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let current_cfg = current_cfg(pool);
    UCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

/// Get an ordered current ADB instance.
async fn get_ordered_current(ctx: Context) -> OCurrentDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let current_cfg = current_cfg(pool);
    OCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

async fn get_store(ctx: Context) -> StoreDb {
    let store_cfg = store_cfg();
    Store::init(ctx, store_cfg).await.unwrap()
}

async fn get_variable_any(ctx: Context) -> VariableAnyDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let variable_any_cfg = variable_any_cfg(pool);
    VariableAny::init(ctx, variable_any_cfg).await.unwrap()
}

/// Generate a large any db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// database is committed after every `commit_frequency` operations (if Some), or at the end (if
/// None).
async fn gen_random_kv<A: Db<<Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest>>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
) -> A {
    // Insert a random value for every possible element into the db.
    let mut rng = StdRng::seed_from_u64(42);
    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = Sha256::hash(&rng.next_u32().to_be_bytes());
        db.update(k, v).await.unwrap();
    }

    // Randomly update / delete them + randomly commit.
    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            db.delete(rand_key).await.unwrap();
            continue;
        }
        let v = Sha256::hash(&rng.next_u32().to_be_bytes());
        db.update(rand_key, v).await.unwrap();
        if let Some(freq) = commit_frequency {
            if rng.next_u32() % freq == 0 {
                db.commit().await.unwrap();
            }
        }
    }

    db.commit().await.unwrap();
    db
}

async fn gen_random_kv_batched<
    A: Db<<Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest>
        + Batchable<<Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest>,
>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
) -> A {
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.start_batch();

    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = Sha256::hash(&rng.next_u32().to_be_bytes());
        batch.update(k, v).await.unwrap();
    }
    let iter = batch.into_iter();
    db.write_batch(iter).await.unwrap();
    batch = db.start_batch();

    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            batch.delete(rand_key).await.unwrap();
            continue;
        }
        let v = Sha256::hash(&rng.next_u32().to_be_bytes());
        batch.update(rand_key, v).await.unwrap();
        if let Some(freq) = commit_frequency {
            if rng.next_u32() % freq == 0 {
                let iter = batch.into_iter();
                db.write_batch(iter).await.unwrap();
                db.commit().await.unwrap();
                batch = db.start_batch();
            }
        }
    }

    let iter = batch.into_iter();
    db.write_batch(iter).await.unwrap();
    db.commit().await.unwrap();
    db
}
