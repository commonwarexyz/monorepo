//! Benchmarks of QMDB variants on fixed-size values.
//!
//! While this benchmark involves updating a database with fixed-size values, we also include the db
//! variants capable of handling variable-size values to gauge the impact of the extra indirection
//! they perform.

use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::PoolRef, tokio::Context, RayonPoolSpawner};
use commonware_storage::{
    kv::{Deletable as _, Updatable as _},
    qmdb::{
        any::{
            ordered::{fixed::Db as OFixed, variable::Db as OVariable},
            states::{MutableAny, UnmerkleizedDurableAny},
            unordered::{fixed::Db as UFixed, variable::Db as UVariable},
            FixedConfig as AConfig, VariableConfig as VariableAnyConfig,
        },
        current::{
            ordered::fixed::Db as OCurrent, unordered::fixed::Db as UCurrent,
            FixedConfig as CConfig,
        },
        store::LogStore,
    },
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod generate;
pub mod init;

pub type Digest = <Sha256 as Hasher>::Digest;

#[derive(Debug, Clone, Copy)]
enum Variant {
    AnyUnorderedFixed,
    AnyOrderedFixed,
    AnyUnorderedVariable,
    AnyOrderedVariable,
    CurrentUnorderedFixed,
    CurrentOrderedFixed,
}

impl Variant {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AnyUnorderedFixed => "any::unordered::fixed",
            Self::AnyOrderedFixed => "any::ordered::fixed",
            Self::AnyUnorderedVariable => "any::unordered::variable",
            Self::AnyOrderedVariable => "any::ordered::variable",
            Self::CurrentUnorderedFixed => "current::unordered::fixed",
            Self::CurrentOrderedFixed => "current::ordered::fixed",
        }
    }
}

const VARIANTS: [Variant; 6] = [
    Variant::AnyUnorderedFixed,
    Variant::AnyOrderedFixed,
    Variant::AnyUnorderedVariable,
    Variant::AnyOrderedVariable,
    Variant::CurrentUnorderedFixed,
    Variant::CurrentOrderedFixed,
];

const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const PARTITION_SUFFIX: &str = "any_fixed_bench_partition";

/// Chunk size for the current QMDB bitmap - must be a power of 2 (as assumed in
/// current::grafting_height()) and a multiple of digest size.
const CHUNK_SIZE: usize = 32;

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores.
const THREADS: NonZeroUsize = NZUsize!(8);

/// Use a "prod sized" page size to test the performance of the journal.
const PAGE_SIZE: NonZeroUsize = NZUsize!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Default delete frequency (1/10th of the updates will be deletes).
const DELETE_FREQUENCY: u32 = 10;

/// Default write buffer size.
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Clean (Merkleized, Durable) Db type aliases for Any databases.
type UFixedDb = UFixed<Context, Digest, Digest, Sha256, EightCap>;
type OFixedDb = OFixed<Context, Digest, Digest, Sha256, EightCap>;
type UVAnyDb = UVariable<Context, Digest, Digest, Sha256, EightCap>;
type OVAnyDb = OVariable<Context, Digest, Digest, Sha256, EightCap>;

type UCurrentDb = UCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;
type OCurrentDb = OCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE>;

/// Configuration for any QMDB.
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

/// Configuration for current QMDB.
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

fn variable_any_cfg(pool: ThreadPool) -> VariableAnyConfig<EightCap, ()> {
    VariableAnyConfig::<EightCap, ()> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: (),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        translator: EightCap,
        thread_pool: Some(pool),
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Get an unordered fixed Any QMDB instance in clean state.
async fn get_any_unordered_fixed(ctx: Context) -> UFixedDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    UFixedDb::init(ctx, any_cfg).await.unwrap()
}

/// Get an ordered fixed Any QMDB instance in clean state.
async fn get_any_ordered_fixed(ctx: Context) -> OFixedDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    OFixedDb::init(ctx, any_cfg).await.unwrap()
}

/// Get an unordered variable Any QMDB instance in clean state.
async fn get_any_unordered_variable(ctx: Context) -> UVAnyDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let variable_any_cfg = variable_any_cfg(pool);
    UVAnyDb::init(ctx, variable_any_cfg).await.unwrap()
}

/// Get an ordered variable Any QMDB instance in clean state.
async fn get_any_ordered_variable(ctx: Context) -> OVAnyDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let variable_any_cfg = variable_any_cfg(pool);
    OVAnyDb::init(ctx, variable_any_cfg).await.unwrap()
}

/// Get an unordered current QMDB instance.
async fn get_current_unordered_fixed(ctx: Context) -> UCurrentDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let current_cfg = current_cfg(pool);
    UCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

/// Get an ordered current QMDB instance.
async fn get_current_ordered_fixed(ctx: Context) -> OCurrentDb {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    let current_cfg = current_cfg(pool);
    OCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE>::init(ctx, current_cfg)
        .await
        .unwrap()
}

/// Generate a large db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// database is committed after every `commit_frequency` operations (if Some), or at the end (if
/// None).
///
/// Takes a mutable database and returns it in durable state after final commit.
async fn gen_random_kv<M>(
    mut db: M,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
) -> M::Durable
where
    M: MutableAny<Key = Digest> + LogStore<Value = Digest>,
    M::Durable: UnmerkleizedDurableAny<Mutable = M>,
{
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
                let (durable, _) = db.commit(None).await.unwrap();
                db = durable.into_mutable();
            }
        }
    }

    let (durable, _) = db.commit(None).await.unwrap();
    durable
}

async fn gen_random_kv_batched<M>(
    mut db: M,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
) -> M::Durable
where
    M: MutableAny<Key = Digest> + LogStore<Value = Digest>,
    M::Durable: UnmerkleizedDurableAny<Mutable = M>,
{
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.start_batch();

    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = Sha256::hash(&rng.next_u32().to_be_bytes());
        batch.update(k, v).await.expect("update shouldn't fail");
    }
    let iter = batch.into_iter();
    db.write_batch(iter)
        .await
        .expect("write_batch shouldn't fail");
    batch = db.start_batch();

    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            batch.delete(rand_key).await.expect("delete shouldn't fail");
            continue;
        }
        let v = Sha256::hash(&rng.next_u32().to_be_bytes());
        batch
            .update(rand_key, v)
            .await
            .expect("update shouldn't fail");
        if let Some(freq) = commit_frequency {
            if rng.next_u32() % freq == 0 {
                let iter = batch.into_iter();
                db.write_batch(iter)
                    .await
                    .expect("write_batch shouldn't fail");
                let (durable, _) = db.commit(None).await.expect("commit shouldn't fail");
                db = durable.into_mutable();
                batch = db.start_batch();
            }
        }
    }

    let iter = batch.into_iter();
    db.write_batch(iter)
        .await
        .expect("write_batch shouldn't fail");
    let (durable, _) = db.commit(None).await.expect("commit shouldn't fail");
    durable
}
