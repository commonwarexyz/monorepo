//! Benchmarks of ADB variants on variable-sized values.

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::PoolRef, create_pool, tokio::Context, ThreadPool};
use commonware_storage::{
    adb::{
        any::{unordered::variable::Any, CleanAny, DirtyAny as _, VariableConfig as AConfig},
        store::{Batchable, DirtyStore as _},
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
    Any,
}

impl Variant {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Any => "any",
        }
    }

    /// Returns whether this variant supports the CleanAny/DirtyAny pattern.
    /// Store doesn't implement these traits.
    pub const fn supports_clean_any(&self) -> bool {
        !matches!(self, Self::Store)
    }
}

const VARIANTS: [Variant; 2] = [Variant::Store, Variant::Any];

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

type AnyDb = Any<Context, <Sha256 as Hasher>::Digest, Vec<u8>, Sha256, EightCap>;

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

async fn get_any(ctx: Context) -> AnyDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let any_cfg = any_cfg(pool);
    Any::init(ctx, any_cfg).await.unwrap()
}

/// Generate a large any db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// ratio of updates to deletes is configured with `DELETE_FREQUENCY`. The database is committed
/// after every `commit_frequency` operations.
async fn gen_random_kv<A>(db: A, num_elements: u64, num_operations: u64, commit_frequency: u32) -> A
where
    A: CleanAny<Key = <Sha256 as Hasher>::Digest, Value = Vec<u8>>,
{
    let mut db = db.into_dirty();

    // Insert a random value for every possible element into the db.
    let mut rng = StdRng::seed_from_u64(42);
    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
        db.update(k, v).await.unwrap();
    }

    // Randomly update / delete them + randomly commit.
    for _ in 0u64..num_operations {
        let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
        if rng.next_u32() % DELETE_FREQUENCY == 0 {
            db.delete(rand_key).await.unwrap();
            continue;
        }
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
        db.update(rand_key, v).await.unwrap();
        if rng.next_u32() % commit_frequency == 0 {
            let mut clean_db = db.merkleize().await;
            clean_db.commit(None).await.unwrap();
            db = clean_db.into_dirty();
        }
    }

    let mut clean_db = db.merkleize().await;
    clean_db.commit(None).await.unwrap();
    clean_db
        .prune(clean_db.inactivity_floor_loc())
        .await
        .unwrap();
    clean_db
}

async fn gen_random_kv_batched<A>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: u32,
) -> A
where
    A: Batchable<Key = <Sha256 as Hasher>::Digest, Value = Vec<u8>>
        + CleanAny<Key = <Sha256 as Hasher>::Digest, Value = Vec<u8>>,
{
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.start_batch();

    for i in 0u64..num_elements {
        let k = Sha256::hash(&i.to_be_bytes());
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 16) + 24) as usize];
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
        let v = vec![(rng.next_u32() % 255) as u8; ((rng.next_u32() % 24) + 20) as usize];
        batch.update(rand_key, v).await.unwrap();
        if rng.next_u32() % commit_frequency == 0 {
            let iter = batch.into_iter();
            db.write_batch(iter).await.unwrap();
            db.commit(None).await.unwrap();
            batch = db.start_batch();
        }
    }

    let iter = batch.into_iter();
    db.write_batch(iter).await.unwrap();
    db.commit(None).await.unwrap();
    db.prune(db.inactivity_floor_loc()).await.unwrap();

    db
}
