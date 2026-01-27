//! Benchmarks of QMDB variants on fixed-size values.
//!
//! While this benchmark involves updating a database with fixed-size values, we also include the db
//! variants capable of handling variable-size values to gauge the impact of the extra indirection
//! they perform.

use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::{Rayon, Sequential, Strategy};
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
            ordered::{fixed::Db as OCurrent, variable::Db as OVCurrent},
            unordered::{fixed::Db as UCurrent, variable::Db as UVCurrent},
            FixedConfig as CConfig, VariableConfig as VariableCurrentConfig,
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
    AnyUnorderedFixed,
    AnyOrderedFixed,
    AnyUnorderedVariable,
    AnyOrderedVariable,
    CurrentUnorderedFixed,
    CurrentOrderedFixed,
    CurrentUnorderedVariable,
    CurrentOrderedVariable,
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
            Self::CurrentUnorderedVariable => "current::unordered::variable",
            Self::CurrentOrderedVariable => "current::ordered::variable",
        }
    }
}

const VARIANTS: [Variant; 8] = [
    Variant::AnyUnorderedFixed,
    Variant::AnyOrderedFixed,
    Variant::AnyUnorderedVariable,
    Variant::AnyOrderedVariable,
    Variant::CurrentUnorderedFixed,
    Variant::CurrentOrderedFixed,
    Variant::CurrentUnorderedVariable,
    Variant::CurrentOrderedVariable,
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
const PAGE_SIZE: NonZeroU16 = NZU16!(16384);

/// The number of pages to cache in the buffer pool.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);

/// Default delete frequency (1/10th of the updates will be deletes).
const DELETE_FREQUENCY: u32 = 10;

/// Default write buffer size.
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Clean (Merkleized, Durable) Db type aliases for Any databases (Sequential).
type UFixedDbSeq = UFixed<Context, Digest, Digest, Sha256, EightCap, Sequential>;
type OFixedDbSeq = OFixed<Context, Digest, Digest, Sha256, EightCap, Sequential>;
type UVAnyDbSeq = UVariable<Context, Digest, Digest, Sha256, EightCap, Sequential>;
type OVAnyDbSeq = OVariable<Context, Digest, Digest, Sha256, EightCap, Sequential>;

type UCurrentDbSeq = UCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Sequential>;
type OCurrentDbSeq = OCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Sequential>;
type UVCurrentDbSeq = UVCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Sequential>;
type OVCurrentDbSeq = OVCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Sequential>;

/// Clean (Merkleized, Durable) Db type aliases for Any databases (Rayon).
type UFixedDbPar = UFixed<Context, Digest, Digest, Sha256, EightCap, Rayon>;
type OFixedDbPar = OFixed<Context, Digest, Digest, Sha256, EightCap, Rayon>;
type UVAnyDbPar = UVariable<Context, Digest, Digest, Sha256, EightCap, Rayon>;
type OVAnyDbPar = OVariable<Context, Digest, Digest, Sha256, EightCap, Rayon>;

type UCurrentDbPar = UCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;
type OCurrentDbPar = OCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;
type UVCurrentDbPar = UVCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;
type OVCurrentDbPar = OVCurrent<Context, Digest, Digest, Sha256, EightCap, CHUNK_SIZE, Rayon>;

/// Configuration for any QMDB.
fn any_cfg<S: Strategy>(strategy: S) -> AConfig<EightCap, S> {
    AConfig::<EightCap, S> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        translator: EightCap,
        strategy,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Configuration for current QMDB.
fn current_cfg<S: Strategy>(strategy: S) -> CConfig<EightCap, S> {
    CConfig::<EightCap, S> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_journal_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        bitmap_metadata_partition: format!("bitmap_metadata_{PARTITION_SUFFIX}"),
        translator: EightCap,
        strategy,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn variable_any_cfg<S: Strategy>(strategy: S) -> VariableAnyConfig<EightCap, (), S> {
    VariableAnyConfig::<EightCap, (), S> {
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
        strategy,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Configuration for variable current QMDB.
fn variable_current_cfg<S: Strategy>(strategy: S) -> VariableCurrentConfig<EightCap, (), S> {
    VariableCurrentConfig::<EightCap, (), S> {
        mmr_journal_partition: format!("journal_{PARTITION_SUFFIX}"),
        mmr_metadata_partition: format!("metadata_{PARTITION_SUFFIX}"),
        mmr_items_per_blob: ITEMS_PER_BLOB,
        mmr_write_buffer: WRITE_BUFFER_SIZE,
        log_partition: format!("log_journal_{PARTITION_SUFFIX}"),
        log_codec_config: (),
        log_items_per_blob: ITEMS_PER_BLOB,
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        bitmap_metadata_partition: format!("bitmap_metadata_{PARTITION_SUFFIX}"),
        translator: EightCap,
        strategy,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Get an unordered fixed Any QMDB instance in clean state (Sequential).
async fn get_any_unordered_fixed_seq(ctx: Context) -> UFixedDbSeq {
    UFixedDbSeq::init(ctx, any_cfg(Sequential)).await.unwrap()
}

/// Get an unordered fixed Any QMDB instance in clean state (Parallel).
async fn get_any_unordered_fixed_par(ctx: Context) -> UFixedDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    UFixedDbPar::init(ctx, any_cfg(Rayon::with_pool(pool)))
        .await
        .unwrap()
}

/// Get an ordered fixed Any QMDB instance in clean state (Sequential).
async fn get_any_ordered_fixed_seq(ctx: Context) -> OFixedDbSeq {
    OFixedDbSeq::init(ctx, any_cfg(Sequential)).await.unwrap()
}

/// Get an ordered fixed Any QMDB instance in clean state (Parallel).
async fn get_any_ordered_fixed_par(ctx: Context) -> OFixedDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    OFixedDbPar::init(ctx, any_cfg(Rayon::with_pool(pool)))
        .await
        .unwrap()
}

/// Get an unordered variable Any QMDB instance in clean state (Sequential).
async fn get_any_unordered_variable_seq(ctx: Context) -> UVAnyDbSeq {
    UVAnyDbSeq::init(ctx, variable_any_cfg(Sequential))
        .await
        .unwrap()
}

/// Get an unordered variable Any QMDB instance in clean state (Parallel).
async fn get_any_unordered_variable_par(ctx: Context) -> UVAnyDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    UVAnyDbPar::init(ctx, variable_any_cfg(Rayon::with_pool(pool)))
        .await
        .unwrap()
}

/// Get an ordered variable Any QMDB instance in clean state (Sequential).
async fn get_any_ordered_variable_seq(ctx: Context) -> OVAnyDbSeq {
    OVAnyDbSeq::init(ctx, variable_any_cfg(Sequential))
        .await
        .unwrap()
}

/// Get an ordered variable Any QMDB instance in clean state (Parallel).
async fn get_any_ordered_variable_par(ctx: Context) -> OVAnyDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    OVAnyDbPar::init(ctx, variable_any_cfg(Rayon::with_pool(pool)))
        .await
        .unwrap()
}

/// Get an unordered current QMDB instance (Sequential).
async fn get_current_unordered_fixed_seq(ctx: Context) -> UCurrentDbSeq {
    UCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Sequential>::init(
        ctx,
        current_cfg(Sequential),
    )
    .await
    .unwrap()
}

/// Get an unordered current QMDB instance (Parallel).
async fn get_current_unordered_fixed_par(ctx: Context) -> UCurrentDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    UCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Rayon>::init(
        ctx,
        current_cfg(Rayon::with_pool(pool)),
    )
    .await
    .unwrap()
}

/// Get an ordered current QMDB instance (Sequential).
async fn get_current_ordered_fixed_seq(ctx: Context) -> OCurrentDbSeq {
    OCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Sequential>::init(
        ctx,
        current_cfg(Sequential),
    )
    .await
    .unwrap()
}

/// Get an ordered current QMDB instance (Parallel).
async fn get_current_ordered_fixed_par(ctx: Context) -> OCurrentDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    OCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Rayon>::init(
        ctx,
        current_cfg(Rayon::with_pool(pool)),
    )
    .await
    .unwrap()
}

/// Get an unordered variable current QMDB instance (Sequential).
async fn get_current_unordered_variable_seq(ctx: Context) -> UVCurrentDbSeq {
    UVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Sequential>::init(
        ctx,
        variable_current_cfg(Sequential),
    )
    .await
    .unwrap()
}

/// Get an unordered variable current QMDB instance (Parallel).
async fn get_current_unordered_variable_par(ctx: Context) -> UVCurrentDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    UVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Rayon>::init(
        ctx,
        variable_current_cfg(Rayon::with_pool(pool)),
    )
    .await
    .unwrap()
}

/// Get an ordered variable current QMDB instance (Sequential).
async fn get_current_ordered_variable_seq(ctx: Context) -> OVCurrentDbSeq {
    OVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Sequential>::init(
        ctx,
        variable_current_cfg(Sequential),
    )
    .await
    .unwrap()
}

/// Get an ordered variable current QMDB instance (Parallel).
async fn get_current_ordered_variable_par(ctx: Context) -> OVCurrentDbPar {
    let pool = ctx.clone().create_pool(THREADS).unwrap();
    OVCurrent::<_, _, _, Sha256, EightCap, CHUNK_SIZE, Rayon>::init(
        ctx,
        variable_current_cfg(Rayon::with_pool(pool)),
    )
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
