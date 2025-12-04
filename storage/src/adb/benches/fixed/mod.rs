//! Benchmarks of ADB variants on fixed-size values.

use commonware_codec::Codec;
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    buffer::PoolRef, create_pool, tokio::Context, Clock, Metrics, Storage, ThreadPool,
};
use commonware_storage::{
    adb::{
        any::{
            ordered::fixed::Any as OAny,
            unordered::{fixed::Any as UAny, variable::Any as VariableAny},
            CleanAny, DirtyAny, FixedConfig as AConfig, VariableConfig as VariableAnyConfig,
        },
        current::{
            ordered::Current as OCurrent, unordered::Current as UCurrent, Config as CConfig,
        },
        store::{Batchable, Config as StoreConfig, DirtyStore, LogStore, Store},
        Error,
    },
    mmr::Location,
    store::{Store as StoreTrait, StoreDeletable, StoreMut, StorePersistable},
    translator::{EightCap, Translator},
};
use commonware_utils::{Array, NZUsize, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
};

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
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::AnyUnordered => "any::fixed::unordered",
            Self::AnyOrdered => "any::fixed::ordered",
            Self::Variable => "any::variable",
            Self::CurrentUnordered => "current::unordered",
            Self::CurrentOrdered => "current::ordered",
        }
    }
}

// =============================================================================
// BenchmarkableDb trait and implementations
// =============================================================================

/// A trait abstracting databases for benchmarking purposes.
/// Allows both authenticated (CleanAny) and unauthenticated (Store) databases
/// to be tested with the same benchmark functions.
pub trait BenchmarkableDb {
    type Key;
    type Value;
    type Error: std::fmt::Debug;

    /// Get the value for a given key.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>>;

    /// Update a key with a new value.
    fn update(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Delete a key. Returns true if deleted, false if didn't exist.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Self::Error>>;

    /// Commit changes, optionally with metadata. Ensures durability.
    fn commit(
        &mut self,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Prune historical operations before the given location.
    fn prune(&mut self, loc: Location) -> impl Future<Output = Result<(), Self::Error>>;

    /// Get the inactivity floor location.
    fn inactivity_floor_loc(&self) -> Location;

    /// Close the database.
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Destroy the database, removing all data.
    fn destroy(self) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Implementation of BenchmarkableDb for the unauthenticated Store type.
impl<E, K, V, T> BenchmarkableDb for Store<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Codec + Clone,
    T: Translator,
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        StoreTrait::get(self, key).await
    }

    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        StoreMut::update(self, key, value).await
    }

    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        StoreDeletable::delete(self, key).await
    }

    async fn commit(&mut self, _metadata: Option<Self::Value>) -> Result<(), Self::Error> {
        // Store doesn't support metadata in commit, so ignore it
        Store::commit(self, None).await.map(|_| ())
    }

    async fn prune(&mut self, loc: Location) -> Result<(), Self::Error> {
        Store::prune(self, loc).await
    }

    fn inactivity_floor_loc(&self) -> Location {
        LogStore::inactivity_floor_loc(self)
    }

    async fn close(self) -> Result<(), Self::Error> {
        Store::close(self).await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        Store::destroy(self).await
    }
}

// =============================================================================
// CleanAnyWrapper - wraps CleanAny types for BenchmarkableDb compatibility
// =============================================================================

/// Wrapper that makes CleanAny types compatible with BenchmarkableDb.
/// Handles state transitions (into_dirty/merkleize) transparently.
/// Stays in Dirty state during mutations and only merkleizes when necessary.
pub struct CleanAnyWrapper<A: CleanAny> {
    inner: Option<CleanAnyState<A>>,
}

enum CleanAnyState<A: CleanAny> {
    Clean(A),
    Dirty(A::Dirty),
}

impl<A: CleanAny> CleanAnyWrapper<A> {
    pub fn new(db: A) -> Self {
        Self {
            inner: Some(CleanAnyState::Clean(db)),
        }
    }

    /// Ensure we're in dirty state, transitioning if necessary
    fn ensure_dirty(&mut self) {
        let state = self.inner.take().expect("wrapper should never be empty");
        self.inner = Some(match state {
            CleanAnyState::Clean(clean) => CleanAnyState::Dirty(clean.into_dirty()),
            CleanAnyState::Dirty(dirty) => CleanAnyState::Dirty(dirty),
        });
    }

    /// Merkleize if in dirty state, ensuring we're in clean state
    async fn ensure_clean(&mut self) {
        let state = self.inner.take().expect("wrapper should never be empty");
        self.inner = Some(match state {
            CleanAnyState::Clean(clean) => CleanAnyState::Clean(clean),
            CleanAnyState::Dirty(dirty) => CleanAnyState::Clean(dirty.merkleize().await),
        });
    }
}

impl<A> BenchmarkableDb for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    type Key = A::Key;
    type Value = <A as LogStore>::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.get(key).await,
            CleanAnyState::Dirty(dirty) => dirty.get(key).await,
        }
    }

    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        // Ensure we're in dirty state, then update
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => dirty.update(key, value).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }

    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        // Ensure we're in dirty state, then delete
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => dirty.delete(key).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }

    async fn commit(&mut self, metadata: Option<Self::Value>) -> Result<(), Self::Error> {
        // Merkleize before commit
        self.ensure_clean().await;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.commit(metadata).await.map(|_| ()),
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    async fn prune(&mut self, loc: Location) -> Result<(), Self::Error> {
        // Merkleize before prune
        self.ensure_clean().await;
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.prune(loc).await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    fn inactivity_floor_loc(&self) -> Location {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.inactivity_floor_loc(),
            CleanAnyState::Dirty(dirty) => dirty.inactivity_floor_loc(),
        }
    }

    async fn close(mut self) -> Result<(), Self::Error> {
        // Merkleize before close
        self.ensure_clean().await;
        match self.inner.take().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.close().await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }

    async fn destroy(mut self) -> Result<(), Self::Error> {
        // Merkleize before destroy
        self.ensure_clean().await;
        match self.inner.take().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => clean.destroy().await,
            _ => unreachable!("ensure_clean guarantees Clean state"),
        }
    }
}

// Implement standard store traits for CleanAnyWrapper to enable Batchable blanket impl
impl<A> StoreTrait for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    type Key = A::Key;
    type Value = <A as LogStore>::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        match self.inner.as_ref().expect("wrapper should never be empty") {
            CleanAnyState::Clean(clean) => CleanAny::get(clean, key).await,
            CleanAnyState::Dirty(dirty) => DirtyAny::get(dirty, key).await,
        }
    }
}

impl<A> StoreMut for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => DirtyAny::update(dirty, key, value).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}

impl<A> StoreDeletable for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.ensure_dirty();
        match self.inner.as_mut().expect("wrapper should never be empty") {
            CleanAnyState::Dirty(dirty) => DirtyAny::delete(dirty, key).await,
            _ => unreachable!("ensure_dirty guarantees Dirty state"),
        }
    }
}

impl<A> StorePersistable for CleanAnyWrapper<A>
where
    A: CleanAny,
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Self::Error> {
        BenchmarkableDb::commit(self, None).await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        BenchmarkableDb::destroy(self).await
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
type VariableAnyDb =
    VariableAny<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, Sha256, EightCap>;
type StoreDb = Store<Context, <Sha256 as Hasher>::Digest, <Sha256 as Hasher>::Digest, EightCap>;

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

async fn get_variable_any(ctx: Context) -> VariableAnyDb {
    let pool = create_pool(ctx.clone(), THREADS).unwrap();
    let variable_any_cfg = variable_any_cfg(pool);
    VariableAny::init(ctx, variable_any_cfg).await.unwrap()
}

/// Configuration for Store.
fn store_cfg() -> StoreConfig<EightCap, ()> {
    StoreConfig::<EightCap, ()> {
        log_partition: format!("store_{PARTITION_SUFFIX}"),
        log_write_buffer: WRITE_BUFFER_SIZE,
        log_compression: None,
        log_codec_config: (),
        log_items_per_section: ITEMS_PER_BLOB,
        translator: EightCap,
        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

/// Get a Store instance.
async fn get_store(ctx: Context) -> StoreDb {
    let cfg = store_cfg();
    Store::init(ctx, cfg).await.unwrap()
}

/// Generate a large db with random data. The function seeds the db with exactly `num_elements`
/// elements by inserting them in order, each with a new random value. Then, it performs
/// `num_operations` over these elements, each selected uniformly at random for each operation. The
/// database is committed after every `commit_frequency` operations (if Some), or at the end (if
/// None).
async fn gen_random_kv<A>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
) -> A
where
    A: BenchmarkableDb<Key = <Sha256 as Hasher>::Digest, Value = <Sha256 as Hasher>::Digest>,
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
                db.commit(None).await.unwrap();
            }
        }
    }

    db.commit(None).await.unwrap();
    db
}

async fn gen_random_kv_batched<A>(
    mut db: A,
    num_elements: u64,
    num_operations: u64,
    commit_frequency: Option<u32>,
) -> A
where
    A: Batchable<Key = <Sha256 as Hasher>::Digest, Value = <Sha256 as Hasher>::Digest>
        + BenchmarkableDb<
            Key = <Sha256 as Hasher>::Digest,
            Value = <Sha256 as Hasher>::Digest,
            Error = Error,
        >,
{
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
                db.commit(None).await.unwrap();
                batch = db.start_batch();
            }
        }
    }

    let iter = batch.into_iter();
    db.write_batch(iter).await.unwrap();
    db.commit(None).await.unwrap();
    db
}
