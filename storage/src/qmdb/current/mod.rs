//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it. The
//! implementations are based on a [crate::qmdb::any] authenticated database combined with an
//! authenticated [crate::bitmap::MerkleizedBitMap] over the activity status of each operation.
//! The two structures are "grafted" together to minimize proof sizes.

use crate::{
    bitmap::MerkleizedBitMap,
    index::Unordered as UnorderedIndex,
    journal::contiguous::{fixed::Journal as FJournal, variable::Journal as VJournal},
    mmr::{Location, StandardHasher},
    qmdb::{
        any::{
            self,
            operation::{Operation, Update},
            FixedConfig as AnyFixedConfig, ValueEncoding, VariableConfig as AnyVariableConfig,
        },
        operation::Committable,
        Durable, Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, CodecFixedShared, FixedSize, Read};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use commonware_utils::Array;
use std::num::{NonZeroU64, NonZeroUsize};

pub mod db;
pub mod ordered;
pub mod proof;
pub mod unordered;

/// Configuration for a `Current` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
    /// The name of the storage partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the storage partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

impl<T: Translator> From<FixedConfig<T>> for AnyFixedConfig<T> {
    fn from(cfg: FixedConfig<T>) -> Self {
        Self {
            mmr_journal_partition: cfg.mmr_journal_partition,
            mmr_metadata_partition: cfg.mmr_metadata_partition,
            mmr_items_per_blob: cfg.mmr_items_per_blob,
            mmr_write_buffer: cfg.mmr_write_buffer,
            log_journal_partition: cfg.log_journal_partition,
            log_items_per_blob: cfg.log_items_per_blob,
            log_write_buffer: cfg.log_write_buffer,
            translator: cfg.translator,
            thread_pool: cfg.thread_pool,
            page_cache: cfg.page_cache,
        }
    }
}

#[derive(Clone)]
pub struct VariableConfig<T: Translator, C> {
    /// The name of the storage partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the storage partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for the log.
    pub log_codec_config: C,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The name of the storage partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

impl<T: Translator, C> From<VariableConfig<T, C>> for AnyVariableConfig<T, C> {
    fn from(cfg: VariableConfig<T, C>) -> Self {
        Self {
            mmr_journal_partition: cfg.mmr_journal_partition,
            mmr_metadata_partition: cfg.mmr_metadata_partition,
            mmr_items_per_blob: cfg.mmr_items_per_blob,
            mmr_write_buffer: cfg.mmr_write_buffer,
            log_items_per_blob: cfg.log_items_per_blob,
            log_partition: cfg.log_partition,
            log_write_buffer: cfg.log_write_buffer,
            log_compression: cfg.log_compression,
            log_codec_config: cfg.log_codec_config,
            translator: cfg.translator,
            thread_pool: cfg.thread_pool,
            page_cache: cfg.page_cache,
        }
    }
}

/// Shared initialization logic for fixed-sized value Current [db::Db].
pub(super) async fn init_fixed<E, K, V, U, H, T, I, const N: usize, NewIndex>(
    context: E,
    config: FixedConfig<T>,
    new_index: NewIndex,
) -> Result<
    db::Db<E, FJournal<E, Operation<K, V, U>>, I, H, U, N, db::Merkleized<DigestOf<H>>, Durable>,
    Error,
>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V> + Send + Sync,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    NewIndex: FnOnce(E, T) -> I,
    Operation<K, V, U>: CodecFixedShared + Committable,
{
    // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
    const {
        // A compile-time assertion that the chunk size is some multiple of digest size. A multiple
        // of 1 is optimal with respect to proof size, but a higher multiple allows for a smaller
        // (RAM resident) merkle tree over the structure.
        assert!(
            N.is_multiple_of(H::Digest::SIZE),
            "chunk size must be some multiple of the digest size",
        );
        // A compile-time assertion that chunk size is a power of 2, which is necessary to allow
        // the status bitmap tree to be aligned with the underlying operations MMR.
        assert!(N.is_power_of_two(), "chunk size must be a power of 2");
    }

    let thread_pool = config.thread_pool.clone();
    let bitmap_metadata_partition = config.bitmap_metadata_partition.clone();

    let mut hasher = StandardHasher::<H>::new();
    let mut status = MerkleizedBitMap::init(
        context.with_label("bitmap"),
        &bitmap_metadata_partition,
        thread_pool,
        &mut hasher,
    )
    .await?
    .into_dirty();

    // Initialize the anydb with a callback that initializes the status bitmap.
    let last_known_inactivity_floor = Location::new_unchecked(status.len());
    let any = any::init_fixed(
        context.with_label("any"),
        config.into(),
        Some(last_known_inactivity_floor),
        |append: bool, loc: Option<Location>| {
            status.push(append);
            if let Some(loc) = loc {
                status.set_bit(*loc, false);
            }
        },
        new_index,
    )
    .await?;

    let status = db::merkleize_grafted_bitmap(&mut hasher, status, &any.log.mmr).await?;

    // Compute and cache the root
    let root = db::root(&mut hasher, &status, &any.log.mmr).await?;

    Ok(db::Db {
        any,
        status,
        state: db::Merkleized { root },
    })
}

/// Shared initialization logic for variable-sized value Current [db::Db].
pub(super) async fn init_variable<E, K, V, U, H, T, I, const N: usize, NewIndex>(
    context: E,
    config: VariableConfig<T, <Operation<K, V, U> as Read>::Cfg>,
    new_index: NewIndex,
) -> Result<
    db::Db<E, VJournal<E, Operation<K, V, U>>, I, H, U, N, db::Merkleized<DigestOf<H>>, Durable>,
    Error,
>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V> + Send + Sync,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    NewIndex: FnOnce(E, T) -> I,
    Operation<K, V, U>: Codec + Committable,
{
    // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
    const {
        // A compile-time assertion that the chunk size is some multiple of digest size. A multiple
        // of 1 is optimal with respect to proof size, but a higher multiple allows for a smaller
        // (RAM resident) merkle tree over the structure.
        assert!(
            N.is_multiple_of(H::Digest::SIZE),
            "chunk size must be some multiple of the digest size",
        );
        // A compile-time assertion that chunk size is a power of 2, which is necessary to allow
        // the status bitmap tree to be aligned with the underlying operations MMR.
        assert!(N.is_power_of_two(), "chunk size must be a power of 2");
    }

    let thread_pool = config.thread_pool.clone();
    let bitmap_metadata_partition = config.bitmap_metadata_partition.clone();

    let mut hasher = StandardHasher::<H>::new();
    let mut status = MerkleizedBitMap::init(
        context.with_label("bitmap"),
        &bitmap_metadata_partition,
        thread_pool,
        &mut hasher,
    )
    .await?
    .into_dirty();

    // Initialize the anydb with a callback that initializes the status bitmap.
    let last_known_inactivity_floor = Location::new_unchecked(status.len());
    let any = any::init_variable(
        context.with_label("any"),
        config.into(),
        Some(last_known_inactivity_floor),
        |append: bool, loc: Option<Location>| {
            status.push(append);
            if let Some(loc) = loc {
                status.set_bit(*loc, false);
            }
        },
        new_index,
    )
    .await?;

    let status = db::merkleize_grafted_bitmap(&mut hasher, status, &any.log.mmr).await?;

    // Compute and cache the root
    let root = db::root(&mut hasher, &status, &any.log.mmr).await?;

    Ok(db::Db {
        any,
        status,
        state: db::Merkleized { root },
    })
}

/// Extension trait for Current QMDB types that exposes bitmap information for testing.
#[cfg(any(test, feature = "test-traits"))]
pub trait BitmapPrunedBits {
    /// Returns the number of bits that have been pruned from the bitmap.
    fn pruned_bits(&self) -> u64;

    /// Returns the value of the bit at the given index.
    fn get_bit(&self, index: u64) -> bool;

    /// Returns the position of the oldest retained bit.
    fn oldest_retained(&self) -> u64;
}

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for Current QMDB variants.

    pub use super::BitmapPrunedBits;
    use super::{ordered, unordered, FixedConfig, VariableConfig};
    use crate::{
        kv::{Deletable as _, Updatable as _},
        qmdb::{
            any::states::{CleanAny, MutableAny as _, UnmerkleizedDurableAny as _},
            store::{
                batch_tests::{TestKey, TestValue},
                LogStore,
            },
            Error,
        },
        translator::Translator,
    };
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        Metrics as _, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use core::future::Future;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::num::{NonZeroU16, NonZeroUsize};
    use tracing::warn;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    /// Shared config factory for fixed-value Current QMDB tests.
    pub(crate) fn fixed_config<T: Translator + Default>(partition_prefix: &str) -> FixedConfig<T> {
        FixedConfig {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("{partition_prefix}_partition_prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Shared config factory for variable-value Current QMDB tests with unit codec config.
    pub(crate) fn variable_config<T: Translator + Default>(
        partition_prefix: &str,
    ) -> VariableConfig<T, ()> {
        VariableConfig {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("{partition_prefix}_partition_prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Apply random operations to the given db, committing them (randomly and at the end) only if
    /// `commit_changes` is true. Returns a mutable db; callers should commit if needed.
    pub async fn apply_random_ops<C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        mut db: C::Mutable,
    ) -> Result<C::Mutable, Error>
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
    {
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        for i in 0u64..num_elements {
            let k = TestKey::from_seed(i);
            let v = TestValue::from_seed(rng.next_u64());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency.
        for _ in 0u64..num_elements * 10 {
            let rand_key = TestKey::from_seed(rng.next_u64() % num_elements);
            if rng.next_u32() % 7 == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = TestValue::from_seed(rng.next_u64());
            db.update(rand_key, v).await.unwrap();
            if commit_changes && rng.next_u32() % 20 == 0 {
                // Commit every ~20 updates.
                let (durable_db, _) = db.commit(None).await?;
                let clean_db: C = durable_db.into_merkleized().await?;
                db = clean_db.into_mutable();
            }
        }
        if commit_changes {
            let (durable_db, _) = db.commit(None).await?;
            let clean_db: C = durable_db.into_merkleized().await?;
            db = clean_db.into_mutable();
        }
        Ok(db)
    }

    /// Run `test_build_random_close_reopen` against a database factory.
    ///
    /// The factory should return a clean (Merkleized, Durable) database when given a context and
    /// partition name. The factory will be called multiple times to test reopening.
    pub fn test_build_random_close_reopen<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        let state1 = executor.start(|mut context| async move {
            let partition = "build_random".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db_clone(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();

            // Drop and reopen the db
            let root = db.root();
            drop(db);
            let db: C = open_db_clone(context.with_label("second"), partition).await;

            // Ensure the root matches
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
            context.auditor().state()
        });

        // Run again to verify determinism
        let executor = deterministic::Runner::default();
        let state2 = executor.start(|mut context| async move {
            let partition = "build_random".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();

            let root = db.root();
            drop(db);
            let db: C = open_db(context.with_label("second"), partition).await;
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
            context.auditor().state()
        });

        assert_eq!(state1, state2);
    }

    /// Run `test_simulate_write_failures` against a database factory.
    ///
    /// This test builds a random database and simulates recovery from different types of
    /// failure scenarios.
    pub fn test_simulate_write_failures<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "build_random_fail_commit".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            let committed_root = db.root();
            let committed_op_count = db.bounds().end;
            let committed_inactivity_floor = db.inactivity_floor_loc();
            db.prune(committed_inactivity_floor).await.unwrap();

            // Perform more random operations without committing any of them.
            let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();

            // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
            // state of the DB should be as of the last commit.
            drop(db);
            let db: C = open_db(context.with_label("scenario1"), partition.clone()).await;
            assert_eq!(db.root(), committed_root);
            assert_eq!(db.bounds().end, committed_op_count);

            // Re-apply the exact same uncommitted operations.
            let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();

            // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
            // before the state of the pruned bitmap can be written to disk (i.e., before
            // into_merkleized is called). We do this by committing and then dropping the durable
            // db without calling close or into_merkleized.
            let (durable_db, _) = db.commit(None).await.unwrap();
            let committed_op_count = durable_db.bounds().end;
            drop(durable_db);

            // We should be able to recover, so the root should differ from the previous commit, and
            // the op count should be greater than before.
            let db: C = open_db(context.with_label("scenario2"), partition.clone()).await;
            let scenario_2_root = db.root();

            // To confirm the second committed hash is correct we'll re-build the DB in a new
            // partition, but without any failures. They should have the exact same state.
            let fresh_partition = "build_random_fail_commit_fresh".to_string();
            let db: C = open_db(context.with_label("fresh"), fresh_partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            // State from scenario #2 should match that of a successful commit.
            assert_eq!(db.bounds().end, committed_op_count);
            assert_eq!(db.root(), scenario_2_root);

            db.destroy().await.unwrap();
        });
    }

    /// Run `test_different_pruning_delays_same_root` against a database factory.
    ///
    /// This test verifies that pruning operations do not affect the root hash - two databases
    /// with identical operations but different pruning schedules should have the same root.
    pub fn test_different_pruning_delays_same_root<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const NUM_OPERATIONS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            // Create two databases that are identical other than how they are pruned.
            let mut db_no_pruning: C = open_db_clone(
                context.with_label("no_pruning"),
                "no_pruning_test".to_string(),
            )
            .await;
            let mut db_pruning: C =
                open_db(context.with_label("pruning"), "pruning_test".to_string()).await;

            let mut db_no_pruning_mut = db_no_pruning.into_mutable();
            let mut db_pruning_mut = db_pruning.into_mutable();

            // Apply identical operations to both databases, but only prune one.
            for i in 0..NUM_OPERATIONS {
                let key: C::Key = TestKey::from_seed(i);
                let value: <C as LogStore>::Value = TestValue::from_seed(i * 1000);

                db_no_pruning_mut.update(key, value.clone()).await.unwrap();
                db_pruning_mut.update(key, value).await.unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    let (db_1, _) = db_no_pruning_mut.commit(None).await.unwrap();
                    let clean_no_pruning: C = db_1.into_merkleized().await.unwrap();
                    let (db_2, _) = db_pruning_mut.commit(None).await.unwrap();
                    let mut clean_pruning: C = db_2.into_merkleized().await.unwrap();
                    clean_pruning
                        .prune(clean_no_pruning.inactivity_floor_loc())
                        .await
                        .unwrap();
                    db_no_pruning_mut = clean_no_pruning.into_mutable();
                    db_pruning_mut = clean_pruning.into_mutable();
                }
            }

            // Final commit
            let (db_1, _) = db_no_pruning_mut.commit(None).await.unwrap();
            db_no_pruning = db_1.into_merkleized().await.unwrap();
            let (db_2, _) = db_pruning_mut.commit(None).await.unwrap();
            db_pruning = db_2.into_merkleized().await.unwrap();

            // Get roots from both databases - they should match
            let root_no_pruning = db_no_pruning.root();
            let root_pruning = db_pruning.root();
            assert_eq!(root_no_pruning, root_pruning);

            // Also verify inactivity floors match
            assert_eq!(
                db_no_pruning.inactivity_floor_loc(),
                db_pruning.inactivity_floor_loc()
            );

            db_no_pruning.destroy().await.unwrap();
            db_pruning.destroy().await.unwrap();
        });
    }

    /// Run `test_sync_persists_bitmap_pruning_boundary` against a database factory.
    ///
    /// This test verifies that calling `sync()` persists the bitmap pruning boundary that was
    /// set during `into_merkleized()`. If `sync()` didn't call `write_pruned`, the
    /// `pruned_bits()` count would be 0 after reopen instead of the expected value.
    pub fn test_sync_persists_bitmap_pruning_boundary<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny + BitmapPrunedBits,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 500;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|mut context| async move {
            let partition = "sync_bitmap_pruning".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db_clone(context.with_label("first"), partition.clone()).await;

            // Apply random operations with commits to advance the inactivity floor.
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();

            // The bitmap should have been pruned during into_merkleized().
            let pruned_bits_before = db.pruned_bits();
            warn!(
                "pruned_bits_before={}, inactivity_floor={}, op_count={}",
                pruned_bits_before,
                *db.inactivity_floor_loc(),
                *db.bounds().end
            );

            // Verify we actually have some pruning (otherwise the test is meaningless).
            assert!(
                pruned_bits_before > 0,
                "Expected bitmap to have pruned bits after merkleization"
            );

            // Call sync() WITHOUT calling prune(). The bitmap pruning boundary was set
            // during into_merkleized(), and sync() should persist it.
            db.sync().await.unwrap();

            // Record the root before dropping.
            let root_before = db.root();
            drop(db);

            // Reopen the database.
            let db: C = open_db(context.with_label("second"), partition).await;

            // The pruned bits count should match. If sync() didn't persist the bitmap pruned
            // state, this would be 0.
            let pruned_bits_after = db.pruned_bits();
            warn!("pruned_bits_after={}", pruned_bits_after);

            assert_eq!(
                pruned_bits_after, pruned_bits_before,
                "Bitmap pruned bits mismatch after reopen - sync() may not have called write_pruned()"
            );

            // Also verify the root matches.
            assert_eq!(db.root(), root_before);

            db.destroy().await.unwrap();
        });
    }

    /// Run `test_current_db_build_big` against a database factory.
    ///
    /// This test builds a database with 1000 keys, updates some, deletes some, and verifies that
    /// the final state matches an independently computed HashMap. It also verifies that the state
    /// persists correctly after close and reopen.
    ///
    /// The `expected_op_count` and `expected_inactivity_floor` parameters specify the expected
    /// values after commit + merkleize + prune. These differ between ordered and unordered variants.
    pub fn test_current_db_build_big<C, F, Fut>(
        mut open_db: F,
        expected_op_count: u64,
        expected_inactivity_floor: u64,
    ) where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        use crate::mmr::Location;

        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            let mut db = open_db_clone(context.with_label("first"), "build_big".to_string())
                .await
                .into_mutable();

            let mut map = std::collections::HashMap::<C::Key, <C as LogStore>::Value>::default();
            for i in 0u64..ELEMENTS {
                let k: C::Key = TestKey::from_seed(i);
                let v: <C as LogStore>::Value = TestValue::from_seed(i * 1000);
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k: C::Key = TestKey::from_seed(i);
                let v: <C as LogStore>::Value = TestValue::from_seed((i + 1) * 10000);
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k: C::Key = TestKey::from_seed(i);
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            // Test that commit + sync w/ pruning will raise the activity floor.
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();

            // Verify expected state after prune.
            assert_eq!(db.bounds().end, Location::new_unchecked(expected_op_count));
            assert_eq!(
                db.inactivity_floor_loc(),
                Location::new_unchecked(expected_inactivity_floor)
            );

            // Record root before dropping.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);

            // Reopen the db and verify it has exactly the same state.
            let db: C = open_db(context.with_label("second"), "build_big".to_string()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.bounds().end, Location::new_unchecked(expected_op_count));
            assert_eq!(
                db.inactivity_floor_loc(),
                Location::new_unchecked(expected_inactivity_floor)
            );

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..ELEMENTS {
                let k: C::Key = TestKey::from_seed(i);
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }
        });
    }

    // ============================================================
    // Consolidated tests for all 12 Current QMDB variants
    // ============================================================

    use crate::translator::OneCap;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;

    // Type aliases for all 12 variants (all use OneCap for collision coverage).
    type OrderedFixedDb = ordered::fixed::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedVariableDb = ordered::variable::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedFixedDb = unordered::fixed::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedVariableDb = unordered::variable::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedFixedP1Db =
        ordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type OrderedVariableP1Db =
        ordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type UnorderedFixedP1Db =
        unordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type UnorderedVariableP1Db =
        unordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type OrderedFixedP2Db =
        ordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;
    type OrderedVariableP2Db =
        ordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;
    type UnorderedFixedP2Db =
        unordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;
    type UnorderedVariableP2Db =
        unordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;

    // Helper macro to create an open_db closure for a specific variant.
    macro_rules! open_db_fn {
        ($db:ty, $cfg:ident) => {
            |ctx: Context, partition: String| async move {
                <$db>::init(ctx, $cfg::<OneCap>(&partition)).await.unwrap()
            }
        };
    }

    // Defines all 12 variants. Calls $cb!($($args)*, $label, $type, $config) for each.
    macro_rules! with_all_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "of", OrderedFixedDb, fixed_config);
            $cb!($($args)*, "ov", OrderedVariableDb, variable_config);
            $cb!($($args)*, "uf", UnorderedFixedDb, fixed_config);
            $cb!($($args)*, "uv", UnorderedVariableDb, variable_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1Db, fixed_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1Db, variable_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1Db, fixed_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1Db, variable_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2Db, fixed_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2Db, variable_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2Db, fixed_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2Db, variable_config);
        };
    }

    // Defines 6 ordered variants.
    macro_rules! with_ordered_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "of", OrderedFixedDb, fixed_config);
            $cb!($($args)*, "ov", OrderedVariableDb, variable_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1Db, fixed_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1Db, variable_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2Db, fixed_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2Db, variable_config);
        };
    }

    // Defines 6 unordered variants.
    macro_rules! with_unordered_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "uf", UnorderedFixedDb, fixed_config);
            $cb!($($args)*, "uv", UnorderedVariableDb, variable_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1Db, fixed_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1Db, variable_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2Db, fixed_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2Db, variable_config);
        };
    }

    // Runner macros - receive common args followed by (label, type, config).
    macro_rules! test_simple {
        ($f:expr, $l:literal, $db:ty, $cfg:ident) => {
            Box::pin(async {
                $f(open_db_fn!($db, $cfg));
            })
            .await
        };
    }

    macro_rules! test_with_db {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                $f(open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await).await
            })
            .await
        }};
    }

    // Macro to run a test on DB variants.
    macro_rules! for_all_variants {
        (simple: $f:expr) => {{
            with_all_variants!(test_simple!($f));
        }};
        (ordered: $f:expr) => {{
            with_ordered_variants!(test_simple!($f));
        }};
        (unordered: $f:expr) => {{
            with_unordered_variants!(test_simple!($f));
        }};
        ($ctx:expr, $sfx:expr, with_db: $f:expr) => {{
            with_all_variants!(test_with_db!($ctx, $sfx, $f));
        }};
    }

    // Wrapper functions for build_big tests with ordered/unordered expected values.
    fn test_ordered_build_big<C, F, Fut>(open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<C, F, Fut>(open_db, 4241, 3383);
    }

    fn test_unordered_build_big<C, F, Fut>(open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<C, F, Fut>(open_db, 1957, 838);
    }

    #[test_traced("WARN")]
    fn test_all_variants_build_random_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_build_random_close_reopen);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_simulate_write_failures() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_simulate_write_failures);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_different_pruning_delays_same_root);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_sync_persists_bitmap_pruning_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_sync_persists_bitmap_pruning_boundary);
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_variants_build_big() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(ordered: test_ordered_build_big);
        });
    }

    #[test_traced("WARN")]
    fn test_unordered_variants_build_big() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(unordered: test_unordered_build_big);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "snr", with_db: crate::qmdb::any::test::test_any_db_steps_not_reset);
        });
    }

    #[test_traced("DEBUG")]
    fn test_ordered_variants_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(ordered: ordered::tests::test_build_small_close_reopen);
        });
    }

    #[test_traced("DEBUG")]
    fn test_unordered_variants_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(unordered: unordered::tests::test_build_small_close_reopen);
        });
    }
}
