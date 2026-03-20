//! An _Any_ authenticated database provides succinct proofs of any value ever associated with a
//! key.
//!
//! The specific variants provided within this module include:
//! - Unordered: The database does not maintain or require any ordering over the key space.
//!   - Fixed-size values
//!   - Variable-size values
//! - Ordered: The database maintains a total order over active keys.
//!   - Fixed-size values
//!   - Variable-size values
//!
//! # Examples
//!
//! ```ignore
//! // Simple mode: apply a batch, then durably commit it.
//! let merkleized = db.new_batch()
//!     .write(key, Some(value))    // upsert
//!     .write(other_key, None)     // delete
//!     .merkleize(None, &db).await?;
//! let root = merkleized.root();
//! let finalized = merkleized.finalize();
//! db.apply_batch(finalized).await?;
//! db.commit().await?;
//!
//! // Use `sync()` instead of `commit()` if you want a durability guarantee plus the guarantee
//! // that no recovery would be required should the application crash.
//! db.sync().await?;
//! ```
//!
//! ```ignore
//! // Batches can still fork before you apply them.
//! // The batch is lifetime-free, so it can be stored independently of the DB.
//! let parent = db.new_batch()
//!     .write(key_a, Some(val_a))
//!     .merkleize(None, &db).await?;
//!
//! let child_a = parent.new_batch()
//!     .write(key_b, Some(val_b))
//!     .merkleize(None, &db).await?;
//!
//! let child_b = parent.new_batch()
//!     .write(key_c, Some(val_c))
//!     .merkleize(None, &db).await?;
//!
//! // Only one fork can be applied; the others become stale.
//! db.apply_batch(child_a.finalize()).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Advanced usage: while the previous batch is being committed, concurrently build a child
//! // batch from the newly published state.
//! let parent_finalized = db.new_batch()
//!     .write(key_a, Some(val_a))
//!     .merkleize(None, &db).await?.finalize();
//! db.apply_batch(parent_finalized).await?;
//!
//! let (child_finalized, commit_result) = futures::join!(
//!     async {
//!         db.new_batch()
//!             .write(key_b, Some(val_b))
//!             .merkleize(None, &db).await.map(|batch| batch.finalize())
//!     },
//!     db.commit(),
//! );
//! let child_finalized = child_finalized?;
//! commit_result?;
//!
//! db.apply_batch(child_finalized).await?;
//! db.commit().await?;
//! ```

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        authenticated,
        contiguous::{
            fixed::{Config as FConfig, Journal as FJournal},
            variable::{Config as VConfig, Journal as VJournal},
        },
    },
    mmr::{journaled::Config as MmrConfig, Location},
    qmdb::{
        any::operation::{Operation, Update},
        operation::Committable,
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, CodecFixedShared, Read};
use commonware_cryptography::Hasher;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::warn;

pub mod batch;
pub mod db;
pub mod operation;
#[cfg(any(test, feature = "test-traits"))]
pub mod traits;
pub mod value;
pub use value::{FixedValue, ValueEncoding, VariableValue};
pub mod ordered;
pub(crate) mod sync;
pub mod unordered;

/// Configuration for an `Any` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

/// Configuration for an `Any` authenticated db with variable-sized values.
#[derive(Clone)]
pub struct VariableConfig<T: Translator, C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each blob of the journal.
    pub log_items_per_blob: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

/// Shared initialization logic for fixed-sized value [db::Db].
pub(super) async fn init_fixed<E, U, H, T, I, F, NewIndex>(
    context: E,
    cfg: FixedConfig<T>,
    known_inactivity_floor: Option<Location>,
    callback: F,
    new_index: NewIndex,
) -> Result<db::Db<E, FJournal<E, Operation<U>>, I, H, U>, Error>
where
    E: Storage + Clock + Metrics,
    U: Update + Send + Sync,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    F: FnMut(bool, Option<Location>),
    NewIndex: FnOnce(E, T) -> I,
    Operation<U>: CodecFixedShared + Committable,
{
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        page_cache: cfg.page_cache.clone(),
    };

    let journal_config = FConfig {
        partition: cfg.log_journal_partition,
        items_per_blob: cfg.log_items_per_blob,
        write_buffer: cfg.log_write_buffer,
        page_cache: cfg.page_cache,
    };

    let mut log = authenticated::Journal::<_, FJournal<_, _>, _>::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        Operation::is_commit,
    )
    .await?;

    if log.size().await == 0 {
        warn!("Authenticated log is empty, initializing new db");
        let commit_floor = Operation::CommitFloor(None, Location::new(0));
        log.append(&commit_floor).await?;
        log.sync().await?;
    }

    let index = new_index(context.with_label("index"), cfg.translator);
    db::Db::init_from_log(index, log, known_inactivity_floor, callback).await
}

/// Shared initialization logic for variable-sized value [db::Db].
pub(super) async fn init_variable<E, U, H, T, I, F, NewIndex>(
    context: E,
    cfg: VariableConfig<T, <Operation<U> as Read>::Cfg>,
    known_inactivity_floor: Option<Location>,
    callback: F,
    new_index: NewIndex,
) -> Result<db::Db<E, VJournal<E, Operation<U>>, I, H, U>, Error>
where
    E: Storage + Clock + Metrics,
    U: Update + Send + Sync,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    F: FnMut(bool, Option<Location>),
    NewIndex: FnOnce(E, T) -> I,
    Operation<U>: Codec + Committable,
{
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        page_cache: cfg.page_cache.clone(),
    };

    let journal_config = VConfig {
        partition: cfg.log_partition,
        items_per_section: cfg.log_items_per_blob,
        compression: cfg.log_compression,
        codec_config: cfg.log_codec_config,
        page_cache: cfg.page_cache,
        write_buffer: cfg.log_write_buffer,
    };

    let mut log = authenticated::Journal::<_, VJournal<_, _>, _>::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        Operation::is_commit,
    )
    .await?;

    if log.size().await == 0 {
        warn!("Authenticated log is empty, initializing new db");
        let commit_floor = Operation::CommitFloor(None, Location::new(0));
        log.append(&commit_floor).await?;
        log.sync().await?;
    }

    let index = new_index(context.with_label("index"), cfg.translator);
    db::Db::init_from_log(index, log, known_inactivity_floor, callback).await
}

#[cfg(test)]
// pub(crate) so qmdb/current can use the generic tests.
pub(crate) mod test {
    use super::*;
    use crate::{
        qmdb::any::{FixedConfig, VariableConfig},
        translator::OneCap,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    pub(crate) fn fixed_db_config<T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> FixedConfig<T> {
        FixedConfig {
            mmr_journal_partition: format!("journal-{suffix}"),
            mmr_metadata_partition: format!("metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log-journal-{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    pub(crate) fn variable_db_config<T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> VariableConfig<T, ((), ())> {
        VariableConfig {
            mmr_journal_partition: format!("journal-{suffix}"),
            mmr_metadata_partition: format!("metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log-journal-{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((), ()),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    use crate::{
        mmr::Location,
        qmdb::any::traits::{DbAny, MerkleizedBatch as _, Provable, UnmerkleizedBatch as _},
    };
    use commonware_codec::{Codec, CodecShared};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_runtime::{deterministic::Context, BufferPooler};
    use core::{future::Future, pin::Pin};
    use std::collections::HashMap;

    /// Test recovery on non-empty db.
    pub(crate) async fn test_any_db_non_empty_recovery<D, V: Clone + CodecShared>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest>,
    {
        const ELEMENTS: u64 = 1000;

        // Commit initial batch.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        db.prune(db.inactivity_floor_loc().await).await.unwrap();
        let root = db.root();
        let op_count = db.size().await;
        let inactivity_floor_loc = db.inactivity_floor_loc().await;

        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.size().await, op_count);
        assert_eq!(db.inactivity_floor_loc().await, inactivity_floor_loc);
        assert_eq!(db.root(), root);

        // Write without applying (unapplied batch should be lost on reopen).
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _ = batch.merkleize(None, &db).await.unwrap().finalize();
        }
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.size().await, op_count);
        assert_eq!(db.inactivity_floor_loc().await, inactivity_floor_loc);
        assert_eq!(db.root(), root);

        // Write without applying again.
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _ = batch.merkleize(None, &db).await.unwrap().finalize();
        }
        let db = reopen_db(context.with_label("reopen3")).await;
        assert_eq!(db.size().await, op_count);
        assert_eq!(db.root(), root);

        // Three rounds of unapplied batches.
        for _ in 0..3 {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _ = batch.merkleize(None, &db).await.unwrap().finalize();
        }
        let mut db = reopen_db(context.with_label("reopen4")).await;
        assert_eq!(db.size().await, op_count);
        assert_eq!(db.root(), root);

        // Now actually commit a batch.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.size().await > op_count);
        assert_ne!(db.inactivity_floor_loc().await, inactivity_floor_loc);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test recovery on empty db.
    pub(crate) async fn test_any_db_empty_recovery<D, V: Clone + CodecShared>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest>,
    {
        let root = db.root();

        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.size().await, 1);
        assert_eq!(db.root(), root);

        // Write without applying (unapplied batch should be lost on reopen).
        {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _ = batch.merkleize(None, &db).await.unwrap().finalize();
        }
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.size().await, 1);
        assert_eq!(db.root(), root);

        // Write without applying again.
        {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _ = batch.merkleize(None, &db).await.unwrap().finalize();
        }
        drop(db);
        let db = reopen_db(context.with_label("reopen3")).await;
        assert_eq!(db.size().await, 1);
        assert_eq!(db.root(), root);

        // Three rounds of unapplied batches.
        for _ in 0..3 {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _ = batch.merkleize(None, &db).await.unwrap().finalize();
        }
        drop(db);
        let mut db = reopen_db(context.with_label("reopen4")).await;
        assert_eq!(db.size().await, 1);
        assert_eq!(db.root(), root);

        // Now actually commit a batch.
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.size().await > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test that a large mixed workload can be authenticated and replayed correctly.
    pub(crate) async fn test_any_db_build_and_authenticate<D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest> + Provable,
        V: CodecShared + Clone + Eq + std::hash::Hash + std::fmt::Debug,
        <D as Provable>::Operation: Codec,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};

        const ELEMENTS: u64 = 1000;

        let mut map = HashMap::<Digest, V>::default();
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }

            // Update every 3rd key.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }

            // Delete every 7th key.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                batch = batch.write(k, None);
                map.remove(&k);
            }

            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        // Commit + sync with pruning raises inactivity floor.
        db.apply_batch(finalized).await.unwrap();
        db.sync().await.unwrap();
        db.prune(db.inactivity_floor_loc().await).await.unwrap();

        // Drop & reopen and ensure state matches.
        let root = db.root();
        db.sync().await.unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopened")).await;
        assert_eq!(root, db.root());

        // State matches reference map.
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            if let Some(map_value) = map.get(&k) {
                let Some(db_value) = db.get(&k).await.unwrap() else {
                    panic!("key not found in db: {k}");
                };
                assert_eq!(*map_value, db_value);
            } else {
                assert!(db.get(&k).await.unwrap().is_none());
            }
        }

        let hasher = StandardHasher::<Sha256>::new();
        let bounds = db.bounds().await;
        let inactivity_floor = db.inactivity_floor_loc().await;
        for loc in *inactivity_floor..*bounds.end {
            let loc = Location::new(loc);
            let (proof, ops) = db.proof(loc, NZU64!(10)).await.unwrap();
            assert!(verify_proof(&hasher, &proof, loc, &ops, &root));
        }

        db.destroy().await.unwrap();
    }

    /// Test that replaying multiple updates of the same key on startup preserves correct state.
    pub(crate) async fn test_any_db_log_replay<
        D,
        V: Clone + CodecShared + PartialEq + std::fmt::Debug,
    >(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest>,
    {
        // Update the same key many times within a single batch.
        const UPDATES: u64 = 100;
        let k = Sha256::hash(&UPDATES.to_be_bytes());
        let mut last_value = None;
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..UPDATES {
                let v = make_value(i * 1000);
                last_value = Some(v.clone());
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();

        // Reopen and verify the state is preserved correctly.
        drop(db);
        let db = reopen_db(context.with_label("reopened")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.get(&k).await.unwrap(), last_value);

        db.destroy().await.unwrap();
    }

    /// Test that historical_proof returns correct proofs for past database states.
    pub(crate) async fn test_any_db_historical_proof_basic<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest> + Provable,
        <D as Provable>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};
        use commonware_utils::NZU64;

        // Add some operations
        const OPS: u64 = 20;
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..OPS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();
        let root_hash = db.root();
        let original_op_count = db.size().await;

        // Historical proof should match "regular" proof when historical size == current database size
        let max_ops = NZU64!(10);
        let start_loc = Location::new(5);
        let (historical_proof, historical_ops) = db
            .historical_proof(original_op_count, start_loc, max_ops)
            .await
            .unwrap();
        let (regular_proof, regular_ops) = db.proof(start_loc, max_ops).await.unwrap();

        assert_eq!(historical_proof.leaves, regular_proof.leaves);
        assert_eq!(historical_proof.digests, regular_proof.digests);
        assert_eq!(historical_ops, regular_ops);
        let hasher = StandardHasher::<Sha256>::new();
        assert!(verify_proof(
            &hasher,
            &historical_proof,
            start_loc,
            &historical_ops,
            &root_hash
        ));

        // Add more operations to the database
        let finalized = {
            let mut batch = db.new_batch();
            for i in OPS..(OPS + 5) {
                let k = Sha256::hash(&(i + 1000).to_be_bytes()); // different keys
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Historical proof should remain the same even though database has grown
        let (historical_proof2, historical_ops2) = db
            .historical_proof(original_op_count, start_loc, max_ops)
            .await
            .unwrap();
        assert_eq!(historical_proof2.leaves, original_op_count);
        assert_eq!(historical_proof2.digests, regular_proof.digests);
        assert_eq!(historical_ops2, regular_ops);
        assert!(verify_proof(
            &hasher,
            &historical_proof2,
            start_loc,
            &historical_ops2,
            &root_hash
        ));

        db.destroy().await.unwrap();
    }

    /// Test that tampering with historical proofs causes verification to fail.
    pub(crate) async fn test_any_db_historical_proof_invalid<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest> + Provable,
        <D as Provable>::Operation: Codec + PartialEq + std::fmt::Debug + Clone,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};
        use commonware_utils::NZU64;

        // Add some operations
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..10 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        let historical_op_count = Location::new(5);
        let (proof, ops) = db
            .historical_proof(historical_op_count, Location::new(1), NZU64!(10))
            .await
            .unwrap();
        assert_eq!(proof.leaves, historical_op_count);
        assert_eq!(ops.len(), 4);

        let hasher = StandardHasher::<Sha256>::new();

        // Changing the proof digests should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.digests[0] = Sha256::hash(b"invalid");
            let root_hash = db.root();
            assert!(!verify_proof(
                &hasher,
                &tampered_proof,
                Location::new(1),
                &ops,
                &root_hash
            ));
        }

        // Appending an extra digest should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.digests.push(Sha256::hash(b"invalid"));
            let root_hash = db.root();
            assert!(!verify_proof(
                &hasher,
                &tampered_proof,
                Location::new(1),
                &ops,
                &root_hash
            ));
        }

        // Changing the ops should cause verification to fail
        {
            let root_hash = db.root();
            let mut tampered_ops = ops.clone();
            // Swap first two ops if we have at least 2
            if tampered_ops.len() >= 2 {
                tampered_ops.swap(0, 1);
                assert!(!verify_proof(
                    &hasher,
                    &proof,
                    Location::new(1),
                    &tampered_ops,
                    &root_hash
                ));
            }
        }

        // Appending an extra (duplicate) op should cause verification to fail
        {
            let root_hash = db.root();
            let mut tampered_ops = ops.clone();
            tampered_ops.push(tampered_ops[0].clone());
            assert!(!verify_proof(
                &hasher,
                &proof,
                Location::new(1),
                &tampered_ops,
                &root_hash
            ));
        }

        // Changing the start location should cause verification to fail
        {
            let root_hash = db.root();
            assert!(!verify_proof(
                &hasher,
                &proof,
                Location::new(2),
                &ops,
                &root_hash
            ));
        }

        // Changing the root digest should cause verification to fail
        {
            let invalid_root = Sha256::hash(b"invalid");
            assert!(!verify_proof(
                &hasher,
                &proof,
                Location::new(1),
                &ops,
                &invalid_root
            ));
        }

        // Changing the proof leaves count should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.leaves = Location::new(100);
            let root_hash = db.root();
            assert!(!verify_proof(
                &hasher,
                &tampered_proof,
                Location::new(1),
                &ops,
                &root_hash
            ));
        }

        db.destroy().await.unwrap();
    }

    /// Test historical_proof edge cases: singleton db, limited ops, min position.
    pub(crate) async fn test_any_db_historical_proof_edge_cases<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest> + Provable,
        <D as Provable>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use commonware_utils::NZU64;

        // Add 50 operations
        let finalized = {
            let mut batch = db.new_batch();
            for i in 0u64..50 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            batch.merkleize(None, &db).await.unwrap().finalize()
        };
        db.apply_batch(finalized).await.unwrap();

        // Test singleton database (historical size = 2 means 1 op after initial commit)
        let (single_proof, single_ops) = db
            .historical_proof(Location::new(2), Location::new(1), NZU64!(1))
            .await
            .unwrap();
        assert_eq!(single_proof.leaves, Location::new(2));
        assert_eq!(single_ops.len(), 1);

        // Test requesting more operations than available in historical position
        let (_limited_proof, limited_ops) = db
            .historical_proof(Location::new(11), Location::new(6), NZU64!(20))
            .await
            .unwrap();
        assert_eq!(limited_ops.len(), 5); // Should be limited by historical position

        // Test proof at minimum historical position
        let (min_proof, min_ops) = db
            .historical_proof(Location::new(4), Location::new(1), NZU64!(3))
            .await
            .unwrap();
        assert_eq!(min_proof.leaves, Location::new(4));
        assert_eq!(min_ops.len(), 3);

        db.destroy().await.unwrap();
    }

    /// Test making multiple commits, one of which deletes a key from a previous commit.
    pub(crate) async fn test_any_db_multiple_commits_delete_replayed<D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<Key = Digest, Value = V, Digest = Digest>,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let mut map = HashMap::<Digest, V>::default();
        const ELEMENTS: u64 = 10;
        let metadata_value = make_value(42);
        let key_at = |j: u64, i: u64| Sha256::hash(&(j * 1000 + i).to_be_bytes());
        for j in 0u64..ELEMENTS {
            let finalized = {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    let k = key_at(j, i);
                    let v = make_value(i * 1000);
                    batch = batch.write(k, Some(v.clone()));
                    map.insert(k, v);
                }
                batch
                    .merkleize(Some(metadata_value.clone()), &db)
                    .await
                    .unwrap()
                    .finalize()
            };
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
        }
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_value));
        let k = key_at(ELEMENTS - 1, ELEMENTS - 1);

        let finalized = db
            .new_batch()
            .write(k, None)
            .merkleize(None, &db)
            .await
            .unwrap()
            .finalize();
        db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(db.get(&k).await.unwrap().is_none());

        let root = db.root();
        drop(db);
        let db = reopen_db(context.with_label("reopened")).await;
        assert_eq!(root, db.root());
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(db.get(&k).await.unwrap().is_none());

        db.destroy().await.unwrap();
    }

    use crate::qmdb::any::{
        ordered::{fixed::Db as OrderedFixedDb, variable::Db as OrderedVariableDb},
        unordered::{fixed::Db as UnorderedFixedDb, variable::Db as UnorderedVariableDb},
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{deterministic, Runner as _};

    // Type aliases for all 12 variants (all use OneCap for collision coverage).
    type UnorderedFixed = UnorderedFixedDb<Context, Digest, Digest, Sha256, OneCap>;
    type UnorderedVariable = UnorderedVariableDb<Context, Digest, Digest, Sha256, OneCap>;
    type OrderedFixed = OrderedFixedDb<Context, Digest, Digest, Sha256, OneCap>;
    type OrderedVariable = OrderedVariableDb<Context, Digest, Digest, Sha256, OneCap>;
    type UnorderedFixedP1 =
        unordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1>;
    type UnorderedVariableP1 =
        unordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1>;
    type OrderedFixedP1 =
        ordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1>;
    type OrderedVariableP1 =
        ordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1>;
    type UnorderedFixedP2 =
        unordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2>;
    type UnorderedVariableP2 =
        unordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2>;
    type OrderedFixedP2 =
        ordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2>;
    type OrderedVariableP2 =
        ordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2>;

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    // Defines all 12 variants in one place. Calls $cb!($($args)*, $label, $type, $config) for each.
    macro_rules! with_all_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "uf", UnorderedFixed, fixed_db_config);
            $cb!($($args)*, "uv", UnorderedVariable, variable_db_config);
            $cb!($($args)*, "of", OrderedFixed, fixed_db_config);
            $cb!($($args)*, "ov", OrderedVariable, variable_db_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1, fixed_db_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1, variable_db_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1, fixed_db_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1, variable_db_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2, fixed_db_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2, variable_db_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2, fixed_db_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2, variable_db_config);
        };
    }

    // Runner macros - each receives common args followed by (label, type, config) from with_all_variants.
    // Uses Box::pin to move futures to the heap and avoid stack overflow.
    macro_rules! test_with_reopen {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                let ctx = $ctx.with_label($l);
                let db = <$db>::init(ctx.clone(), $cfg::<OneCap>(p, &ctx))
                    .await
                    .unwrap();
                $f(
                    ctx,
                    db,
                    |ctx| {
                        Box::pin(async move {
                            <$db>::init(ctx.clone(), $cfg::<OneCap>(p, &ctx))
                                .await
                                .unwrap()
                        })
                    },
                    to_digest,
                )
                .await;
            })
            .await
        }};
    }

    macro_rules! test_with_make_value {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                let ctx = $ctx.with_label($l);
                let db = <$db>::init(ctx.clone(), $cfg::<OneCap>(p, &ctx))
                    .await
                    .unwrap();
                $f(ctx, db, to_digest).await;
            })
            .await
        }};
    }

    // Macro to run a test on all 12 DB variants.
    macro_rules! for_all_variants {
        ($ctx:expr, $sfx:expr, with_reopen: $f:expr) => {{
            with_all_variants!(test_with_reopen!($ctx, $sfx, $f));
        }};
        ($ctx:expr, $sfx:expr, with_make_value: $f:expr) => {{
            with_all_variants!(test_with_make_value!($ctx, $sfx, $f));
        }};
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "lr", with_reopen: test_any_db_log_replay);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "baa", with_reopen: test_any_db_build_and_authenticate);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "hpb", with_make_value: test_any_db_historical_proof_basic);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "hpi", with_make_value: test_any_db_historical_proof_invalid);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "hpec", with_make_value: test_any_db_historical_proof_edge_cases);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_multiple_commits_delete_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "mcdr", with_reopen: test_any_db_multiple_commits_delete_replayed);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_non_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "ner", with_reopen: test_any_db_non_empty_recovery);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "er", with_reopen: test_any_db_empty_recovery);
        });
    }

    fn key(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    fn val(i: u64) -> Digest {
        Sha256::hash(&(i + 10000).to_be_bytes())
    }

    /// Helper: commit a batch of key-value writes and return the applied range.
    async fn commit_writes(
        db: &mut UnorderedVariable,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) -> std::ops::Range<Location> {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let finalized = batch.merkleize(metadata, &*db).await.unwrap().finalize();
        let range = db.apply_batch(finalized).await.unwrap();
        db.commit().await.unwrap();
        range
    }

    /// An empty batch (no mutations) still produces a valid commit.
    #[test_traced("INFO")]
    fn test_any_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("e", &ctx))
                    .await
                    .unwrap();

            let root_before = db.root();
            let batch = db.new_batch();
            let finalized = batch.merkleize(None, &db).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();

            // A CommitFloor op was appended, so root must change.
            assert_ne!(db.root(), root_before);

            // DB should still be functional.
            commit_writes(&mut db, [(key(0), Some(val(0)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            db.destroy().await.unwrap();
        });
    }

    /// Metadata propagates through merkleize and clears with None.
    #[test_traced("INFO")]
    fn test_any_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("m", &ctx))
                    .await
                    .unwrap();

            let metadata = val(42);

            // Batch with metadata.
            commit_writes(&mut db, [(key(0), Some(val(0)))], Some(metadata)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Batch without metadata clears it.
            let batch = db.new_batch();
            let finalized = batch.merkleize(None, &db).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// batch.get() reads through: pending mutations -> base DB.
    /// Updates shadow the base value; deletes hide the key.
    #[test_traced("INFO")]
    fn test_any_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("g", &ctx))
                    .await
                    .unwrap();

            // Pre-populate with key A.
            let ka = key(0);
            let va = val(0);
            commit_writes(&mut db, [(ka, Some(va))], None).await;

            let kb = key(1);
            let vb = val(1);
            let kc = key(2);

            let mut batch = db.new_batch();

            // Read-through to base DB.
            assert_eq!(batch.get(&ka, &db).await.unwrap(), Some(va));

            // Pending mutation visible.
            batch = batch.write(kb, Some(vb));
            assert_eq!(batch.get(&kb, &db).await.unwrap(), Some(vb));

            // Nonexistent key.
            assert_eq!(batch.get(&kc, &db).await.unwrap(), None);

            // Update shadows base DB value.
            let va2 = val(100);
            batch = batch.write(ka, Some(va2));
            assert_eq!(batch.get(&ka, &db).await.unwrap(), Some(va2));

            // Delete hides the key.
            batch = batch.write(ka, None);
            assert_eq!(batch.get(&ka, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// merkleized.get() reflects the resolved diff after merkleize.
    #[test_traced("INFO")]
    fn test_any_batch_get_on_merkleized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("mg", &ctx))
                    .await
                    .unwrap();

            let ka = key(0);
            let kb = key(1);
            let kc = key(2);
            let kd = key(3);

            // Pre-populate A and B.
            commit_writes(&mut db, [(ka, Some(val(0))), (kb, Some(val(1)))], None).await;

            // Batch: update A, delete B, create C.
            let va2 = val(100);
            let vc = val(2);
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(va2));
            batch = batch.write(kb, None);
            batch = batch.write(kc, Some(vc));
            let merkleized = batch.merkleize(None, &db).await.unwrap();

            assert_eq!(merkleized.get(&ka, &db).await.unwrap(), Some(va2));
            assert_eq!(merkleized.get(&kb, &db).await.unwrap(), None);
            assert_eq!(merkleized.get(&kc, &db).await.unwrap(), Some(vc));
            assert_eq!(merkleized.get(&kd, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Child batch reads through: child mutations -> parent diff -> base DB.
    #[test_traced("INFO")]
    fn test_any_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("sg", &ctx))
                    .await
                    .unwrap();

            let ka = key(0);
            let kb = key(1);

            // Parent batch writes A.
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(val(0)));
            let merkleized = batch.merkleize(None, &db).await.unwrap();

            // Child reads parent's A.
            let mut child = merkleized.new_batch::<Sha256>();
            assert_eq!(child.get(&ka, &db).await.unwrap(), Some(val(0)));

            // Child overwrites A.
            child = child.write(ka, Some(val(100)));
            assert_eq!(child.get(&ka, &db).await.unwrap(), Some(val(100)));

            // Child writes new key B.
            child = child.write(kb, Some(val(1)));
            assert_eq!(child.get(&kb, &db).await.unwrap(), Some(val(1)));

            // Child deletes A.
            child = child.write(ka, None);
            assert_eq!(child.get(&ka, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Parent deletes a base-DB key, child re-creates it.
    #[test_traced("INFO")]
    fn test_any_batch_stacked_delete_recreate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("dr", &ctx))
                    .await
                    .unwrap();

            let ka = key(0);

            // Pre-populate with key A.
            commit_writes(&mut db, [(ka, Some(val(0)))], None).await;

            // Parent batch deletes A.
            let mut parent = db.new_batch();
            parent = parent.write(ka, None);
            let parent_m = parent.merkleize(None, &db).await.unwrap();
            assert_eq!(parent_m.get(&ka, &db).await.unwrap(), None);

            // Child re-creates A with a new value.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.write(ka, Some(val(200)));
            let child_m = child.merkleize(None, &db).await.unwrap();
            assert_eq!(child_m.get(&ka, &db).await.unwrap(), Some(val(200)));

            // Apply and verify DB state.
            let finalized = child_m.finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get(&ka).await.unwrap(), Some(val(200)));

            db.destroy().await.unwrap();
        });
    }

    /// Floor raise during merkleize moves active operations to the tip.
    /// All keys remain accessible with correct values.
    #[test_traced("INFO")]
    fn test_any_batch_floor_raise() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("fr", &ctx))
                    .await
                    .unwrap();

            // Pre-populate with 100 keys.
            let init: Vec<_> = (0..100).map(|i| (key(i), Some(val(i)))).collect();
            commit_writes(&mut db, init, None).await;

            let floor_before = db.inactivity_floor_loc();

            // Update 30 keys.
            let updates: Vec<_> = (0..30).map(|i| (key(i), Some(val(i + 500)))).collect();
            commit_writes(&mut db, updates, None).await;

            // Floor should have advanced.
            assert!(db.inactivity_floor_loc() > floor_before);

            // All keys should still be accessible with correct values.
            for i in 0..30 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i + 500)),
                    "updated key {i} mismatch"
                );
            }
            for i in 30..100 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i)),
                    "untouched key {i} mismatch"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// apply_batch() returns the correct range of committed locations.
    #[test_traced("INFO")]
    fn test_any_batch_apply_returns_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("ar", &ctx))
                    .await
                    .unwrap();

            // First batch: 5 keys.
            let writes: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            let range1 = commit_writes(&mut db, writes, None).await;

            // Range should start after the initial CommitFloor (location 0).
            assert_eq!(range1.start, Location::new(1));
            // Range length >= 6 (5 writes + 1 CommitFloor + possible floor raise ops).
            assert!(range1.end.saturating_sub(*range1.start) >= 6);

            // Second batch: ranges must be contiguous.
            let writes: Vec<_> = (5..10).map(|i| (key(i), Some(val(i)))).collect();
            let range2 = commit_writes(&mut db, writes, None).await;
            assert_eq!(range2.start, range1.end);

            db.destroy().await.unwrap();
        });
    }

    /// 3-level chain: parent -> child -> grandchild, finalize grandchild and apply.
    #[test_traced("INFO")]
    fn test_any_batch_deep_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("dc", &ctx))
                    .await
                    .unwrap();

            // Pre-populate with keys 0..5.
            let init: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            commit_writes(&mut db, init, None).await;

            // Parent: overwrite key 0, add key 5.
            let mut parent = db.new_batch();
            parent = parent.write(key(0), Some(val(100)));
            parent = parent.write(key(5), Some(val(5)));
            let parent_m = parent.merkleize(None, &db).await.unwrap();

            // Child: overwrite key 1, add key 6.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.write(key(1), Some(val(101)));
            child = child.write(key(6), Some(val(6)));
            let child_m = child.merkleize(None, &db).await.unwrap();

            // Grandchild: delete key 2, add key 7.
            let mut grandchild = child_m.new_batch::<Sha256>();
            grandchild = grandchild.write(key(2), None);
            grandchild = grandchild.write(key(7), Some(val(7)));
            let grandchild_m = grandchild.merkleize(None, &db).await.unwrap();

            // Verify reads through the chain.
            assert_eq!(
                grandchild_m.get(&key(0), &db).await.unwrap(),
                Some(val(100))
            );
            assert_eq!(
                grandchild_m.get(&key(1), &db).await.unwrap(),
                Some(val(101))
            );
            assert_eq!(grandchild_m.get(&key(2), &db).await.unwrap(), None);
            assert_eq!(grandchild_m.get(&key(7), &db).await.unwrap(), Some(val(7)));

            // Finalize and apply.
            let finalized = grandchild_m.finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(100)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(101)));
            assert_eq!(db.get(&key(2)).await.unwrap(), None);
            assert_eq!(db.get(&key(3)).await.unwrap(), Some(val(3)));
            assert_eq!(db.get(&key(4)).await.unwrap(), Some(val(4)));
            assert_eq!(db.get(&key(5)).await.unwrap(), Some(val(5)));
            assert_eq!(db.get(&key(6)).await.unwrap(), Some(val(6)));
            assert_eq!(db.get(&key(7)).await.unwrap(), Some(val(7)));

            db.destroy().await.unwrap();
        });
    }

    /// Chained batch produces the same DB state as sequential apply_batch calls.
    #[test_traced("INFO")]
    fn test_any_batch_chain_matches_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");

            // DB A: sequential apply.
            let ctx_a = ctx.with_label("a");
            let mut db_a: UnorderedVariable = UnorderedVariableDb::init(
                ctx_a.clone(),
                variable_db_config::<OneCap>("cms-a", &ctx_a),
            )
            .await
            .unwrap();

            // DB B: chained batch.
            let ctx_b = ctx.with_label("b");
            let mut db_b: UnorderedVariable = UnorderedVariableDb::init(
                ctx_b.clone(),
                variable_db_config::<OneCap>("cms-b", &ctx_b),
            )
            .await
            .unwrap();

            // Batch 1 operations: create keys 0..5.
            let writes1: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();

            // Batch 2 operations: update key 0, delete key 1, create key 5.
            let writes2 = vec![
                (key(0), Some(val(100))),
                (key(1), None),
                (key(5), Some(val(5))),
            ];

            // DB A: apply sequentially.
            commit_writes(&mut db_a, writes1.clone(), None).await;
            commit_writes(&mut db_a, writes2.clone(), None).await;

            // DB B: apply as chain.
            let mut parent = db_b.new_batch();
            for (k, v) in &writes1 {
                parent = parent.write(*k, *v);
            }
            let parent_m = parent.merkleize(None, &db_b).await.unwrap();

            let mut child = parent_m.new_batch::<Sha256>();
            for (k, v) in &writes2 {
                child = child.write(*k, *v);
            }
            let child_m = child.merkleize(None, &db_b).await.unwrap();
            let finalized = child_m.finalize();
            db_b.apply_batch(finalized).await.unwrap();

            // Both DBs must have the same state.
            assert_eq!(db_a.root(), db_b.root());
            for i in 0..6 {
                assert_eq!(
                    db_a.get(&key(i)).await.unwrap(),
                    db_b.get(&key(i)).await.unwrap(),
                    "key {i} mismatch"
                );
            }

            db_a.destroy().await.unwrap();
            db_b.destroy().await.unwrap();
        });
    }

    /// Create and delete the same key in a single batch produces no net change for that key.
    #[test_traced("INFO")]
    fn test_any_batch_create_then_delete_same_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("cd", &ctx))
                    .await
                    .unwrap();

            // Pre-populate key A.
            commit_writes(&mut db, [(key(0), Some(val(0)))], None).await;

            // In one batch: create B then delete B, also create C and delete A.
            let mut batch = db.new_batch();
            batch = batch.write(key(1), Some(val(1))); // create B
            batch = batch.write(key(1), None); // delete B (net: no B)
            batch = batch.write(key(2), Some(val(2))); // create C
            batch = batch.write(key(0), None); // delete A
            let finalized = batch.merkleize(None, &db).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), None);
            assert_eq!(db.get(&key(1)).await.unwrap(), None);
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.destroy().await.unwrap();
        });
    }

    /// Deleting all keys exercises the total_active_keys == 0 floor-raise fast path.
    #[test_traced("INFO")]
    fn test_any_batch_delete_all_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("da", &ctx))
                    .await
                    .unwrap();

            // Pre-populate 5 keys.
            let init: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            commit_writes(&mut db, init, None).await;

            // Delete all 5.
            let deletes: Vec<_> = (0..5).map(|i| (key(i), None)).collect();
            commit_writes(&mut db, deletes, None).await;

            for i in 0..5 {
                assert_eq!(db.get(&key(i)).await.unwrap(), None, "key {i} not deleted");
            }

            // DB should still be functional after deleting everything.
            commit_writes(&mut db, [(key(10), Some(val(10)))], None).await;
            assert_eq!(db.get(&key(10)).await.unwrap(), Some(val(10)));

            db.destroy().await.unwrap();
        });
    }

    /// Two independent batches from the same DB do not interfere with each other.
    #[test_traced("INFO")]
    fn test_any_batch_parallel_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("pf", &ctx))
                    .await
                    .unwrap();

            // Pre-populate.
            commit_writes(&mut db, [(key(0), Some(val(0)))], None).await;
            let root_before = db.root();

            // Fork A: update key 0 and create key 1.
            let fork_a_m = db
                .new_batch()
                .write(key(0), Some(val(100)))
                .write(key(1), Some(val(1)))
                .merkleize(None, &db)
                .await
                .unwrap();

            // Fork B: delete key 0 and create key 2.
            let fork_b_m = db
                .new_batch()
                .write(key(0), None)
                .write(key(2), Some(val(2)))
                .merkleize(None, &db)
                .await
                .unwrap();

            // Different mutations must produce different roots.
            assert_ne!(fork_a_m.root(), fork_b_m.root());

            // DB is unchanged (neither batch applied).
            assert_eq!(db.root(), root_before);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), None);

            // Apply fork A only.
            let finalized = fork_a_m.finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(100)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Floor raise advances correctly across a chained batch.
    #[test_traced("INFO")]
    fn test_any_batch_floor_raise_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("frc", &ctx))
                    .await
                    .unwrap();

            // Pre-populate with 50 keys.
            let init: Vec<_> = (0..50).map(|i| (key(i), Some(val(i)))).collect();
            commit_writes(&mut db, init, None).await;
            let floor_before = db.inactivity_floor_loc();

            // Parent: update keys 0..20.
            let mut parent = db.new_batch();
            for i in 0..20 {
                parent = parent.write(key(i), Some(val(i + 500)));
            }
            let parent_m = parent.merkleize(None, &db).await.unwrap();

            // Child: update keys 20..30.
            let mut child = parent_m.new_batch::<Sha256>();
            for i in 20..30 {
                child = child.write(key(i), Some(val(i + 500)));
            }
            let child_m = child.merkleize(None, &db).await.unwrap();

            let finalized = child_m.finalize();
            db.apply_batch(finalized).await.unwrap();

            // Floor must have advanced.
            assert!(db.inactivity_floor_loc() > floor_before);

            // All keys should be accessible.
            for i in 0..30 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i + 500)),
                    "updated key {i} mismatch"
                );
            }
            for i in 30..50 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i)),
                    "untouched key {i} mismatch"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// Dropping a batch without applying it leaves the DB unchanged.
    #[test_traced("INFO")]
    fn test_any_batch_abandoned() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("ab", &ctx))
                    .await
                    .unwrap();

            commit_writes(&mut db, [(key(0), Some(val(0)))], None).await;
            let root_before = db.root();

            // Create, populate, merkleize, then drop without apply.
            {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(999)));
                batch = batch.write(key(1), Some(val(1)));
                let _merkleized = batch.merkleize(None, &db).await.unwrap();
                // dropped here
            }

            // DB state is identical.
            assert_eq!(db.root(), root_before);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Applying without `commit()` publishes in memory but is not recovered after reopen.
    #[test_traced("INFO")]
    fn test_any_batch_apply_requires_commit_for_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "apply_requires_commit";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<OneCap>(partition, &ctx),
            )
            .await
            .unwrap();

            let committed_root = db.root();

            let finalized = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(None, &db)
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            drop(db);

            let reopened: UnorderedVariable = UnorderedVariableDb::init(
                context.with_label("reopen"),
                variable_db_config::<OneCap>(partition, &context),
            )
            .await
            .unwrap();
            assert_eq!(reopened.root(), committed_root);
            assert_eq!(reopened.get(&key(0)).await.unwrap(), None);

            reopened.destroy().await.unwrap();
        });
    }

    /// One-stage pipelining lets the next batch be built while the prior batch commits.
    #[test_traced("INFO")]
    fn test_any_batch_single_stage_pipeline() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<OneCap>("pipe", &ctx))
                    .await
                    .unwrap();

            let parent_finalized = {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(0)));
                batch.merkleize(None, &db).await.unwrap().finalize()
            };
            db.apply_batch(parent_finalized).await.unwrap();

            let (child_finalized, commit_result) = futures::join!(
                async {
                    assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
                    let mut child = db.new_batch();
                    child = child.write(key(1), Some(val(1)));
                    child
                        .merkleize(None, &db)
                        .await
                        .map(|batch| batch.finalize())
                },
                db.commit(),
            );
            let child_finalized = child_finalized.unwrap();
            commit_result.unwrap();

            db.apply_batch(child_finalized).await.unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }
}
