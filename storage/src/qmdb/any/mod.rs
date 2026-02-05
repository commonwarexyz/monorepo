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

use crate::{
    journal::{
        authenticated,
        contiguous::fixed::{Config as JConfig, Journal},
    },
    mmr::journaled::Config as MmrConfig,
    qmdb::{operation::Committable, Error, Merkleized},
    translator::Translator,
};
use commonware_codec::CodecFixedShared;
use commonware_cryptography::Hasher;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use std::num::{NonZeroU64, NonZeroUsize};

pub(crate) mod db;
pub(crate) mod operation;
#[cfg(any(test, feature = "test-traits"))]
pub mod states;
pub(crate) mod value;
pub(crate) use value::{FixedValue, ValueEncoding, VariableValue};
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

type AuthenticatedLog<E, O, H, S = Merkleized<H>> = authenticated::Journal<E, Journal<E, O>, H, S>;

/// Initialize a fixed-size authenticated log from the given config.
pub(crate) async fn init_fixed_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Committable + CodecFixedShared,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: FixedConfig<T>,
) -> Result<AuthenticatedLog<E, O, H>, Error> {
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        page_cache: cfg.page_cache.clone(),
    };

    let journal_config = JConfig {
        partition: cfg.log_journal_partition,
        items_per_blob: cfg.log_items_per_blob,
        write_buffer: cfg.log_write_buffer,
        page_cache: cfg.page_cache,
    };

    AuthenticatedLog::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await
    .map_err(Into::into)
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

    pub(crate) fn fixed_db_config<T: Translator + Default>(suffix: &str) -> FixedConfig<T> {
        FixedConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    pub(crate) fn variable_db_config<T: Translator + Default>(
        suffix: &str,
    ) -> VariableConfig<T, ()> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    use crate::{
        kv::{Deletable, Updatable},
        mmr::Location,
        qmdb::{
            any::states::{CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny},
            store::{LogStore, MerkleizedStore},
        },
        Persistable,
    };
    use commonware_codec::Codec;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_runtime::deterministic::Context;
    use core::{future::Future, pin::Pin};
    use std::collections::HashMap;

    /// Test that merkleization state changes don't reset `steps`.
    pub(crate) async fn test_any_db_steps_not_reset<D>(db: D)
    where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = Digest, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = Digest, Error = crate::qmdb::Error>,
    {
        // Create a db with a couple keys.
        let mut db = db.into_mutable();

        assert!(db
            .create(Sha256::fill(1u8), Sha256::fill(2u8))
            .await
            .unwrap());
        assert!(db
            .create(Sha256::fill(3u8), Sha256::fill(4u8))
            .await
            .unwrap());
        let (clean_db, _) = db.commit(None).await.unwrap();
        let mut db = clean_db.into_mutable();

        // Updating an existing key should make steps non-zero.
        db.update(Sha256::fill(1u8), Sha256::fill(5u8))
            .await
            .unwrap();
        let steps = db.steps();
        assert_ne!(steps, 0);

        // Steps shouldn't change from merkleization.
        let db = db.into_merkleized().await.unwrap();
        let db = db.into_mutable();
        assert_eq!(db.steps(), steps);

        // Cleanup
        let (db, _) = db.commit(None).await.unwrap();
        let db = db.into_merkleized().await.unwrap();
        db.destroy().await.unwrap();
    }

    /// Test recovery on non-empty db.
    pub(crate) async fn test_any_db_non_empty_recovery<D, V: Clone>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>,
    {
        const ELEMENTS: u64 = 1000;

        let mut db = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let mut db = db.into_merkleized().await.unwrap();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        let root = db.root();
        let op_count = db.size();
        let inactivity_floor_loc = db.inactivity_floor_loc();

        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        let mut dirty = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            dirty.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.with_label("reopen3")).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for _ in 0..3 {
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                db.update(k, v).await.unwrap();
            }
        }
        let db = reopen_db(context.with_label("reopen4")).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let _ = db.commit(None).await.unwrap();
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.size() > op_count);
        assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test recovery on empty db.
    pub(crate) async fn test_any_db_empty_recovery<D, V: Clone>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>,
    {
        let root = db.root();

        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        drop(db);
        let db = reopen_db(context.with_label("reopen3")).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for _ in 0..3 {
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                db.update(k, v).await.unwrap();
            }
        }
        drop(db);
        let db = reopen_db(context.with_label("reopen4")).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.size() > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test that replaying multiple updates of the same key on startup preserves correct state.
    pub(crate) async fn test_any_db_log_replay<D, V: Clone + PartialEq + std::fmt::Debug>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>,
    {
        let mut db = db.into_mutable();

        // Update the same key many times.
        const UPDATES: u64 = 100;
        let k = Sha256::hash(&UPDATES.to_be_bytes());
        let mut last_value = None;
        for i in 0u64..UPDATES {
            let v = make_value(i * 1000);
            last_value = Some(v.clone());
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();
        let root = db.root();

        // Reopen and verify the state is preserved correctly.
        drop(db);
        let db = reopen_db(context.with_label("reopened")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.get(&k).await.unwrap(), last_value);

        db.destroy().await.unwrap();
    }

    /// Test that historical_proof returns correct proofs for past database states.
    pub(crate) async fn test_any_db_historical_proof_basic<D, V: Clone>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>,
        <D as MerkleizedStore>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};
        use commonware_utils::NZU64;

        let mut db = db.into_mutable();

        // Add some operations
        const OPS: u64 = 20;
        for i in 0u64..OPS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();
        let root_hash = db.root();
        let original_op_count = db.size();

        // Historical proof should match "regular" proof when historical size == current database size
        let max_ops = NZU64!(10);
        let start_loc = Location::new_unchecked(5);
        let (historical_proof, historical_ops) = db
            .historical_proof(original_op_count, start_loc, max_ops)
            .await
            .unwrap();
        let (regular_proof, regular_ops) = db.proof(start_loc, max_ops).await.unwrap();

        assert_eq!(historical_proof.leaves, regular_proof.leaves);
        assert_eq!(historical_proof.digests, regular_proof.digests);
        assert_eq!(historical_ops, regular_ops);
        let mut hasher = StandardHasher::<Sha256>::new();
        assert!(verify_proof(
            &mut hasher,
            &historical_proof,
            start_loc,
            &historical_ops,
            &root_hash
        ));

        // Add more operations to the database
        let mut db = db.into_mutable();
        for i in OPS..(OPS + 5) {
            let k = Sha256::hash(&(i + 1000).to_be_bytes()); // different keys
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();

        // Historical proof should remain the same even though database has grown
        let (historical_proof2, historical_ops2) = db
            .historical_proof(original_op_count, start_loc, max_ops)
            .await
            .unwrap();
        assert_eq!(historical_proof2.leaves, original_op_count);
        assert_eq!(historical_proof2.digests, regular_proof.digests);
        assert_eq!(historical_ops2, regular_ops);
        assert!(verify_proof(
            &mut hasher,
            &historical_proof2,
            start_loc,
            &historical_ops2,
            &root_hash
        ));

        db.destroy().await.unwrap();
    }

    /// Test that tampering with historical proofs causes verification to fail.
    pub(crate) async fn test_any_db_historical_proof_invalid<D, V: Clone>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>,
        <D as MerkleizedStore>::Operation: Codec + PartialEq + std::fmt::Debug + Clone,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};
        use commonware_utils::NZU64;

        let mut db = db.into_mutable();

        // Add some operations
        for i in 0u64..10 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();

        let historical_op_count = Location::new_unchecked(5);
        let (proof, ops) = db
            .historical_proof(historical_op_count, Location::new_unchecked(1), NZU64!(10))
            .await
            .unwrap();
        assert_eq!(proof.leaves, historical_op_count);
        assert_eq!(ops.len(), 4);

        let mut hasher = StandardHasher::<Sha256>::new();

        // Changing the proof digests should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.digests[0] = Sha256::hash(b"invalid");
            let root_hash = db.root();
            assert!(!verify_proof(
                &mut hasher,
                &tampered_proof,
                Location::new_unchecked(1),
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
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(1),
                    &tampered_ops,
                    &root_hash
                ));
            }
        }

        db.destroy().await.unwrap();
    }

    /// Test historical_proof edge cases: singleton db, limited ops, min position.
    pub(crate) async fn test_any_db_historical_proof_edge_cases<D, V: Clone>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>,
        <D as MerkleizedStore>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use commonware_utils::NZU64;

        let mut db = db.into_mutable();

        // Add 50 operations
        for i in 0u64..50 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();

        // Test singleton database (historical size = 2 means 1 op after initial commit)
        let (single_proof, single_ops) = db
            .historical_proof(
                Location::new_unchecked(2),
                Location::new_unchecked(1),
                NZU64!(1),
            )
            .await
            .unwrap();
        assert_eq!(single_proof.leaves, Location::new_unchecked(2));
        assert_eq!(single_ops.len(), 1);

        // Test requesting more operations than available in historical position
        let (_limited_proof, limited_ops) = db
            .historical_proof(
                Location::new_unchecked(11),
                Location::new_unchecked(6),
                NZU64!(20),
            )
            .await
            .unwrap();
        assert_eq!(limited_ops.len(), 5); // Should be limited by historical position

        // Test proof at minimum historical position
        let (min_proof, min_ops) = db
            .historical_proof(
                Location::new_unchecked(4),
                Location::new_unchecked(1),
                NZU64!(3),
            )
            .await
            .unwrap();
        assert_eq!(min_proof.leaves, Location::new_unchecked(4));
        assert_eq!(min_ops.len(), 3);

        db.destroy().await.unwrap();
    }

    /// Test making multiple commits, one of which deletes a key from a previous commit.
    pub(crate) async fn test_any_db_multiple_commits_delete_replayed<D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>,
        D::Mutable: Updatable<Key = Digest, Value = V, Error = crate::qmdb::Error>
            + Deletable<Key = Digest, Error = crate::qmdb::Error>,
        V: Clone + Eq + std::fmt::Debug,
    {
        let mut map = HashMap::<Digest, V>::default();
        const ELEMENTS: u64 = 10;
        let metadata_value = make_value(42);
        let mut db = db.into_mutable();
        let key_at = |j: u64, i: u64| Sha256::hash(&(j * 1000 + i).to_be_bytes());
        for j in 0u64..ELEMENTS {
            for i in 0u64..ELEMENTS {
                let k = key_at(j, i);
                let v = make_value(i * 1000);
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }
            let (clean_db, _) = db.commit(Some(metadata_value.clone())).await.unwrap();
            db = clean_db.into_merkleized().await.unwrap().into_mutable();
        }
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_value));
        let k = key_at(ELEMENTS - 1, ELEMENTS - 1);

        db.delete(k).await.unwrap();
        let (db, _) = db.commit(None).await.unwrap();
        let db = db.into_merkleized().await.unwrap();
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
    use commonware_macros::test_traced;
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
    macro_rules! test_simple {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                $f(<$db>::init($ctx.with_label($l), $cfg::<OneCap>(p))
                    .await
                    .unwrap())
                .await;
            })
            .await
        }};
    }

    macro_rules! test_with_reopen {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                let ctx = $ctx.with_label($l);
                let db = <$db>::init(ctx.clone(), $cfg::<OneCap>(p)).await.unwrap();
                $f(
                    ctx,
                    db,
                    |ctx| {
                        Box::pin(async move { <$db>::init(ctx, $cfg::<OneCap>(p)).await.unwrap() })
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
                let db = <$db>::init(ctx.clone(), $cfg::<OneCap>(p)).await.unwrap();
                $f(ctx, db, to_digest).await;
            })
            .await
        }};
    }

    // Macro to run a test on all 12 DB variants.
    macro_rules! for_all_variants {
        ($ctx:expr, $sfx:expr, simple: $f:expr) => {{
            with_all_variants!(test_simple!($ctx, $sfx, $f));
        }};
        ($ctx:expr, $sfx:expr, with_reopen: $f:expr) => {{
            with_all_variants!(test_with_reopen!($ctx, $sfx, $f));
        }};
        ($ctx:expr, $sfx:expr, with_make_value: $f:expr) => {{
            with_all_variants!(test_with_make_value!($ctx, $sfx, $f));
        }};
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "snr", simple: test_any_db_steps_not_reset);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "lr", with_reopen: test_any_db_log_replay);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "hpb", with_make_value: test_any_db_historical_proof_basic);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "hpi", with_make_value: test_any_db_historical_proof_invalid);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "hpec", with_make_value: test_any_db_historical_proof_edge_cases);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_multiple_commits_delete_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "mcdr", with_reopen: test_any_db_multiple_commits_delete_replayed);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_non_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "ner", with_reopen: test_any_db_non_empty_recovery);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "er", with_reopen: test_any_db_empty_recovery);
        });
    }
}
