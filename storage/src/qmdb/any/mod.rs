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
//! // 1. Create a batch and apply it.
//! let batch = db.new_batch()
//!     .write(key, Some(value))    // upsert
//!     .write(other_key, None)     // delete
//!     .merkleize(&db, None).await?;
//! let root = batch.root();        // speculative root
//! db.apply_batch(batch).await?;
//! db.commit().await?;             // flush to disk
//! ```
//!
//! ```ignore
//! // 2. Fork two batches from the same parent. Apply one; the other is stale.
//! let parent = db.new_batch().write(k1, Some(v1)).merkleize(&db, None).await?;
//! let fork_a = parent.new_batch::<Sha256>().write(k2, Some(v2)).merkleize(&db, None).await?;
//! let fork_b = parent.new_batch::<Sha256>().write(k3, Some(v3)).merkleize(&db, None).await?;
//!
//! db.apply_batch(fork_a).await?;                 // OK -- includes parent
//! assert!(db.apply_batch(fork_b).await.is_err()); // StaleBatch
//! ```
//!
//! ```ignore
//! // 3. Chain two batches. Apply parent first, then child.
//! let parent = db.new_batch().write(k1, Some(v1)).merkleize(&db, None).await?;
//! let child = parent.new_batch::<Sha256>().write(k2, Some(v2)).merkleize(&db, None).await?;
//!
//! db.apply_batch(parent).await?;           // apply parent
//! db.apply_batch(child).await?;            // ancestors skipped automatically
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // 4. Chain two batches. Apply child directly (includes parent's changes).
//! let parent = db.new_batch().write(k1, Some(v1)).merkleize(&db, None).await?;
//! let child = parent.new_batch::<Sha256>().write(k2, Some(v2)).merkleize(&db, None).await?;
//!
//! db.apply_batch(child).await?;                  // OK -- includes parent
//! assert!(db.apply_batch(parent).await.is_err()); // StaleBatch
//! ```
//!
//! ```ignore
//! // 5. Two independent chains. Commit the tail of one; the other chain is stale.
//! let a1 = db.new_batch().write(k1, Some(v1)).merkleize(&db, None).await?;
//! let a2 = a1.new_batch::<Sha256>().write(k2, Some(v2)).merkleize(&db, None).await?;
//!
//! let b1 = db.new_batch().write(k3, Some(v3)).merkleize(&db, None).await?;
//! let b2 = b1.new_batch::<Sha256>().write(k4, Some(v4)).merkleize(&db, None).await?;
//!
//! db.apply_batch(a2).await?;                 // OK -- includes a1
//! assert!(db.apply_batch(b2).await.is_err()); // StaleBatch
//! ```

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated::Inner,
        contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    },
    merkle::{full::Config as MerkleConfig, Bagging, Family, Location},
    qmdb::{
        any::operation::{Operation, Update},
        bitmap::Shared,
        operation::Committable,
    },
    translator::Translator,
    Context,
};
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use std::sync::Arc;
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

const BITMAP_CHUNK_BYTES: usize = 64;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, J> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle_config: MerkleConfig,

    /// Configuration for the operations log journal.
    pub journal_config: J,

    /// The translator used by the compressed index.
    pub translator: T,

    /// Whether the operations root commits to the inactive-prefix split.
    pub split_root: bool,

    /// Bagging used by the operations root.
    pub root_bagging: Bagging,
}

/// Configuration for an `Any` authenticated db with fixed-size values.
pub type FixedConfig<T> = Config<T, FConfig>;

/// Configuration for an `Any` authenticated db with variable-sized values.
pub type VariableConfig<T, C> = Config<T, VConfig<C>>;

/// Initialize an `Any` authenticated db from the given config.
pub async fn init<F, E, U, H, T, I, J>(
    context: E,
    cfg: Config<T, J::Config>,
) -> Result<db::Db<F, E, J, I, H, U>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    U: Update + Send + Sync,
    H: Hasher,
    T: Translator,
    I: IndexFactory<T, Value = Location<F>>,
    J: Inner<E, Item = Operation<F, U>>,
    Operation<F, U>: Committable + CodecShared,
{
    init_with_bitmap::<F, E, U, H, T, I, J, BITMAP_CHUNK_BYTES>(context, cfg, None).await
}

/// Like [`init`] but accepts a pre-allocated bitmap (used by `current::Db`, which sizes pruned
/// chunks from grafted metadata). `bitmap = None` allocates internally.
pub(crate) async fn init_with_bitmap<F, E, U, H, T, I, J, const N: usize>(
    context: E,
    cfg: Config<T, J::Config>,
    bitmap: Option<Arc<Shared<N>>>,
) -> Result<db::Db<F, E, J, I, H, U, N>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    U: Update + Send + Sync,
    H: Hasher,
    T: Translator,
    I: IndexFactory<T, Value = Location<F>>,
    J: Inner<E, Item = Operation<F, U>>,
    Operation<F, U>: Committable + CodecShared,
{
    let split_root = cfg.split_root;
    let root_bagging = cfg.root_bagging;
    let mut log = J::init::<F, H>(
        context.with_label("log"),
        cfg.merkle_config,
        cfg.journal_config,
        Operation::is_commit,
        root_bagging,
    )
    .await?;

    if log.size().await == 0 {
        warn!("Authenticated log is empty, initializing new db");
        let commit_floor = Operation::CommitFloor(None, Location::new(0));
        log.append(&commit_floor).await?;
        log.sync().await?;
    }

    let index = I::new(context.with_label("index"), cfg.translator);
    db::Db::init_from_log(index, log, bitmap, split_root, root_bagging).await
}

#[cfg(test)]
// pub(crate) so qmdb/current can use the generic tests.
pub(crate) mod test {
    use super::*;
    use crate::{
        journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
        qmdb::{
            self,
            any::{FixedConfig, MerkleConfig, VariableConfig},
        },
        translator::OneCap,
    };
    use commonware_codec::{Codec, CodecShared};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic::Context, BufferPooler, Metrics,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use core::{future::Future, pin::Pin};
    use std::{
        collections::HashMap,
        num::{NonZeroU16, NonZeroUsize},
    };

    pub(crate) fn colliding_digest(prefix: u8, suffix: u64) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = prefix;
        bytes[24..].copy_from_slice(&suffix.to_be_bytes());
        Digest::from(bytes)
    }

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    pub(crate) fn fixed_db_config<F: qmdb::Bagging, T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> FixedConfig<T> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: FConfig {
                partition: format!("log-journal-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: T::default(),
            split_root: true,
            root_bagging: <F as qmdb::Bagging>::BAGGING,
        }
    }

    pub(crate) fn variable_db_config<F: qmdb::Bagging, T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> VariableConfig<T, ((), ())> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        VariableConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: VConfig {
                partition: format!("log-journal-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: T::default(),
            split_root: true,
            root_bagging: <F as qmdb::Bagging>::BAGGING,
        }
    }

    use crate::{
        index::Unordered as UnorderedIndex,
        journal::contiguous::Mutable,
        merkle::{mmb, mmr},
        qmdb::any::{
            db::Db as AnyDb,
            operation::{update::Update as UpdateTrait, Operation as AnyOperation},
            traits::{DbAny, Provable, UnmerkleizedBatch as _},
        },
    };

    type Error = crate::qmdb::Error<mmr::Family>;
    type Location = mmr::Location;

    pub(crate) trait RewindableDb {
        fn rewind_to_size(
            &mut self,
            size: Location,
        ) -> impl Future<Output = Result<(), Error>> + Send;
    }

    impl<E, U, C, I, H> RewindableDb for AnyDb<mmr::Family, E, C, I, H, U>
    where
        E: crate::Context,
        U: UpdateTrait,
        C: Mutable<Item = AnyOperation<mmr::Family, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        AnyOperation<mmr::Family, U>: Codec,
    {
        async fn rewind_to_size(&mut self, size: Location) -> Result<(), Error> {
            self.rewind(size).await?;
            Ok(())
        }
    }

    /// Test recovery on non-empty db.
    pub(crate) async fn test_any_db_non_empty_recovery<F: Family, D, V: Clone + CodecShared>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
    {
        const ELEMENTS: u64 = 1000;

        // Commit initial batch.
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        db.prune(db.sync_boundary().await).await.unwrap();
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
            let _merkleized = batch.merkleize(&db, None).await.unwrap();
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
            let _merkleized = batch.merkleize(&db, None).await.unwrap();
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
            let _merkleized = batch.merkleize(&db, None).await.unwrap();
        }
        let mut db = reopen_db(context.with_label("reopen4")).await;
        assert_eq!(db.size().await, op_count);
        assert_eq!(db.root(), root);

        // Now actually commit a batch.
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.size().await > op_count);
        assert_ne!(db.inactivity_floor_loc().await, inactivity_floor_loc);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test recovery on empty db.
    pub(crate) async fn test_any_db_empty_recovery<F: Family, D, V: Clone + CodecShared>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
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
            let _merkleized = batch.merkleize(&db, None).await.unwrap();
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
            let _merkleized = batch.merkleize(&db, None).await.unwrap();
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
            let _merkleized = batch.merkleize(&db, None).await.unwrap();
        }
        drop(db);
        let mut db = reopen_db(context.with_label("reopen4")).await;
        assert_eq!(db.size().await, 1);
        assert_eq!(db.root(), root);

        // Now actually commit a batch.
        {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.size().await > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test rewinding to a prior committed state and recovering that state after reopen.
    pub(crate) async fn test_any_db_rewind_recovery<D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + RewindableDb,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let key0 = Sha256::hash(&0u64.to_be_bytes());
        let key1 = Sha256::hash(&1u64.to_be_bytes());
        let key2 = Sha256::hash(&2u64.to_be_bytes());
        let initial_root = db.root();
        let initial_size = db.size().await;
        let initial_floor = db.inactivity_floor_loc().await;

        // Empty-batch rewind on an otherwise empty DB should apply no snapshot undos.
        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let empty_range = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(empty_range.start, initial_size);
        assert_eq!(db.size().await, empty_range.end);
        db.rewind_to_size(initial_size).await.unwrap();
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.size().await, initial_size);
        assert_eq!(db.inactivity_floor_loc().await, initial_floor);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        let value0_a = make_value(10);
        let value1_a = make_value(11);
        let metadata_a = make_value(12);

        let merkleized = db
            .new_batch()
            .write(key0, Some(value0_a.clone()))
            .write(key1, Some(value1_a.clone()))
            .merkleize(&db, Some(metadata_a.clone()))
            .await
            .unwrap();
        let range_a = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        let root_a = db.root();
        let size_a = db.size().await;
        let floor_a = db.inactivity_floor_loc().await;
        assert_eq!(size_a, range_a.end);

        let value0_b = make_value(20);
        let value2_b = make_value(21);
        let metadata_b = make_value(22);

        let merkleized = db
            .new_batch()
            .write(key0, Some(value0_b))
            .write(key1, None)
            .write(key2, Some(value2_b))
            .merkleize(&db, Some(metadata_b))
            .await
            .unwrap();
        let range_b = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(range_b.start, size_a);
        assert_ne!(db.root(), root_a);

        let value0_c = make_value(30);
        let value1_c = make_value(31);
        let metadata_c = make_value(32);
        let merkleized = db
            .new_batch()
            .write(key0, Some(value0_c))
            .write(key1, Some(value1_c))
            .write(key2, None)
            .merkleize(&db, Some(metadata_c))
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Rewind across a tail where:
        // - the same key (`key0`) was updated multiple times
        // - `key1` was deleted then recreated (exercises net-zero active_keys_delta path)
        db.rewind_to_size(size_a).await.unwrap();
        assert_eq!(db.root(), root_a);
        assert_eq!(db.size().await, size_a);
        assert_eq!(db.inactivity_floor_loc().await, floor_a);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a.clone()));
        assert_eq!(db.get(&key0).await.unwrap(), Some(value0_a));
        assert_eq!(db.get(&key1).await.unwrap(), Some(value1_a));
        assert_eq!(db.get(&key2).await.unwrap(), None);

        db.commit().await.unwrap();
        drop(db);
        let mut db = reopen_db(context.with_label("reopen_after_rewind")).await;
        assert_eq!(db.root(), root_a);
        assert_eq!(db.size().await, size_a);
        assert_eq!(db.inactivity_floor_loc().await, floor_a);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
        assert_eq!(db.get(&key0).await.unwrap(), Some(make_value(10)));
        assert_eq!(db.get(&key1).await.unwrap(), Some(make_value(11)));
        assert_eq!(db.get(&key2).await.unwrap(), None);

        // Fresh writes from the rewound tip should produce a correct new chain and persist
        // across reopen.
        let value2_d = make_value(40);
        let metadata_d = make_value(41);
        let merkleized = db
            .new_batch()
            .write(key2, Some(value2_d.clone()))
            .merkleize(&db, Some(metadata_d.clone()))
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_d.clone()));
        assert_eq!(db.get(&key0).await.unwrap(), Some(make_value(10)));
        assert_eq!(db.get(&key1).await.unwrap(), Some(make_value(11)));
        assert_eq!(db.get(&key2).await.unwrap(), Some(value2_d.clone()));

        drop(db);
        let mut db = reopen_db(context.with_label("reopen_after_rewind_new_writes")).await;
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_d));
        assert_eq!(db.get(&key0).await.unwrap(), Some(make_value(10)));
        assert_eq!(db.get(&key1).await.unwrap(), Some(make_value(11)));
        assert_eq!(db.get(&key2).await.unwrap(), Some(value2_d));

        // Rewind all the way to the initial commit boundary (`first_commit_loc + 1`).
        db.rewind_to_size(initial_size).await.unwrap();
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.size().await, initial_size);
        assert_eq!(db.inactivity_floor_loc().await, initial_floor);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(&key0).await.unwrap(), None);
        assert_eq!(db.get(&key1).await.unwrap(), None);
        assert_eq!(db.get(&key2).await.unwrap(), None);

        db.commit().await.unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopen_initial_boundary")).await;
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.size().await, initial_size);
        assert_eq!(db.inactivity_floor_loc().await, initial_floor);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(&key0).await.unwrap(), None);
        assert_eq!(db.get(&key1).await.unwrap(), None);
        assert_eq!(db.get(&key2).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// Test that a large mixed workload can be authenticated and replayed correctly.
    pub(crate) async fn test_any_db_build_and_authenticate<D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        V: CodecShared + Clone + Eq + std::hash::Hash + std::fmt::Debug,
        <D as Provable<mmr::Family>>::Operation: Codec,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};

        const ELEMENTS: u64 = 1000;

        let mut map = HashMap::<Digest, V>::default();
        {
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

            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
        // Commit + sync with pruning raises inactivity floor.
        db.sync().await.unwrap();
        db.prune(db.sync_boundary().await).await.unwrap();

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
            let spec = proof.inactive_peaks;
            assert!(verify_proof(&hasher, &proof, loc, &ops, &root, spec));
        }

        db.destroy().await.unwrap();
    }

    /// Test that replaying multiple updates of the same key on startup preserves correct state.
    pub(crate) async fn test_any_db_log_replay<
        F: Family,
        D,
        V: Clone + CodecShared + PartialEq + std::fmt::Debug,
    >(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
    {
        // Update the same key many times within a single batch.
        const UPDATES: u64 = 100;
        let k = Sha256::hash(&UPDATES.to_be_bytes());
        let mut last_value = None;
        {
            let mut batch = db.new_batch();
            for i in 0u64..UPDATES {
                let v = make_value(i * 1000);
                last_value = Some(v.clone());
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
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
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        <D as Provable<mmr::Family>>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};
        use commonware_utils::NZU64;

        // Add some operations
        const OPS: u64 = 20;
        {
            let mut batch = db.new_batch();
            for i in 0u64..OPS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
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
            &root_hash,
            historical_proof.inactive_peaks,
        ));

        // Add more operations to the database
        {
            let mut batch = db.new_batch();
            for i in OPS..(OPS + 5) {
                let k = Sha256::hash(&(i + 1000).to_be_bytes()); // different keys
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }

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
            &root_hash,
            historical_proof2.inactive_peaks,
        ));

        db.destroy().await.unwrap();
    }

    /// Test that tampering with historical proofs causes verification to fail.
    pub(crate) async fn test_any_db_historical_proof_invalid<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        <D as Provable<mmr::Family>>::Operation: Codec + PartialEq + std::fmt::Debug + Clone,
    {
        use crate::{mmr::StandardHasher, qmdb::verify_proof};
        use commonware_utils::NZU64;

        // Apply two single-write batches and capture the commit-boundary size after the
        // first batch. `historical_proof` requires the historical size to land on a commit
        // boundary when the db uses a split-root spec.
        let mut historical_op_count = Location::new(0);
        for i in 0u64..2 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            let merkleized = db
                .new_batch()
                .write(k, Some(v))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            if i == 0 {
                historical_op_count = db.bounds().await.end;
            }
        }

        let expected_ops_len = (*historical_op_count - 1) as usize;
        let (proof, ops) = db
            .historical_proof(historical_op_count, Location::new(1), NZU64!(10))
            .await
            .unwrap();
        assert_eq!(proof.leaves, historical_op_count);
        assert_eq!(ops.len(), expected_ops_len);

        let hasher = StandardHasher::<Sha256>::new();
        let inactive_peaks = proof.inactive_peaks;

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
                &root_hash,
                inactive_peaks,
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
                &root_hash,
                inactive_peaks,
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
                    &root_hash,
                    inactive_peaks,
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
                &root_hash,
                inactive_peaks,
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
                &root_hash,
                inactive_peaks,
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
                &invalid_root,
                inactive_peaks,
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
                &root_hash,
                inactive_peaks,
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
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        <D as Provable<mmr::Family>>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use commonware_utils::NZU64;

        // Apply a sequence of single-write batches and record the commit-boundary size
        // reached after each. `historical_proof` requires the historical size to be a
        // commit boundary when the db uses a split-root spec, so we anchor each test on
        // one of the boundaries we recorded here rather than hardcoding sizes that depend
        // on internal floor-raising behavior.
        let initial_size = db.bounds().await.end;
        let mut boundaries = vec![initial_size];
        for i in 0u64..5 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            let merkleized = db
                .new_batch()
                .write(k, Some(v))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            boundaries.push(db.bounds().await.end);
        }

        // Singleton historical state: only the initial CommitFloor is visible.
        let singleton_size = boundaries[0];
        let (single_proof, single_ops) = db
            .historical_proof(singleton_size, Location::new(0), NZU64!(1))
            .await
            .unwrap();
        assert_eq!(single_proof.leaves, singleton_size);
        assert_eq!(single_ops.len(), 1);

        // max_ops exceeds the ops remaining at this historical size, so the returned count
        // is capped at `historical_size - start_loc`. Anchor at the earliest post-batch
        // boundary that has at least 3 ops past `boundaries[1]`.
        let limited_size = boundaries[2];
        let limited_start = boundaries[1];
        let expected_limited = (*limited_size - *limited_start) as usize;
        assert!(expected_limited > 0);
        let (_limited_proof, limited_ops) = db
            .historical_proof(limited_size, limited_start, NZU64!(20))
            .await
            .unwrap();
        assert_eq!(limited_ops.len(), expected_limited);

        // Standard historical proof anchored at an early commit boundary, requesting a
        // bounded number of ops within the historical range.
        let min_size = boundaries[2];
        let max_ops = NZU64!(3);
        let expected_min = core::cmp::min(max_ops.get(), *min_size - 1) as usize;
        let (min_proof, min_ops) = db
            .historical_proof(min_size, Location::new(1), max_ops)
            .await
            .unwrap();
        assert_eq!(min_proof.leaves, min_size);
        assert_eq!(min_ops.len(), expected_min);

        db.destroy().await.unwrap();
    }

    /// Test making multiple commits, one of which deletes a key from a previous commit.
    pub(crate) async fn test_any_db_multiple_commits_delete_replayed<F: Family, D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let mut map = HashMap::<Digest, V>::default();
        const ELEMENTS: u64 = 10;
        let metadata_value = make_value(42);
        let key_at = |j: u64, i: u64| Sha256::hash(&(j * 1000 + i).to_be_bytes());
        for j in 0u64..ELEMENTS {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = key_at(j, i);
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }
            let merkleized = batch
                .merkleize(&db, Some(metadata_value.clone()))
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();
        }
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_value));
        let k = key_at(ELEMENTS - 1, ELEMENTS - 1);

        let merkleized = db
            .new_batch()
            .write(k, None)
            .merkleize(&db, None)
            .await
            .unwrap();
        db.apply_batch(merkleized).await.unwrap();
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

    // Type aliases for all 12 MMR variants (all use OneCap for collision coverage).
    type UnorderedFixed = UnorderedFixedDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap>;
    type UnorderedVariable =
        UnorderedVariableDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap>;
    type OrderedFixed = OrderedFixedDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap>;
    type OrderedVariable = OrderedVariableDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap>;
    type UnorderedFixedP1 =
        unordered::fixed::partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 1>;
    type UnorderedVariableP1 = unordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
    >;
    type OrderedFixedP1 =
        ordered::fixed::partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 1>;
    type OrderedVariableP1 =
        ordered::variable::partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 1>;
    type UnorderedFixedP2 =
        unordered::fixed::partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 2>;
    type UnorderedVariableP2 = unordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
    >;
    type OrderedFixedP2 =
        ordered::fixed::partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 2>;
    type OrderedVariableP2 =
        ordered::variable::partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 2>;

    // MMB type aliases for with_all_variants.
    mod mmb_types {
        use super::*;
        use crate::{
            index::{ordered::Index as OrderedIndex, unordered::Index as UnorderedIndex},
            journal::contiguous::{fixed::Journal as FJournal, variable::Journal as VJournal},
            merkle::{mmb, Location},
            qmdb::any::{
                operation::{update, Operation},
                value::{FixedEncoding, VariableEncoding},
            },
        };

        type MmbLocation = Location<mmb::Family>;

        pub type MmbUnorderedFixed = super::super::db::Db<
            mmb::Family,
            Context,
            FJournal<
                Context,
                Operation<mmb::Family, update::Unordered<Digest, FixedEncoding<Digest>>>,
            >,
            UnorderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Unordered<Digest, FixedEncoding<Digest>>,
        >;

        pub type MmbUnorderedVariable = super::super::db::Db<
            mmb::Family,
            Context,
            VJournal<
                Context,
                Operation<mmb::Family, update::Unordered<Digest, VariableEncoding<Digest>>>,
            >,
            UnorderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Unordered<Digest, VariableEncoding<Digest>>,
        >;

        pub type MmbOrderedFixed = super::super::db::Db<
            mmb::Family,
            Context,
            FJournal<
                Context,
                Operation<mmb::Family, update::Ordered<Digest, FixedEncoding<Digest>>>,
            >,
            OrderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Ordered<Digest, FixedEncoding<Digest>>,
        >;

        pub type MmbOrderedVariable = super::super::db::Db<
            mmb::Family,
            Context,
            VJournal<
                Context,
                Operation<mmb::Family, update::Ordered<Digest, VariableEncoding<Digest>>>,
            >,
            OrderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Ordered<Digest, VariableEncoding<Digest>>,
        >;
    }
    use mmb_types::*;

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    // Defines MMR-only variants (for tests that require mmr::Family, e.g. proof verification).
    macro_rules! with_mmr_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "uf", UnorderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, "uv", UnorderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, "of", OrderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, "ov", OrderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1, mmr::Family, fixed_db_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1, mmr::Family, variable_db_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1, mmr::Family, fixed_db_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1, mmr::Family, variable_db_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2, mmr::Family, fixed_db_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2, mmr::Family, variable_db_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2, mmr::Family, fixed_db_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2, mmr::Family, variable_db_config);
        };
    }

    // Defines all variants (MMR + MMB). Calls $cb!($($args)*, $label, $type, $family, $config) for each.
    macro_rules! with_all_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "uf", UnorderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, "uv", UnorderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, "of", OrderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, "ov", OrderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1, mmr::Family, fixed_db_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1, mmr::Family, variable_db_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1, mmr::Family, fixed_db_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1, mmr::Family, variable_db_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2, mmr::Family, fixed_db_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2, mmr::Family, variable_db_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2, mmr::Family, fixed_db_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2, mmr::Family, variable_db_config);
            $cb!($($args)*, "uf_mmb", MmbUnorderedFixed, mmb::Family, fixed_db_config);
            $cb!($($args)*, "uv_mmb", MmbUnorderedVariable, mmb::Family, variable_db_config);
            $cb!($($args)*, "of_mmb", MmbOrderedFixed, mmb::Family, fixed_db_config);
            $cb!($($args)*, "ov_mmb", MmbOrderedVariable, mmb::Family, variable_db_config);
        };
    }

    // Runner macros - each receives common args followed by (label, type, family, config) from with_all_variants.
    // Uses Box::pin to move futures to the heap and avoid stack overflow.
    macro_rules! test_with_reopen {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $family:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                let ctx = $ctx.with_label($l);
                let db = <$db>::init(ctx.clone(), $cfg::<$family, OneCap>(p, &ctx))
                    .await
                    .unwrap();
                $f(
                    ctx,
                    db,
                    |ctx| {
                        Box::pin(async move {
                            <$db>::init(ctx.clone(), $cfg::<$family, OneCap>(p, &ctx))
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
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $family:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                let ctx = $ctx.with_label($l);
                let db = <$db>::init(ctx.clone(), $cfg::<$family, OneCap>(p, &ctx))
                    .await
                    .unwrap();
                $f(ctx, db, to_digest).await;
            })
            .await
        }};
    }

    // Macro to run a test on all DB variants (MMR + MMB).
    macro_rules! for_all_variants {
        ($ctx:expr, $sfx:expr, with_reopen: $f:expr) => {{
            with_all_variants!(test_with_reopen!($ctx, $sfx, $f));
        }};
        ($ctx:expr, $sfx:expr, with_make_value: $f:expr) => {{
            with_all_variants!(test_with_make_value!($ctx, $sfx, $f));
        }};
    }

    // Macro to run a test on MMR-only DB variants (for tests that use mmr::Family-specific
    // features like Location::new or verify_proof).
    macro_rules! for_mmr_variants {
        ($ctx:expr, $sfx:expr, with_reopen: $f:expr) => {{
            with_mmr_variants!(test_with_reopen!($ctx, $sfx, $f));
        }};
        ($ctx:expr, $sfx:expr, with_make_value: $f:expr) => {{
            with_mmr_variants!(test_with_make_value!($ctx, $sfx, $f));
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
            for_mmr_variants!(context, "baa", with_reopen: test_any_db_build_and_authenticate);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_mmr_variants!(context, "hpb", with_make_value: test_any_db_historical_proof_basic);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_mmr_variants!(context, "hpi", with_make_value: test_any_db_historical_proof_invalid);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_mmr_variants!(context, "hpec", with_make_value: test_any_db_historical_proof_edge_cases);
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

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_rewind_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_mmr_variants!(context, "rr", with_reopen: test_any_db_rewind_recovery);
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
    ) -> std::ops::Range<crate::mmr::Location> {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(&*db, metadata).await.unwrap();
        let range = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        range
    }

    /// An empty batch (no mutations) still produces a valid commit.
    #[test_traced("INFO")]
    fn test_any_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("e", &ctx),
            )
            .await
            .unwrap();

            let root_before = db.root();
            let batch = db.new_batch();
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();

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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("m", &ctx),
            )
            .await
            .unwrap();

            let metadata = val(42);

            // Batch with metadata.
            commit_writes(&mut db, [(key(0), Some(val(0)))], Some(metadata)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Batch without metadata clears it.
            let batch = db.new_batch();
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("g", &ctx),
            )
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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("mg", &ctx),
            )
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
            let merkleized = batch.merkleize(&db, None).await.unwrap();

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
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("sg", &ctx),
            )
            .await
            .unwrap();

            let ka = key(0);
            let kb = key(1);

            // Parent batch writes A.
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(val(0)));
            let merkleized = batch.merkleize(&db, None).await.unwrap();

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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("dr", &ctx),
            )
            .await
            .unwrap();

            let ka = key(0);

            // Pre-populate with key A.
            commit_writes(&mut db, [(ka, Some(val(0)))], None).await;

            // Parent batch deletes A.
            let mut parent = db.new_batch();
            parent = parent.write(ka, None);
            let parent_m = parent.merkleize(&db, None).await.unwrap();
            assert_eq!(parent_m.get(&ka, &db).await.unwrap(), None);

            // Child re-creates A with a new value.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.write(ka, Some(val(200)));
            let child_m = child.merkleize(&db, None).await.unwrap();
            assert_eq!(child_m.get(&ka, &db).await.unwrap(), Some(val(200)));

            // Apply and verify DB state.
            db.apply_batch(child_m).await.unwrap();
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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("fr", &ctx),
            )
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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("ar", &ctx),
            )
            .await
            .unwrap();

            // First batch: 5 keys.
            let writes: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            let range1 = commit_writes(&mut db, writes, None).await;

            // Range should start after the initial CommitFloor (location 0).
            assert_eq!(range1.start, crate::mmr::Location::new(1));
            // Range length >= 6 (5 writes + 1 CommitFloor + possible floor raise ops).
            assert!(range1.end.saturating_sub(*range1.start) >= 6);

            // Second batch: ranges must be contiguous.
            let writes: Vec<_> = (5..10).map(|i| (key(i), Some(val(i)))).collect();
            let range2 = commit_writes(&mut db, writes, None).await;
            assert_eq!(range2.start, range1.end);

            db.destroy().await.unwrap();
        });
    }

    /// 3-level chain: parent -> child -> grandchild, merkleize grandchild and apply.
    #[test_traced("INFO")]
    fn test_any_batch_deep_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("dc", &ctx),
            )
            .await
            .unwrap();

            // Pre-populate with keys 0..5.
            let init: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            commit_writes(&mut db, init, None).await;

            // Parent: overwrite key 0, add key 5.
            let mut parent = db.new_batch();
            parent = parent.write(key(0), Some(val(100)));
            parent = parent.write(key(5), Some(val(5)));
            let parent_m = parent.merkleize(&db, None).await.unwrap();

            // Child: overwrite key 1, add key 6.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.write(key(1), Some(val(101)));
            child = child.write(key(6), Some(val(6)));
            let child_m = child.merkleize(&db, None).await.unwrap();

            // Grandchild: delete key 2, add key 7.
            let mut grandchild = child_m.new_batch::<Sha256>();
            grandchild = grandchild.write(key(2), None);
            grandchild = grandchild.write(key(7), Some(val(7)));
            let grandchild_m = grandchild.merkleize(&db, None).await.unwrap();

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

            // Apply.
            db.apply_batch(grandchild_m).await.unwrap();

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
                variable_db_config::<mmr::Family, OneCap>("cms-a", &ctx_a),
            )
            .await
            .unwrap();

            // DB B: chained batch.
            let ctx_b = ctx.with_label("b");
            let mut db_b: UnorderedVariable = UnorderedVariableDb::init(
                ctx_b.clone(),
                variable_db_config::<mmr::Family, OneCap>("cms-b", &ctx_b),
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
            let parent_m = parent.merkleize(&db_b, None).await.unwrap();

            let mut child = parent_m.new_batch::<Sha256>();
            for (k, v) in &writes2 {
                child = child.write(*k, *v);
            }
            let child_m = child.merkleize(&db_b, None).await.unwrap();
            db_b.apply_batch(child_m).await.unwrap();

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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("cd", &ctx),
            )
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
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();

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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("da", &ctx),
            )
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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("pf", &ctx),
            )
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
                .merkleize(&db, None)
                .await
                .unwrap();

            // Fork B: delete key 0 and create key 2.
            let fork_b_m = db
                .new_batch()
                .write(key(0), None)
                .write(key(2), Some(val(2)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Different mutations must produce different roots.
            assert_ne!(fork_a_m.root(), fork_b_m.root());

            // DB is unchanged (neither batch applied).
            assert_eq!(db.root(), root_before);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), None);

            // Apply fork A only.
            db.apply_batch(fork_a_m).await.unwrap();
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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("frc", &ctx),
            )
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
            let parent_m = parent.merkleize(&db, None).await.unwrap();

            // Child: update keys 20..30.
            let mut child = parent_m.new_batch::<Sha256>();
            for i in 20..30 {
                child = child.write(key(i), Some(val(i + 500)));
            }
            let child_m = child.merkleize(&db, None).await.unwrap();
            db.apply_batch(child_m).await.unwrap();

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
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("ab", &ctx),
            )
            .await
            .unwrap();

            commit_writes(&mut db, [(key(0), Some(val(0)))], None).await;
            let root_before = db.root();

            // Create, populate, merkleize, then drop without apply.
            {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(999)));
                batch = batch.write(key(1), Some(val(1)));
                let _merkleized = batch.merkleize(&db, None).await.unwrap();
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
                variable_db_config::<mmr::Family, OneCap>(partition, &ctx),
            )
            .await
            .unwrap();

            let committed_root = db.root();

            let merkleized = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            drop(db);

            let reopened: UnorderedVariable = UnorderedVariableDb::init(
                context.with_label("reopen"),
                variable_db_config::<mmr::Family, OneCap>(partition, &context),
            )
            .await
            .unwrap();
            assert_eq!(reopened.root(), committed_root);
            assert_eq!(reopened.get(&key(0)).await.unwrap(), None);

            reopened.destroy().await.unwrap();
        });
    }

    /// Rewinding to a pruned target returns an error.
    #[test_traced("INFO")]
    fn test_any_rewind_pruned_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const KEYS: u64 = 64;

            let ctx = context.with_label("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("rp", &ctx),
            )
            .await
            .unwrap();

            let initial: Vec<_> = (0..KEYS).map(|i| (key(i), Some(val(i)))).collect();
            let first_range = commit_writes(&mut db, initial, None).await;

            let mut round = 0u64;
            loop {
                round += 1;
                assert!(
                    round <= 64,
                    "failed to prune enough history for rewind test"
                );

                let updates: Vec<_> = (0..KEYS)
                    .map(|i| (key(i), Some(val(1000 + round * KEYS + i))))
                    .collect();
                commit_writes(&mut db, updates, None).await;

                db.prune(db.sync_boundary()).await.unwrap();
                let bounds = db.bounds().await;
                if bounds.start > first_range.start {
                    break;
                }
            }

            let oldest_retained = db.bounds().await.start;
            let boundary_err = db.rewind(oldest_retained).await.unwrap_err();
            assert!(
                matches!(
                    boundary_err,
                    crate::qmdb::Error::Journal(crate::journal::Error::ItemPruned(_))
                ),
                "unexpected rewind error at retained boundary: {boundary_err:?}"
            );

            let err = db.rewind(first_range.start).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::qmdb::Error::Journal(crate::journal::Error::ItemPruned(_))
                ),
                "unexpected rewind error: {err:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Rewinding rejects out-of-range targets and keeps state unchanged.
    #[test_traced("INFO")]
    fn test_any_rewind_invalid_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("ri", &ctx),
            )
            .await
            .unwrap();

            let root_before = db.root();
            let size_before = db.size().await;
            db.rewind(size_before).await.unwrap();
            assert_eq!(db.root(), root_before);
            assert_eq!(db.size().await, size_before);

            let zero_err = db.rewind(Location::new(0)).await.unwrap_err();
            assert!(
                matches!(
                    zero_err,
                    crate::qmdb::Error::Journal(crate::journal::Error::InvalidRewind(0))
                ),
                "unexpected rewind error: {zero_err:?}"
            );
            assert_eq!(db.root(), root_before);
            assert_eq!(db.size().await, size_before);

            let too_large_target = Location::new(*size_before + 1);
            let too_large_err = db.rewind(too_large_target).await.unwrap_err();
            assert!(
                matches!(
                    too_large_err,
                    crate::qmdb::Error::Journal(crate::journal::Error::InvalidRewind(size))
                    if size == *too_large_target
                ),
                "unexpected rewind error: {too_large_err:?}"
            );
            assert_eq!(db.root(), root_before);
            assert_eq!(db.size().await, size_before);

            db.destroy().await.unwrap();
        });
    }

    /// Rewinding fails when the target commit's inactivity floor has been pruned, even if the
    /// target commit location is still retained.
    #[test_traced("INFO")]
    fn test_any_rewind_rejects_target_with_pruned_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const KEYS: u64 = 64;

            let ctx = context.with_label("db");
            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), variable_db_config::<mmr::Family, OneCap>("rf", &ctx))
                    .await
                    .unwrap();

            commit_writes(&mut db, (0..KEYS).map(|i| (key(i), Some(val(i)))), None).await;
            commit_writes(
                &mut db,
                (0..KEYS).map(|i| (key(i), Some(val(1_000 + i)))),
                None,
            )
            .await;

            let rewind_target = db.size().await;
            let target_floor = db.inactivity_floor_loc();
            let prune_loc = Location::new(*target_floor + (KEYS / 2));
            assert!(
                rewind_target > *prune_loc,
                "test setup expected target size > prune_loc; target={rewind_target:?}, floor={target_floor:?}"
            );

            let mut round = 0u64;
            while db.inactivity_floor_loc() < prune_loc {
                round += 1;
                assert!(
                    round <= 8,
                    "failed to advance inactivity floor enough for floor-pruned rewind test"
                );
                commit_writes(
                    &mut db,
                    (0..KEYS).map(|i| (key(i), Some(val(10_000 + round * KEYS + i)))),
                    None,
                )
                .await;
            }

            db.prune(prune_loc).await.unwrap();
            let bounds = db.bounds().await;
            assert!(
                bounds.start > *target_floor,
                "test setup expected pruned start beyond target floor; bounds={bounds:?}, target_floor={target_floor:?}"
            );
            assert!(
                rewind_target > bounds.start,
                "test setup expected target commit retained; target={rewind_target:?}, bounds={bounds:?}"
            );

            let err = db.rewind(rewind_target).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::qmdb::Error::Journal(crate::journal::Error::ItemPruned(_))
                ),
                "unexpected rewind error: {err:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// `prune()` must advance the bitmap only as far as the authenticated journal actually
    /// pruned. Journal pruning is section-granular while bitmap pruning rounds to chunk
    /// boundaries, so a coarse `items_per_section` can leave the journal retaining from the
    /// start while the bitmap has already crossed the next chunk boundary. A subsequent
    /// `rewind()` to a still-retained early commit must still succeed.
    #[test_traced("INFO")]
    fn test_any_prune_keeps_bitmap_aligned_with_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Bitmap chunk size in bits. The bug requires the bitmap to round across at least
            // one chunk boundary while the journal cannot prune any section.
            const BITMAP_CHUNK_BITS: u64 =
                commonware_utils::bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;
            // Items-per-section is chosen so that no full section fits in the test's op count,
            // forcing the journal to retain from 0 even when prune is requested past the first
            // bitmap chunk boundary.
            const ITEMS_PER_SECTION: u64 = 2048;
            const { assert!(ITEMS_PER_SECTION > BITMAP_CHUNK_BITS) };

            let ctx = context.with_label("db");
            let mut cfg = variable_db_config::<mmr::Family, OneCap>("rg", &ctx);
            cfg.journal_config.items_per_section = NZU64!(ITEMS_PER_SECTION);

            let mut db: UnorderedVariable =
                UnorderedVariableDb::init(ctx.clone(), cfg).await.unwrap();

            commit_writes(&mut db, (0..100).map(|i| (key(i), Some(val(i)))), None).await;
            let rewind_target = db.size().await;
            // Rewind target must lie below the chunk boundary the buggy prune would advance
            // to; otherwise the unfixed code would not panic on truncate.
            assert!(
                *rewind_target < BITMAP_CHUNK_BITS,
                "rewind_target {rewind_target:?} must be < {BITMAP_CHUNK_BITS} for the bug to manifest"
            );
            let root_at_target = db.root();

            commit_writes(
                &mut db,
                (0..700).map(|i| (key(i), Some(val(1_000 + i)))),
                None,
            )
            .await;
            commit_writes(
                &mut db,
                (0..700).map(|i| (key(i), Some(val(10_000 + i)))),
                None,
            )
            .await;

            // Pre-rewind size must actually exceed the rewind target so the rewind is not a
            // no-op.
            let pre_prune_size = db.size().await;
            assert!(pre_prune_size > rewind_target);

            let prune_loc = Location::new(600);
            // prune_loc must cross at least one bitmap chunk boundary; otherwise the buggy
            // bitmap prune would correctly stay at 0 and the test would pass even unfixed.
            assert!(
                *prune_loc > BITMAP_CHUNK_BITS,
                "prune_loc {prune_loc:?} must exceed one bitmap chunk ({BITMAP_CHUNK_BITS} bits)"
            );
            // prune_loc must lie within the first journal section so the journal cannot
            // prune any section, leaving bounds.start at 0 to expose the bitmap drift.
            assert!(
                *prune_loc < ITEMS_PER_SECTION,
                "prune_loc {prune_loc:?} must be < {ITEMS_PER_SECTION} so the journal retains section 0"
            );
            assert!(db.inactivity_floor_loc() >= prune_loc);

            db.prune(prune_loc).await.unwrap();

            // Journal could not prune any section, so it still retains from 0. The bitmap
            // must therefore also remain at 0.
            let bounds = db.bounds().await;
            assert_eq!(bounds.start, Location::new(0));
            assert_eq!(
                db.bitmap.pruned_bits(),
                0,
                "bitmap pruned past journal retained start"
            );

            // Rewind to the still-retained early commit must succeed and restore visible
            // state (root match implies the snapshot was rebuilt correctly).
            db.rewind(rewind_target).await.unwrap();
            assert_eq!(db.size().await, rewind_target);
            assert_eq!(db.root(), root_at_target);

            db.destroy().await.unwrap();
        });
    }

    // --- MMB family tests ---
    //
    // The tests above use MMR-backed databases (via the concrete Db type aliases). The tests
    // below verify the same core operations work with the MMB family, exercising the generic
    // `init_fixed`/`init_variable` path with `mmb::Family`.

    type MmbVariable = super::db::Db<
        crate::merkle::mmb::Family,
        Context,
        crate::journal::contiguous::variable::Journal<
            Context,
            super::operation::Operation<
                crate::merkle::mmb::Family,
                super::operation::update::Unordered<Digest, super::value::VariableEncoding<Digest>>,
            >,
        >,
        crate::index::unordered::Index<OneCap, crate::merkle::Location<crate::merkle::mmb::Family>>,
        Sha256,
        super::operation::update::Unordered<Digest, super::value::VariableEncoding<Digest>>,
    >;

    async fn open_mmb_db(context: Context, suffix: &str) -> MmbVariable {
        let cfg = variable_db_config::<mmr::Family, OneCap>(suffix, &context);
        super::init(context, cfg).await.unwrap()
    }

    async fn commit_writes_mmb(
        db: &mut MmbVariable,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(db, metadata).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_mmb_batch_crud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_mmb_db(context.with_label("db"), "crud").await;

            // Insert and read back.
            commit_writes_mmb(&mut db, [(key(0), Some(val(0)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            // Update existing key.
            commit_writes_mmb(&mut db, [(key(0), Some(val(1)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(1)));

            // Delete key.
            commit_writes_mmb(&mut db, [(key(0), None)], None).await;
            assert!(db.get(&key(0)).await.unwrap().is_none());

            // Multiple keys.
            commit_writes_mmb(
                &mut db,
                [(key(1), Some(val(1))), (key(2), Some(val(2)))],
                None,
            )
            .await;
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_mmb_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_mmb_db(context.with_label("db"), "empty").await;
            let root_before = db.root();

            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            assert_ne!(db.root(), root_before);

            commit_writes_mmb(&mut db, [(key(0), Some(val(0)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_mmb_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_mmb_db(context.with_label("db"), "meta").await;

            let metadata = val(42);
            commit_writes_mmb(&mut db, [(key(0), Some(val(0)))], Some(metadata)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_mmb_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_mmb_db(context.with_label("db0"), "recovery").await;

            commit_writes_mmb(&mut db, [(key(0), Some(val(0)))], Some(val(99))).await;
            commit_writes_mmb(&mut db, [(key(1), Some(val(1)))], None).await;

            let root = db.root();
            let bounds = db.bounds().await;
            db.sync().await.unwrap();
            drop(db);

            // Reopen and verify state.
            let db = open_mmb_db(context.with_label("db1"), "recovery").await;
            assert_eq!(db.root(), root);
            assert_eq!(db.bounds().await, bounds);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_mmb_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_mmb_db(context.with_label("db"), "prune").await;

            for i in 0u64..20 {
                commit_writes_mmb(&mut db, [(key(i), Some(val(i)))], None).await;
            }

            let floor = db.inactivity_floor_loc();
            db.prune(floor).await.unwrap();

            // All keys still accessible.
            for i in 0u64..20 {
                assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i)));
            }

            db.destroy().await.unwrap();
        });
    }

    /// One-stage pipelining lets the next batch be built while the prior batch commits.
    #[test_traced("INFO")]
    fn test_any_batch_single_stage_pipeline() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.clone(),
                variable_db_config::<mmr::Family, OneCap>("pipe", &ctx),
            )
            .await
            .unwrap();

            {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(0)));
                let merkleized = batch.merkleize(&db, None).await.unwrap();
                db.apply_batch(merkleized).await.unwrap();
            }

            let (child_merkleized, commit_result) = futures::join!(
                async {
                    assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
                    let mut child = db.new_batch();
                    child = child.write(key(1), Some(val(1)));
                    child.merkleize(&db, None).await.unwrap()
                },
                db.commit(),
            );
            commit_result.unwrap();

            db.apply_batch(child_merkleized).await.unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }
}

#[cfg(test)]
mod bitmap_tests {
    //! Regression tests for activity-bitmap maintenance in `any::Db`. The mutation code in
    //! `apply_batch`, `prune_bitmap`, and `rewind` is independent of the snapshot index variant,
    //! so one variant (`unordered::variable`) suffices as the test bed.
    use crate::{
        merkle::Location,
        qmdb::any::unordered::variable::test::{create_test_config, AnyTest},
    };
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Metrics, Runner as _,
    };
    use commonware_utils::bitmap::Readable as _;

    /// Open a fresh test DB.
    async fn open_db(context: Context) -> AnyTest {
        let cfg = create_test_config(0, &context);
        AnyTest::init(context, cfg).await.unwrap()
    }

    /// Active locations (bit=1) in `[pruned_bits, len)` of `db.bitmap`.
    fn bitmap_active_locs(db: &AnyTest) -> Vec<u64> {
        let b = &db.bitmap;
        (b.pruned_bits()..b.len())
            .filter(|loc| b.get_bit(*loc))
            .collect()
    }

    /// Commit, drop, reopen, and assert the rebuilt bitmap matches the in-memory bitmap.
    async fn assert_oracle_round_trip(db: AnyTest, context: Context, label: &str) -> AnyTest {
        let pre_active = bitmap_active_locs(&db);
        let pre_len = db.bitmap.len();
        let pre_pruned = db.bitmap.pruned_bits();

        db.commit().await.unwrap();
        drop(db);

        let db = open_db(context.with_label(label)).await;

        assert_eq!(
            db.bitmap.pruned_bits(),
            pre_pruned,
            "pruned_bits diverged on reopen",
        );
        assert_eq!(db.bitmap.len(), pre_len, "bitmap len diverged on reopen");
        assert_eq!(
            bitmap_active_locs(&db),
            pre_active,
            "active locations diverged on reopen",
        );
        db
    }

    /// CommitFloor convention: only the *current* `last_commit_loc` carries bit=1; every earlier
    /// (now intermediate) commit boundary carries bit=0.
    ///
    /// Maintained by `apply_batch`'s explicit demote-then-promote pair on CommitFloor bits. If
    /// the demote step were missed, intermediate commits would persist at bit=1.
    #[test_traced]
    fn current_commit_floor_bit_is_one_others_zero() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Apply three single-write batches; each produces one CommitFloor op.
            let mut commit_locs = Vec::new();
            for i in 0..3u64 {
                let key = Sha256::hash(&i.to_be_bytes());
                let batch = db
                    .new_batch()
                    .write(key, Some(vec![i as u8]))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                commit_locs.push(batch.new_last_commit_loc);
                db.apply_batch(batch).await.unwrap();
            }
            db.commit().await.unwrap();

            // Setup sanity: three strictly-increasing commit locations, all within the bitmap.
            assert_eq!(commit_locs.len(), 3);
            assert!(*commit_locs[0] < *commit_locs[1]);
            assert!(*commit_locs[1] < *commit_locs[2]);
            assert!(*commit_locs[2] < db.bitmap.len());

            // Earlier two commits are intermediate -> bit=0.
            assert!(!db.bitmap.get_bit(*commit_locs[0]));
            assert!(!db.bitmap.get_bit(*commit_locs[1]));
            // Most recent commit is current -> bit=1.
            assert!(db.bitmap.get_bit(*commit_locs[2]));

            let db = assert_oracle_round_trip(db, context, "commit_floor").await;
            db.destroy().await.unwrap();
        });
    }

    /// `any::Db::rewind` restores bitmap state correctly.
    ///
    /// `any::rewind` is the sole writer of the bitmap during rewind; it must:
    ///   1. truncate the bitmap to the rewind size,
    ///   2. flip restored locs (committed snapshot entries the rewound tail had superseded) back
    ///      to active,
    ///   3. set the rewound tail's CommitFloor bit to 1 (the new current commit).
    ///
    /// The oracle round-trip catches all three: any divergence from `init_from_log`'s rebuild
    /// fails the comparison.
    #[test_traced]
    fn rewind_restores_bitmap_to_target_commit() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let k1 = Sha256::hash(&[1]);
            let k2 = Sha256::hash(&[2]);

            // Two committed batches; remember the size after the first.
            let b1 = db
                .new_batch()
                .write(k1, Some(vec![10]))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(b1).await.unwrap();
            db.commit().await.unwrap();
            let size_after_first = Location::new(*db.last_commit_loc + 1);

            let b2 = db
                .new_batch()
                .write(k2, Some(vec![20]))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(b2).await.unwrap();

            // Setup sanity: both keys present, db has advanced past size_after_first.
            assert_eq!(db.get(&k1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&k2).await.unwrap(), Some(vec![20]));
            assert!(*db.last_commit_loc + 1 > *size_after_first);

            // Rewind to the state after the first commit.
            db.rewind(size_after_first).await.unwrap();

            // Post-rewind: k2 gone, k1 remains.
            assert_eq!(db.get(&k1).await.unwrap(), Some(vec![10]));
            assert!(db.get(&k2).await.unwrap().is_none());

            let db = assert_oracle_round_trip(db, context, "rewind").await;
            db.destroy().await.unwrap();
        });
    }

    /// Floor-scan falls through to the uncommitted tail when the committed bitmap region runs
    /// out of active bits.
    ///
    /// `next_candidate` returns set-bit locations within `[floor, bitmap.len)` (skipping inactive
    /// ones), then sequential candidates beyond `bitmap.len` (uncommitted ancestor ops not
    /// tracked in the bitmap). `is_active_at` revalidation in the floor-raise loop is the only
    /// thing that prevents stale ancestor locations from being moved when a child batch
    /// supersedes the same key.
    ///
    /// Setup: 1 committed key + uncommitted parent re-touching that key + uncommitted child that
    /// supersedes the key AND writes many other keys. The added user mutations push
    /// `total_steps` past the active bits available in the committed region, forcing the scan
    /// to walk into the tail.
    ///
    /// Failure modes caught:
    /// - tail-fallthrough boundary off-by-one → wrong root,
    /// - missing `is_active_at` revalidation → parent's superseded loc gets moved → divergent
    ///   root,
    /// - bitmap state inconsistent with `init_from_log` → oracle reopen mismatch.
    #[test_traced]
    fn floor_scan_falls_through_to_uncommitted_tail() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let anchor = Sha256::hash(&[0xAA]);

            // Commit one key.
            let b = db
                .new_batch()
                .write(anchor, Some(vec![1]))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(b).await.unwrap();

            // Setup sanity: anchor in committed snapshot.
            assert_eq!(db.get(&anchor).await.unwrap(), Some(vec![1]));
            let committed_bitmap_len = db.bitmap.len();

            // Uncommitted parent: re-touch anchor at a location above the committed bitmap.
            let parent = db
                .new_batch()
                .write(anchor, Some(vec![2]))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert!(
                parent.total_size > committed_bitmap_len,
                "parent must extend past committed bitmap to exercise the tail path",
            );

            // Uncommitted child: supersede anchor + add 16 more writes. The extra user_steps
            // ensure `total_steps` exceeds active bits in the committed region, forcing the
            // floor-raise scan into the uncommitted tail.
            let mut child_batch = parent.new_batch::<Sha256>();
            child_batch = child_batch.write(anchor, Some(vec![3]));
            for i in 0..16u64 {
                let k = Sha256::hash(&(1000 + i).to_be_bytes());
                child_batch = child_batch.write(k, Some(vec![i as u8]));
            }
            let child = child_batch.merkleize(&db, None).await.unwrap();
            assert!(
                child.total_size > committed_bitmap_len,
                "child must include an uncommitted tail beyond committed bitmap",
            );
            let expected_root = child.root();

            // Apply. If tail-fallthrough or revalidation were wrong, the produced root would
            // diverge from the merkleize-time root.
            db.apply_batch(child).await.unwrap();
            assert_eq!(db.root(), expected_root);
            assert_eq!(db.get(&anchor).await.unwrap(), Some(vec![3]));

            let db = assert_oracle_round_trip(db, context, "tail").await;
            db.destroy().await.unwrap();
        });
    }
}
