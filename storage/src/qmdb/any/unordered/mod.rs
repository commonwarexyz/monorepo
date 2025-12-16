use crate::{
    index::unordered::Index,
    journal::contiguous::{fixed::Journal as FixedJournal, variable::Journal as VariableJournal},
    mmr::{mem::Clean, Location},
    qmdb::{
        any::{
            db::IndexedLog, init_fixed_authenticated_log, init_variable_authenticated_log,
            FixedConfig, FixedEncoding, FixedValue, UnorderedOperation, UnorderedUpdate,
            VariableConfig, VariableEncoding, VariableValue,
        },
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, CodecFixed, Read};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

pub mod sync;

#[cfg(test)]
mod fixed;
#[cfg(test)]
mod variable;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Any<E, K, V, C, I, H, S = Clean<DigestOf<H>>> =
    IndexedLog<E, K, V, UnorderedUpdate<K, V>, C, I, H, S>;

/// Operation type for unordered databases.
pub type Operation<K, V> = UnorderedOperation<K, V>;

/// A fixed-size unordered Any database with standard journal and index types.
pub type FixedDb<E, K, V, H, T> = Any<
    E,
    K,
    FixedEncoding<V>,
    FixedJournal<E, UnorderedOperation<K, FixedEncoding<V>>>,
    Index<T, Location>,
    H,
>;

/// A variable-size unordered Any database with standard journal and index types.
pub type VariableDb<E, K, V, H, T> = Any<
    E,
    K,
    VariableEncoding<V>,
    VariableJournal<E, UnorderedOperation<K, VariableEncoding<V>>>,
    Index<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    VariableDb<E, K, V, H, T>
where
    UnorderedOperation<K, VariableEncoding<V>>: Codec,
{
    /// Returns an [Any] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <UnorderedOperation<K, VariableEncoding<V>> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_variable_authenticated_log(context.clone(), cfg).await?;

        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(UnorderedOperation::CommitFloor(
                None,
                Location::new_unchecked(0),
            ))
            .await?;
            log.sync().await?;
        }

        let index = Index::new(context.with_label("index"), translator);
        Self::init_from_log(index, log, None, |_, _| {}).await
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher, T: Translator>
    FixedDb<E, K, V, H, T>
where
    UnorderedOperation<K, FixedEncoding<V>>: CodecFixed<Cfg = ()>,
{
    /// Returns an [Any] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: FixedConfig<T>) -> Result<Self, Error> {
        Self::init_with_callback(context, cfg, None, |_, _| {}).await
    }

    /// Initialize the DB, invoking `callback` for each operation processed during recovery.
    ///
    /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the snapshot
    /// is built from the log, `callback` is invoked for each operation with its activity status and
    /// previous location (if any).
    pub(crate) async fn init_with_callback(
        context: E,
        cfg: FixedConfig<T>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_fixed_authenticated_log(context.clone(), cfg).await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(UnorderedOperation::CommitFloor(
                None,
                Location::new_unchecked(0),
            ))
            .await?;
            log.sync().await?;
        }
        let index = Index::new(context.with_label("index"), translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        journal::contiguous::fixed::Journal,
        mmr::{Location, StandardHasher},
        qmdb::{
            any::{
                test::{fixed_db_config, variable_db_config},
                CleanAny, DirtyAny as _,
            },
            store::{DirtyStore as _, LogStore as _},
            verify_proof,
        },
        translator::TwoCap,
    };
    use commonware_codec::{Codec, Encode};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::NZU64;
    use core::{future::Future, pin::Pin};
    use std::collections::HashMap;

    /// A type alias for the concrete [Any] type used in these unit tests.
    type FixedDb = Any<
        Context,
        Digest,
        FixedEncoding<Digest>,
        Journal<Context, UnorderedOperation<Digest, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// A type alias for the concrete [Any] type used in these unit tests.
    type VariableDb = Any<
        Context,
        Digest,
        VariableEncoding<Digest>,
        VariableJournal<Context, UnorderedOperation<Digest, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return an `Any` database initialized with a fixed config.
    pub(crate) async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    /// Return an `Any` database initialized with a variable config.
    pub(crate) async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("partition"))
            .await
            .unwrap()
    }

    async fn test_any_db_empty<D>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn std::future::Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = Digest, Value = Digest, Digest = Digest>,
    {
        assert_eq!(db.op_count(), 1);
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
        assert!(db.get_metadata().await.unwrap().is_none());
        let empty_root = db.root();

        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let mut db = db.into_dirty();
        db.update(k1, v1).await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.root(), empty_root);

        // Test calling commit on an empty db.
        let metadata = Sha256::fill(3u8);
        let range = db.commit(Some(metadata)).await.unwrap();
        assert_eq!(range.start, 1);
        assert_eq!(range.end, 2);
        assert_eq!(db.op_count(), 2); // another commit op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 2);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
        // non-empty db.
        let mut db = db.into_dirty();
        db.update(k1, v1).await.unwrap();
        for _ in 1..100 {
            let mut clean_db = db.merkleize().await.unwrap();
            clean_db.commit(None).await.unwrap();
            db = clean_db.into_dirty();
            // Distance should equal 3 after the second commit, with inactivity_floor
            // referencing the previous commit operation.
            assert!(db.op_count() - db.inactivity_floor_loc() <= 3);
        }

        // Confirm the inactivity floor is raised to tip when the db becomes empty.
        db.delete(k1).await.unwrap();
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        assert!(db.is_empty());
        assert_eq!(db.op_count() - 1, db.inactivity_floor_loc());

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_any_db_empty(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    /// Shared test: build a db with mixed updates/deletes, verify state, proofs, reopen.
    pub(crate) async fn test_any_db_build_and_authenticate<D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest, Value = V, Digest = Digest, Operation: Encode>,
        V: Clone + Eq + std::hash::Hash + std::fmt::Debug + Codec,
    {
        const ELEMENTS: u64 = 1000;

        let mut db = db.into_dirty();
        let mut map = HashMap::<Digest, V>::default();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v.clone()).await.unwrap();
            map.insert(k, v);
        }

        // Update every 3rd key
        for i in 0u64..ELEMENTS {
            if i % 3 != 0 {
                continue;
            }
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v.clone()).await.unwrap();
            map.insert(k, v);
        }

        // Delete every 7th key
        for i in 0u64..ELEMENTS {
            if i % 7 != 1 {
                continue;
            }
            let k = Sha256::hash(&i.to_be_bytes());
            db.delete(k).await.unwrap();
            map.remove(&k);
        }

        assert_eq!(db.op_count(), Location::new_unchecked(1478));
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

        // Commit + sync with pruning raises inactivity floor.
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        db.sync().await.unwrap();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        assert_eq!(db.op_count(), Location::new_unchecked(1957));
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));

        // Close & reopen and ensure state matches.
        let root = db.root();
        db.close().await.unwrap();
        let db = reopen_db(context.clone()).await;
        assert_eq!(root, db.root());
        assert_eq!(db.op_count(), Location::new_unchecked(1957));
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));

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

        let mut hasher = StandardHasher::<Sha256>::new();
        for loc in *db.inactivity_floor_loc()..*db.op_count() {
            let loc = Location::new_unchecked(loc);
            let (proof, ops) = db.proof(loc, NZU64!(10)).await.unwrap();
            assert!(verify_proof(&mut hasher, &proof, loc, &ops, &root));
        }

        db.destroy().await.unwrap();
    }

    /// Test basic CRUD and commit behavior.
    pub(crate) async fn test_any_db_basic<D>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = Digest, Value = Digest, Digest = Digest>,
    {
        let mut db = db.into_dirty();

        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let d1 = Sha256::fill(1u8);
        let d2 = Sha256::fill(2u8);
        let v1 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);

        assert!(db.get(&d1).await.unwrap().is_none());
        assert!(db.get(&d2).await.unwrap().is_none());

        assert!(db.create(d1, v1).await.unwrap());
        assert_eq!(db.get(&d1).await.unwrap().unwrap(), v1);
        assert!(db.get(&d2).await.unwrap().is_none());

        assert!(db.create(d2, v1).await.unwrap());
        assert_eq!(db.get(&d1).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

        db.delete(d1).await.unwrap();
        assert!(db.get(&d1).await.unwrap().is_none());
        assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

        db.update(d1, v2).await.unwrap();
        assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

        db.update(d2, v1).await.unwrap();
        assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

        assert_eq!(db.op_count(), 6); // 4 updates, 1 deletion + initial commit.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();

        // Make sure create won't modify active keys.
        assert!(!db.create(d1, v1).await.unwrap());
        assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

        // Should have moved 3 active operations to tip, leading to floor of 7.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(7));
        assert_eq!(db.op_count(), 10); // floor of 7 + 2 active keys.

        // Delete all keys.
        assert!(db.delete(d1).await.unwrap());
        assert!(db.delete(d2).await.unwrap());
        assert!(db.get(&d1).await.unwrap().is_none());
        assert!(db.get(&d2).await.unwrap().is_none());
        assert_eq!(db.op_count(), 12); // 2 new delete ops.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(7));

        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(12));
        assert_eq!(db.op_count(), 13); // only commit should remain.

        // Multiple deletions of the same key should be a no-op.
        assert!(!db.delete(d1).await.unwrap());
        assert_eq!(db.op_count(), 13);

        // Deletions of non-existent keys should be a no-op.
        let d3 = Sha256::fill(3u8);
        assert!(!db.delete(d3).await.unwrap());
        assert_eq!(db.op_count(), 13);

        // Make sure closing/reopening gets us back to the same state.
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        assert_eq!(db.op_count(), 14);
        let root = db.root();
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 14);
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Re-activate the keys by updating them.
        db.update(d1, v1).await.unwrap();
        db.update(d2, v2).await.unwrap();
        db.delete(d1).await.unwrap();
        db.update(d2, v1).await.unwrap();
        db.update(d1, v2).await.unwrap();

        // Make sure last_commit is updated by changing the metadata back to None.
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        assert_eq!(db.op_count(), 23);
        let root = db.root();
        let mut db = reopen_db(context.clone()).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), 23);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        db.commit(None).await.unwrap();

        assert!(db.root() != root);

        // Pruning inactive ops should not affect current state or root
        let root = db.root();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_any_fixed_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_any_db_basic(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    /// Test recovery on non-empty db.
    pub(crate) async fn test_any_db_non_empty_recovery<D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest, Value = V, Digest = Digest>,
        V: Clone,
    {
        const ELEMENTS: u64 = 1000;

        let mut db = db.into_dirty();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        let root = db.root();
        let op_count = db.op_count();
        let inactivity_floor_loc = db.inactivity_floor_loc();

        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        let mut dirty = db.into_dirty();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            dirty.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for _ in 0..3 {
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                db.update(k, v).await.unwrap();
            }
        }
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let db = reopen_db(context.clone()).await;
        assert!(db.op_count() > op_count);
        assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test recovery on empty db.
    pub(crate) async fn test_any_db_empty_recovery<D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest, Value = V, Digest = Digest>,
        V: Clone,
    {
        let root = db.root();

        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for _ in 0..3 {
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = make_value((i + 1) * 10000);
                db.update(k, v).await.unwrap();
            }
        }
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_dirty();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let db = reopen_db(context.clone()).await;
        assert!(db.op_count() > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test making multiple commits, one of which deletes a key from a previous commit.
    pub(crate) async fn test_any_db_multiple_commits_delete_replayed<D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: CleanAny<Key = Digest, Value = V, Digest = Digest>,
        V: Clone + Eq + std::fmt::Debug,
    {
        let mut map = HashMap::<Digest, V>::default();
        const ELEMENTS: u64 = 10;
        let metadata_value = make_value(42);
        let mut db = db.into_dirty();
        let key_at = |j: u64, i: u64| Sha256::hash(&(j * 1000 + i).to_be_bytes());
        for j in 0u64..ELEMENTS {
            for i in 0u64..ELEMENTS {
                let k = key_at(j, i);
                let v = make_value(i * 1000);
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }
            let mut clean_db = db.merkleize().await.unwrap();
            clean_db.commit(Some(metadata_value.clone())).await.unwrap();
            db = clean_db.into_dirty();
        }
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_value));
        let k = key_at(ELEMENTS - 1, ELEMENTS - 1);

        db.delete(k).await.unwrap();
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(db.get(&k).await.unwrap().is_none());

        let root = db.root();
        db.close().await.unwrap();
        let db = reopen_db(context.clone()).await;
        assert_eq!(root, db.root());
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(db.get(&k).await.unwrap().is_none());

        db.destroy().await.unwrap();
    }
}
