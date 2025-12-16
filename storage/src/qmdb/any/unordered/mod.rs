use crate::{
    index::{unordered::Index as UnorderedIndex, Unordered as UnorderedIndexTrait},
    journal::contiguous::{
        fixed::Journal as FixedJournal, variable::Journal as VariableJournal, Contiguous,
        MutableContiguous, PersistableContiguous,
    },
    mmr::{
        mem::{Dirty, State},
        Location,
    },
    qmdb::{
        any::{
            init_fixed_authenticated_log, init_variable_authenticated_log, CleanAny, Db, DirtyAny,
            FixedConfig, FixedEncoding, FixedValue, UnorderedOperation, UnorderedUpdate,
            VariableConfig, VariableEncoding, VariableValue,
        },
        create_key, delete_key, delete_known_loc,
        operation::Operation as OperationTrait,
        store::Batchable,
        update_key, update_known_loc, Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, CodecFixed, Read};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use std::{collections::BTreeMap, ops::Range};
use tracing::warn;

pub mod sync;

/// A fixed-size unordered database with standard journal and index types.
pub type Fixed<E, K, V, H, T> = Db<
    E,
    K,
    FixedEncoding<V>,
    UnorderedUpdate<K, FixedEncoding<V>>,
    FixedJournal<E, UnorderedOperation<K, FixedEncoding<V>>>,
    UnorderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher, T: Translator>
    Fixed<E, K, V, H, T>
where
    UnorderedOperation<K, FixedEncoding<V>>: CodecFixed<Cfg = ()>,
{
    /// Returns a [Fixed] QMDB initialized from `cfg`. Any uncommitted log operations will be
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
        let index = UnorderedIndex::new(context.with_label("index"), translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}

/// A variable-size unordered database with standard journal and index types.
pub type Variable<E, K, V, H, T> = Db<
    E,
    K,
    VariableEncoding<V>,
    UnorderedUpdate<K, VariableEncoding<V>>,
    VariableJournal<E, UnorderedOperation<K, VariableEncoding<V>>>,
    UnorderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Variable<E, K, V, H, T>
where
    UnorderedOperation<K, VariableEncoding<V>>: Codec,
{
    /// Returns a [Variable] QMDB initialized from `cfg`. Any uncommitted log operations will be
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

        let index = UnorderedIndex::new(context.with_label("index"), translator);
        Self::init_from_log(index, log, None, |_, _| {}).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: crate::qmdb::any::ValueEncoding,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > Db<E, K, V, UnorderedUpdate<K, V>, C, I, H, S>
where
    UnorderedOperation<K, V>: Codec,
{
    /// Returns the value for `key` and its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(V::Value, Location)>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            let update = Self::get_update(&self.log, loc).await?;
            let (k, v) = (update.0, update.1);
            if &k == key {
                return Ok(Some((v, loc)));
            }
        }

        Ok(None)
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.get_with_loc(key)
            .await
            .map(|op| op.map(|(value, _)| value))
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: crate::qmdb::any::ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > Db<E, K, V, UnorderedUpdate<K, V>, C, I, H, S>
where
    UnorderedOperation<K, V>: Codec,
{
    /// Appends the given delete operation to the log, updating the snapshot and other state to
    /// reflect the deletion.
    pub(crate) async fn delete_key(&mut self, key: K) -> Result<Option<Location>, Error> {
        let Some(loc) = delete_key(&mut self.snapshot, &self.log, &key).await? else {
            return Ok(None);
        };
        self.log.append(UnorderedOperation::Delete(key)).await?;
        self.steps += 1;
        self.active_keys -= 1;

        Ok(Some(loc))
    }

    /// Appends the provided update to the log, returning the old location of the key if
    /// it was previously assigned some value, and None otherwise.
    pub(crate) async fn update_key(
        &mut self,
        key: K,
        value: V::Value,
    ) -> Result<Option<Location>, Error> {
        let new_loc = self.op_count();
        let res = self.update_loc(&key, new_loc).await?;

        self.log
            .append(UnorderedOperation::Update(UnorderedUpdate(key, value)))
            .await?;
        if res.is_some() {
            self.steps += 1;
        } else {
            self.active_keys += 1;
        }

        Ok(res)
    }

    /// Creates a new key with the given operation, or returns false if the key already exists.
    pub(crate) async fn create_key(&mut self, key: K, value: V::Value) -> Result<bool, Error> {
        let new_loc = self.op_count();
        if !create_key(&mut self.snapshot, &self.log, &key, new_loc).await? {
            return Ok(false);
        }

        self.log
            .append(UnorderedOperation::Update(UnorderedUpdate(key, value)))
            .await?;
        self.active_keys += 1;

        Ok(true)
    }

    /// Updates the location of `key` in the snapshot to `new_loc`, returning the previous location
    /// of the key if any was found.
    pub(crate) async fn update_loc(
        &mut self,
        key: &K,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        update_key(&mut self.snapshot, &self.log, key, new_loc).await
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V::Value) -> Result<(), Error> {
        self.update_key(key, value).await.map(|_| ())
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V::Value) -> Result<bool, Error> {
        self.create_key(key, value).await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        Ok(self.delete_key(key).await?.is_some())
    }

    /// Performs a batch update, invoking the callback for each resulting operation. The first
    /// argument of the callback is the activity status of the operation, and the second argument is
    /// the location of the operation it inactivates (if any).
    pub(crate) async fn write_batch_with_callback<F>(
        &mut self,
        iter: impl Iterator<Item = (K, Option<V::Value>)>,
        mut callback: F,
    ) -> Result<(), Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        // We use a BTreeMap here to collect the updates to ensure determinism in iteration order.
        let mut updates = BTreeMap::new();
        let mut locations = Vec::with_capacity(iter.size_hint().0);
        for (key, value) in iter {
            let iter = self.snapshot.get(&key);
            locations.extend(iter.copied());
            updates.insert(key, value);
        }

        // Concurrently look up all possible matching locations.
        locations.sort();
        locations.dedup();
        let futures = locations.iter().map(|loc| self.log.read(*loc));
        let results = try_join_all(futures).await?;

        // Process the deletes & updates of existing keys, which must appear in the results.
        for (op, old_loc) in (results.into_iter()).zip(locations) {
            let key = op.key().expect("updates should have a key");
            let Some(update) = updates.remove(key) else {
                continue; // translated key collision
            };

            let new_loc = self.op_count();
            if let Some(value) = update {
                update_known_loc(&mut self.snapshot, key, old_loc, new_loc);
                self.log
                    .append(UnorderedOperation::Update(UnorderedUpdate(
                        key.clone(),
                        value,
                    )))
                    .await?;
                callback(true, Some(old_loc));
            } else {
                delete_known_loc(&mut self.snapshot, key, old_loc);
                self.log
                    .append(UnorderedOperation::Delete(key.clone()))
                    .await?;
                callback(false, Some(old_loc));
                self.active_keys -= 1;
            }
            self.steps += 1;
        }

        // Process the creates.
        for (key, value) in updates {
            let Some(value) = value else {
                continue; // attempt to delete a non-existent key
            };
            self.snapshot.insert(&key, self.op_count());
            self.log
                .append(UnorderedOperation::Update(UnorderedUpdate(key, value)))
                .await?;
            callback(true, None);
            self.active_keys += 1;
        }

        Ok(())
    }
}

impl<E, K, V, C, I, H> Batchable for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H>
where
    E: Storage + Clock + Metrics,
    K: Array,
    C: MutableContiguous<Item = UnorderedOperation<K, V>>,
    I: UnorderedIndexTrait<Value = Location>,
    H: Hasher,
    V: crate::qmdb::any::ValueEncoding,
    UnorderedOperation<K, V>: Codec,
{
    async fn write_batch(
        &mut self,
        iter: impl Iterator<Item = (K, Option<V::Value>)>,
    ) -> Result<(), Error> {
        // We use a BTreeMap here to collect the updates to ensure determinism in iteration order.
        let mut updates = BTreeMap::new();
        let mut locations = Vec::with_capacity(iter.size_hint().0);
        for (key, value) in iter {
            let iter = self.snapshot.get(&key);
            locations.extend(iter.copied());
            updates.insert(key, value);
        }

        // Concurrently look up all possible matching locations.
        locations.sort();
        locations.dedup();
        let futures = locations.iter().map(|loc| self.log.read(*loc));
        let results = try_join_all(futures).await?;

        // Process the deletes & updates of existing keys, which must appear in the results.
        for (op, old_loc) in (results.into_iter()).zip(locations) {
            let key = op.key().expect("updates should have a key");
            let Some(update) = updates.remove(key) else {
                continue; // translated key collision
            };

            let new_loc = self.op_count();
            if let Some(value) = update {
                update_known_loc(&mut self.snapshot, key, old_loc, new_loc);
                self.log
                    .append(UnorderedOperation::Update(UnorderedUpdate(
                        key.clone(),
                        value,
                    )))
                    .await?;
            } else {
                delete_known_loc(&mut self.snapshot, key, old_loc);
                self.log
                    .append(UnorderedOperation::Delete(key.clone()))
                    .await?;
                self.active_keys -= 1;
            }
            self.steps += 1;
        }

        // Process the creates.
        for (key, value) in updates {
            let Some(value) = value else {
                continue; // attempt to delete a non-existent key
            };
            self.snapshot.insert(&key, self.op_count());
            self.log
                .append(UnorderedOperation::Update(UnorderedUpdate(key, value)))
                .await?;
            self.active_keys += 1;
        }

        Ok(())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: crate::qmdb::any::ValueEncoding,
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
    > crate::store::StorePersistable for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    async fn commit(&mut self) -> Result<(), Error> {
        self.commit(None).await.map(|_| ())
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
        V: crate::qmdb::any::ValueEncoding,
    > crate::store::Store for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    type Key = K;
    type Value = V::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
        V: crate::qmdb::any::ValueEncoding,
    > crate::store::StoreMut for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
        V: crate::qmdb::any::ValueEncoding,
    > crate::store::StoreDeletable for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: crate::qmdb::any::ValueEncoding,
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
    > CleanAny for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    type Key = K;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Error> {
        self.get(key).await
    }

    async fn commit(&mut self, metadata: Option<Self::Value>) -> Result<Range<Location>, Error> {
        self.commit(metadata).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn close(self) -> Result<(), Error> {
        self.close().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: crate::qmdb::any::ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndexTrait<Value = Location>,
        H: Hasher,
    > DirtyAny for Db<E, K, V, UnorderedUpdate<K, V>, C, I, H, Dirty>
where
    UnorderedOperation<K, V>: Codec,
{
    type Key = K;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn create(&mut self, key: Self::Key, value: Self::Value) -> Result<bool, Error> {
        self.create(key, value).await
    }

    async fn delete(&mut self, key: Self::Key) -> Result<bool, Error> {
        self.delete(key).await
    }
}

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        index::unordered::Index,
        journal::contiguous::fixed::Journal,
        mmr::{Location, Position, StandardHasher},
        qmdb::{
            any::{
                test::{fixed_db_config, variable_db_config},
                CleanAny,
            },
            store::{batch_tests, CleanStore as _, DirtyStore as _, LogStore as _},
            verify_proof, Error,
        },
        translator::TwoCap,
    };
    use commonware_codec::{Codec, Encode};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use core::{future::Future, pin::Pin};
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::collections::HashMap;

    /// A type alias for the concrete database type used in these unit tests.
    type FixedDb = Db<
        Context,
        Digest,
        FixedEncoding<Digest>,
        UnorderedUpdate<Digest, FixedEncoding<Digest>>,
        Journal<Context, UnorderedOperation<Digest, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// A type alias for the concrete database type used in these unit tests.
    type VariableDb = Db<
        Context,
        Digest,
        VariableEncoding<Digest>,
        UnorderedUpdate<Digest, VariableEncoding<Digest>>,
        VariableJournal<Context, UnorderedOperation<Digest, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a fixed config.
    pub(crate) async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    /// Return a database initialized with a variable config.
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

    // Janky page & cache sizes to exercise boundary conditions.
    const FIXED_PAGE_SIZE: usize = 101;
    const FIXED_PAGE_CACHE_SIZE: usize = 11;

    type FixedOperation = UnorderedOperation<Digest, FixedEncoding<Digest>>;

    /// A type alias for the concrete database type used in fixed-size unit tests.
    pub(crate) type FixedDbTest = Db<
        Context,
        Digest,
        FixedEncoding<Digest>,
        UnorderedUpdate<Digest, FixedEncoding<Digest>>,
        Journal<Context, FixedOperation>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    pub(crate) fn fixed_db_test_config(suffix: &str) -> crate::qmdb::any::FixedConfig<TwoCap> {
        crate::qmdb::any::FixedConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(FIXED_PAGE_SIZE), NZUsize!(FIXED_PAGE_CACHE_SIZE)),
        }
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    /// Return a database initialized with a fixed config.
    async fn open_fixed_db_test(context: Context) -> FixedDbTest {
        FixedDbTest::init(context, fixed_db_test_config("partition"))
            .await
            .unwrap()
    }

    pub(crate) fn create_fixed_test_config(seed: u64) -> crate::qmdb::any::FixedConfig<TwoCap> {
        crate::qmdb::any::FixedConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(13), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(11), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(FIXED_PAGE_SIZE), NZUsize!(FIXED_PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_fixed_db_test(mut context: Context) -> FixedDbTest {
        let seed = context.next_u64();
        let config = create_fixed_test_config(seed);
        FixedDbTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_fixed_test_ops(n') is a suffix of create_fixed_test_ops(n) for n' > n.
    pub(crate) fn create_fixed_test_ops(n: usize) -> Vec<FixedOperation> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(FixedOperation::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(FixedOperation::Update(UnorderedUpdate(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_fixed_ops(db: &mut FixedDbTest, ops: Vec<FixedOperation>) {
        for op in ops {
            match op {
                FixedOperation::Update(UnorderedUpdate(key, value)) => {
                    db.update(key, value).await.unwrap();
                }
                FixedOperation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                FixedOperation::CommitFloor(metadata, _) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_build_and_authenticate() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_non_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_non_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_any_fixed_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db_test(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_fixed_db_test(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_multiple_commits_delete_gets_replayed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db_test(context.clone()).await;
            test_any_db_multiple_commits_delete_replayed(
                context,
                db,
                |ctx| Box::pin(open_fixed_db_test(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_fixed_db_test(context.clone()).await;
            let ops = create_fixed_test_ops(20);
            apply_fixed_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();
            let root_hash = db.root();
            let original_op_count = db.op_count();

            // Historical proof should match "regular" proof when historical size == current database size
            let max_ops = NZU64!(10);
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(6), max_ops)
                .await
                .unwrap();
            let (regular_proof, regular_ops) =
                db.proof(Location::new_unchecked(6), max_ops).await.unwrap();

            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert_eq!(historical_ops, ops[5..15]);
            let mut hasher = StandardHasher::<Sha256>::new();
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(6),
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            let more_ops = create_fixed_test_ops(5);
            apply_fixed_ops(&mut db, more_ops.clone()).await;
            db.commit(None).await.unwrap();

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(6), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(
                historical_proof.size,
                Position::try_from(original_op_count).unwrap()
            );
            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_ops.len(), 10);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(6),
                &historical_ops,
                &root_hash
            ));

            // Try to get historical proof with op_count > number of operations and confirm it
            // returns RangeOutOfBounds error.
            assert!(matches!(
                db.historical_proof(db.op_count() + 1, Location::new_unchecked(6), NZU64!(10))
                    .await,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_edge_cases() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_fixed_db_test(context.clone()).await;
            let ops = create_fixed_test_ops(50);
            apply_fixed_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = StandardHasher::<Sha256>::new();

            // Test singleton database
            let (single_proof, single_ops) = db
                .historical_proof(
                    Location::new_unchecked(2),
                    Location::new_unchecked(1),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(
                single_proof.size,
                Position::try_from(Location::new_unchecked(2)).unwrap()
            );
            assert_eq!(single_ops.len(), 1);

            // Create historical database with single operation
            let mut single_db = create_fixed_db_test(context.clone()).await;
            apply_fixed_ops(&mut single_db, ops[0..1].to_vec()).await;
            // Don't commit - this changes the root due to commit operations
            single_db.sync().await.unwrap();
            let single_root = single_db.root();

            assert!(verify_proof(
                &mut hasher,
                &single_proof,
                Location::new_unchecked(1),
                &single_ops,
                &single_root
            ));

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
            assert_eq!(limited_ops, ops[5..10]);

            // Test proof at minimum historical position
            let (min_proof, min_ops) = db
                .historical_proof(
                    Location::new_unchecked(4),
                    Location::new_unchecked(1),
                    NZU64!(3),
                )
                .await
                .unwrap();
            assert_eq!(
                min_proof.size,
                Position::try_from(Location::new_unchecked(4)).unwrap()
            );
            assert_eq!(min_ops.len(), 3);
            assert_eq!(min_ops, ops[0..3]);

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_fixed_db_test(context.clone()).await;
            let ops = create_fixed_test_ops(100);
            apply_fixed_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = StandardHasher::<Sha256>::new();

            // Test historical proof generation for several historical states.
            let start_loc = Location::new_unchecked(21);
            let max_ops = NZU64!(10);
            for end_loc in 32..51 {
                let end_loc = Location::new_unchecked(end_loc);
                let (historical_proof, historical_ops) = db
                    .historical_proof(end_loc, start_loc, max_ops)
                    .await
                    .unwrap();

                assert_eq!(historical_proof.size, Position::try_from(end_loc).unwrap());

                // Create reference database at the given historical size
                let mut ref_db = create_fixed_db_test(context.clone()).await;
                apply_fixed_ops(&mut ref_db, ops[0..(*end_loc - 1) as usize].to_vec()).await;
                // Sync to process dirty nodes but don't commit - commit changes the root due to commit operations
                ref_db.sync().await.unwrap();

                let (ref_proof, ref_ops) = ref_db.proof(start_loc, max_ops).await.unwrap();
                assert_eq!(ref_proof.size, historical_proof.size);
                assert_eq!(ref_ops, historical_ops);
                assert_eq!(ref_proof.digests, historical_proof.digests);
                let end_loc = std::cmp::min(start_loc.checked_add(max_ops.get()).unwrap(), end_loc);
                assert_eq!(
                    ref_ops,
                    ops[(*start_loc - 1) as usize..(*end_loc - 1) as usize]
                );

                // Verify proof against reference root
                let ref_root = ref_db.root();
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &ref_root
                ),);

                ref_db.destroy().await.unwrap();
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_invalid() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_fixed_db_test(context.clone()).await;
            let ops = create_fixed_test_ops(10);
            apply_fixed_ops(&mut db, ops).await;
            db.commit(None).await.unwrap();

            let historical_op_count = Location::new_unchecked(5);
            let historical_mmr_size = Position::try_from(historical_op_count).unwrap();
            let (proof, ops) = db
                .historical_proof(historical_op_count, Location::new_unchecked(1), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(proof.size, historical_mmr_size);
            assert_eq!(ops.len(), 4);

            let mut hasher = StandardHasher::<Sha256>::new();

            // Changing the proof digests should cause verification to fail
            {
                let mut proof = proof.clone();
                proof.digests[0] = Sha256::hash(b"invalid");
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }
            {
                let mut proof = proof.clone();
                proof.digests.push(Sha256::hash(b"invalid"));
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the ops should cause verification to fail
            {
                let mut ops = ops.clone();
                ops[0] = FixedOperation::Update(UnorderedUpdate(
                    Sha256::hash(b"key1"),
                    Sha256::hash(b"value1"),
                ));
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }
            {
                let mut ops = ops.clone();
                ops.push(FixedOperation::Update(UnorderedUpdate(
                    Sha256::hash(b"key1"),
                    Sha256::hash(b"value1"),
                )));
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the start location should cause verification to fail
            {
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(1),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the root digest should cause verification to fail
            {
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &Sha256::hash(b"invalid")
                ));
            }

            // Changing the proof size should cause verification to fail
            {
                let mut proof = proof.clone();
                proof.size = Position::new(100);
                let root_hash = db.root();
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_any_fixed_batch() {
        batch_tests::test_batch(|ctx| async move { create_fixed_db_test(ctx).await });
    }

    // ============================================================================
    // Variable-size value tests (moved from variable.rs)
    // ============================================================================

    const VARIABLE_PAGE_SIZE: usize = 77;
    const VARIABLE_PAGE_CACHE_SIZE: usize = 9;

    fn variable_any_db_config(
        suffix: &str,
    ) -> crate::qmdb::any::VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        crate::qmdb::any::VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(
                NZUsize!(VARIABLE_PAGE_SIZE),
                NZUsize!(VARIABLE_PAGE_CACHE_SIZE),
            ),
        }
    }

    /// A type alias for the concrete database type used in variable-size unit tests.
    type VariableDbTest = Db<
        Context,
        Digest,
        VariableEncoding<Vec<u8>>,
        UnorderedUpdate<Digest, VariableEncoding<Vec<u8>>>,
        VariableJournal<Context, UnorderedOperation<Digest, VariableEncoding<Vec<u8>>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Deterministic byte vector generator for variable-value tests.
    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Return a database initialized with a variable config.
    async fn open_variable_db_test(context: Context) -> VariableDbTest {
        VariableDbTest::init(context, variable_any_db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_any_variable_db_build_and_authenticate() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db_test(context.clone()).await;
            test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_variable_db_test(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_any_variable_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db_test(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = to_bytes(i);
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_variable_db_test(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_any_variable_db_multiple_commits_delete_gets_replayed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db_test(context.clone()).await;
            test_any_db_multiple_commits_delete_replayed(
                context,
                db,
                |ctx| Box::pin(open_variable_db_test(ctx)),
                |i| vec![(i % 255) as u8; ((i % 7) + 3) as usize],
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_any_variable_db_recovery() {
        let executor = Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = open_variable_db_test(context.clone()).await;
            let root = db.root();

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root();
            assert_eq!(db.op_count(), 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(756)
            );
            assert_eq!(db.snapshot.items(), 857);

            // Confirm state is preserved after close and reopen.
            db.close().await.unwrap();
            let db = open_variable_db_test(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(756)
            );
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_non_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db_test(context.clone()).await;

            // Insert 1000 keys then sync.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root();
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(), root);

            async fn apply_more_ops(db: &mut VariableDbTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_variable_db_test(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let db = open_variable_db_test(context.clone()).await;
            let root = db.root();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            async fn apply_ops(db: &mut VariableDbTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Insert another 1000 keys then simulate failure after syncing the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_variable_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_variable_db_test(context.clone()).await;
            assert!(db.op_count() > 1);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_prune_beyond_inactivity_floor() {
        let executor = Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_variable_db_test(context.clone()).await;

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.update(key1, vec![10]).await.unwrap();
            db.update(key2, vec![20]).await.unwrap();
            db.update(key3, vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                        if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_any_variable_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let cfg = variable_any_db_config(&format!("batch_{seed}"));
            VariableDbTest::init(ctx, cfg).await.unwrap()
        });
    }
}
