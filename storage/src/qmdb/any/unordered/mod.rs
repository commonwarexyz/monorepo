use crate::{
    index::Unordered as Index,
    journal::contiguous::{Contiguous, MutableContiguous},
    kv::{self, Batchable},
    mmr::Location,
    qmdb::{
        any::{
            db::{AuthenticatedLog, Db},
            ValueEncoding,
        },
        build_snapshot_from_log, create_key, delete_key, delete_known_loc,
        operation::{Committable, Operation as OperationTrait},
        update_key, update_known_loc, DurabilityState, Durable, Error, MerkleizationState,
        Merkleized, NonDurable, Unmerkleized,
    },
};
#[cfg(any(test, feature = "test-traits"))]
use crate::{
    qmdb::any::states::{CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny},
    Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use std::collections::BTreeMap;

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Unordered as Update, Unordered as Operation};

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        M: MerkleizationState<DigestOf<H>> + Send + Sync,
        D: DurabilityState,
    > Db<E, C, I, H, Update<K, V>, M, D>
where
    Operation<K, V>: Codec,
{
    /// Returns the value for `key` and its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(V::Value, Location)>, Error> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location> = self.snapshot.get(key).copied().collect();
        for loc in locs {
            let op = self.log.read(loc).await?;
            match &op {
                Operation::Update(Update(k, value)) => {
                    if k == key {
                        return Ok(Some((value.clone(), loc)));
                    }
                }
                _ => unreachable!("location {loc} does not reference update operation"),
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
        V: ValueEncoding,
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    /// Appends the given delete operation to the log, updating the snapshot and other state to
    /// reflect the deletion.
    pub(crate) async fn delete_key(&mut self, key: K) -> Result<Option<Location>, Error> {
        let Some(loc) = delete_key(&mut self.snapshot, &self.log, &key).await? else {
            return Ok(None);
        };
        self.log.append(Operation::Delete(key)).await?;
        self.durable_state.steps += 1;
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
        let new_loc = self.log.bounds().end;
        let res = self.update_loc(&key, new_loc).await?;

        self.log
            .append(Operation::Update(Update(key, value)))
            .await?;
        if res.is_some() {
            self.durable_state.steps += 1;
        } else {
            self.active_keys += 1;
        }

        Ok(res)
    }

    /// Creates a new key with the given operation, or returns false if the key already exists.
    pub(crate) async fn create_key(&mut self, key: K, value: V::Value) -> Result<bool, Error> {
        let new_loc = self.log.bounds().end;
        if !create_key(&mut self.snapshot, &self.log, &key, new_loc).await? {
            return Ok(false);
        }

        self.log
            .append(Operation::Update(Update(key, value)))
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

            let new_loc = self.log.bounds().end;
            if let Some(value) = update {
                update_known_loc(&mut self.snapshot, key, old_loc, new_loc);
                self.log
                    .append(Operation::Update(Update(key.clone(), value)))
                    .await?;
                callback(true, Some(old_loc));
            } else {
                delete_known_loc(&mut self.snapshot, key, old_loc);
                self.log.append(Operation::Delete(key.clone())).await?;
                callback(false, Some(old_loc));
                self.active_keys -= 1;
            }
            self.durable_state.steps += 1;
        }

        // Process the creates.
        for (key, value) in updates {
            let Some(value) = value else {
                continue; // attempt to delete a non-existent key
            };
            self.snapshot.insert(&key, self.log.bounds().end);
            self.log
                .append(Operation::Update(Update(key, value)))
                .await?;
            callback(true, None);
            self.active_keys += 1;
        }

        Ok(())
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = O>,
        O: OperationTrait + Codec + Committable + Send + Sync,
        I: Index<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Db<E, C, I, H, U, Merkleized<H>, Durable>
{
    /// Returns an [Db] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last operation is assumed to be a commit.
    pub(crate) async fn from_components(
        inactivity_floor_loc: Location,
        log: AuthenticatedLog<E, C, H>,
        mut snapshot: I,
    ) -> Result<Self, Error> {
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;
        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");
        assert!(log.read(last_commit_loc).await?.is_commit());

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot,
            last_commit_loc,
            durable_state: Durable {},
            active_keys,
            _update: core::marker::PhantomData,
        })
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
        M: MerkleizationState<DigestOf<H>> + Send + Sync,
        D: DurabilityState,
    > kv::Gettable for Db<E, C, I, H, Update<K, V>, M, D>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
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
        V: ValueEncoding,
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
    > kv::Updatable for Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
    > kv::Deletable for Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
where
    Operation<K, V>: CodecShared,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

impl<E, K, V, C, I, H> Batchable for Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = Operation<K, V>>,
    I: Index<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V>: CodecShared,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Error>
    where
        Iter: Iterator<Item = (K, Option<V::Value>)> + Send + 'a,
    {
        self.write_batch_with_callback(iter, |_, _| {}).await
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> CleanAny for Db<E, C, I, H, Update<K, V>, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V>: CodecShared,
{
    type Mutable = Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> UnmerkleizedDurableAny
    for Db<E, C, I, H, Update<K, V>, Unmerkleized, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Mutable = Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>;
    type Merkleized = Db<E, C, I, H, Update<K, V>, Merkleized<H>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        Ok(self.into_merkleized())
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> MerkleizedNonDurableAny
    for Db<E, C, I, H, Update<K, V>, Merkleized<H>, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    type Mutable = Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> MutableAny for Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Durable = Db<E, C, I, H, Update<K, V>, Unmerkleized, Durable>;
    type Merkleized = Db<E, C, I, H, Update<K, V>, Merkleized<H>, NonDurable>;

    async fn commit(
        self,
        metadata: Option<V::Value>,
    ) -> Result<(Self::Durable, core::ops::Range<Location>), Error> {
        self.commit(metadata).await
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        Ok(self.into_merkleized())
    }

    fn steps(&self) -> u64 {
        self.durable_state.steps
    }
}

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        kv::{Deletable as _, Gettable as _, Updatable as _},
        mmr::StandardHasher,
        qmdb::{
            any::test::{fixed_db_config, variable_db_config},
            store::{LogStore, MerkleizedStore},
            verify_proof,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::NZU64;
    use core::{future::Future, pin::Pin};
    use std::collections::HashMap;

    /// A type alias for the concrete [fixed::Db] type used in these unit tests.
    type FixedDb = fixed::Db<Context, Digest, Digest, Sha256, TwoCap, Merkleized<Sha256>, Durable>;

    /// A type alias for the concrete [variable::Db] type used in these unit tests.
    type VariableDb =
        variable::Db<Context, Digest, Digest, Sha256, TwoCap, Merkleized<Sha256>, Durable>;

    /// Helper trait for testing Any databases that cycle through all four states.
    pub(crate) trait TestableAnyDb<V>:
        CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>
    {
    }

    impl<T, V> TestableAnyDb<V> for T where
        T: CleanAny<Key = Digest> + MerkleizedStore<Value = V, Digest = Digest>
    {
    }

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

    /// Test an empty database.
    ///
    /// The `reopen_db` closure receives a unique index for each invocation to enable
    /// unique metric labels (the deterministic runtime panics on duplicates).
    async fn test_any_db_empty<D: TestableAnyDb<Digest>>(
        mut db: D,
        mut reopen_db: impl FnMut(usize) -> Pin<Box<dyn std::future::Future<Output = D> + Send>>,
    ) {
        let mut reopen_counter = 0usize;
        let mut next_db = || {
            let idx = reopen_counter;
            reopen_counter += 1;
            reopen_db(idx)
        };

        assert_eq!(db.bounds().end, 1);
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
        assert!(db.get_metadata().await.unwrap().is_none());
        let empty_root = db.root();

        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let mut db = db.into_mutable();
        db.update(k1, v1).await.unwrap();
        drop(db);
        let db = next_db().await;
        assert_eq!(db.bounds().end, 1);
        assert_eq!(db.root(), empty_root);

        // Test calling commit on an empty db.
        let metadata = Sha256::fill(3u8);
        let db = db.into_mutable();
        let (db, range) = db.commit(Some(metadata)).await.unwrap();
        assert_eq!(range.start, 1);
        assert_eq!(range.end, 2);
        assert_eq!(db.bounds().end, 2); // another commit op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let mut db = db.into_merkleized().await.unwrap();
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        drop(db);
        let db = next_db().await;
        assert_eq!(db.bounds().end, 2);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
        // non-empty db.
        let mut db = db.into_mutable();
        db.update(k1, v1).await.unwrap();
        for _ in 1..100 {
            let (clean_db, _) = db.commit(None).await.unwrap();
            // Distance should equal 3 after the second commit, with inactivity_floor
            // referencing the previous commit operation.
            assert!(clean_db.bounds().end - clean_db.inactivity_floor_loc() <= 3);
            db = clean_db.into_mutable();
            assert!(db.bounds().end - db.inactivity_floor_loc() <= 3);
        }

        // Confirm the inactivity floor is raised to tip when the db becomes empty.
        db.delete(k1).await.unwrap();
        let (db, _) = db.commit(None).await.unwrap();
        assert!(db.is_empty());
        assert_eq!(db.bounds().end - 1, db.inactivity_floor_loc());

        let db = db.into_merkleized().await.unwrap();
        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_fixed_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_variable_db(ctx))
            })
            .await;
        });
    }

    pub(crate) async fn test_any_db_build_and_authenticate<
        D: TestableAnyDb<V>,
        V: Codec + Clone + Eq + std::hash::Hash + std::fmt::Debug,
    >(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        <D as MerkleizedStore>::Operation: Codec,
    {
        const ELEMENTS: u64 = 1000;

        let mut db = db.into_mutable();
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

        assert_eq!(db.bounds().end, Location::new_unchecked(1478));
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

        // Commit + sync with pruning raises inactivity floor.
        let (db, _) = db.commit(None).await.unwrap();
        let mut db = db.into_merkleized().await.unwrap();
        db.sync().await.unwrap();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        assert_eq!(db.bounds().end, Location::new_unchecked(1957));
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));

        // Drop & reopen and ensure state matches.
        let root = db.root();
        db.sync().await.unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopened")).await;
        assert_eq!(root, db.root());
        assert_eq!(db.bounds().end, Location::new_unchecked(1957));
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
        for loc in *db.inactivity_floor_loc()..*db.bounds().end {
            let loc = Location::new_unchecked(loc);
            let (proof, ops) = db.proof(loc, NZU64!(10)).await.unwrap();
            assert!(verify_proof(&mut hasher, &proof, loc, &ops, &root));
        }

        db.destroy().await.unwrap();
    }

    /// Test basic CRUD and commit behavior.
    ///
    /// The `reopen_db` closure receives a unique index for each invocation to enable
    /// unique metric labels (the deterministic runtime panics on duplicates).
    pub(crate) async fn test_any_db_basic<D: TestableAnyDb<Digest>>(
        db: D,
        mut reopen_db: impl FnMut(usize) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        let mut reopen_counter = 0usize;
        let mut next_db = || {
            let idx = reopen_counter;
            reopen_counter += 1;
            reopen_db(idx)
        };

        let mut db = db.into_mutable();

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

        assert_eq!(db.bounds().end, 6); // 4 updates, 1 deletion + initial commit.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
        let (db, _) = db.commit(None).await.unwrap();
        let mut db = db.into_mutable();

        // Make sure create won't modify active keys.
        assert!(!db.create(d1, v1).await.unwrap());
        assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

        // Should have moved 3 active operations to tip, leading to floor of 7.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(7));
        assert_eq!(db.bounds().end, 10); // floor of 7 + 2 active keys.

        // Delete all keys.
        assert!(db.delete(d1).await.unwrap());
        assert!(db.delete(d2).await.unwrap());
        assert!(db.get(&d1).await.unwrap().is_none());
        assert!(db.get(&d2).await.unwrap().is_none());
        assert_eq!(db.bounds().end, 12); // 2 new delete ops.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(7));

        let (db, _) = db.commit(None).await.unwrap();
        let mut db = db.into_mutable();
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(12));
        assert_eq!(db.bounds().end, 13); // only commit should remain.

        // Multiple deletions of the same key should be a no-op.
        assert!(!db.delete(d1).await.unwrap());
        assert_eq!(db.bounds().end, 13);

        // Deletions of non-existent keys should be a no-op.
        let d3 = Sha256::fill(3u8);
        assert!(!db.delete(d3).await.unwrap());
        assert_eq!(db.bounds().end, 13);

        // Make sure closing/reopening gets us back to the same state.
        let db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();
        assert_eq!(db.bounds().end, 14);
        let root = db.root();
        drop(db);
        let db = next_db().await;
        assert_eq!(db.bounds().end, 14);
        assert_eq!(db.root(), root);
        let mut db = db.into_mutable();

        // Re-activate the keys by updating them.
        db.update(d1, v1).await.unwrap();
        db.update(d2, v2).await.unwrap();
        db.delete(d1).await.unwrap();
        db.update(d2, v1).await.unwrap();
        db.update(d1, v2).await.unwrap();

        // Make sure last_commit is updated by changing the metadata back to None.
        let db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();

        // Confirm close/reopen gets us back to the same state.
        assert_eq!(db.bounds().end, 23);
        let root = db.root();
        let db = next_db().await;

        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().end, 23);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        let db = db.into_mutable();
        let mut db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();

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
            let db = open_fixed_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_fixed_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_variable_db(ctx))
            })
            .await;
        });
    }

    /// Test recovery on non-empty db.
    pub(crate) async fn test_any_db_non_empty_recovery<D: TestableAnyDb<V>, V: Clone>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) {
        const ELEMENTS: u64 = 1000;

        let mut db = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value(i * 1000);
            db.update(k, v).await.unwrap();
        }
        let mut db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        let root = db.root();
        let op_count = db.bounds().end;
        let inactivity_floor_loc = db.inactivity_floor_loc();

        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.bounds().end, op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.bounds().end, op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        let mut dirty = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            dirty.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.with_label("reopen3")).await;
        assert_eq!(db.bounds().end, op_count);
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
        assert_eq!(db.bounds().end, op_count);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let _ = db.commit(None).await.unwrap();
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.bounds().end > op_count);
        assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test recovery on empty db.
    pub(crate) async fn test_any_db_empty_recovery<D: TestableAnyDb<V>, V: Clone>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) {
        let root = db.root();

        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.bounds().end, 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.bounds().end, 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        drop(db);
        let db = reopen_db(context.with_label("reopen3")).await;
        assert_eq!(db.bounds().end, 1);
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
        assert_eq!(db.bounds().end, 1);
        assert_eq!(db.root(), root);

        let mut db = db.into_mutable();
        for i in 0u64..1000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = make_value((i + 1) * 10000);
            db.update(k, v).await.unwrap();
        }
        let db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();
        drop(db);
        let db = reopen_db(context.with_label("reopen5")).await;
        assert!(db.bounds().end > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test making multiple commits, one of which deletes a key from a previous commit.
    pub(crate) async fn test_any_db_multiple_commits_delete_replayed<D: TestableAnyDb<V>, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
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
}
