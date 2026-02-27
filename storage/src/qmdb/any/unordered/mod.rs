#[cfg(any(test, feature = "test-traits"))]
use crate::qmdb::any::states::TestableAny;
use crate::{
    index::Unordered as Index,
    journal::contiguous::{Contiguous, Mutable, Reader},
    kv::{self, Batchable},
    mmr::Location,
    qmdb::{
        any::{
            db::{AuthenticatedLog, Db},
            ValueEncoding,
        },
        build_snapshot_from_log, delete_known_loc,
        operation::{Committable, Key, Operation as OperationTrait},
        update_known_loc, Error,
    },
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
#[cfg(any(test, feature = "test-traits"))]
use core::ops::Range;
use futures::future::try_join_all;
use std::collections::BTreeMap;

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Unordered as Update, Unordered as Operation};

impl<
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > Db<E, C, I, H, Update<K, V>>
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

        let reader = self.log.reader().await;
        for loc in locs {
            let op = reader.read(*loc).await?;
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
        K: Key,
        V: ValueEncoding,
        C: Mutable<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > Db<E, C, I, H, Update<K, V>>
where
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
{
    /// Performs a batch update, invoking the callback for each resulting operation. The first
    /// argument of the callback is the activity status of the operation, and the second argument is
    /// the location of the operation it inactivates (if any).
    pub(crate) async fn write_batch_with_callback<F>(
        &mut self,
        iter: impl IntoIterator<Item = (K, Option<V::Value>)>,
        mut callback: F,
    ) -> Result<(), Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        // We use a BTreeMap here to collect the updates to ensure determinism in iteration order.
        let mut updates = BTreeMap::new();
        let iter = iter.into_iter();
        let mut locations = Vec::with_capacity(iter.size_hint().0);
        for (key, value) in iter {
            let iter = self.snapshot.get(&key);
            locations.extend(iter.copied());
            updates.insert(key, value);
        }

        // Concurrently look up all possible matching locations.
        locations.sort();
        locations.dedup();
        let results = {
            let reader = self.log.reader().await;
            let futures = locations.iter().map(|loc| reader.read(**loc));
            try_join_all(futures).await?
        };

        // Process the deletes & updates of existing keys, which must appear in the results.
        for (op, old_loc) in (results.into_iter()).zip(locations) {
            let key = op.key().expect("updates should have a key");
            let Some(update) = updates.remove(key) else {
                continue; // translated key collision
            };

            let new_loc = self.log.size().await;
            if let Some(value) = update {
                update_known_loc(&mut self.snapshot, key, old_loc, new_loc);
                self.log
                    .append(&Operation::Update(Update(key.clone(), value)))
                    .await?;
                callback(true, Some(old_loc));
            } else {
                delete_known_loc(&mut self.snapshot, key, old_loc);
                self.log.append(&Operation::Delete(key.clone())).await?;
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
            self.snapshot.insert(&key, self.log.size().await);
            self.log
                .append(&Operation::Update(Update(key, value)))
                .await?;
            callback(true, None);
            self.active_keys += 1;
        }

        Ok(())
    }

    /// Writes a batch of key-value pairs to the database.
    ///
    /// For each item in the iterator:
    /// - `(key, Some(value))` updates or creates the key with the given value
    /// - `(key, None)` deletes the key
    pub async fn write_batch(
        &mut self,
        iter: impl IntoIterator<Item = (K, Option<V::Value>)>,
    ) -> Result<(), Error> {
        self.write_batch_with_callback(iter, |_, _| {}).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item = O>,
        O: OperationTrait + Codec + Committable + Send + Sync,
        I: Index<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Db<E, C, I, H, U>
{
    /// Returns an [Db] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last operation is assumed to be a commit.
    pub(crate) async fn from_components(
        inactivity_floor_loc: Location,
        log: AuthenticatedLog<E, C, H>,
        mut snapshot: I,
    ) -> Result<Self, Error> {
        let (active_keys, last_commit_loc) = {
            let reader = log.reader().await;
            let active_keys =
                build_snapshot_from_log(inactivity_floor_loc, &reader, &mut snapshot, |_, _| {})
                    .await?;
            let last_commit_loc = Location::new_unchecked(
                reader
                    .bounds()
                    .end
                    .checked_sub(1)
                    .expect("commit should exist"),
            );
            assert!(reader.read(*last_commit_loc).await?.is_commit());
            (active_keys, last_commit_loc)
        };

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot,
            last_commit_loc,
            steps: 0,
            active_keys,
            _update: core::marker::PhantomData,
        })
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
    > kv::Gettable for Db<E, C, I, H, Update<K, V>>
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

impl<E, K, V, C, I, H> Batchable for Db<E, C, I, H, Update<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>>,
    I: Index<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V>: CodecShared,
{
    async fn write_batch<'a, Iter>(&'a mut self, iter: Iter) -> Result<(), Error>
    where
        Iter: IntoIterator<Item = (K, Option<V::Value>)> + Send + 'a,
        Iter::IntoIter: Send,
    {
        self.write_batch(iter).await
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> TestableAny for Db<E, C, I, H, Update<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + crate::Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: PartialEq + std::fmt::Debug + Send + Sync + 'static,
{
    type Key = K;
    type Value = V::Value;
    type Digest = H::Digest;
    type Operation = Operation<K, V>;

    fn steps(&self) -> u64 {
        self.steps
    }

    async fn commit(
        &mut self,
        metadata: Option<V::Value>,
    ) -> Result<std::ops::Range<Location>, crate::qmdb::Error> {
        self.commit(metadata).await
    }

    async fn size(&self) -> Location {
        self.log.size().await
    }

    async fn bounds(&self) -> std::ops::Range<Location> {
        let bounds = self.log.reader().await.bounds();
        Location::new_unchecked(bounds.start)..Location::new_unchecked(bounds.end)
    }

    async fn get(&self, key: &K) -> Result<Option<V::Value>, crate::qmdb::Error> {
        crate::kv::Gettable::get(self, key).await
    }

    async fn write_batch(
        &mut self,
        batch: Vec<(K, Option<V::Value>)>,
    ) -> Result<(), crate::qmdb::Error> {
        crate::kv::Batchable::write_batch(self, batch).await
    }

    async fn get_metadata(&self) -> Result<Option<V::Value>, crate::qmdb::Error> {
        crate::qmdb::store::LogStore::get_metadata(self).await
    }

    fn root(&self) -> H::Digest {
        self.root()
    }

    async fn proof(
        &self,
        start_loc: Location,
        max_ops: std::num::NonZeroU64,
    ) -> Result<(crate::mmr::Proof<H::Digest>, Vec<Operation<K, V>>), crate::qmdb::Error> {
        crate::qmdb::store::MerkleizedStore::proof(self, start_loc, max_ops).await
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: std::num::NonZeroU64,
    ) -> Result<(crate::mmr::Proof<H::Digest>, Vec<Operation<K, V>>), crate::qmdb::Error> {
        crate::qmdb::store::MerkleizedStore::historical_proof(
            self,
            historical_size,
            start_loc,
            max_ops,
        )
        .await
    }

    async fn sync(&self) -> Result<(), crate::qmdb::Error> {
        crate::Persistable::sync(self).await
    }

    async fn prune(&mut self, loc: Location) -> Result<(), crate::qmdb::Error> {
        Self::prune(self, loc).await
    }

    async fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn destroy(self) -> Result<(), crate::qmdb::Error> {
        Self::destroy(self).await
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> crate::qmdb::any::states::CleanAny for Db<E, C, I, H, Update<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + crate::Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: PartialEq + std::fmt::Debug + Send + Sync + 'static,
{
    type Mutable = Self;

    fn into_mutable(self) -> Self::Mutable {
        self
    }
}

#[cfg(any(test, feature = "test-traits"))]
impl<E, K, V, C, I, H> crate::qmdb::any::states::MutableAny for Db<E, C, I, H, Update<K, V>>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + crate::Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: PartialEq + std::fmt::Debug + Send + Sync + 'static,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Clean = Self;

    #[allow(clippy::manual_async_fn, clippy::needless_borrow)]
    fn commit(
        self,
        metadata: Option<V::Value>,
    ) -> impl std::future::Future<Output = Result<(Self::Clean, Range<Location>), crate::qmdb::Error>>
           + Send {
        async move {
            let mut db = self;
            let range = (&mut db).commit(metadata).await?;
            Ok::<_, crate::qmdb::Error>((db, range))
        }
    }

    fn steps(&self) -> u64 {
        self.steps
    }
}
