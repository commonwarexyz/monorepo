use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, MutableContiguous, PersistableContiguous},
    mmr::{
        mem::{Dirty, State},
        Location,
    },
    qmdb::{
        any::{
            db::Db, value::ValueEncoding, CleanAny, DirtyAny, UnorderedOperation, UnorderedUpdate,
        },
        create_key, delete_key, delete_known_loc,
        operation::Operation as OperationTrait,
        store::Batchable,
        update_key, update_known_loc, Error,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use std::{collections::BTreeMap, ops::Range};

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndex<Value = Location>,
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
        V: ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndex<Value = Location>,
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
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    V: ValueEncoding,
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
        V: ValueEncoding,
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndex<Value = Location>,
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
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
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
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
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
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
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
        V: ValueEncoding,
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndex<Value = Location>,
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
        V: ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: UnorderedIndex<Value = Location>,
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
