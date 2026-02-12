use crate::{
    index::Ordered as Index,
    journal::contiguous::{Contiguous, Mutable, Reader},
    kv::{self, Batchable},
    mmr::Location,
    qmdb::{
        any::{db::Db, ValueEncoding},
        delete_known_loc,
        operation::Operation as OperationTrait,
        update_known_loc, DurabilityState, Error, MerkleizationState, NonDurable, Unmerkleized,
    },
};
#[cfg(any(test, feature = "test-traits"))]
use crate::{
    qmdb::{
        any::states::{CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny},
        Durable, Merkleized,
    },
    Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
#[cfg(any(test, feature = "test-traits"))]
use core::ops::Range;
use futures::{
    future::try_join_all,
    stream::{self, Stream},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Ordered as Update, Ordered as Operation};

/// Type alias for a location and its associated key data.
type LocatedKey<K, V> = Option<(Location, Update<K, V>)>;

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
    V::Value: Send + Sync,
{
    async fn get_update_op(
        reader: &impl Reader<Item = Operation<K, V>>,
        loc: Location,
    ) -> Result<Update<K, V>, Error> {
        match reader.read(*loc).await? {
            Operation::Update(key_data) => Ok(key_data),
            _ => unreachable!("expected update operation at location {}", loc),
        }
    }

    /// Whether the span defined by `span_start` and `span_end` contains `key`.
    pub fn span_contains(span_start: &K, span_end: &K, key: &K) -> bool {
        if span_start >= span_end {
            // cyclic span case
            if key >= span_start || key < span_end {
                return true;
            }
        } else {
            // normal span case
            if key >= span_start && key < span_end {
                return true;
            }
        }

        false
    }

    /// Find the span produced by the provided locations that contains `key`, if any.
    async fn find_span(
        &self,
        locs: impl IntoIterator<Item = Location>,
        key: &K,
    ) -> Result<LocatedKey<K, V>, Error> {
        let reader = self.log.reader().await;
        for loc in locs {
            // Iterate over conflicts in the snapshot entry to find the span.
            let data = Self::get_update_op(&reader, loc).await?;
            if Self::span_contains(&data.key, &data.next_key, key) {
                return Ok(Some((loc, data)));
            }
        }

        Ok(None)
    }

    /// Get the operation that defines the span whose range contains `key`, or None if the DB is
    /// empty.
    pub async fn get_span(&self, key: &K) -> Result<LocatedKey<K, V>, Error> {
        if self.is_empty() {
            return Ok(None);
        }

        // If the translated key is in the snapshot, get a cursor to look for the key.
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location> = self.snapshot.get(key).copied().collect();
        let span = self.find_span(locs, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        let Some((iter, _)) = self.snapshot.prev_translated_key(key) else {
            // DB is empty.
            return Ok(None);
        };

        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location> = iter.copied().collect();
        let span = self
            .find_span(locs, key)
            .await?
            .expect("a span that includes any given key should always exist if db is non-empty");

        Ok(Some(span))
    }

    /// Get the (value, next-key) pair of `key` in the db, or None if it has no value.
    pub async fn get_all(&self, key: &K) -> Result<Option<(V::Value, K)>, Error> {
        self.get_with_loc(key)
            .await
            .map(|res| res.map(|(data, _)| (data.value, data.next_key)))
    }

    /// Returns the key data for `key` with its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(Update<K, V>, Location)>, Error> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location> = self.snapshot.get(key).copied().collect();
        let reader = self.log.reader().await;
        for loc in locs {
            let op = reader.read(*loc).await?;
            assert!(
                op.is_update(),
                "location does not reference update operation. loc={loc}"
            );
            if op.key().expect("update operation must have key") == key {
                let Operation::Update(data) = op else {
                    unreachable!("expected update operation");
                };
                return Ok(Some((data, loc)));
            }
        }

        Ok(None)
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.get_with_loc(key)
            .await
            .map(|op| op.map(|(data, _)| data.value))
    }

    /// Streams all active (key, value) pairs in the database in key order, starting from the first
    /// active key greater than or equal to `start`.
    pub async fn stream_range<'a>(
        &'a self,
        start: K,
    ) -> Result<impl Stream<Item = Result<(K, V::Value), Error>> + 'a, Error>
    where
        V: 'a,
        V::Value: Send + Sync,
    {
        let start_iter = self.snapshot.get(&start);
        let mut init_pending = self.fetch_all_updates(start_iter).await?;
        init_pending.retain(|x| x.key >= start);

        Ok(stream::unfold(
            (start, init_pending),
            move |(driver_key, mut pending): (K, Vec<Update<K, V>>)| async move {
                if !pending.is_empty() {
                    let item = pending.pop().expect("pending is not empty");
                    return Some((Ok((item.key, item.value)), (driver_key, pending)));
                }

                let Some((iter, wrapped)) = self.snapshot.next_translated_key(&driver_key) else {
                    return None; // DB is empty
                };
                if wrapped {
                    return None; // End of DB
                }

                // TODO(https://github.com/commonwarexyz/monorepo/issues/2527): concurrently
                // fetch a much larger batch of "pending" keys.
                match self.fetch_all_updates(iter).await {
                    Ok(mut pending) => {
                        let item = pending.pop().expect("pending is not empty");
                        let key = item.key.clone();
                        Some((Ok((item.key, item.value)), (key, pending)))
                    }
                    Err(e) => Some((Err(e), (driver_key, pending))),
                }
            },
        ))
    }

    /// Fetches all update operations corresponding to the input locations, returning the result in
    /// reverse order of the keys.
    async fn fetch_all_updates(
        &self,
        locs: impl IntoIterator<Item = &Location>,
    ) -> Result<Vec<Update<K, V>>, Error> {
        let reader = self.log.reader().await;
        let futures = locs
            .into_iter()
            .map(|loc| Self::get_update_op(&reader, *loc));
        let mut updates = try_join_all(futures).await?;
        updates.sort_by(|a, b| b.key.cmp(&a.key));

        Ok(updates)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Mutable<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
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
        // Collect all the possible matching `locations` for any referenced key, while retaining
        // each item in the batch in a `mutations` map.
        let mut mutations = BTreeMap::new();
        let iter = iter.into_iter();
        let mut locations = Vec::with_capacity(iter.size_hint().0);
        for (key, value) in iter {
            let iter = self.snapshot.get(&key);
            locations.extend(iter.copied());
            mutations.insert(key, value);
        }

        // Concurrently look up all possible matching locations.
        locations.sort();
        locations.dedup();
        let results = {
            let reader = self.log.reader().await;
            let futures = locations
                .iter()
                .map(|loc| Self::get_update_op(&reader, *loc));
            try_join_all(futures).await?
        };

        // A set of possible "next_key" values for any keys whose next_key value will need to be
        // updated.
        let mut possible_next = BTreeSet::new();
        // A set of possible previous keys to any new or deleted keys.
        let mut possible_previous = BTreeMap::new();

        // We divide keys in the batch into three disjoint sets:
        //   - `deleted`
        //   - `created`
        //   - `updated`
        //
        // Populate the the deleted and updated sets, and for deleted keys only, immediately update
        // the log and snapshot.
        let mut deleted = Vec::new();
        let mut updated = BTreeMap::new();
        for (key_data, old_loc) in (results.into_iter()).zip(locations) {
            let key = key_data.key;
            possible_previous.insert(key.clone(), (key_data.value, old_loc));
            possible_next.insert(key_data.next_key);

            let Some(mutation) = mutations.remove(&key) else {
                // Due to translated key collisions, we may look up keys that aren't in the
                // mutations set. Note that these could still end up next or previous keys to other
                // keys in the batch, so they are still added to these sets above.
                continue;
            };

            if let Some(new_value) = mutation {
                // This is an update of an existing key.
                updated.insert(key.clone(), (new_value, old_loc));
            } else {
                // This is a delete of an existing key.
                deleted.push(key.clone());

                // Update the log and snapshot.
                delete_known_loc(&mut self.snapshot, &key, old_loc);
                self.log.append(Operation::Delete(key)).await?;
                callback(false, Some(old_loc));

                // Each delete reduces the active key count by one and inactivates that key.
                self.active_keys -= 1;
                self.durable_state.steps += 1;
            }
        }

        // Any key remaining in `mutations` must be a new key so move it to the created map.
        let mut created = BTreeMap::new();
        for (key, value) in mutations {
            let Some(value) = value else {
                continue; // can happen from attempt to delete a non-existent key
            };
            created.insert(key.clone(), value);

            // Any newly created key must be a next_key for some remaining key.
            possible_next.insert(key);
        }

        // Complete the `possible_previous` and `possible_next` sets by including entries from the
        // previous _translated_ key for any created or deleted key.
        let mut locations = Vec::new();
        for key in deleted.iter().chain(created.keys()) {
            let Some((iter, _)) = self.snapshot.prev_translated_key(key) else {
                continue;
            };
            locations.extend(iter.copied());
        }
        locations.sort();
        locations.dedup();
        let results = {
            let reader = self.log.reader().await;
            let futures = locations.iter().map(|loc| reader.read(loc.as_u64()));
            try_join_all(futures).await?
        };

        for (op, old_loc) in (results.into_iter()).zip(locations) {
            let Operation::Update(key_data) = op else {
                unreachable!("updates should have key data");
            };
            possible_next.insert(key_data.next_key);
            possible_previous.insert(key_data.key, (key_data.value, old_loc));
        }

        // Remove deleted keys from the possible_* sets.
        for key in deleted.iter() {
            possible_previous.remove(key);
            possible_next.remove(key);
        }

        // Apply the updates of existing keys.
        let mut already_updated = BTreeSet::new();
        for (key, (value, loc)) in updated {
            let new_loc = self.log.size().await;
            update_known_loc(&mut self.snapshot, &key, loc, new_loc);

            let next_key = find_next_key(&key, &possible_next);
            let op = Operation::Update(Update {
                key: key.clone(),
                value: value.clone(),
                next_key,
            });
            self.log.append(op).await?;
            callback(true, Some(loc));

            // Each update of an existing key inactivates its previous location.
            self.durable_state.steps += 1;
            already_updated.insert(key);
        }

        // Create each new key, and update its previous key if it hasn't already been updated.
        for (key, value) in created {
            let new_loc = self.log.size().await;
            self.snapshot.insert(&key, new_loc);
            let next_key = find_next_key(&key, &possible_next);
            let op = Operation::Update(Update {
                key: key.clone(),
                value: value.clone(),
                next_key,
            });

            // Each newly created key increases the active key count.
            self.log.append(op).await?;
            callback(true, None);
            self.active_keys += 1;

            // Update the next_key value of its previous key (unless there are no existing keys).
            if possible_previous.is_empty() {
                continue;
            }
            let (prev_key, (prev_value, prev_loc)) = find_prev_key(&key, &possible_previous);
            if already_updated.contains(prev_key) {
                continue;
            }
            already_updated.insert(prev_key.clone());

            let new_loc = self.log.size().await;
            update_known_loc(&mut self.snapshot, prev_key, *prev_loc, new_loc);
            let next_key = find_next_key(prev_key, &possible_next);
            let op = Operation::Update(Update {
                key: prev_key.clone(),
                value: prev_value.clone(),
                next_key,
            });
            self.log.append(op).await?;
            callback(true, Some(*prev_loc));

            // Each key whose next-key value is updated inactivates its previous location.
            self.durable_state.steps += 1;
        }

        if possible_next.is_empty() || possible_previous.is_empty() {
            return Ok(());
        }

        // Update the previous key of each deleted key if it hasn't already been updated.
        for key in deleted.iter() {
            let (prev_key, (prev_value, prev_loc)) = find_prev_key(key, &possible_previous);
            if already_updated.contains(prev_key) {
                continue;
            }
            already_updated.insert(prev_key.clone());

            let new_loc = self.log.size().await;
            update_known_loc(&mut self.snapshot, prev_key, *prev_loc, new_loc);
            let next_key = find_next_key(prev_key, &possible_next);
            let op = Operation::Update(Update {
                key: prev_key.clone(),
                value: prev_value.clone(),
                next_key,
            });
            self.log.append(op).await?;
            callback(true, Some(*prev_loc));

            // Each key whose next-key value is updated inactivates its previous location.
            self.durable_state.steps += 1;
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
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location> + Send + Sync + 'static,
        H: Hasher,
        M: MerkleizationState<DigestOf<H>> + Send + Sync,
        D: DurabilityState,
    > kv::Gettable for Db<E, C, I, H, Update<K, V>, M, D>
where
    Operation<K, V>: CodecShared,
{
    type Key = K;
    type Value = V::Value;
    type Error = Error;

    fn get(
        &self,
        key: &Self::Key,
    ) -> impl std::future::Future<Output = Result<Option<Self::Value>, Self::Error>> {
        self.get(key)
    }
}

/// Returns the next key to `key` within `possible_next`. The result will "cycle around" to the
/// first key if `key` is the last key.
///
/// # Panics
///
/// Panics if `possible_next` is empty.
fn find_next_key<K: Ord + Clone>(key: &K, possible_next: &BTreeSet<K>) -> K {
    let next = possible_next
        .range((Bound::Excluded(key), Bound::Unbounded))
        .next();
    if let Some(next) = next {
        return next.clone();
    }
    possible_next
        .first()
        .expect("possible_next should not be empty")
        .clone()
}

/// Returns the previous key to `key` within `possible_previous`. The result will "cycle around"
/// to the last key if `key` is the first key.
///
/// # Panics
///
/// Panics if `possible_previous` is empty.
fn find_prev_key<'a, K: Ord, V>(key: &K, possible_previous: &'a BTreeMap<K, V>) -> (&'a K, &'a V) {
    let prev = possible_previous
        .range((Bound::Unbounded, Bound::Excluded(key)))
        .next_back();
    if let Some(prev) = prev {
        return prev;
    }
    possible_previous
        .iter()
        .next_back()
        .expect("possible_previous should not be empty")
}

impl<E, K, V, C, I, H> Batchable for Db<E, C, I, H, Update<K, V>, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>>,
    I: Index<Value = Location> + 'static,
    H: Hasher,
    Operation<K, V>: Codec,
    V::Value: Send + Sync,
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
impl<E, K, V, C, I, H> CleanAny for Db<E, C, I, H, Update<K, V>, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
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
impl<E, K, V, C, I, H> UnmerkleizedDurableAny
    for Db<E, C, I, H, Update<K, V>, Unmerkleized, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
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
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
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
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = crate::journal::Error>,
    I: Index<Value = Location> + 'static,
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
    ) -> Result<(Self::Durable, Range<Location>), Error> {
        self.commit(metadata).await
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        Ok(self.into_merkleized())
    }

    fn steps(&self) -> u64 {
        self.durable_state.steps
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        kv::Gettable as _,
        qmdb::store::{LogStore as _, MerkleizedStore},
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_runtime::deterministic::Context;
    use commonware_utils::sequence::FixedBytes;
    use core::{future::Future, pin::Pin};

    /// Helper trait for testing Any databases with FixedBytes<4> keys.
    /// Used for edge case tests that require specific key patterns.
    pub(crate) trait FixedBytesDb:
        CleanAny<Key = FixedBytes<4>> + MerkleizedStore<Value = Digest, Digest = Digest>
    {
    }
    impl<T> FixedBytesDb for T where
        T: CleanAny<Key = FixedBytes<4>> + MerkleizedStore<Value = Digest, Digest = Digest>
    {
    }

    /// Helper trait for testing Any databases with Digest keys.
    /// Used for generic tests that can be shared with partitioned variants.
    pub(crate) trait DigestDb:
        CleanAny<Key = Digest> + MerkleizedStore<Value = Digest, Digest = Digest>
    {
    }
    impl<T> DigestDb for T where
        T: CleanAny<Key = Digest> + MerkleizedStore<Value = Digest, Digest = Digest>
    {
    }

    /// Test an empty database with Digest keys.
    ///
    /// This function is pub(crate) so partitioned variants can call it.
    pub(crate) async fn test_digest_ordered_any_db_empty<D: DigestDb>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        assert_eq!(db.size().await, 1);
        assert!(db.get_metadata().await.unwrap().is_none());
        assert!(matches!(
            db.prune(db.inactivity_floor_loc().await).await,
            Ok(())
        ));

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let d1 = Sha256::fill(1u8);
        let d2 = Sha256::fill(2u8);
        let root = db.root();
        let mut db = db.into_mutable();
        db.write_batch([(d1, Some(d2))]).await.unwrap();
        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.size().await, 1);

        // Test calling commit on an empty db.
        let metadata = Sha256::fill(3u8);
        let db = db.into_mutable();
        let (db, range) = db.commit(Some(metadata)).await.unwrap();
        let mut db = db.into_merkleized().await.unwrap();
        assert_eq!(range.start, Location::new_unchecked(1));
        assert_eq!(range.end, Location::new_unchecked(2));
        assert_eq!(db.size().await, 2); // floor op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(
            db.prune(db.inactivity_floor_loc().await).await,
            Ok(())
        ));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.size().await, 2);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
        let mut mutable_db = db.into_mutable();
        for _ in 1..100 {
            let (durable_db, _) = mutable_db.commit(None).await.unwrap();
            assert_eq!(
                durable_db.size().await - 1,
                durable_db.inactivity_floor_loc().await
            );
            mutable_db = durable_db.into_mutable();
        }
        let db = mutable_db.commit(None).await.unwrap().0;
        db.into_merkleized().await.unwrap().destroy().await.unwrap();
    }

    /// Test basic CRUD and commit behavior with Digest keys.
    ///
    /// This function is pub(crate) so partitioned variants can call it.
    pub(crate) async fn test_digest_ordered_any_db_basic<D: DigestDb>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let key1 = Sha256::fill(1u8);
        let key2 = Sha256::fill(2u8);
        let val1 = Sha256::fill(3u8);
        let val2 = Sha256::fill(4u8);

        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.into_mutable();
        assert!(db.get(&key1).await.unwrap().is_none());
        db.write_batch([(key1, Some(val1))]).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.get(&key2).await.unwrap().is_none());
        db.write_batch([(key2, Some(val2))]).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        db.write_batch([(key1, None)]).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        db.write_batch([(key1, Some(new_val))]).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        db.write_batch([(key2, Some(new_val))]).await.unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // 2 new keys (4 ops), 2 updates (2 ops), 1 deletion (2 ops) + 1 initial commit = 9 ops
        assert_eq!(db.size().await, 9);
        assert_eq!(db.inactivity_floor_loc().await, Location::new_unchecked(0));
        let (durable_db, _) = db.commit(None).await.unwrap();
        let mut db = durable_db.into_merkleized().await.unwrap().into_mutable();

        // Make sure key1 is already active.
        assert!(db.get(&key1).await.unwrap().is_some());

        // Delete all keys.
        assert!(db.get(&key1).await.unwrap().is_some());
        db.write_batch([(key1, None)]).await.unwrap();
        assert!(db.get(&key2).await.unwrap().is_some());
        db.write_batch([(key2, None)]).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();

        // Multiple deletions of the same key should be a no-op.
        let prev_op_count = db.size().await;
        let db = db.into_mutable();
        // Note: commit always adds a floor op, so op_count will increase by 1 after commit.
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.size().await, prev_op_count);

        // Deletions of non-existent keys should be a no-op.
        let key3 = Sha256::fill(6u8);
        assert!(db.get(&key3).await.unwrap().is_none());
        assert_eq!(db.size().await, prev_op_count);

        // Make sure closing/reopening gets us back to the same state.
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();
        let op_count = db.size().await;
        let root = db.root();
        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.size().await, op_count);
        assert_eq!(db.root(), root);
        let mut db = db.into_mutable();

        // Re-activate the keys by updating them.
        db.write_batch([(key1, Some(val1))]).await.unwrap();
        db.write_batch([(key2, Some(val2))]).await.unwrap();
        db.write_batch([(key1, None)]).await.unwrap();
        db.write_batch([(key2, Some(val1))]).await.unwrap();
        db.write_batch([(key1, Some(val2))]).await.unwrap();

        let db = db
            .commit(None)
            .await
            .unwrap()
            .0
            .into_merkleized()
            .await
            .unwrap();

        // Confirm close/reopen gets us back to the same state.
        let op_count = db.size().await;
        let root = db.root();
        let db = reopen_db(context.with_label("reopen2")).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.size().await, op_count);

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

        // Pruning inactive ops should not affect current state or root.
        let root = db.root();
        db.prune(db.inactivity_floor_loc().await).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_ordered_any_db_empty<D: FixedBytesDb>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        assert_eq!(db.bounds().await.end, 1);
        assert!(db.get_metadata().await.unwrap().is_none());
        assert!(matches!(
            db.prune(db.inactivity_floor_loc().await).await,
            Ok(())
        ));

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let d1 = FixedBytes::from([1u8; 4]);
        let d2 = Sha256::fill(2u8);
        let root = db.root();
        let mut db = db.into_mutable();
        db.write_batch([(d1, Some(d2))]).await.unwrap();
        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, 1);

        // Test calling commit on an empty db.
        let metadata = Sha256::fill(3u8);
        let db = db.into_mutable();
        let (db, range) = db.commit(Some(metadata)).await.unwrap();
        let mut db = db.into_merkleized().await.unwrap();
        assert_eq!(range.start, Location::new_unchecked(1));
        assert_eq!(range.end, Location::new_unchecked(2));
        assert_eq!(db.bounds().await.end, 2); // floor op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(
            db.prune(db.inactivity_floor_loc().await).await,
            Ok(())
        ));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let db = reopen_db(context.with_label("reopen2")).await;
        assert_eq!(db.bounds().await.end, 2);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
        let mut mutable_db = db.into_mutable();
        for _ in 1..100 {
            let (durable_db, _) = mutable_db.commit(None).await.unwrap();
            assert_eq!(
                durable_db.bounds().await.end - 1,
                durable_db.inactivity_floor_loc().await
            );
            mutable_db = durable_db.into_mutable();
        }
        let db = mutable_db.commit(None).await.unwrap().0;
        db.into_merkleized().await.unwrap().destroy().await.unwrap();
    }

    pub(crate) async fn test_ordered_any_db_basic<D: FixedBytesDb>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) {
        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let key1 = FixedBytes::from([1u8; 4]);
        let key2 = FixedBytes::from([2u8; 4]);
        let val1 = Sha256::fill(3u8);
        let val2 = Sha256::fill(4u8);

        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.into_mutable();
        assert!(db.get(&key1).await.unwrap().is_none());
        db.write_batch([(key1.clone(), Some(val1))]).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.get(&key2).await.unwrap().is_none());
        db.write_batch([(key2.clone(), Some(val2))]).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        db.write_batch([(key1.clone(), None)]).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        db.write_batch([(key1.clone(), Some(new_val))])
            .await
            .unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        db.write_batch([(key2.clone(), Some(new_val))])
            .await
            .unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // 2 new keys (4 ops), 2 updates (2 ops), 1 deletion (2 ops) + 1 initial commit = 9 ops
        assert_eq!(db.bounds().await.end, 9);
        assert_eq!(db.inactivity_floor_loc().await, Location::new_unchecked(0));
        let (durable_db, _) = db.commit(None).await.unwrap();
        let mut db = durable_db.into_merkleized().await.unwrap().into_mutable();

        // Make sure key1 is already active.
        assert!(db.get(&key1).await.unwrap().is_some());

        // Delete all keys.
        assert!(db.get(&key1).await.unwrap().is_some());
        db.write_batch([(key1.clone(), None)]).await.unwrap();
        assert!(db.get(&key2).await.unwrap().is_some());
        db.write_batch([(key2.clone(), None)]).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();

        // Multiple deletions of the same key should be a no-op.
        let prev_op_count = db.bounds().await.end;
        let db = db.into_mutable();
        // Note: commit always adds a floor op, so op_count will increase by 1 after commit.
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.bounds().await.end, prev_op_count);

        // Deletions of non-existent keys should be a no-op.
        let key3 = FixedBytes::from([6u8; 4]);
        assert!(db.get(&key3).await.unwrap().is_none());
        assert_eq!(db.bounds().await.end, prev_op_count);

        // Make sure closing/reopening gets us back to the same state.
        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();
        let op_count = db.bounds().await.end;
        let root = db.root();
        let db = reopen_db(context.with_label("reopen1")).await;
        assert_eq!(db.bounds().await.end, op_count);
        assert_eq!(db.root(), root);
        let mut db = db.into_mutable();

        // Re-activate the keys by updating them.
        db.write_batch([(key1.clone(), Some(val1))]).await.unwrap();
        db.write_batch([(key2.clone(), Some(val2))]).await.unwrap();
        db.write_batch([(key1.clone(), None)]).await.unwrap();
        db.write_batch([(key2.clone(), Some(val1))]).await.unwrap();
        db.write_batch([(key1.clone(), Some(val2))]).await.unwrap();

        let db = db.commit(None).await.unwrap().0;
        let db = db.into_merkleized().await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        let op_count = db.bounds().await.end;
        let root = db.root();
        let db = reopen_db(context.with_label("reopen2")).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, op_count);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        let db = db.into_mutable();
        let db = db.commit(None).await.unwrap().0;
        let mut db = db.into_merkleized().await.unwrap();

        assert!(db.root() != root);

        // Pruning inactive ops should not affect current state or root.
        let root = db.root();
        db.prune(db.inactivity_floor_loc().await).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Builds a db with colliding keys to make sure the "cycle around when there are translated
    /// key collisions" edge case is exercised.
    pub(crate) async fn test_ordered_any_update_collision_edge_case<D: FixedBytesDb>(db: D) {
        // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
        // collisions.
        let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
        let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
        // Our last must precede the others to trigger previous-key cycle around.
        let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 0u8, 0u8]);
        let val = Sha256::fill(1u8);

        let mut db = db.into_mutable();
        db.write_batch([(key1.clone(), Some(val))]).await.unwrap();
        db.write_batch([(key2.clone(), Some(val))]).await.unwrap();
        db.write_batch([(key3.clone(), Some(val))]).await.unwrap();

        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

        let db = db.commit(None).await.unwrap().0;
        db.into_merkleized().await.unwrap().destroy().await.unwrap();
    }
}
