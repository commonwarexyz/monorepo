use crate::{
    index::{Cursor as _, Ordered as Index},
    journal::{
        authenticated,
        contiguous::{Contiguous, MutableContiguous, PersistableContiguous},
    },
    mmr::{
        mem::{Clean, Dirty, State},
        Location, Proof,
    },
    qmdb::{
        any::{
            ordered::{self, KeyData as OrderedKeyData},
            unordered::{self},
            CleanAny, DirtyAny, ValueEncoding, VariableValue,
        },
        build_snapshot_from_log, create_key, delete_key, delete_known_loc,
        operation::{Committable, Operation as _},
        store::{Batchable, LogStore},
        update_key, update_known_loc, Error, FloorHelper,
    },
    AuthenticatedBitMap,
};
use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::{num::NonZeroU64, ops::Range};
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};
use tracing::debug;

type OrderedOperation<K, V> = ordered::Operation<K, V>;
type UnorderedOperation<K, V> = unordered::Operation<K, V>;

type AuthenticatedLog<E, C, H, S = Clean<DigestOf<H>>> = authenticated::Journal<E, C, H, S>;

/// Type alias for a location and its associated key data.
type LocatedKey<K, V> = Option<(Location, OrderedKeyData<K, V>)>;

/// The return type of the `Any::update_loc` method.
enum UpdateLocResult<K: Array, V: VariableValue> {
    /// The key already exists in the snapshot. The wrapped value is its next-key.
    Exists(K),

    /// The key did not already exist in the snapshot. The wrapped key data is for the first
    /// preceding key that does exist in the snapshot.
    NotExists(OrderedKeyData<K, V>),
}

/// An indexed, authenticated log of ordered database operations.
pub struct IndexedLog<
    E: Storage + Clock + Metrics,
    Op: Codec,
    C: Contiguous<Item = Op>,
    I: Index,
    H: Hasher,
    S: State<DigestOf<H>> = Clean<DigestOf<H>>,
> {
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    pub(crate) log: AuthenticatedLog<E, C, H, S>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(crate) inactivity_floor_loc: Location,

    /// The location of the last commit operation (if any exists).
    pub(crate) last_commit: Option<Location>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// - Only references [Operation::Update]s.
    pub(crate) snapshot: I,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,

    /// The number of active keys in the snapshot.
    pub(crate) active_keys: usize,
}

impl<
        E: Storage + Clock + Metrics,
        Op: Codec,
        C: Contiguous<Item = Op>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, Op, C, I, H, S>
{
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    pub fn op_count(&self) -> Location {
        self.log.size()
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Whether the span defined by `span_start` and `span_end` contains `key`.
    pub fn span_contains<K: Ord>(span_start: &K, span_end: &K, key: &K) -> bool {
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

    /// Returns the location of the oldest operation that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_loc()
    }

    /// Returns the location before which all operations have been pruned.
    pub fn pruning_boundary(&self) -> Location {
        self.log.pruning_boundary()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, OrderedOperation<K, V>, C, I, H, S>
where
    OrderedOperation<K, V>: Codec,
{
    /// Returns the inactivity floor from an authenticated log known to be in a consistent state by
    /// reading it from the last commit, which is assumed to be the last operation in the log.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub(crate) async fn recover_inactivity_floor(
        log: &AuthenticatedLog<E, C, H, S>,
    ) -> Result<Location, Error> {
        let last_commit_loc = log.size().checked_sub(1);
        if let Some(last_commit_loc) = last_commit_loc {
            match log.read(last_commit_loc).await? {
                OrderedOperation::CommitFloor(_, location) => Ok(location),
                _ => unreachable!("last commit is not a CommitFloor operation"),
            }
        } else {
            Ok(Location::new_unchecked(0))
        }
    }

    async fn get_update_op(
        log: &AuthenticatedLog<E, C, H, S>,
        loc: Location,
    ) -> Result<OrderedKeyData<K, V::Value>, Error> {
        match log.read(loc).await? {
            OrderedOperation::Update(key_data) => Ok(key_data),
            _ => unreachable!("expected update operation at location {}", loc),
        }
    }

    /// Finds and returns the location and KeyData for the lexicographically-last key produced by
    /// `iter`, skipping over locations that are beyond the log's range.
    async fn last_key_in_iter(
        &self,
        iter: impl Iterator<Item = &Location>,
    ) -> Result<LocatedKey<K, V::Value>, Error> {
        let mut last_key: LocatedKey<K, V::Value> = None;
        for &loc in iter {
            if loc >= self.op_count() {
                // Don't try to look up operations that don't yet exist in the log. This can happen
                // when there are translated key conflicts between a created key and its
                // previous-key.
                continue;
            }
            let data = Self::get_update_op(&self.log, loc).await?;
            if let Some(ref other_key) = last_key {
                if data.key > other_key.1.key {
                    last_key = Some((loc, data));
                }
            } else {
                last_key = Some((loc, data));
            }
        }

        Ok(last_key)
    }

    /// Find the span produced by the provided `iter` that contains `key`, if any.
    async fn find_span(
        &self,
        iter: impl Iterator<Item = &Location>,
        key: &K,
    ) -> Result<LocatedKey<K, V::Value>, Error> {
        for &loc in iter {
            // Iterate over conflicts in the snapshot entry to find the span.
            let data = Self::get_update_op(&self.log, loc).await?;
            if Self::span_contains(&data.key, &data.next_key, key) {
                return Ok(Some((loc, data)));
            }
        }

        Ok(None)
    }

    /// Get the operation that defines the span whose range contains `key`, or None if the DB is
    /// empty.
    pub async fn get_span(&self, key: &K) -> Result<LocatedKey<K, V::Value>, Error> {
        if self.is_empty() {
            return Ok(None);
        }

        // If the translated key is in the snapshot, get a cursor to look for the key.
        let iter = self.snapshot.get(key);
        let span = self.find_span(iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        let Some(iter) = self.snapshot.prev_translated_key(key) else {
            // DB is empty.
            return Ok(None);
        };

        let span = self
            .find_span(iter, key)
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
    ) -> Result<Option<(OrderedKeyData<K, V::Value>, Location)>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            let op = self.log.read(loc).await?;
            assert!(
                op.is_update(),
                "location does not reference update operation. loc={loc}"
            );
            if op.key().expect("update operation must have key") == key {
                let OrderedOperation::Update(data) = op else {
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

    /// Get the metadata associated with the last commit, or None if no commit has been made.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        match self.log.read(last_commit).await? {
            OrderedOperation::CommitFloor(metadata, _) => Ok(metadata),
            _ => unreachable!("last commit is not a CommitFloor operation"),
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, UnorderedOperation<K, V>, C, I, H, S>
where
    UnorderedOperation<K, V>: Codec,
{
    /// Returns the inactivity floor from an authenticated log known to be in a consistent state by
    /// reading it from the last commit, which is assumed to be the last operation in the log.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub(crate) async fn recover_inactivity_floor(
        log: &AuthenticatedLog<E, C, H, S>,
    ) -> Result<Location, Error> {
        let last_commit_loc = log.size().checked_sub(1);
        if let Some(last_commit_loc) = last_commit_loc {
            let last_commit = log.read(last_commit_loc).await?;
            let inactivity_floor = match last_commit {
                UnorderedOperation::CommitFloor(_, loc) => loc,
                _ => {
                    unreachable!("last commit is not a CommitFloor operation");
                }
            };
            Ok(inactivity_floor)
        } else {
            Ok(Location::new_unchecked(0))
        }
    }

    /// Returns the value for `key` and its location, or None if the key is not active.
    pub(crate) async fn get_with_loc(
        &self,
        key: &K,
    ) -> Result<Option<(V::Value, Location)>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            let op = self.log.read(loc).await?;
            match &op {
                UnorderedOperation::Update(k, value) => {
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

    /// Get the metadata associated with the last commit, or None if no commit has been made.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        let op = self.log.read(last_commit).await?;
        match op {
            UnorderedOperation::CommitFloor(value, _) => Ok(value),
            _ => unreachable!("last commit is not a CommitFloor operation"),
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, OrderedOperation<K, V>, C, I, H, S>
where
    OrderedOperation<K, V>: Codec,
{
    /// Finds and updates the location of the previous key to `key` in the snapshot for cases where
    /// the previous key does not share the same translated key, returning an UpdateLocResult
    /// indicating the specific outcome.
    ///
    /// # Panics
    ///
    /// Panics if the db is empty.
    async fn update_non_colliding_prev_key_loc(
        &mut self,
        key: &K,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<K, V::Value>, Error> {
        let Some(iter) = self.snapshot.prev_translated_key(key) else {
            unreachable!("database should not be empty");
        };

        let last_key = self.last_key_in_iter(iter).await?;
        let (loc, last_key) = last_key.expect("no last key found in non-empty snapshot");

        callback(Some(loc));
        update_known_loc(&mut self.snapshot, &last_key.key, loc, next_loc);

        Ok(UpdateLocResult::NotExists(last_key))
    }

    /// Update the location of `key` to `next_loc` in the snapshot, and update the location of
    /// previous key to `next_loc + 1` if its next key will need to be updated to `key`. Returns an
    /// UpdateLocResult indicating the specific outcome. If `create_only` is true, then the key is
    /// only updated if it is not already in the snapshot, and otherwise NotExists is returned
    /// without performing any state changes.
    async fn update_loc(
        &mut self,
        key: &K,
        create_only: bool,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<K, V::Value>, Error> {
        let mut best_prev_key: LocatedKey<K, V::Value> = None;
        {
            // If the translated key is not in the snapshot, insert the new location and return the
            // previous key info.
            let Some(mut cursor) = self.snapshot.get_mut_or_insert(key, next_loc) else {
                callback(None);
                return self
                    .update_non_colliding_prev_key_loc(key, next_loc + 1, callback)
                    .await;
            };

            // Iterate over conflicts in the snapshot entry to try and find the key, or its
            // predecessor if it doesn't exist.
            while let Some(&loc) = cursor.next() {
                let data = Self::get_update_op(&self.log, loc).await?;
                if data.key == *key {
                    // Found the key in the snapshot.
                    if create_only {
                        return Ok(UpdateLocResult::Exists(data.next_key));
                    }
                    // Update its location and return its next-key.
                    assert!(next_loc > loc);
                    cursor.update(next_loc);
                    callback(Some(loc));
                    return Ok(UpdateLocResult::Exists(data.next_key));
                }
                if data.key > *key {
                    continue;
                }
                if let Some((_, ref key_data)) = best_prev_key {
                    if data.key > key_data.key {
                        best_prev_key = Some((loc, data));
                    }
                } else {
                    best_prev_key = Some((loc, data));
                }
            }

            // If we get here, a new key is being created. Insert its location into the snapshot.
            cursor.insert(next_loc);
            callback(None);
        }

        // Update `next_key` for the previous key to point to the newly created key.
        let Some((loc, prev_key_data)) = best_prev_key else {
            // The previous key has not yet been found, meaning it does not share the same
            // translated key, or it precedes all other keys in the ordering requiring we link
            // it to the last key instead.
            return self
                .update_non_colliding_prev_key_loc(key, next_loc + 1, callback)
                .await;
        };

        // The previous key was found within the same snapshot entry as `key`.
        let mut cursor = self
            .snapshot
            .get_mut(&prev_key_data.key)
            .expect("prev_key already known to exist");
        assert!(
            cursor.find(|&l| *l == loc),
            "prev_key should have been found"
        );
        cursor.update(next_loc + 1);
        callback(Some(loc));

        Ok(UpdateLocResult::NotExists(prev_key_data))
    }

    /// Updates `key` to have value `value` while maintaining appropriate next_key spans. The
    /// operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. For each operation added to the log by this method, the callback is
    /// invoked with the old location of the affected key (if any).
    pub(crate) async fn update_with_callback(
        &mut self,
        key: K,
        value: V::Value,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<(), Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.snapshot.insert(&key, next_loc);
            let op = OrderedOperation::Update(OrderedKeyData {
                key: key.clone(),
                value,
                next_key: key.clone(),
            });
            callback(None);
            self.log.append(op).await?;
            self.active_keys += 1;
            return Ok(());
        }
        let res = self.update_loc(&key, false, next_loc, callback).await?;
        let op = match res {
            UpdateLocResult::Exists(next_key) => OrderedOperation::Update(OrderedKeyData {
                key: key.clone(),
                value,
                next_key,
            }),
            UpdateLocResult::NotExists(prev_data) => {
                self.active_keys += 1;
                self.log
                    .append(OrderedOperation::Update(OrderedKeyData {
                        key: key.clone(),
                        value,
                        next_key: prev_data.next_key,
                    }))
                    .await?;
                // For a key that was not previously active, we need to update the next_key value of
                // the previous key.
                OrderedOperation::Update(OrderedKeyData {
                    key: prev_data.key,
                    value: prev_data.value,
                    next_key: key,
                })
            }
        };

        self.log.append(op).await?;

        // For either a new key or an update of existing key, we inactivate exactly one previous
        // operation. A new key inactivates a previous span, and an update of existing key
        // inactivates a previous value.
        self.steps += 1;

        Ok(())
    }

    pub(crate) async fn create_with_callback(
        &mut self,
        key: K,
        value: V::Value,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<bool, Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.snapshot.insert(&key, next_loc);
            let op = OrderedOperation::Update(OrderedKeyData {
                key: key.clone(),
                value,
                next_key: key.clone(),
            });
            callback(None);
            self.log.append(op).await?;
            self.active_keys += 1;
            return Ok(true);
        }
        let res = self.update_loc(&key, true, next_loc, callback).await?;
        match res {
            UpdateLocResult::Exists(_) => {
                return Ok(false);
            }
            UpdateLocResult::NotExists(prev_data) => {
                self.active_keys += 1;
                let value_update_op = OrderedOperation::Update(OrderedKeyData {
                    key: key.clone(),
                    value,
                    next_key: prev_data.next_key,
                });
                let next_key_update_op = OrderedOperation::Update(OrderedKeyData {
                    key: prev_data.key,
                    value: prev_data.value,
                    next_key: key,
                });
                self.log.append(value_update_op).await?;
                self.log.append(next_key_update_op).await?;
            }
        };

        // Creating a new key involves inactivating a previous span, requiring we increment `steps`.
        self.steps += 1;

        Ok(true)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. For each operation added to the log by this method, the callback is
    /// invoked with the old location of the affected key (if any).
    pub(crate) async fn delete_with_callback(
        &mut self,
        key: K,
        mut callback: impl FnMut(bool, Option<Location>),
    ) -> Result<(), Error> {
        let mut prev_key = None;
        let mut next_key = None;
        {
            // If the translated key is in the snapshot, get a cursor to look for the key.
            let Some(mut cursor) = self.snapshot.get_mut(&key) else {
                // no-op
                return Ok(());
            };

            // Iterate over conflicts in the snapshot entry to delete the key if it exists, and
            // potentially find the previous key.
            while let Some(&loc) = cursor.next() {
                let data = Self::get_update_op(&self.log, loc).await?;
                if data.key == key {
                    // The key is in the snapshot, so delete it.
                    cursor.delete();
                    next_key = Some(data.next_key);
                    callback(false, Some(loc));
                    continue;
                }
                if data.key > key {
                    continue;
                }
                let Some((_, ref current_prev_key, _)) = prev_key else {
                    prev_key = Some((loc, data.key.clone(), data.value));
                    continue;
                };
                if data.key > *current_prev_key {
                    prev_key = Some((loc, data.key.clone(), data.value));
                }
            }
        }

        let Some(next_key) = next_key else {
            // no-op
            return Ok(());
        };

        self.active_keys -= 1;
        let op = OrderedOperation::Delete(key.clone());
        self.log.append(op).await?;
        self.steps += 1;

        if self.is_empty() {
            // This was the last key in the DB so there is no span to update.
            return Ok(());
        }

        // Find & update the affected span.
        if prev_key.is_none() {
            let Some(iter) = self.snapshot.prev_translated_key(&key) else {
                unreachable!("DB should not be empty");
            };
            let last_key = self.last_key_in_iter(iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }

        let prev_key = prev_key.expect("prev_key should have been found");

        let loc = self.op_count();
        callback(true, Some(prev_key.0));
        update_known_loc(&mut self.snapshot, &prev_key.1, prev_key.0, loc);

        let op = OrderedOperation::Update(OrderedKeyData {
            key: prev_key.1,
            value: prev_key.2,
            next_key,
        });
        self.log.append(op).await?;
        self.steps += 1;

        Ok(())
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V::Value) -> Result<(), Error> {
        self.update_with_callback(key, value, |_| {}).await
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V::Value) -> Result<bool, Error> {
        self.create_with_callback(key, value, |_| {}).await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let mut r = false;
        self.delete_with_callback(key, |_, _| r = true).await?;
        Ok(r)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, UnorderedOperation<K, V>, C, I, H, S>
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
            .append(UnorderedOperation::Update(key, value))
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
            .append(UnorderedOperation::Update(key, value))
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
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
{
    /// Returns a [IndexedLog] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub async fn init_from_log<F>(
        mut index: I,
        log: AuthenticatedLog<E, C, H>,
        known_inactivity_floor: Option<Location>,
        mut callback: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        // If the last-known inactivity floor is behind the current floor, then invoke the callback
        // appropriately to report the inactive bits.
        let inactivity_floor_loc = Self::recover_inactivity_floor(&log).await?;
        if let Some(mut known_inactivity_floor) = known_inactivity_floor {
            while known_inactivity_floor < inactivity_floor_loc {
                callback(false, None);
                known_inactivity_floor += 1;
            }
        }

        // Build snapshot from the log
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut index, callback).await?;

        let last_commit = log.size().checked_sub(1);

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot: index,
            last_commit,
            steps: 0,
            active_keys,
        })
    }

    /// Raises the inactivity floor by exactly one step, moving the first active operation to tip.
    /// Raises the floor to the tip if the db is empty.
    pub(crate) async fn raise_floor(&mut self) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }
        self.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Same as `raise_floor` but uses the status bitmap to more efficiently find the first active
    /// operation above the inactivity floor.
    pub(crate) async fn raise_floor_with_bitmap<D: Digest, const N: usize>(
        &mut self,
        status: &mut AuthenticatedBitMap<D, N, Dirty>,
    ) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self
                    .as_floor_helper()
                    .raise_floor_with_bitmap(status, loc)
                    .await?;
            }
        }
        self.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Returns a FloorHelper wrapping the current state of the log.
    pub(crate) const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, I, AuthenticatedLog<E, C, H>> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    /// Returns a [IndexedLog] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub async fn init_from_log<F>(
        mut index: I,
        log: AuthenticatedLog<E, C, H>,
        known_inactivity_floor: Option<Location>,
        mut callback: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        // If the last-known inactivity floor is behind the current floor, then invoke the callback
        // appropriately to report the inactive bits.
        let inactivity_floor_loc = Self::recover_inactivity_floor(&log).await?;
        if let Some(mut known_inactivity_floor) = known_inactivity_floor {
            while known_inactivity_floor < inactivity_floor_loc {
                callback(false, None);
                known_inactivity_floor += 1;
            }
        }

        // Build snapshot from the log
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut index, callback).await?;

        let last_commit = log.size().checked_sub(1);

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot: index,
            last_commit,
            steps: 0,
            active_keys,
        })
    }

    /// Returns an [IndexedLog] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last commit location is set to None and it is the responsibility of the
    /// caller to ensure it is set correctly.
    async fn from_components(
        inactivity_floor_loc: Location,
        log: AuthenticatedLog<E, C, H>,
        mut snapshot: I,
    ) -> Result<Self, Error> {
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot,
            last_commit: None,
            steps: 0,
            active_keys,
        })
    }

    /// Raises the inactivity floor by exactly one step, moving the first active operation to tip.
    /// Raises the floor to the tip if the db is empty.
    pub(crate) async fn raise_floor(&mut self) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }
        self.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Same as `raise_floor` but uses the status bitmap to more efficiently find the first active
    /// operation above the inactivity floor.
    pub(crate) async fn raise_floor_with_bitmap<D: Digest, const N: usize>(
        &mut self,
        status: &mut AuthenticatedBitMap<D, N, Dirty>,
    ) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self
                    .as_floor_helper()
                    .raise_floor_with_bitmap(status, loc)
                    .await?;
            }
        }
        self.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Returns a FloorHelper wrapping the current state of the log.
    pub(crate) const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, I, AuthenticatedLog<E, C, H>> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        Op: Codec,
        C: Contiguous<Item = Op>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, Op, C, I, H>
{
    /// Convert this database into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> IndexedLog<E, Op, C, I, H, Dirty> {
        IndexedLog {
            log: self.log.into_dirty(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit: self.last_commit,
            snapshot: self.snapshot,
            steps: self.steps,
            active_keys: self.active_keys,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        Op: Codec,
        C: MutableContiguous<Item = Op>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, Op, C, I, H>
{
    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        self.log.prune(prune_loc).await?;

        Ok(())
    }
}

impl<
        E: Storage + Clock + Metrics,
        Op: Codec,
        C: PersistableContiguous<Item = Op>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, Op, C, I, H>
{
    /// Applies the given commit operation to the log and commits it to disk. Does not raise the
    /// inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(crate) async fn apply_commit_op(&mut self, op: C::Item) -> Result<(), Error> {
        self.last_commit = Some(self.op_count());
        self.log.append(op).await?;

        self.log.commit().await.map_err(Into::into)
    }

    /// Simulate an unclean shutdown by consuming the db. If commit_log is true, the underlying
    /// authenticated log will be be committed before consuming.
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(mut self, commit_log: bool) -> Result<(), Error> {
        if commit_log {
            self.log.commit().await?;
        }

        Ok(())
    }

    /// Sync all database state to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    pub async fn close(self) -> Result<(), Error> {
        self.log.close().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: PersistableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
{
    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `(start_loc, end_loc]` location range of committed operations.
    pub async fn commit(&mut self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let start_loc = self
            .last_commit
            .map_or_else(|| Location::new_unchecked(0), |last_commit| last_commit + 1);

        let inactivity_floor_loc = self.raise_floor().await?;

        // Append the commit operation with the new inactivity floor.
        self.apply_commit_op(OrderedOperation::CommitFloor(
            metadata,
            inactivity_floor_loc,
        ))
        .await?;

        Ok(start_loc..self.op_count())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `(start_loc, end_loc]` location range of committed operations.
    pub async fn commit(&mut self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let start_loc = self
            .last_commit
            .map_or_else(|| Location::new_unchecked(0), |last_commit| last_commit + 1);

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.raise_floor().await?;

        // Commit the log to ensure this commit is durable.
        self.apply_commit_op(UnorderedOperation::CommitFloor(
            metadata,
            inactivity_floor_loc,
        ))
        .await?;

        Ok(start_loc..self.op_count())
    }
}

impl<
        E: Storage + Clock + Metrics,
        Op: Codec,
        C: Contiguous<Item = Op>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, Op, C, I, H, Dirty>
{
    /// Merkleize the database and compute the root digest.
    pub fn merkleize(self) -> IndexedLog<E, Op, C, I, H, Clean<H::Digest>> {
        IndexedLog {
            log: self.log.merkleize(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit: self.last_commit,
            snapshot: self.snapshot,
            steps: self.steps,
            active_keys: self.active_keys,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: PersistableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StorePersistable for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
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
        V: ValueEncoding,
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StorePersistable for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
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
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::LogStorePrunable for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
    > crate::qmdb::store::LogStorePrunable for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::CleanStore for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = OrderedOperation<K, V>;
    type Dirty = IndexedLog<E, OrderedOperation<K, V>, C, I, H, Dirty>;

    fn into_dirty(self) -> Self::Dirty {
        self.into_dirty()
    }

    fn root(&self) -> H::Digest {
        self.log.root()
    }

    async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Self::Operation>), Error> {
        let size = self.op_count();
        self.historical_proof(size, start_loc, max_ops).await
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Self::Operation>), Error> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::CleanStore for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
where
    UnorderedOperation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = UnorderedOperation<K, V>;
    type Dirty = IndexedLog<E, UnorderedOperation<K, V>, C, I, H, Dirty>;

    fn into_dirty(self) -> Self::Dirty {
        self.into_dirty()
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }

    async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        let size = self.op_count();
        self.log
            .historical_proof(size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > LogStore for IndexedLog<E, OrderedOperation<K, V>, C, I, H, S>
where
    OrderedOperation<K, V>: Codec,
{
    type Value = V::Value;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
        V: ValueEncoding,
    > LogStore for IndexedLog<E, UnorderedOperation<K, V>, C, I, H, S>
where
    UnorderedOperation<K, V>: Codec,
{
    type Value = V::Value;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::Store for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
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
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
    > crate::store::Store for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
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
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StoreMut for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
    > crate::store::StoreMut for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
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
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StoreDeletable for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        V: ValueEncoding,
    > crate::store::StoreDeletable for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
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
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::DirtyStore for IndexedLog<E, OrderedOperation<K, V>, C, I, H, Dirty>
where
    OrderedOperation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = OrderedOperation<K, V>;
    type Clean = IndexedLog<E, OrderedOperation<K, V>, C, I, H>;

    async fn merkleize(self) -> Result<Self::Clean, Error> {
        Ok(self.merkleize())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::DirtyStore for IndexedLog<E, UnorderedOperation<K, V>, C, I, H, Dirty>
where
    UnorderedOperation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = C::Item;
    type Clean = IndexedLog<E, UnorderedOperation<K, V>, C, I, H>;

    async fn merkleize(self) -> Result<Self::Clean, Error> {
        Ok(self.merkleize())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: PersistableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > CleanAny for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    OrderedOperation<K, V>: Codec,
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
        C: PersistableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > CleanAny for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
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
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > DirtyAny for IndexedLog<E, OrderedOperation<K, V>, C, I, H, Dirty>
where
    OrderedOperation<K, V>: Codec,
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

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = UnorderedOperation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > DirtyAny for IndexedLog<E, UnorderedOperation<K, V>, C, I, H, Dirty>
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

impl<E, K, V, C, I, H> Batchable for IndexedLog<E, OrderedOperation<K, V>, C, I, H>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = OrderedOperation<K, V>>,
    I: Index<Value = Location>,
    H: Hasher,
    OrderedOperation<K, V>: Codec,
{
    async fn write_batch(
        &mut self,
        iter: impl Iterator<Item = (K, Option<V::Value>)>,
    ) -> Result<(), Error> {
        // Collect all the possible matching `locations` for any referenced key, while retaining
        // each item in the batch in a `mutations` map.
        let mut mutations = BTreeMap::new();
        let mut locations = Vec::with_capacity(iter.size_hint().0);
        for (key, value) in iter {
            let iter = self.snapshot.get(&key);
            locations.extend(iter.copied());
            mutations.insert(key, value);
        }

        // Concurrently look up all possible matching locations.
        locations.sort();
        locations.dedup();
        let futures = locations.iter().map(|loc| self.log.read(*loc));
        let results = try_join_all(futures).await?;

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
        for (op, old_loc) in (results.into_iter()).zip(locations) {
            let OrderedOperation::Update(key_data) = op else {
                unreachable!("updates should have key data");
            };
            let key = key_data.key.clone();
            possible_previous.insert(key.clone(), (key_data.value, old_loc));
            possible_next.insert(key_data.next_key);

            let Some(update) = mutations.remove(&key) else {
                // Due to translated key collisions, we may look up keys that aren't in the
                // mutations set. Note that these could still end up next or previous keys to other
                // keys in the batch, so they are still added to these sets above.
                continue;
            };

            if let Some(value) = update {
                // This is an update of an existing key.
                updated.insert(key.clone(), (value, old_loc));
            } else {
                // This is a delete of an existing key.
                deleted.push(key.clone());

                // Update the log and snapshot.
                delete_known_loc(&mut self.snapshot, &key, old_loc);
                self.log.append(OrderedOperation::Delete(key)).await?;

                // Each delete reduces the active key count by one and inactivates that key.
                self.active_keys -= 1;
                self.steps += 1;
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
            let iter = self.snapshot.prev_translated_key(key);
            let Some(iter) = iter else {
                continue;
            };
            locations.extend(iter.copied());
        }
        locations.sort();
        locations.dedup();
        let futures = locations.iter().map(|loc| self.log.read(*loc));
        let results = try_join_all(futures).await?;

        for (op, old_loc) in (results.into_iter()).zip(locations) {
            let OrderedOperation::Update(key_data) = op else {
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
            let new_loc = self.op_count();
            update_known_loc(&mut self.snapshot, &key, loc, new_loc);

            let next_key = find_next_key(&key, &possible_next);
            let op = OrderedOperation::Update(OrderedKeyData {
                key: key.clone(),
                value: value.clone(),
                next_key,
            });
            self.log.append(op).await?;

            // Each update of an existing key inactivates its previous location.
            self.steps += 1;
            already_updated.insert(key);
        }

        // Create each new key, and update its previous key if it hasn't already been updated.
        for (key, value) in created {
            let new_loc = self.op_count();
            self.snapshot.insert(&key, new_loc);
            let next_key = find_next_key(&key, &possible_next);
            let op = OrderedOperation::Update(OrderedKeyData {
                key: key.clone(),
                value: value.clone(),
                next_key,
            });

            // Each newly created key increases the active key count.
            self.log.append(op).await?;
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

            let new_loc = self.op_count();
            update_known_loc(&mut self.snapshot, prev_key, *prev_loc, new_loc);
            let next_key = find_next_key(prev_key, &possible_next);
            let op = OrderedOperation::Update(OrderedKeyData {
                key: prev_key.clone(),
                value: prev_value.clone(),
                next_key,
            });
            self.log.append(op).await?;

            // Each key whose next-key value is updated inactivates its previous location.
            self.steps += 1;
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

            let new_loc = self.op_count();
            update_known_loc(&mut self.snapshot, prev_key, *prev_loc, new_loc);
            let next_key = find_next_key(prev_key, &possible_next);
            let op = OrderedOperation::Update(OrderedKeyData {
                key: prev_key.clone(),
                value: prev_value.clone(),
                next_key,
            });
            self.log.append(op).await?;

            // Each key whose next-key value is updated inactivates its previous location.
            self.steps += 1;
        }

        Ok(())
    }
}

impl<E, K, V, C, I, H> Batchable for IndexedLog<E, UnorderedOperation<K, V>, C, I, H>
where
    E: Storage + Clock + Metrics,
    K: Array,
    C: MutableContiguous<Item = UnorderedOperation<K, V>>,
    I: Index<Value = Location>,
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
                    .append(UnorderedOperation::Update(key.clone(), value))
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
                .append(UnorderedOperation::Update(key, value))
                .await?;
            self.active_keys += 1;
        }

        Ok(())
    }
}
