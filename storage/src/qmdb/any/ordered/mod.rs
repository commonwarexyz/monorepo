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
        any::{CleanAny, DirtyAny, ValueEncoding},
        build_snapshot_from_log, delete_known_loc,
        operation::{Committable, Operation as _},
        store::{Batchable, LogStore},
        update_known_loc, Error, FloorHelper,
    },
    AuthenticatedBitMap,
};
use commonware_codec::Codec;
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

pub mod fixed;
pub mod variable;

pub use crate::qmdb::any::operation::{update::Ordered as Update, Ordered as Operation};

type AuthenticatedLog<E, C, H, S = Clean<DigestOf<H>>> = authenticated::Journal<E, C, H, S>;

/// Type alias for a location and its associated key data.
type LocatedKey<K, V> = Option<(Location, Update<K, V>)>;

/// The return type of the `Any::update_loc` method.
enum UpdateLocResult<K: Array, V: ValueEncoding> {
    /// The key already exists in the snapshot. The wrapped value is its next-key.
    Exists(K),

    /// The key did not already exist in the snapshot. The wrapped key data is for the first
    /// preceding key that does exist in the snapshot.
    NotExists(Update<K, V>),
}

/// An indexed, authenticated log of ordered database operations.
pub struct IndexedLog<
    E: Storage + Clock + Metrics,
    C: Contiguous,
    I: Index,
    H: Hasher,
    S: State<DigestOf<H>> = Clean<DigestOf<H>>,
> where
    C::Item: Codec,
{
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    /// - There is always at least one commit operation in the log.
    pub(crate) log: AuthenticatedLog<E, C, H, S>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(crate) inactivity_floor_loc: Location,

    /// The location of the last commit operation.
    pub(crate) last_commit_loc: Location,

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
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, C, I, H, S>
where
    Operation<K, V>: Codec,
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

    /// Returns the inactivity floor from an authenticated log known to be in a consistent state by
    /// reading it from the last commit, which is assumed to be the last operation in the log.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub(crate) async fn recover_inactivity_floor(
        log: &AuthenticatedLog<E, C, H, S>,
    ) -> Result<Location, Error> {
        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");
        let last_commit = log.read(last_commit_loc).await?;
        let inactivity_floor = match last_commit {
            Operation::CommitFloor(_, loc) => loc,
            _ => unreachable!("last commit is not a CommitFloor operation"),
        };

        Ok(inactivity_floor)
    }

    async fn get_update_op(
        log: &AuthenticatedLog<E, C, H, S>,
        loc: Location,
    ) -> Result<Update<K, V>, Error> {
        match log.read(loc).await? {
            Operation::Update(key_data) => Ok(key_data),
            _ => unreachable!("expected update operation at location {}", loc),
        }
    }

    /// Finds and returns the location and Update for the lexicographically-last key produced by
    /// `iter`, skipping over locations that are beyond the log's range.
    async fn last_key_in_iter(
        &self,
        iter: impl Iterator<Item = &Location>,
    ) -> Result<LocatedKey<K, V>, Error> {
        let mut last_key: LocatedKey<K, V> = None;
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

    /// Find the span produced by the provided `iter` that contains `key`, if any.
    async fn find_span(
        &self,
        iter: impl Iterator<Item = &Location>,
        key: &K,
    ) -> Result<LocatedKey<K, V>, Error> {
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
    pub async fn get_span(&self, key: &K) -> Result<LocatedKey<K, V>, Error> {
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
    ) -> Result<Option<(Update<K, V>, Location)>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            let op = self.log.read(loc).await?;
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

    /// Returns the location of the oldest operation that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_loc()
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.get_with_loc(key)
            .await
            .map(|op| op.map(|(data, _)| data.value))
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        match self.log.read(self.last_commit_loc).await? {
            Operation::CommitFloor(metadata, _) => Ok(metadata),
            _ => unreachable!("last commit is not a CommitFloor operation"),
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, C, I, H, S>
where
    Operation<K, V>: Codec,
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
    ) -> Result<UpdateLocResult<K, V>, Error> {
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
    ) -> Result<UpdateLocResult<K, V>, Error> {
        let mut best_prev_key: LocatedKey<K, V> = None;
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
            let op = Operation::Update(Update {
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
            UpdateLocResult::Exists(next_key) => Operation::Update(Update {
                key: key.clone(),
                value,
                next_key,
            }),
            UpdateLocResult::NotExists(prev_data) => {
                self.active_keys += 1;
                self.log
                    .append(Operation::Update(Update {
                        key: key.clone(),
                        value,
                        next_key: prev_data.next_key,
                    }))
                    .await?;
                // For a key that was not previously active, we need to update the next_key value of
                // the previous key.
                Operation::Update(Update {
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
            let op = Operation::Update(Update {
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
                let value_update_op = Operation::Update(Update {
                    key: key.clone(),
                    value,
                    next_key: prev_data.next_key,
                });
                let next_key_update_op = Operation::Update(Update {
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
        let op = Operation::Delete(key.clone());
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

        let op = Operation::Update(Update {
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
            let Operation::Update(key_data) = op else {
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
                self.log.append(Operation::Delete(key)).await?;
                callback(false, Some(old_loc));

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
            let new_loc = self.op_count();
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
            self.steps += 1;
            already_updated.insert(key);
        }

        // Create each new key, and update its previous key if it hasn't already been updated.
        for (key, value) in created {
            let new_loc = self.op_count();
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

            let new_loc = self.op_count();
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
            let op = Operation::Update(Update {
                key: prev_key.clone(),
                value: prev_value.clone(),
                next_key,
            });
            self.log.append(op).await?;
            callback(true, Some(*prev_loc));

            // Each key whose next-key value is updated inactivates its previous location.
            self.steps += 1;
        }

        Ok(())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
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

        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot: index,
            last_commit_loc,
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
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
{
    /// Convert this database into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> IndexedLog<E, C, I, H, Dirty> {
        IndexedLog {
            log: self.log.into_dirty(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
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
        C: PersistableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
{
    /// Applies the given commit operation to the log and commits it to disk. Does not raise the
    /// inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(crate) async fn apply_commit_op(&mut self, op: Operation<K, V>) -> Result<(), Error> {
        assert!(op.is_commit(), "commit operation expected");
        self.last_commit_loc = self.op_count();
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

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `(start_loc, end_loc]` location range of committed operations.
    pub async fn commit(&mut self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let start_loc = self.last_commit_loc + 1;

        let inactivity_floor_loc = self.raise_floor().await?;

        // Append the commit operation with the new inactivity floor.
        self.apply_commit_op(Operation::CommitFloor(metadata, inactivity_floor_loc))
            .await?;

        Ok(start_loc..self.op_count())
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
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H, Dirty>
where
    Operation<K, V>: Codec,
{
    /// Merkleize the database and compute the root digest.
    pub fn merkleize(self) -> IndexedLog<E, C, I, H, Clean<H::Digest>> {
        IndexedLog {
            log: self.log.merkleize(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
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
        C: PersistableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StorePersistable for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
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
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::LogStorePrunable for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::CleanStore for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Dirty = IndexedLog<E, C, I, H, Dirty>;

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
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > LogStore for IndexedLog<E, C, I, H, S>
where
    Operation<K, V>: Codec,
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
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::Store for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
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
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StoreMut for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
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
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StoreDeletable for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::DirtyStore for IndexedLog<E, C, I, H, Dirty>
where
    Operation<K, V>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Clean = IndexedLog<E, C, I, H>;

    async fn merkleize(self) -> Result<Self::Clean, Error> {
        Ok(self.merkleize())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: PersistableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > CleanAny for IndexedLog<E, C, I, H>
where
    Operation<K, V>: Codec,
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
        C: MutableContiguous<Item = Operation<K, V>>,
        I: Index<Value = Location>,
        H: Hasher,
    > DirtyAny for IndexedLog<E, C, I, H, Dirty>
where
    Operation<K, V>: Codec,
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

impl<E, K, V, C, I, H> Batchable for IndexedLog<E, C, I, H>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = Operation<K, V>>,
    I: Index<Value = Location>,
    H: Hasher,
    Operation<K, V>: Codec,
{
    async fn write_batch(
        &mut self,
        iter: impl Iterator<Item = (K, Option<V::Value>)>,
    ) -> Result<(), Error> {
        self.write_batch_with_callback(iter, |_, _| {}).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::{
            any::test::{fixed_db_config, variable_db_config},
            store::DirtyStore as _,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::sequence::FixedBytes;
    use core::{future::Future, pin::Pin};

    /// A type alias for the concrete [Any] type used in these unit tests.
    type FixedDb = fixed::Any<Context, FixedBytes<4>, Digest, Sha256, TwoCap>;

    /// A type alias for the concrete [Any] type used in these unit tests.
    type VariableDb = variable::Any<Context, FixedBytes<4>, Digest, Sha256, TwoCap, Clean<Digest>>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    /// Return an `Any` database initialized with a variable config.
    async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("partition"))
            .await
            .unwrap()
    }

    async fn test_ordered_any_db_empty<D>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    {
        assert_eq!(db.op_count(), 1);
        assert!(db.get_metadata().await.unwrap().is_none());
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let d1 = FixedBytes::from([1u8; 4]);
        let d2 = Sha256::fill(2u8);
        let root = db.root();
        let mut db = db.into_dirty();
        db.update(d1, d2).await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), 1);

        // Test calling commit on an empty db.
        let metadata = Sha256::fill(3u8);
        let range = db.commit(Some(metadata)).await.unwrap();
        assert_eq!(range.start, Location::new_unchecked(1));
        assert_eq!(range.end, Location::new_unchecked(2));
        assert_eq!(db.op_count(), 2); // floor op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 2);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
        for _ in 1..100 {
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count() - 1, db.inactivity_floor_loc());
        }

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    async fn test_ordered_any_db_basic<D>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    {
        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let key1 = FixedBytes::from([1u8; 4]);
        let key2 = FixedBytes::from([2u8; 4]);
        let val1 = Sha256::fill(3u8);
        let val2 = Sha256::fill(4u8);

        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.into_dirty();
        assert!(db.create(key1.clone(), val1).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.create(key2.clone(), val2).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        db.delete(key1.clone()).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        db.update(key1.clone(), new_val).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        db.update(key2.clone(), new_val).await.unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // 2 new keys (4 ops), 2 updates (2 ops), 1 deletion (2 ops) + 1 initial commit = 9 ops
        assert_eq!(db.op_count(), 9);
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();

        // Make sure create won't modify active keys.
        assert!(!db.create(key1.clone(), val1).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        // Delete all keys.
        assert!(db.delete(key1.clone()).await.unwrap());
        assert!(db.delete(key2.clone()).await.unwrap());
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let root = db.root();

        // Multiple deletions of the same key should be a no-op.
        let prev_op_count = db.op_count();
        let mut db = db.into_dirty();
        assert!(!db.delete(key1.clone()).await.unwrap());
        assert_eq!(db.op_count(), prev_op_count);
        let db = db.merkleize().await.unwrap();
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Deletions of non-existent keys should be a no-op.
        let key3 = FixedBytes::from([6u8; 4]);
        assert!(!db.delete(key3).await.unwrap());
        assert_eq!(db.op_count(), prev_op_count);

        // Make sure closing/reopening gets us back to the same state.
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let op_count = db.op_count();
        let root = db.root();
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Re-activate the keys by updating them.
        db.update(key1.clone(), val1).await.unwrap();
        db.update(key2.clone(), val2).await.unwrap();
        db.delete(key1.clone()).await.unwrap();
        db.update(key2.clone(), val1).await.unwrap();
        db.update(key1.clone(), val2).await.unwrap();

        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        let op_count = db.op_count();
        let root = db.root();
        let mut db = reopen_db(context.clone()).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), op_count);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        db.commit(None).await.unwrap();

        assert!(db.root() != root);

        // Pruning inactive ops should not affect current state or root.
        let root = db.root();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    /// Builds a db with colliding keys to make sure the "cycle around when there are translated
    /// key collisions" edge case is exercised.
    async fn test_ordered_any_update_collision_edge_case<D>(db: D)
    where
        D: CleanAny<Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    {
        // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
        // collisions.
        let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
        let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
        // Our last must precede the others to trigger previous-key cycle around.
        let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 0u8, 0u8]);
        let val = Sha256::fill(1u8);

        let mut db = db.into_dirty();
        db.update(key1.clone(), val).await.unwrap();
        db.update(key2.clone(), val).await.unwrap();
        db.update(key3.clone(), val).await.unwrap();

        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

        let db = db.merkleize().await.unwrap();
        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_ordered_any_update_collision_edge_case_fixed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_update_collision_edge_case_variable() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    /// Builds a db with two colliding keys, and creates a new one between them using a batch
    /// update.
    #[test_traced("WARN")]
    fn test_ordered_any_update_batch_create_between_collisions() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db(context.clone()).await;

            // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
            // collisions.
            let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
            let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
            let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 7u8, 0u8]);
            let val = Sha256::fill(1u8);

            db.update(key1.clone(), val).await.unwrap();
            db.update(key3.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            // Batch-insert the middle key.
            let mut batch = db.start_batch();
            batch.update(key2.clone(), val).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key1);

            db.destroy().await.unwrap();
        });
    }

    /// Builds a db with one key, and then creates another non-colliding key preceeding it in a
    /// batch. The prev_key search will have to "cycle around" in order to find the correct next_key
    /// value.
    #[test_traced("WARN")]
    fn test_ordered_any_batch_create_with_cycling_next_key() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db(context.clone()).await;

            let mid_key = FixedBytes::from([0xAAu8; 4]);
            let val = Sha256::fill(1u8);

            db.create(mid_key.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            // Batch-insert a preceeding non-translated-colliding key.
            let preceeding_key = FixedBytes::from([0x55u8; 4]);
            let mut batch = db.start_batch();
            assert!(batch.create(preceeding_key.clone(), val).await.unwrap());
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&preceeding_key).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&mid_key).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&preceeding_key).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, mid_key);
            let span2 = db.get_span(&mid_key).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, preceeding_key);

            db.destroy().await.unwrap();
        });
    }

    /// Builds a db with three keys A < B < C, then batch-deletes B. Verifies that A's next_key is
    /// correctly updated to C (skipping the deleted B).
    #[test_traced("WARN")]
    fn test_ordered_any_batch_delete_middle_key() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db(context.clone()).await;

            let key_a = FixedBytes::from([0x11u8; 4]);
            let key_b = FixedBytes::from([0x22u8; 4]);
            let key_c = FixedBytes::from([0x33u8; 4]);
            let val = Sha256::fill(1u8);

            // Create three keys in order: A -> B -> C -> A (circular)
            db.create(key_a.clone(), val).await.unwrap();
            db.create(key_b.clone(), val).await.unwrap();
            db.create(key_c.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            // Verify initial spans
            let span_a = db.get_span(&key_a).await.unwrap().unwrap();
            assert_eq!(span_a.1.next_key, key_b);
            let span_b = db.get_span(&key_b).await.unwrap().unwrap();
            assert_eq!(span_b.1.next_key, key_c);
            let span_c = db.get_span(&key_c).await.unwrap().unwrap();
            assert_eq!(span_c.1.next_key, key_a);

            // Batch-delete the middle key B
            let mut batch = db.start_batch();
            batch.delete(key_b.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            // Verify B is deleted
            assert!(db.get(&key_b).await.unwrap().is_none());

            // Verify A's next_key is now C (not B)
            let span_a = db.get_span(&key_a).await.unwrap().unwrap();
            assert_eq!(span_a.1.next_key, key_c);

            // Verify C's next_key is still A
            let span_c = db.get_span(&key_c).await.unwrap().unwrap();
            assert_eq!(span_c.1.next_key, key_a);

            db.destroy().await.unwrap();
        });
    }

    /// Batch create/delete cases where the deleted key is the previous key of a newly created key,
    /// and vice-versa.
    #[test_traced("WARN")]
    fn test_ordered_any_batch_create_delete_prev_links() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let key1 = FixedBytes::from([0x10u8, 0x00, 0x00, 0x00]);
            let key2 = FixedBytes::from([0x20u8, 0x00, 0x00, 0x00]);
            let key3 = FixedBytes::from([0x30u8, 0x00, 0x00, 0x00]);
            let val1 = Sha256::fill(1u8);
            let val2 = Sha256::fill(2u8);
            let val3 = Sha256::fill(3u8);

            // Delete the previous key of a newly created key.
            let mut db = open_variable_db(context.clone()).await;
            db.update(key1.clone(), val1).await.unwrap();
            db.update(key3.clone(), val3).await.unwrap();
            db.commit(None).await.unwrap();

            let mut batch = db.start_batch();
            batch.delete(key1.clone()).await.unwrap();
            batch.create(key2.clone(), val2).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert!(db.get(&key1).await.unwrap().is_none());
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert_eq!(db.get(&key3).await.unwrap(), Some(val3));
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key2);
            db.destroy().await.unwrap();

            // Create a key that becomes the previous key of a concurrently deleted key.
            let mut db = open_variable_db(context.clone()).await;
            db.update(key1.clone(), val1).await.unwrap();
            db.update(key3.clone(), val3).await.unwrap();
            db.commit(None).await.unwrap();

            let mut batch = db.start_batch();
            batch.create(key2.clone(), val2).await.unwrap();
            batch.delete(key3.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(val1));
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert!(db.get(&key3).await.unwrap().is_none());
            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key1);
            db.destroy().await.unwrap();
        });
    }
}
