use crate::{
    index::{Cursor as _, Ordered as OrderedIndexTrait},
    journal::contiguous::{Contiguous, MutableContiguous, PersistableContiguous},
    mmr::{
        mem::{Dirty, State},
        Location,
    },
    qmdb::{
        any::{value::ValueEncoding, CleanAny, Db, DirtyAny, OrderedOperation, OrderedUpdate},
        delete_known_loc,
        operation::Operation as OperationTrait,
        store::Batchable,
        update_known_loc, Error,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::ops::Range;
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};

mod fixed;
pub use fixed::Fixed;

mod variable;
pub use variable::Variable;

/// Type alias for a location and its associated ordered update.
type LocatedKey<K, V> = Option<(Location, OrderedUpdate<K, V>)>;

/// The return type of the `update_loc` method.
enum UpdateLocResult<K: Array, V: ValueEncoding> {
    /// The key already exists in the snapshot. The wrapped value is its next-key.
    Exists(K),

    /// The key did not already exist in the snapshot. The wrapped key data is for the first
    /// preceding key that does exist in the snapshot.
    NotExists(OrderedUpdate<K, V>),
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > Db<E, K, V, OrderedUpdate<K, V>, C, I, H, S>
where
    OrderedOperation<K, V>: Codec,
{
    /// Finds and returns the location and update data for the lexicographically-last key produced by
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
            let data = Self::get_update(&self.log, loc).await?;
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
    ) -> Result<LocatedKey<K, V>, Error> {
        for &loc in iter {
            // Iterate over conflicts in the snapshot entry to find the span.
            let data = Self::get_update(&self.log, loc).await?;
            if span_contains(&data.key, &data.next_key, key) {
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
    ) -> Result<Option<(OrderedUpdate<K, V>, Location)>, Error> {
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
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > Db<E, K, V, OrderedUpdate<K, V>, C, I, H, S>
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
                let data = Self::get_update(&self.log, loc).await?;
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            UpdateLocResult::Exists(next_key) => OrderedOperation::Update(OrderedUpdate {
                key: key.clone(),
                value,
                next_key,
            }),
            UpdateLocResult::NotExists(prev_data) => {
                self.active_keys += 1;
                self.log
                    .append(OrderedOperation::Update(OrderedUpdate {
                        key: key.clone(),
                        value,
                        next_key: prev_data.next_key,
                    }))
                    .await?;
                // For a key that was not previously active, we need to update the next_key value of
                // the previous key.
                OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
                let value_update_op = OrderedOperation::Update(OrderedUpdate {
                    key: key.clone(),
                    value,
                    next_key: prev_data.next_key,
                });
                let next_key_update_op = OrderedOperation::Update(OrderedUpdate {
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
                let data = Self::get_update(&self.log, loc).await?;
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

        let op = OrderedOperation::Update(OrderedUpdate {
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
            let OrderedOperation::Update(key_data) = op else {
                unreachable!("updates should have key data");
            };
            let key = key_data.key.clone();
            possible_previous.insert(key.clone(), (key_data.value, old_loc));
            possible_next.insert(key_data.next_key.clone());

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
            let OrderedOperation::Update(key_data) = op else {
                unreachable!("updates should have key data");
            };
            possible_next.insert(key_data.next_key.clone());
            possible_previous.insert(key_data.key.clone(), (key_data.value, old_loc));
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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

impl<E, K, V, C, I, H> Batchable for Db<E, K, V, OrderedUpdate<K, V>, C, I, H>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    C: MutableContiguous<Item = OrderedOperation<K, V>>,
    I: OrderedIndexTrait<Value = Location>,
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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
            let op = OrderedOperation::Update(OrderedUpdate {
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

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        C: PersistableContiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
    > crate::store::StorePersistable for Db<E, K, V, OrderedUpdate<K, V>, C, I, H>
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
        C: Contiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
    > crate::store::Store for Db<E, K, V, OrderedUpdate<K, V>, C, I, H>
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
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
    > crate::store::StoreMut for Db<E, K, V, OrderedUpdate<K, V>, C, I, H>
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
        V: ValueEncoding,
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
    > crate::store::StoreDeletable for Db<E, K, V, OrderedUpdate<K, V>, C, I, H>
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
        V: ValueEncoding,
        C: PersistableContiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
    > CleanAny for Db<E, K, V, OrderedUpdate<K, V>, C, I, H>
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
        C: MutableContiguous<Item = OrderedOperation<K, V>>,
        I: OrderedIndexTrait<Value = Location>,
        H: Hasher,
    > DirtyAny for Db<E, K, V, OrderedUpdate<K, V>, C, I, H, Dirty>
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

/// Whether the span defined by `span_start` and `span_end` contains `key`.
pub(crate) fn span_contains<K: Ord>(span_start: &K, span_end: &K, key: &K) -> bool {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        index::{ordered::Index, Unordered as _},
        journal::contiguous::{fixed::Journal, variable::Journal as VariableJournal},
        mmr::{Location, Position, StandardHasher as Standard},
        qmdb::{
            any::{
                test::{fixed_db_config, variable_db_config},
                CleanAny, FixedEncoding, VariableEncoding,
            },
            store::{batch_tests, CleanStore as _, DirtyStore as _, LogStore as _},
            verify_proof,
        },
        translator::{OneCap, Translator, TwoCap},
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context, Runner},
        Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
    use core::{future::Future, pin::Pin};
    use rand::{rngs::StdRng, seq::IteratorRandom, RngCore, SeedableRng};
    use std::collections::{BTreeMap, HashMap};

    /// A type alias for the concrete database type used in these unit tests.
    type FixedDb = Db<
        Context,
        FixedBytes<4>,
        FixedEncoding<Digest>,
        OrderedUpdate<FixedBytes<4>, FixedEncoding<Digest>>,
        Journal<Context, OrderedOperation<FixedBytes<4>, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// A type alias for the concrete database type used in these unit tests.
    type VariableDb = Db<
        Context,
        FixedBytes<4>,
        VariableEncoding<Digest>,
        OrderedUpdate<FixedBytes<4>, VariableEncoding<Digest>>,
        VariableJournal<Context, OrderedOperation<FixedBytes<4>, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a fixed config.
    async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    /// Return a database initialized with a variable config.
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

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    fn any_db_config(suffix: &str) -> crate::qmdb::any::FixedConfig<TwoCap> {
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
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete database type used in fixed-size unit tests.
    type DbTest = Db<
        deterministic::Context,
        Digest,
        FixedEncoding<Digest>,
        OrderedUpdate<Digest, FixedEncoding<Digest>>,
        Journal<deterministic::Context, OrderedOperation<Digest, FixedEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a fixed config.
    async fn open_db_test(context: deterministic::Context) -> DbTest {
        DbTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    fn create_test_config(seed: u64) -> crate::qmdb::any::FixedConfig<TwoCap> {
        create_generic_test_config::<TwoCap>(seed, TwoCap)
    }

    fn create_generic_test_config<T: Translator>(
        seed: u64,
        t: T,
    ) -> crate::qmdb::any::FixedConfig<T> {
        crate::qmdb::any::FixedConfig {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(12), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(14), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: t,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    async fn create_db_test(mut context: Context) -> DbTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        DbTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<OrderedOperation<Digest, FixedEncoding<Digest>>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(OrderedOperation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                ops.push(OrderedOperation::Update(OrderedUpdate {
                    key,
                    value,
                    next_key,
                }));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    async fn apply_test_ops(
        db: &mut DbTest,
        ops: Vec<OrderedOperation<Digest, FixedEncoding<Digest>>>,
    ) {
        for op in ops {
            match op {
                OrderedOperation::Update(data) => {
                    db.update(data.key, data.value).await.unwrap();
                }
                OrderedOperation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                OrderedOperation::CommitFloor(metadata, _) => {
                    db.commit(metadata).await.unwrap();
                }
            }
        }
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_translated_key_collision_edge_case() {
        let executor = Runner::default();
        executor.start(|mut context| async move {
            let seed = context.next_u64();
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db = Db::<
                Context,
                FixedBytes<2>,
                FixedEncoding<i32>,
                OrderedUpdate<FixedBytes<2>, FixedEncoding<i32>>,
                Journal<Context, OrderedOperation<FixedBytes<2>, FixedEncoding<i32>>>,
                Index<OneCap, Location>,
                Sha256,
            >::init(context.clone(), config)
            .await
            .unwrap();
            let key1 = FixedBytes::<2>::new([1u8, 1u8]);
            let key2 = FixedBytes::<2>::new([1u8, 3u8]);
            // Create some keys that will not be added to the snapshot.
            let early_key = FixedBytes::<2>::new([0u8, 2u8]);
            let late_key = FixedBytes::<2>::new([3u8, 0u8]);
            let middle_key = FixedBytes::<2>::new([1u8, 2u8]);

            db.update(key1.clone(), 1).await.unwrap();
            db.update(key2.clone(), 2).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (1, key2.clone()));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (2, key1.clone()));
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            db.delete(key1.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key2.clone());

            db.delete(key2.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().is_none());
            assert!(db.get_span(&key2).await.unwrap().is_none());

            db.commit(None).await.unwrap();
            assert!(db.is_empty());

            // Update the keys in opposite order from earlier.
            db.update(key2.clone(), 2).await.unwrap();
            db.update(key1.clone(), 1).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (1, key2.clone()));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (2, key1.clone()));
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key2.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            // Delete the keys in opposite order from earlier.
            db.delete(key2.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&key2).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&early_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&middle_key).await.unwrap().unwrap().1.next_key == key1.clone());
            assert!(db.get_span(&late_key).await.unwrap().unwrap().1.next_key == key1.clone());

            db.delete(key1.clone()).await.unwrap();
            assert!(db.get_span(&key1).await.unwrap().is_none());
            assert!(db.get_span(&key2).await.unwrap().is_none());
            db.commit(None).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_build_and_authenticate() {
        let executor = Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db_test(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
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

            assert_eq!(db.op_count(), 2620);
            assert_eq!(db.inactivity_floor_loc(), 0);
            assert_eq!(db.op_count(), 2620);
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            db.commit(None).await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 4241);
            assert_eq!(db.inactivity_floor_loc(), 3383);
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root();
            db.close().await.unwrap();
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 4241);
            assert_eq!(db.inactivity_floor_loc(), 3383);
            assert_eq!(db.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
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

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = NZU64!(4);
            let end_loc = db.op_count();
            let start_pos = db.log.mmr.pruned_to_pos();
            let start_loc = Location::try_from(start_pos).unwrap();
            // Raise the inactivity floor via commit and make sure historical inactive operations
            // are still provable.
            db.commit(None).await.unwrap();
            let root = db.root();
            assert!(start_loc < db.inactivity_floor_loc());

            for i in start_loc.as_u64()..end_loc.as_u64() {
                let loc = Location::from(i);
                let (proof, log) = db.proof(loc, max_ops).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, loc, &log, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_non_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_db_test(context.clone()).await;

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root();
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            async fn apply_more_ops(db: &mut DbTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db_test(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_empty_db_recovery() {
        let executor = Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let db = open_db_test(context.clone()).await;
            let root = db.root();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            async fn apply_ops(db: &mut DbTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure, syncing nothing.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db_test(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db_test(context.clone()).await;
            assert!(db.op_count() > 1);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_log_replay() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_db_test(context.clone()).await;

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
            let db = open_db_test(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_multiple_commits_delete_gets_replayed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_db_test(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            let metadata = Sha256::hash(&42u64.to_be_bytes());
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&(j * 1000 + i).to_be_bytes());
                    let v = Sha256::hash(&(i * 1000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                    map.insert(k, v);
                }
                db.commit(Some(metadata)).await.unwrap();
            }
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
            let k = Sha256::hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit(None).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root();
            db.close().await.unwrap();
            let db = open_db_test(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert!(db.get(&k).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_db_test(context.clone()).await;
            let ops = create_test_ops(20);
            apply_test_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();
            let mut hasher = Standard::<Sha256>::new();
            let root_hash = db.root();
            let original_op_count = db.op_count();

            // Historical proof should match "regular" proof when historical size == current database size
            let max_ops = NZU64!(10);
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(5), max_ops)
                .await
                .unwrap();
            let (regular_proof, regular_ops) =
                db.proof(Location::new_unchecked(5), max_ops).await.unwrap();

            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new_unchecked(5),
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            let more_ops = create_test_ops(5);
            apply_test_ops(&mut db, more_ops.clone()).await;
            db.commit(None).await.unwrap();

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new_unchecked(5), NZU64!(10))
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
                Location::new_unchecked(5),
                &historical_ops,
                &root_hash
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_edge_cases() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_db_test(context.clone()).await;
            let ops = create_test_ops(50);
            apply_test_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = Standard::<Sha256>::new();

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
            let mut single_db = create_db_test(context.clone()).await;
            apply_test_ops(&mut single_db, ops[0..1].to_vec()).await;
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
                    Location::new_unchecked(10),
                    Location::new_unchecked(5),
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
            assert_eq!(
                min_proof.size,
                Position::try_from(Location::new_unchecked(4)).unwrap()
            );
            assert_eq!(min_ops.len(), 3);

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_db_test(context.clone()).await;
            let ops = create_test_ops(100);
            apply_test_ops(&mut db, ops.clone()).await;
            db.commit(None).await.unwrap();

            let mut hasher = Standard::<Sha256>::new();
            let root = db.root();

            let start_loc = Location::new_unchecked(20);
            let max_ops = NZU64!(10);
            let (proof, ops) = db.proof(start_loc, max_ops).await.unwrap();

            // Now keep adding operations and make sure we can still generate a historical proof that matches the original.
            let historical_size = db.op_count();

            for _ in 1..10 {
                let more_ops = create_test_ops(100);
                apply_test_ops(&mut db, more_ops).await;
                db.commit(None).await.unwrap();

                let (historical_proof, historical_ops) = db
                    .historical_proof(historical_size, start_loc, max_ops)
                    .await
                    .unwrap();
                assert_eq!(proof.size, historical_proof.size);
                assert_eq!(ops, historical_ops);
                assert_eq!(proof.digests, historical_proof.digests);

                // Verify proof against reference root
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_invalid() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = create_db_test(context.clone()).await;
            let ops = create_test_ops(10);
            apply_test_ops(&mut db, ops).await;
            db.commit(None).await.unwrap();

            let historical_op_count = Location::new_unchecked(5);
            let historical_mmr_size = Position::try_from(historical_op_count).unwrap();
            let (proof, ops) = db
                .historical_proof(historical_op_count, Location::new_unchecked(1), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(proof.size, historical_mmr_size);
            assert_eq!(ops.len(), 4);

            let mut hasher = Standard::<Sha256>::new();

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
            let changed_op = OrderedOperation::Update(OrderedUpdate {
                key: Sha256::hash(b"key1"),
                value: Sha256::hash(b"value1"),
                next_key: Sha256::hash(b"key2"),
            });
            {
                let mut ops = ops.clone();
                ops[0] = changed_op.clone();
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
                ops.push(changed_op);
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
                proof.size = Position::from(100u64);
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

    #[test]
    fn test_ordered_any_fixed_db_span_maintenance_under_collisions() {
        let executor = Runner::default();
        executor.start(|mut context| async move {
            #[allow(clippy::type_complexity)]
            async fn insert_random<T: Translator>(
                db: &mut Db<
                    Context,
                    Digest,
                    FixedEncoding<i32>,
                    OrderedUpdate<Digest, FixedEncoding<i32>>,
                    Journal<Context, OrderedOperation<Digest, FixedEncoding<i32>>>,
                    Index<T, Location>,
                    Sha256,
                >,
                rng: &mut StdRng,
            ) {
                let mut keys = BTreeMap::new();

                // Insert 1000 random keys into both the db and an ordered map.
                for i in 0..1000 {
                    let key = Digest::random(&mut *rng);
                    keys.insert(key, i);
                    db.update(key, i).await.unwrap();
                }

                db.commit(None).await.unwrap();

                // Make sure the db and ordered map agree on contents & key order.
                let mut iter = keys.iter();
                let first_key = iter.next().unwrap().0;
                let mut next_key = db.get_all(first_key).await.unwrap().unwrap().1;
                for (key, value) in iter {
                    let (v, next) = db.get_all(key).await.unwrap().unwrap();
                    assert_eq!(*value, v);
                    assert_eq!(*key, next_key);
                    assert_eq!(db.get_span(key).await.unwrap().unwrap().1.next_key, next);
                    next_key = next;
                }

                // Delete some random keys and check order agreement again.
                for _ in 0..500 {
                    let key = keys.keys().choose(rng).cloned().unwrap();
                    keys.remove(&key);
                    db.delete(key).await.unwrap();
                }

                let mut iter = keys.iter();
                let first_key = iter.next().unwrap().0;
                let mut next_key = db.get_all(first_key).await.unwrap().unwrap().1;
                for (key, value) in iter {
                    let (v, next) = db.get_all(key).await.unwrap().unwrap();
                    assert_eq!(*value, v);
                    assert_eq!(*key, next_key);
                    assert_eq!(db.get_span(key).await.unwrap().unwrap().1.next_key, next);
                    next_key = next;
                }

                // Delete the rest of the keys and make sure we get back to empty.
                for _ in 0..500 {
                    let key = keys.keys().choose(rng).cloned().unwrap();
                    keys.remove(&key);
                    db.delete(key).await.unwrap();
                }
                assert_eq!(keys.len(), 0);
                assert!(db.is_empty());
                assert_eq!(db.get_span(&Digest::random(&mut *rng)).await.unwrap(), None);
            }

            let mut rng = StdRng::seed_from_u64(context.next_u64());
            let seed = context.next_u64();

            // Use a OneCap to ensure many collisions.
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db = Db::<
                Context,
                Digest,
                FixedEncoding<i32>,
                OrderedUpdate<Digest, FixedEncoding<i32>>,
                Journal<Context, OrderedOperation<Digest, FixedEncoding<i32>>>,
                Index<OneCap, Location>,
                Sha256,
            >::init(context.clone(), config)
            .await
            .unwrap();
            insert_random(&mut db, &mut rng).await;
            db.destroy().await.unwrap();

            // Repeat test with TwoCap to test low/no collisions.
            let config = create_generic_test_config::<TwoCap>(seed, TwoCap);
            let mut db = Db::<
                Context,
                Digest,
                FixedEncoding<i32>,
                OrderedUpdate<Digest, FixedEncoding<i32>>,
                Journal<Context, OrderedOperation<Digest, FixedEncoding<i32>>>,
                Index<TwoCap, Location>,
                Sha256,
            >::init(context.clone(), config)
            .await
            .unwrap();
            insert_random(&mut db, &mut rng).await;
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_ordered_any_fixed_batch() {
        batch_tests::test_batch(|ctx| async move { create_db_test(ctx).await });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::qmdb::any::{FixedEncoding, OrderedOperation, VariableEncoding};
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<OrderedOperation<U64, FixedEncoding<U64>>>,
            CodecConformance<OrderedOperation<U64, VariableEncoding<Vec<u8>>>>,
        }
    }
}
