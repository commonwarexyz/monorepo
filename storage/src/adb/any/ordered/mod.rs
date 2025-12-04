use crate::{
    adb::{
        any::{CleanAny, DirtyAny},
        build_snapshot_from_log,
        operation::{Committable, KeyData, Keyed, Ordered},
        store::{Batchable, LogStore},
        update_known_loc, Error, FloorHelper,
    },
    index::{Cursor as _, Ordered as Index},
    journal::{
        authenticated,
        contiguous::{MutableContiguous, PersistableContiguous},
    },
    mmr::{
        mem::{Clean, Dirty, State},
        Location, Proof,
    },
    AuthenticatedBitMap,
};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use core::{num::NonZeroU64, ops::Range};
use tracing::debug;

pub mod fixed;
pub mod variable;

type Key<T> = <T as Keyed>::Key;
type Value<T> = <T as Keyed>::Value;
type AuthenticatedLog<E, C, H, S = Clean<DigestOf<H>>> = authenticated::Journal<E, C, H, S>;

/// Type alias for a location and its associated key data.
type LocatedKey<K, V> = (Location, KeyData<K, V>);

/// A trait implemented by the ordered Any db operation type.
pub trait Operation: Committable + Keyed + Ordered {
    /// Return a new update operation variant.
    fn new_update(key: Self::Key, value: Self::Value, next_key: Self::Key) -> Self;

    /// Return a new delete operation variant.
    fn new_delete(key: Self::Key) -> Self;

    /// Return a new commit-floor operation variant.
    fn new_commit_floor(metadata: Option<Self::Value>, inactivity_floor_loc: Location) -> Self;
}

/// The return type of the `Any::update_loc` method.
enum UpdateLocResult<O: Keyed> {
    /// The key already exists in the snapshot. The wrapped value is its next-key.
    Exists(O::Key),

    /// The key did not already exist in the snapshot. The wrapped key data is for the first
    /// preceding key that does exist in the snapshot.
    NotExists(KeyData<O::Key, O::Value>),
}

/// An indexed, authenticated log of ordered [Keyed] database operations.
pub struct IndexedLog<
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: Operation>,
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
    /// - Only references update variants of [Keyed] operations.
    pub(crate) snapshot: I,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,

    /// The number of active keys in the snapshot.
    pub(crate) active_keys: usize,
}

impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > IndexedLog<E, C, I, H, S>
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
        let last_commit_loc = log.size().checked_sub(1);
        if let Some(last_commit_loc) = last_commit_loc {
            let last_commit = log.read(last_commit_loc).await?;
            Ok(last_commit
                .has_floor()
                .expect("last commit should have a floor"))
        } else {
            Ok(Location::new_unchecked(0))
        }
    }

    async fn get_update_op(
        log: &AuthenticatedLog<E, C, H, S>,
        loc: Location,
    ) -> Result<KeyData<Key<C::Item>, Value<C::Item>>, Error> {
        Ok(log
            .read(loc)
            .await?
            .into_key_data()
            .expect("update operation must have key data"))
    }

    /// Returns the location and KeyData for the lexicographically-last key produced by `iter`.
    async fn last_key_in_iter(
        &self,
        iter: impl Iterator<Item = &Location>,
    ) -> Result<Option<LocatedKey<Key<C::Item>, Value<C::Item>>>, Error> {
        #[allow(clippy::type_complexity)]
        let mut last_key: Option<LocatedKey<Key<C::Item>, Value<C::Item>>> = None;
        for &loc in iter {
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
    pub fn span_contains(
        span_start: &Key<C::Item>,
        span_end: &Key<C::Item>,
        key: &Key<C::Item>,
    ) -> bool {
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
        key: &Key<C::Item>,
    ) -> Result<Option<LocatedKey<Key<C::Item>, Value<C::Item>>>, Error> {
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
    pub async fn get_span(
        &self,
        key: &Key<C::Item>,
    ) -> Result<Option<LocatedKey<Key<C::Item>, Value<C::Item>>>, Error> {
        if self.is_empty() {
            return Ok(None);
        }

        // If the translated key is in the snapshot, get a cursor to look for the key.
        let iter = self.snapshot.get(key);
        let span = self.find_span(iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        let iter = self.snapshot.prev_translated_key(key);
        let span = self.find_span(iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        // If we get here, then `key` must precede the first key in the snapshot, in which case we
        // have to cycle around to the very last key.
        let iter = self.snapshot.last_translated_key();
        let span = self
            .find_span(iter, key)
            .await?
            .expect("a span that includes any given key should always exist if db is non-empty");

        Ok(Some(span))
    }

    /// Get the (value, next-key) pair of `key` in the db, or None if it has no value.
    pub async fn get_all(
        &self,
        key: &Key<C::Item>,
    ) -> Result<Option<(Value<C::Item>, Key<C::Item>)>, Error> {
        let Some(op) = self.get_key_op_loc(key).await?.map(|(op, _)| op) else {
            return Ok(None);
        };

        let data = op
            .into_key_data()
            .expect("update operation must have key data");

        Ok(Some((data.value, data.next_key)))
    }

    /// Returns the active operation for `key` with its location, or None if the key is not active.
    pub(crate) async fn get_key_op_loc(
        &self,
        key: &Key<C::Item>,
    ) -> Result<Option<(C::Item, Location)>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            let op = self.log.read(loc).await?;
            assert!(
                op.is_update(),
                "location does not reference update operation. loc={loc}"
            );
            if op.key().expect("update operation must have key") == key {
                return Ok(Some((op, loc)));
            }
        }

        Ok(None)
    }

    /// Returns the location of the oldest operation that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_loc()
    }

    /// Returns the location before which all operations have been pruned.
    pub fn pruning_boundary(&self) -> Location {
        self.log.pruning_boundary()
    }

    /// Finds and updates the location of the previous key to `key` in the snapshot for cases where
    /// the previous key does not share the same translated key, returning an UpdateLocResult
    /// indicating the specific outcome.
    ///
    /// # Panics
    ///
    /// Panics if the snapshot is empty.
    async fn update_non_colliding_prev_key_loc(
        &mut self,
        key: &Key<C::Item>,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<C::Item>, Error> {
        assert!(!self.is_empty(), "snapshot should not be empty");
        let iter = self.snapshot.prev_translated_key(key);
        if let Some((loc, prev_key)) = self.last_key_in_iter(iter).await? {
            callback(Some(loc));
            update_known_loc(&mut self.snapshot, &prev_key.key, loc, next_loc);
            return Ok(UpdateLocResult::NotExists(prev_key));
        }

        // Unusual case where there is no previous key, in which case we cycle around to the greatest key.
        let iter = self.snapshot.last_translated_key();
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
        key: &Key<C::Item>,
        create_only: bool,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<C::Item>, Error> {
        let keys = self.active_keys;
        #[allow(clippy::type_complexity)]
        let mut best_prev_key: Option<LocatedKey<Key<C::Item>, Value<C::Item>>> = None;
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

            if keys != 1 || best_prev_key.is_some() {
                // For the special case handled below around the snapshot having only one translated
                // key, avoid inserting the key into the snapshot here otherwise we'll confuse the
                // subsequent search for the best_prev_key.
                cursor.insert(next_loc);
                callback(None);
            }
        }

        if keys == 1 && best_prev_key.is_none() {
            // In this special case, our key precedes all keys in the snapshot, thus we need to
            // "cycle around" to the very last key. But this key must share the same translated
            // key since there's only one.
            let iter = self.snapshot.get(key);
            best_prev_key = self.last_key_in_iter(iter).await?;
            assert!(
                best_prev_key.is_some(),
                "best_prev_key should have been found"
            );
            self.snapshot.insert(key, next_loc);
            callback(None);
        }

        let Some((loc, prev_key_data)) = best_prev_key else {
            // The previous key was not found, meaning it does not share the same translated key.
            // This should be the common case when collisions are rare.
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
        key: Key<C::Item>,
        value: Value<C::Item>,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<(), Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.snapshot.insert(&key, next_loc);
            let op = C::Item::new_update(key.clone(), value, key.clone());
            callback(None);
            self.log.append(op).await?;
            self.active_keys += 1;
            return Ok(());
        }
        let res = self.update_loc(&key, false, next_loc, callback).await?;
        let op = match res {
            UpdateLocResult::Exists(next_key) => C::Item::new_update(key.clone(), value, next_key),
            UpdateLocResult::NotExists(prev_data) => {
                self.active_keys += 1;
                self.log
                    .append(C::Item::new_update(key.clone(), value, prev_data.next_key))
                    .await?;
                // For a key that was not previously active, we need to update the next_key value of
                // the previous key.
                C::Item::new_update(prev_data.key, prev_data.value, key)
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
        key: Key<C::Item>,
        value: Value<C::Item>,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<bool, Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.snapshot.insert(&key, next_loc);
            let op = C::Item::new_update(key.clone(), value, key.clone());
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
                let value_update_op = C::Item::new_update(key.clone(), value, prev_data.next_key);
                let next_key_update_op = C::Item::new_update(prev_data.key, prev_data.value, key);
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
        key: Key<C::Item>,
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
        let op = C::Item::new_delete(key.clone());
        self.log.append(op).await?;
        self.steps += 1;

        if self.is_empty() {
            // This was the last key in the DB so there is no span to update.
            return Ok(());
        }

        // Find & update the affected span.
        if prev_key.is_none() {
            let iter = self.snapshot.prev_translated_key(&key);
            let last_key = self.last_key_in_iter(iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }
        if prev_key.is_none() {
            // Unusual case where we deleted the very first key in the DB, so the very last key in
            // the DB defines the span in need of update.
            let iter = self.snapshot.last_translated_key();
            let last_key = self.last_key_in_iter(iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }

        let prev_key = prev_key.expect("prev_key should have been found");

        let loc = self.op_count();
        callback(true, Some(prev_key.0));
        update_known_loc(&mut self.snapshot, &prev_key.1, prev_key.0, loc);

        let op = C::Item::new_update(prev_key.1, prev_key.2, next_key);
        self.log.append(op).await?;
        self.steps += 1;

        Ok(())
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &Key<C::Item>) -> Result<Option<Value<C::Item>>, Error> {
        self.get_key_op_loc(key)
            .await
            .map(|op| op.map(|(v, _)| v.into_value().expect("update operation must have value")))
    }

    /// Get the metadata associated with the last commit, or None if no commit has been made.
    pub async fn get_metadata(&self) -> Result<Option<Value<C::Item>>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        let op = self.log.read(last_commit).await?;
        Ok(op.into_value())
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: Key<C::Item>, value: Value<C::Item>) -> Result<(), Error> {
        self.update_with_callback(key, value, |_| {}).await
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(
        &mut self,
        key: Key<C::Item>,
        value: Value<C::Item>,
    ) -> Result<bool, Error> {
        self.create_with_callback(key, value, |_| {}).await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: Key<C::Item>) -> Result<bool, Error> {
        let mut r = false;
        self.delete_with_callback(key, |_, _| r = true).await?;
        Ok(r)
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H>
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
        status: &mut AuthenticatedBitMap<D, N>,
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
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H>
{
    /// Applies the given commit operation to the log and commits it to disk. Does not raise the
    /// inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(crate) async fn apply_commit_op(&mut self, op: C::Item) -> Result<(), Error> {
        assert!(op.is_commit(), "commit operation expected");
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

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `(start_loc, end_loc]` location range of committed operations.
    pub async fn commit(
        &mut self,
        metadata: Option<Value<C::Item>>,
    ) -> Result<Range<Location>, Error> {
        let start_loc = self
            .last_commit
            .map_or_else(|| Location::new_unchecked(0), |last_commit| last_commit + 1);

        let inactivity_floor_loc = self.raise_floor().await?;

        // Append the commit operation with the new inactivity floor.
        self.apply_commit_op(C::Item::new_commit_floor(metadata, inactivity_floor_loc))
            .await?;

        Ok(start_loc..self.op_count())
    }

    /// Sync all database state to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
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

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    pub async fn close(self) -> Result<(), Error> {
        self.log.close().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }

    /// Convert this database into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> IndexedLog<E, C, I, H, Dirty> {
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
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > IndexedLog<E, C, I, H, Dirty>
{
    /// Merkleize the database and compute the root digest.
    pub fn merkleize(self) -> IndexedLog<E, C, I, H, Clean<H::Digest>> {
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
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StorePersistable for IndexedLog<E, C, I, H>
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
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::adb::store::LogStorePrunable for IndexedLog<E, C, I, H>
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::adb::store::CleanStore for IndexedLog<E, C, I, H>
{
    type Digest = H::Digest;
    type Operation = C::Item;
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
    ) -> Result<(Proof<H::Digest>, Vec<C::Item>), Error> {
        let size = self.op_count();
        self.historical_proof(size, start_loc, max_ops).await
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<C::Item>), Error> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > LogStore for IndexedLog<E, C, I, H, S>
{
    type Value = Value<C::Item>;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<Value<C::Item>>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::Store for IndexedLog<E, C, I, H>
{
    type Key = Key<C::Item>;
    type Value = Value<C::Item>;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StoreMut for IndexedLog<E, C, I, H>
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::store::StoreDeletable for IndexedLog<E, C, I, H>
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > crate::adb::store::DirtyStore for IndexedLog<E, C, I, H, Dirty>
{
    type Digest = H::Digest;
    type Operation = C::Item;
    type Clean = IndexedLog<E, C, I, H>;

    fn merkleize(self) -> Self::Clean {
        self.merkleize()
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > CleanAny for IndexedLog<E, C, I, H>
{
    type Key = Key<C::Item>;

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
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
    > DirtyAny for IndexedLog<E, C, I, H, Dirty>
{
    type Key = Key<C::Item>;

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

impl<E, C, I, H> Batchable for IndexedLog<E, C, I, H>
where
    E: Storage + Clock + Metrics,
    C: PersistableContiguous<Item: Operation>,
    I: Index<Value = Location>,
    H: Hasher,
{
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        adb::{
            any::test::{fixed_db_config, variable_db_config},
            store::DirtyStore as _,
        },
        mmr::{mem::Mmr as MemMmr, StandardHasher as Standard},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{Context, Runner},
        Runner as _,
    };
    use core::{future::Future, pin::Pin};

    /// A type alias for the concrete [Any] type used in these unit tests.
    type FixedDb = fixed::Any<Context, Digest, Digest, Sha256, TwoCap>;

    /// A type alias for the concrete [Any] type used in these unit tests.
    type VariableDb = variable::Any<Context, Digest, Digest, Sha256, TwoCap, Clean<Digest>>;

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
        D: CleanAny<Key = Digest, Value = Digest, Digest = Digest>,
    {
        let mut hasher = Standard::<Sha256>::new();
        assert_eq!(db.op_count(), 0);
        assert!(db.get_metadata().await.unwrap().is_none());
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
        assert_eq!(
            &db.root(),
            MemMmr::default().merkleize(&mut hasher, None).root()
        );

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let d1 = Sha256::fill(1u8);
        let d2 = Sha256::fill(2u8);
        let root = db.root();
        let mut db = db.into_dirty();
        db.update(d1, d2).await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), 0);

        // Test calling commit on an empty db which should make it (durably) non-empty.
        let metadata = Sha256::fill(3u8);
        let range = db.commit(Some(metadata)).await.unwrap();
        assert_eq!(range.start, Location::new_unchecked(0));
        assert_eq!(range.end, Location::new_unchecked(1));
        assert_eq!(db.op_count(), 1); // floor op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
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
        D: CleanAny<Key = Digest, Value = Digest, Digest = Digest>,
    {
        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let key1 = Sha256::fill(1u8);
        let key2 = Sha256::fill(2u8);
        let val1 = Sha256::fill(3u8);
        let val2 = Sha256::fill(4u8);

        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.into_dirty();
        assert!(db.create(key1, val1).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.create(key2, val2).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        db.delete(key1).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        db.update(key1, new_val).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        db.update(key2, new_val).await.unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // 2 new keys (4 ops), 2 updates (2 ops), 1 deletion (2 ops) = 8 ops
        assert_eq!(db.op_count(), 8);
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();

        // Make sure create won't modify active keys.
        assert!(!db.create(key1, val1).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        // Delete all keys.
        assert!(db.delete(key1).await.unwrap());
        assert!(db.delete(key2).await.unwrap());
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        let root = db.root();

        // Multiple deletions of the same key should be a no-op.
        let prev_op_count = db.op_count();
        let mut db = db.into_dirty();
        assert!(!db.delete(key1).await.unwrap());
        assert_eq!(db.op_count(), prev_op_count);
        let db = db.merkleize();
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Deletions of non-existent keys should be a no-op.
        let key3 = Sha256::fill(6u8);
        assert!(!db.delete(key3).await.unwrap());
        assert_eq!(db.op_count(), prev_op_count);

        // Make sure closing/reopening gets us back to the same state.
        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        let op_count = db.op_count();
        let root = db.root();
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Re-activate the keys by updating them.
        db.update(key1, val1).await.unwrap();
        db.update(key2, val2).await.unwrap();
        db.delete(key1).await.unwrap();
        db.update(key2, val1).await.unwrap();
        db.update(key1, val2).await.unwrap();

        let mut db = db.merkleize();
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
}
