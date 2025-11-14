//! An _ordered_ variant of a Any authenticated database with fixed-size values which additionally
//! maintains the lexicographic-next active key of each active key. For example, if the active key
//! set is `{bar, baz, foo}`, then the next-key value for `bar` is `baz`, the next-key value for
//! `baz` is `foo`, and because we define the next-key of the very last key as the first key, the
//! next-key value for `foo` is `bar`.

use crate::{
    adb::{
        any::fixed::{init_authenticated_log, AuthenticatedLog, Config},
        build_snapshot_from_log,
        operation::fixed::ordered::{KeyData, Operation},
        store::Db,
        Error, FloorHelper,
    },
    index::{ordered::Index, Cursor as _, Ordered as _, Unordered as _},
    mmr::{Location, Proof, StandardHasher},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::marker::PhantomData;
use std::num::NonZeroU64;
use tracing::debug;

/// The return type of the `Any::update_loc` method.
enum UpdateLocResult<K: Array + Ord, V: CodecFixed<Cfg = ()>> {
    /// The key already exists in the snapshot. The wrapped value is its next-key.
    Exists(K),

    /// The key did not already exist in the snapshot. The wrapped key data is for the first
    /// preceding key that does exist in the snapshot.
    NotExists(KeyData<K, V>),
}

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key, and access to the lexicographically-next active key of a given
/// active key.
pub struct Any<
    E: Storage + Clock + Metrics,
    K: Array + Ord,
    V: CodecFixed<Cfg = ()>,
    H: Hasher,
    T: Translator,
> {
    /// A (pruned) log of all operations applied to the db in order of occurrence. The position of
    /// each operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - An operation's location is always equal to the number of the MMR leaf storing the digest
    ///   of the operation.
    /// - The log is never pruned beyond the inactivity floor.
    pub(crate) log: AuthenticatedLog<E, Operation<K, V>, H>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariants
    ///
    /// Only references operations of type [Operation::Update].
    pub(crate) snapshot: Index<T, Location>,

    /// The number of active keys in the db.
    pub(crate) active_keys: usize,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(crate) inactivity_floor_loc: Location,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,
}

/// Type alias for the floor helper state wrapper used by this Any database variant.
type FloorHelperState<'a, E, K, V, H, T> = FloorHelper<
    'a,
    T,
    Index<T, Location>,
    AuthenticatedLog<E, Operation<K, V>, H>,
    Operation<K, V>,
>;

impl<
        E: Storage + Clock + Metrics,
        K: Array + Ord,
        V: CodecFixed<Cfg = ()>,
        H: Hasher,
        T: Translator,
    > Any<E, K, V, H, T>
{
    /// Returns an [Any] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
        let mut snapshot: Index<T, Location> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let (inactivity_floor_loc, log) = init_authenticated_log(context, cfg).await?;

        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;

        let db = Any {
            log,
            snapshot,
            active_keys,
            inactivity_floor_loc,
            steps: 0,
        };

        Ok(db)
    }

    /// Returns the location and KeyData for the lexicographically-last key produced by `iter`.
    async fn last_key_in_iter(
        log: &AuthenticatedLog<E, Operation<K, V>, H>,
        iter: impl Iterator<Item = &Location>,
    ) -> Result<Option<(Location, KeyData<K, V>)>, Error> {
        let mut last_key: Option<(Location, KeyData<K, V>)> = None;
        for &loc in iter {
            let data = Self::get_update_op(log, loc).await?;
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

    /// For the given `key` which is known to exist in the snapshot with location `old_loc`, update
    /// its location to `new_loc`.
    async fn update_known_loc(
        &mut self,
        key: &K,
        old_loc: Location,
        new_loc: Location,
    ) -> Result<(), Error> {
        let mut cursor = self
            .snapshot
            .get_mut(key)
            .expect("key should be known to exist");
        assert!(
            cursor.find(|&loc| *loc == old_loc),
            "prev_key with given old_loc should have been found"
        );
        cursor.update(new_loc);

        Ok(())
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
        key: &K,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<K, V>, Error> {
        assert!(!self.is_empty(), "snapshot should not be empty");
        let iter = self.snapshot.prev_translated_key(key);
        if let Some((loc, prev_key)) = Self::last_key_in_iter(&self.log, iter).await? {
            callback(Some(loc));
            self.update_known_loc(&prev_key.key, loc, next_loc).await?;
            return Ok(UpdateLocResult::NotExists(prev_key));
        }

        // Unusual case where there is no previous key, in which case we cycle around to the greatest key.
        let iter = self.snapshot.last_translated_key();
        let last_key = Self::last_key_in_iter(&self.log, iter).await?;
        let (loc, last_key) = last_key.expect("no last key found in non-empty snapshot");

        callback(Some(loc));
        Self::update_known_loc(self, &last_key.key, loc, next_loc).await?;

        Ok(UpdateLocResult::NotExists(last_key))
    }

    /// Update the location of `key` to `next_loc` in the snapshot, and update the location of
    /// previous key to `next_loc + 1` if its next key will need to be updated to `key`. Returns an
    /// UpdateLocResult indicating the specific outcome.
    async fn update_loc(
        &mut self,
        key: &K,
        next_loc: Location,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<UpdateLocResult<K, V>, Error> {
        let keys = self.active_keys;
        let mut best_prev_key: Option<(Location, KeyData<K, V>)> = None;
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
                    // Found the key in the snapshot.  Update its location and return its next-key.
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
            best_prev_key = Self::last_key_in_iter(&self.log, iter).await?;
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

    /// Get the update operation from `log` corresponding to a known location.
    async fn get_update_op(
        log: &AuthenticatedLog<E, Operation<K, V>, H>,
        loc: Location,
    ) -> Result<KeyData<K, V>, Error> {
        let Operation::Update(data) = log.read(loc).await? else {
            unreachable!("location does not reference update operation. loc={loc}");
        };

        Ok(data)
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.get_key_loc(key).await?.map(|(v, _, _)| v))
    }

    /// Get the (value, next-key) pair of `key` in the db, or None if it has no value.
    pub async fn get_all(&self, key: &K) -> Result<Option<(V, K)>, Error> {
        Ok(self
            .get_key_loc(key)
            .await?
            .map(|(v, next_key, _)| (v, next_key)))
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
        log: &AuthenticatedLog<E, Operation<K, V>, H>,
        iter: impl Iterator<Item = &Location>,
        key: &K,
    ) -> Result<Option<(Location, KeyData<K, V>)>, Error> {
        for &loc in iter {
            // Iterate over conflicts in the snapshot entry to find the span.
            let data = Self::get_update_op(log, loc).await?;
            if Self::span_contains(&data.key, &data.next_key, key) {
                return Ok(Some((loc, data)));
            }
        }

        Ok(None)
    }

    /// Get the operation that defines the span whose range contains `key`, or None if the DB is
    /// empty.
    pub async fn get_span(&self, key: &K) -> Result<Option<(Location, KeyData<K, V>)>, Error> {
        if self.is_empty() {
            return Ok(None);
        }

        // If the translated key is in the snapshot, get a cursor to look for the key.
        let iter = self.snapshot.get(key);
        let span = Self::find_span(&self.log, iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        let iter = self.snapshot.prev_translated_key(key);
        let span = Self::find_span(&self.log, iter, key).await?;
        if let Some(span) = span {
            return Ok(Some(span));
        }

        // If we get here, then `key` must precede the first key in the snapshot, in which case we
        // have to cycle around to the very last key.
        let iter = self.snapshot.last_translated_key();
        let span = Self::find_span(&self.log, iter, key)
            .await?
            .expect("a span that includes any given key should always exist if db is non-empty");

        Ok(Some(span))
    }

    /// Get the value, next-key, and location of the active operation for `key` in the db, or None
    /// if it has no value.
    pub(crate) async fn get_key_loc(&self, key: &K) -> Result<Option<(V, K, Location)>, Error> {
        for &loc in self.snapshot.get(key) {
            let data = Self::get_update_op(&self.log, loc).await?;
            if data.key == *key {
                return Ok(Some((data.value, data.next_key, loc)));
            }
        }

        Ok(None)
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> Location {
        self.log.size()
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Updates `key` to have value `value` while maintaining appropriate next_key spans. The
    /// operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update_with_callback(key, value, |_| {}).await
    }

    /// Updates `key` to have value `value` while maintaining appropriate next_key spans. The
    /// operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. For each operation added to the log by this method, the callback is
    /// invoked with the old location of the affected key (if any).
    pub(crate) async fn update_with_callback(
        &mut self,
        key: K,
        value: V,
        mut callback: impl FnMut(Option<Location>),
    ) -> Result<(), Error> {
        let next_loc = self.op_count();
        if self.is_empty() {
            // We're inserting the very first key. For this special case, the next-key value is the
            // same as the key.
            self.snapshot.insert(&key, next_loc);
            let op = Operation::Update(KeyData {
                key: key.clone(),
                value,
                next_key: key,
            });
            callback(None);
            self.log.append(op).await?;
            self.active_keys += 1;
            return Ok(());
        }
        let res = self.update_loc(&key, next_loc, callback).await?;
        let op = match res {
            UpdateLocResult::Exists(next_key) => Operation::Update(KeyData {
                key,
                value,
                next_key,
            }),
            UpdateLocResult::NotExists(prev_data) => {
                self.active_keys += 1;
                self.log
                    .append(Operation::Update(KeyData {
                        key: key.clone(),
                        value,
                        next_key: prev_data.next_key,
                    }))
                    .await?;
                // For a key that was not previously active, we need to update the next_key value of
                // the previous key.
                Operation::Update(KeyData {
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

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete_with_callback(key, |_, _| {}).await
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
            let iter = self.snapshot.prev_translated_key(&key);
            let last_key = Self::last_key_in_iter(&self.log, iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }
        if prev_key.is_none() {
            // Unusual case where we deleted the very first key in the DB, so the very last key in
            // the DB defines the span in need of update.
            let iter = self.snapshot.last_translated_key();
            let last_key = Self::last_key_in_iter(&self.log, iter).await?;
            prev_key = last_key.map(|(loc, data)| (loc, data.key, data.value));
        }

        let prev_key = prev_key.expect("prev_key should have been found");

        let loc = self.op_count();
        callback(true, Some(prev_key.0));
        self.update_known_loc(&prev_key.1, prev_key.0, loc).await?;

        let op = Operation::Update(KeyData {
            key: prev_key.1,
            value: prev_key.2,
            next_key,
        });
        self.log.append(op).await?;
        self.steps += 1;

        Ok(())
    }

    /// Returns a wrapper around the db's state that can be used to perform shared functions.
    pub(crate) fn as_floor_helper(&mut self) -> FloorHelperState<'_, E, K, V, H, T> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
            translator: PhantomData,
        }
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut StandardHasher<H>) -> H::Digest {
        self.log.root(hasher)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count`.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.log
            .historical_proof(op_count, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
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

        // Apply the commit operation with the new inactivity floor.
        let loc = self.inactivity_floor_loc;
        self.log.append(Operation::CommitFloor(loc)).await?;

        // Sync the log.
        self.log.commit().await.map_err(Into::into)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root or
    /// current snapshot.
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

    /// Simulate an unclean shutdown by consuming the db. If commit_log is true, the log will be
    /// committed before consuming.
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(mut self, commit_log: bool) -> Result<(), Error> {
        if commit_log {
            self.log.commit().await?;
        }

        Ok(())
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: CodecFixed<Cfg = ()>, H: Hasher, T: Translator>
    Db<E, K, V, T> for Any<E, K, V, H, T>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.get(key).await
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update(key, value).await
    }

    async fn delete(&mut self, key: K) -> Result<(), Error> {
        self.delete(key).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit().await
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        adb::verify_proof,
        mmr::{mem::Mmr as MemMmr, Position, StandardHasher as Standard},
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
    use rand::{rngs::StdRng, seq::IteratorRandom, RngCore, SeedableRng};
    use std::collections::{BTreeMap, HashMap};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 103;
    const PAGE_CACHE_SIZE: usize = 13;

    fn any_db_config(suffix: &str) -> Config<TwoCap> {
        Config {
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

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    fn create_test_config(seed: u64) -> Config<TwoCap> {
        create_generic_test_config::<TwoCap>(seed, TwoCap)
    }

    fn create_generic_test_config<T: Translator>(seed: u64, t: T) -> Config<T> {
        Config {
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
    async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let key = Digest::random(&mut rng);
                let next_key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(KeyData {
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
    async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Digest>>) {
        for op in ops {
            match op {
                Operation::Update(data) => {
                    db.update(data.key, data.value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(_) => {
                    db.commit().await.unwrap();
                }
            }
        }
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an
            // uncommitted op, and even without a clean shutdown.
            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            let root = db.root(&mut hasher);
            db.update(d1, d2).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

            // Re-opening the DB without a clean shutdown should still recover the correct state.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(&mut hasher), root);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit().await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    // Test the edge case that arises where we're inserting the second key and it precedes the first
    // key, but shares the same translated key.
    fn test_ordered_any_fixed_db_translated_key_collision_edge_case() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let seed = context.next_u64();
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db =
                Any::<Context, FixedBytes<2>, i32, Sha256, OneCap>::init(context.clone(), config)
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
            db.commit().await.unwrap();
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

            db.commit().await.unwrap();
            assert!(db.is_empty());

            // Update the keys in opposite order from earlier.
            db.update(key2.clone(), 2).await.unwrap();
            db.update(key1.clone(), 1).await.unwrap();
            db.commit().await.unwrap();
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
            db.commit().await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let key1 = Sha256::fill(1u8);
            let key2 = Sha256::fill(2u8);
            let val1 = Sha256::fill(3u8);
            let val2 = Sha256::fill(4u8);

            assert!(db.get(&key1).await.unwrap().is_none());
            assert!(db.get(&key2).await.unwrap().is_none());

            db.update(key1, val1).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (val1, key1));
            assert!(db.get_all(&key2).await.unwrap().is_none());

            db.update(key2, val2).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (val1, key2));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (val2, key1));

            db.delete(key1).await.unwrap();
            assert!(db.get_all(&key1).await.unwrap().is_none());
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (val2, key2));

            let new_val = Sha256::fill(5u8);
            db.update(key1, new_val).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (new_val, key2));

            db.update(key2, new_val).await.unwrap();
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (new_val, key1));

            assert_eq!(db.log.size(), 8); // 2 new keys (4), 2 updates (2), 1 deletion (2)
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc, 0);
            db.sync().await.unwrap();

            // take one floor raising step, which should move the first active op (at location 5) to
            // tip, leaving the floor at the next location (6).
            let loc = db.inactivity_floor_loc;
            db.inactivity_floor_loc = db.as_floor_helper().raise_floor(loc).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(6));
            assert_eq!(db.log.size(), 9);
            db.sync().await.unwrap();

            // Delete all keys and commit the changes.
            db.delete(key1).await.unwrap();
            db.delete(key2).await.unwrap();
            assert!(db.get(&key1).await.unwrap().is_none());
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.log.size(), 12);
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);

            // Since this db no longer has any active keys, the inactivity floor should have been
            // set to tip.
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);

            // Multiple deletions of the same key should be a no-op.
            db.delete(key1).await.unwrap();
            assert_eq!(db.log.size(), 13);
            assert_eq!(db.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let key3 = Sha256::fill(5u8);
            assert!(db.delete(key3).await.is_ok());
            assert_eq!(db.log.size(), 13);
            db.sync().await.unwrap();
            assert_eq!(db.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            assert_eq!(db.log.size(), 13);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.log.size(), 13);
            assert_eq!(db.root(&mut hasher), root);

            // Re-activate the keys by updating them.
            db.update(key1, val1).await.unwrap();
            db.update(key2, val2).await.unwrap();
            db.delete(key1).await.unwrap();
            db.update(key2, val1).await.unwrap();
            db.update(key1, val2).await.unwrap();
            assert_eq!(db.get_all(&key1).await.unwrap().unwrap(), (val2, key2));
            assert_eq!(db.get_all(&key2).await.unwrap().unwrap(), (val1, key1));
            assert_eq!(db.snapshot.keys(), 2);

            // Confirm close/reopen gets us back to the same state.
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.snapshot.keys(), 2);

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit().await.unwrap();

            assert!(db.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root(&mut hasher);
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.root(&mut hasher), root);

            // We should not be able to prune beyond the inactivity floor.
            assert!(matches!(
                db.prune(db.inactivity_floor_loc() + 1).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

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

            assert_eq!(db.op_count(), 2619);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert_eq!(db.log.size(), 2619);
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            db.commit().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.inactivity_floor_loc, 3382);
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 4240);
            assert_eq!(db.inactivity_floor_loc, 3382);
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
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);

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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root(&mut hasher);
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_more_ops(db: &mut AnyTest) {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit().await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let mut hasher = Standard::<Sha256>::new();
            let db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_ops(db: &mut AnyTest) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure, syncing nothing.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit().await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&(j * 1000 + i).to_be_bytes());
                    let v = Sha256::hash(&(i * 1000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                    map.insert(k, v);
                }
                db.commit().await.unwrap();
            }
            let k = Sha256::hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit().await.unwrap();
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert!(db.get(&k).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(20);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();
            let mut hasher = Standard::<Sha256>::new();
            let root_hash = db.root(&mut hasher);
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
            apply_ops(&mut db, more_ops.clone()).await;
            db.commit().await.unwrap();

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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(50);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let mut hasher = Standard::<Sha256>::new();

            // Test singleton database
            let (single_proof, single_ops) = db
                .historical_proof(
                    Location::new_unchecked(1),
                    Location::new_unchecked(0),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(
                single_proof.size,
                Position::try_from(Location::new_unchecked(1)).unwrap()
            );
            assert_eq!(single_ops.len(), 1);

            // Create historical database with single operation
            let mut single_db = create_test_db(context.clone()).await;
            apply_ops(&mut single_db, ops[0..1].to_vec()).await;
            // Don't commit - this changes the root due to commit operations
            single_db.sync().await.unwrap();
            let single_root = single_db.root(&mut hasher);

            assert!(verify_proof(
                &mut hasher,
                &single_proof,
                Location::new_unchecked(0),
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
                    Location::new_unchecked(3),
                    Location::new_unchecked(0),
                    NZU64!(3),
                )
                .await
                .unwrap();
            assert_eq!(
                min_proof.size,
                Position::try_from(Location::new_unchecked(3)).unwrap()
            );
            assert_eq!(min_ops.len(), 3);

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_ordered_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let mut hasher = Standard::<Sha256>::new();
            let root = db.root(&mut hasher);

            let start_loc = Location::new_unchecked(20);
            let max_ops = NZU64!(10);
            let (proof, ops) = db.proof(start_loc, max_ops).await.unwrap();

            // Now keep adding operations and make sure we can still generate a historical proof that matches the original.
            let historical_size = db.op_count();

            for _ in 1..10 {
                let more_ops = create_test_ops(100);
                apply_ops(&mut db, more_ops).await;
                db.commit().await.unwrap();

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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(10);
            apply_ops(&mut db, ops).await;
            db.commit().await.unwrap();

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
                let root_hash = db.root(&mut hasher);
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
                let root_hash = db.root(&mut hasher);
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(0),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the ops should cause verification to fail
            let changed_op = Operation::Update(KeyData {
                key: Sha256::hash(b"key1"),
                value: Sha256::hash(b"value1"),
                next_key: Sha256::hash(b"key2"),
            });
            {
                let mut ops = ops.clone();
                ops[0] = changed_op.clone();
                let root_hash = db.root(&mut hasher);
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
                let root_hash = db.root(&mut hasher);
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
                let root_hash = db.root(&mut hasher);
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
                let root_hash = db.root(&mut hasher);
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
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            async fn insert_random<T: Translator>(
                db: &mut Any<Context, Digest, i32, Sha256, T>,
                rng: &mut StdRng,
            ) {
                let mut keys = BTreeMap::new();

                // Insert 1000 random keys into both the db and an ordered map.
                for i in 0..1000 {
                    let key = Digest::random(rng);
                    keys.insert(key, i);
                    db.update(key, i).await.unwrap();
                }

                db.commit().await.unwrap();

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
                assert_eq!(db.get_span(&Digest::random(rng)).await.unwrap(), None);
            }

            let mut rng = StdRng::seed_from_u64(context.next_u64());
            let seed = context.next_u64();

            // Use a OneCap to ensure many collisions.
            let config = create_generic_test_config::<OneCap>(seed, OneCap);
            let mut db = Any::<Context, Digest, i32, Sha256, OneCap>::init(context.clone(), config)
                .await
                .unwrap();
            insert_random(&mut db, &mut rng).await;
            db.destroy().await.unwrap();

            // Repeat test with TwoCap to test low/no collisions.
            let config = create_generic_test_config::<TwoCap>(seed, TwoCap);
            let mut db = Any::<Context, Digest, i32, Sha256, TwoCap>::init(context.clone(), config)
                .await
                .unwrap();
            insert_random(&mut db, &mut rng).await;
            db.destroy().await.unwrap();
        });
    }
}
