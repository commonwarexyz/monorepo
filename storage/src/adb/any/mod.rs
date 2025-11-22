//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated with
//! a key. The submodules provide two classes of variants, one specialized for fixed-size values and
//! the other allowing variable-size values.

pub mod fixed;
pub mod variable;

use crate::{
    adb::{
        build_snapshot_from_log, create_key, delete_key,
        operation::{Committable, KeyData, Keyed, Ordered},
        update_key, Error, FloorHelper,
    },
    index::{Cursor as _, Unordered},
    journal::{authenticated, contiguous::Contiguous},
    mmr::{Location, Proof, StandardHasher},
    translator::Translator,
    AuthenticatedBitMap,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::{marker::PhantomData, num::NonZeroU64};
use tracing::debug;

type AuthenticatedLog<E, C, O, H> = authenticated::Journal<E, C, O, H>;

/// Type alias for the floor helper state wrapper used by the [OperationLog].
type FloorHelperState<'a, E, C, O, I, H, T> =
    FloorHelper<'a, T, I, AuthenticatedLog<E, C, O, H>, O>;

/// Type alias for a ordered key's data along with its location in the log.
type KeyDataWithLocation<K, V> = Option<(Location, KeyData<K, V>)>;

/// An indexed, authenticated log of [Keyed] database operations.
pub struct OperationLog<
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Committable + Keyed,
    I: Unordered<T>,
    H: Hasher,
    T: Translator,
> {
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    pub(super) log: AuthenticatedLog<E, C, O, H>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(super) inactivity_floor_loc: Location,

    /// The location of the last commit operation (if any exists).
    pub(super) last_commit: Option<Location>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// - Only references update variants of [Keyed] operations.
    pub(super) snapshot: I,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(super) steps: u64,

    /// The number of active keys in the snapshot.
    pub(super) active_keys: usize,

    pub(super) translator: PhantomData<T>,
}

impl<
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = O>,
        O: Committable + Keyed,
        I: Unordered<T, Value = Location>,
        H: Hasher,
        T: Translator,
    > OperationLog<E, C, O, I, H, T>
{
    /// Returns the inactivity floor from an authenticated log known to be in a consistent state by
    /// reading it from the last commit, which is assumed to be the last operation in the log.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub(crate) async fn recover_inactivity_floor(
        log: &AuthenticatedLog<E, C, O, H>,
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

    /// Returns a [OperationLog] initialized from `log` and `translator`.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub async fn init<F>(
        log: AuthenticatedLog<E, C, O, H>,
        mut snapshot: I,
        callback: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        let inactivity_floor_loc = Self::recover_inactivity_floor(&log).await?;

        // Build snapshot from the log
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, callback).await?;
        let last_commit = log.size().checked_sub(1);

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot,
            last_commit,
            steps: 0,
            active_keys,
            translator: PhantomData,
        })
    }

    /// Returns an [OperationLog] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last commit location is set to None and it is the responsibility of the
    /// caller to ensure it is set correctly.
    pub async fn from_components(
        inactivity_floor_loc: Location,
        log: AuthenticatedLog<E, C, O, H>,
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
            translator: PhantomData,
        })
    }

    /// Returns the number of operations that have been appended to the log, including those that
    /// are not yet committed, and any operations that have been pruned.
    pub(super) fn op_count(&self) -> Location {
        self.log.size()
    }

    /// Whether the snapshot currently has no active keys.
    pub(super) fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Returns the value currently assigned to `key`, or None if it has no value.
    pub(super) async fn get(&self, key: &O::Key) -> Result<Option<O::Value>, Error> {
        self.get_key_op_loc(key)
            .await
            .map(|op| op.map(|(v, _)| v.into_value().expect("update operation must have value")))
    }

    /// Returns the active operation for `key` with its location, or None if the key is not active.
    pub(super) async fn get_key_op_loc(
        &self,
        key: &O::Key,
    ) -> Result<Option<(O, Location)>, Error> {
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

    /// Commits the operation log to disk after applying the given commit operation, ensuring
    /// durability of appended operations.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(super) async fn commit(&mut self, op: O) -> Result<(), Error> {
        assert!(op.is_commit(), "commit operation expected");
        self.last_commit = Some(self.op_count());
        self.log.append(op).await?;

        self.log.commit().await.map_err(Into::into)
    }

    /// Syncs the log to disk, ensuring durability of all modifications and a clean recovery even in
    /// the event of an unclean shutdown. Use commit instead to more efficiently ensure durability
    /// without the clean recovery guarantee.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub(super) async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        self.log.prune(prune_loc).await?;

        Ok(())
    }

    /// Returns the location of the oldest operation that remains retrievable.
    pub(super) fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_loc()
    }

    /// Returns the location before which all operations have been pruned.
    pub(super) fn pruning_boundary(&self) -> Location {
        self.log.pruning_boundary()
    }

    /// Closes the log, ensuring all modifications are durably persisted to disk.
    pub(super) async fn close(self) -> Result<(), Error> {
        self.log.close().await.map_err(Into::into)
    }

    /// Destroys the log, removing all persistent data associated with it.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }

    /// Append an operation to the log.
    pub(super) async fn append(&mut self, op: O) -> Result<Location, Error> {
        self.log.append(op).await.map_err(Into::into)
    }

    /// Reads and returns the operation at location `loc` within the log.
    pub(super) async fn read(&self, loc: Location) -> Result<O, Error> {
        self.log.read(loc).await.map_err(Into::into)
    }

    /// Appends the given delete operation to the log, updating the snapshot and other state to
    /// reflect the deletion.
    ///
    /// # Panics
    ///
    /// Panics if the operation is not a delete operation.
    pub(super) async fn delete_key(&mut self, op: O) -> Result<Option<Location>, Error> {
        assert!(op.is_delete(), "delete operation expected");
        let key = op.key().expect("delete operations should have a key");
        let Some(loc) = delete_key(&mut self.snapshot, &self.log, key).await? else {
            return Ok(None);
        };

        self.log.append(op).await?;
        self.steps += 1;
        self.active_keys -= 1;

        Ok(Some(loc))
    }

    /// Appends the provided update operation to the log, returning the old location of the key if
    /// it was previously assigned some value, and None otherwise.
    ///
    /// # Panics
    ///
    /// Panics if the operation is not an update operation.
    pub(crate) async fn update_key_with_op(&mut self, op: O) -> Result<Option<Location>, Error> {
        assert!(op.is_update(), "update operation expected");

        let new_loc = self.op_count();
        let key = op.key().expect("update operations should have a key");
        let res = self.update_loc(key, new_loc).await?;

        self.log.append(op).await?;
        if res.is_some() {
            self.steps += 1;
        } else {
            self.active_keys += 1;
        }

        Ok(res)
    }

    /// Creates a new key with the given operation, or returns false if the key already exists.
    pub(crate) async fn create_key_with_op(&mut self, op: O) -> Result<bool, Error> {
        assert!(op.is_update(), "update operation expected");

        let key = op.key().expect("update operations should have a key");
        let new_loc = self.op_count();
        if !create_key(&mut self.snapshot, &self.log, key, new_loc).await? {
            return Ok(false);
        }

        self.log.append(op).await?;
        self.active_keys += 1;

        Ok(true)
    }

    /// Updates the location of `key` in the snapshot to `new_loc`, returning the previous location
    /// of the key if any was found.
    pub(super) async fn update_loc(
        &mut self,
        key: &O::Key,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        update_key(&mut self.snapshot, &self.log, key, new_loc).await
    }

    /// For the given `key` which is known to exist in the snapshot with location `old_loc`, update
    /// its location to `new_loc`.
    ///
    /// # Panics
    ///
    /// Panics if the key does not exist in the snapshot with the provided old location.
    pub(super) async fn update_known_loc(
        &mut self,
        key: &O::Key,
        old_loc: Location,
        new_loc: Location,
    ) -> Result<(), Error> {
        let mut cursor = self
            .snapshot
            .get_mut(key)
            .expect("key should be known to exist");
        assert!(
            cursor.find(|&loc| *loc == old_loc),
            "key with known location should have been found"
        );
        cursor.update(new_loc);

        Ok(())
    }

    /// Raises the inactivity floor by exactly one step, moving the first active operation to tip.
    /// Raises the floor to the tip if the db is empty.
    pub(super) async fn raise_floor(&mut self) -> Result<Location, Error> {
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
    pub(super) async fn raise_floor_with_bitmap<D: Digest, const N: usize>(
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
    pub(super) fn as_floor_helper(&mut self) -> FloorHelperState<'_, E, C, O, I, H, T> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
            translator: PhantomData,
        }
    }

    /// Returns the root of the authenticated log.
    pub(super) fn root(&self, hasher: &mut StandardHasher<H>) -> H::Digest {
        self.log.root(hasher)
    }

    /// Returns a proof of inclusion of all operations in the range starting at (and including)
    /// location `start_loc`, and ending at the first of either:
    /// - the last operation performed, or
    /// - the operation `max_ops` from the start.
    ///
    /// Also returns a vector of operations corresponding to this range.
    pub(super) async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<O>), Error> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }
}

/// The return type of the `Any::update_loc` method.
enum UpdateLocResult<K: Array + Ord, V: Codec> {
    /// The key already exists in the snapshot. The wrapped value is its next-key.
    Exists(K),

    /// The key did not already exist in the snapshot. The wrapped key data is for the first
    /// preceding key that does exist in the snapshot.
    NotExists(KeyData<K, V>),
}

/// Get the update operation from `log` corresponding to a known location.
async fn get_update_op<E, C, O, H>(
    log: &AuthenticatedLog<E, C, O, H>,
    loc: Location,
) -> Result<KeyData<O::Key, O::Value>, Error>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Ordered,
    H: Hasher,
{
    let Some(data) = log.read(loc).await?.into_key_data() else {
        unreachable!("location does not reference update operation. loc={loc}");
    };

    Ok(data)
}

/// Find the span produced by the provided `iter` that contains `key`, if any.
async fn find_span<E, C, O, H>(
    log: &AuthenticatedLog<E, C, O, H>,
    iter: impl Iterator<Item = &Location>,
    key: &O::Key,
) -> Result<KeyDataWithLocation<O::Key, O::Value>, Error>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Ordered,
    H: Hasher,
{
    for &loc in iter {
        // Iterate over conflicts in the snapshot entry to find the span.
        let data = get_update_op(log, loc).await?;
        if span_contains(&data.key, &data.next_key, key) {
            return Ok(Some((loc, data)));
        }
    }

    Ok(None)
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

/// Returns the location and KeyData for the lexicographically-last key produced by `iter`.
async fn last_key_in_iter<E, C, O, H>(
    log: &AuthenticatedLog<E, C, O, H>,
    iter: impl Iterator<Item = &Location>,
) -> Result<KeyDataWithLocation<O::Key, O::Value>, Error>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Ordered,
    H: Hasher,
{
    let mut last_key: KeyDataWithLocation<O::Key, O::Value> = None;
    for &loc in iter {
        let data = get_update_op(log, loc).await?;
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
