use crate::{
    adb::{
        any::{CleanAny, DirtyAny},
        build_snapshot_from_log, create_key, delete_key,
        operation::{Committable, Keyed},
        store::LogStore,
        update_key, Error, FloorHelper, Index,
    },
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
pub mod sync;
pub mod variable;

type AuthenticatedLog<E, C, H, S = Clean<DigestOf<H>>> = authenticated::Journal<E, C, H, S>;

/// A trait implemented by the unordered Any db operation type.
pub trait Operation: Committable + Keyed {
    /// Return a new update operation variant.
    fn new_update(key: Self::Key, value: Self::Value) -> Self;

    /// Return a new delete operation variant.
    fn new_delete(key: Self::Key) -> Self;

    /// Return a new commit-floor operation variant.
    fn new_commit_floor(metadata: Option<Self::Value>, loc: Location) -> Self;
}

/// An indexed, authenticated log of [Keyed] database operations.
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

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Returns the active operation for `key` with its location, or None if the key is not active.
    pub(crate) async fn get_key_op_loc(
        &self,
        key: &<C::Item as Keyed>::Key,
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

    /// Appends the given delete operation to the log, updating the snapshot and other state to
    /// reflect the deletion.
    pub(crate) async fn delete_key(
        &mut self,
        key: <C::Item as Keyed>::Key,
    ) -> Result<Option<Location>, Error> {
        let Some(loc) = delete_key(&mut self.snapshot, &self.log, &key).await? else {
            return Ok(None);
        };
        self.log.append(C::Item::new_delete(key)).await?;
        self.steps += 1;
        self.active_keys -= 1;

        Ok(Some(loc))
    }

    /// Appends the provided update to the log, returning the old location of the key if
    /// it was previously assigned some value, and None otherwise.
    pub(crate) async fn update_key(
        &mut self,
        key: <C::Item as Keyed>::Key,
        value: <C::Item as Keyed>::Value,
    ) -> Result<Option<Location>, Error> {
        let new_loc = self.op_count();
        let res = self.update_loc(&key, new_loc).await?;

        self.log.append(C::Item::new_update(key, value)).await?;
        if res.is_some() {
            self.steps += 1;
        } else {
            self.active_keys += 1;
        }

        Ok(res)
    }

    /// Creates a new key with the given operation, or returns false if the key already exists.
    pub(crate) async fn create_key(
        &mut self,
        key: <C::Item as Keyed>::Key,
        value: <C::Item as Keyed>::Value,
    ) -> Result<bool, Error> {
        let new_loc = self.op_count();
        if !create_key(&mut self.snapshot, &self.log, &key, new_loc).await? {
            return Ok(false);
        }

        self.log.append(C::Item::new_update(key, value)).await?;
        self.active_keys += 1;

        Ok(true)
    }

    /// Updates the location of `key` in the snapshot to `new_loc`, returning the previous location
    /// of the key if any was found.
    pub(crate) async fn update_loc(
        &mut self,
        key: &<C::Item as Keyed>::Key,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        update_key(&mut self.snapshot, &self.log, key, new_loc).await
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(
        &self,
        key: &<C::Item as Keyed>::Key,
    ) -> Result<Option<<C::Item as Keyed>::Value>, Error> {
        self.get_key_op_loc(key)
            .await
            .map(|op| op.map(|(v, _)| v.into_value().expect("update operation must have value")))
    }

    /// Get the metadata associated with the last commit, or None if no commit has been made.
    pub async fn get_metadata(&self) -> Result<Option<<C::Item as Keyed>::Value>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        let op = self.log.read(last_commit).await?;
        Ok(op.into_value())
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(
        &mut self,
        key: <C::Item as Keyed>::Key,
        value: <C::Item as Keyed>::Value,
    ) -> Result<(), Error> {
        self.update_key(key, value).await.map(|_| ())
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(
        &mut self,
        key: <C::Item as Keyed>::Key,
        value: <C::Item as Keyed>::Value,
    ) -> Result<bool, Error> {
        self.create_key(key, value).await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: <C::Item as Keyed>::Key) -> Result<bool, Error> {
        Ok(self.delete_key(key).await?.is_some())
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
        metadata: Option<<C::Item as Keyed>::Value>,
    ) -> Result<Range<Location>, Error> {
        let start_loc = self
            .last_commit
            .map_or_else(|| Location::new_unchecked(0), |last_commit| last_commit + 1);

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.raise_floor().await?;

        // Commit the log to ensure this commit is durable.
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
        C: PersistableContiguous<Item: Operation>,
        I: Index<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > LogStore for IndexedLog<E, C, I, H, S>
{
    type Value = <C::Item as Keyed>::Value;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<<C::Item as Keyed>::Value>, Error> {
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
    type Key = <C::Item as Keyed>::Key;
    type Value = <C::Item as Keyed>::Value;
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
    type Key = <C::Item as Keyed>::Key;

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
    type Key = <C::Item as Keyed>::Key;

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

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        adb::{
            any::test::{fixed_db_config, variable_db_config},
            store::DirtyStore as _,
            verify_proof,
        },
        mmr::{mem::Mmr as MemMmr, Proof, StandardHasher},
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

    /// A type alias for the concrete [Any] type used in these unit tests.<
    type VariableDb = variable::Any<Context, Digest, Digest, Sha256, TwoCap, Clean<Digest>>;

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

    async fn test_any_db_empty<D>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn std::future::Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = Digest, Value = Digest, Digest = Digest>,
    {
        assert_eq!(db.op_count(), 0);
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
        assert!(db.get_metadata().await.unwrap().is_none());
        let empty_root = db.root();
        let mut hasher = StandardHasher::<Sha256>::new();
        assert_eq!(
            empty_root,
            *MemMmr::default().merkleize(&mut hasher, None).root()
        );

        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let mut db = db.into_dirty();
        db.update(k1, v1).await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 0);
        assert_eq!(db.root(), empty_root);

        let empty_proof = Proof::default();
        let empty_ops: Vec<u8> = vec![];
        assert!(verify_proof(
            &mut hasher,
            &empty_proof,
            Location::new_unchecked(0),
            &empty_ops,
            &empty_root
        ));

        // Test calling commit on an empty db which should make it (durably) non-empty.
        let metadata = Sha256::fill(3u8);
        let range = db.commit(Some(metadata)).await.unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.end, 1);
        assert_eq!(db.op_count(), 1); // commit op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Empty proof should no longer verify.
        assert!(!verify_proof(
            &mut hasher,
            &empty_proof,
            Location::new_unchecked(0),
            &empty_ops,
            &root
        ));

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
        // non-empty db.
        let mut db = db.into_dirty();
        db.update(k1, v1).await.unwrap();
        for _ in 1..100 {
            let mut clean_db = db.merkleize();
            clean_db.commit(None).await.unwrap();
            db = clean_db.into_dirty();
            // Distance should equal 3 after the second commit, with inactivity_floor
            // referencing the previous commit operation.
            assert!(db.op_count() - db.inactivity_floor_loc() <= 3);
        }

        // Confirm the inactivity floor is raised to tip when the db becomes empty.
        db.delete(k1).await.unwrap();
        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        assert!(db.is_empty());
        assert_eq!(db.op_count() - 1, db.inactivity_floor_loc());

        db.destroy().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_any_db_empty(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    async fn test_any_db_basic<D>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = Digest, Value = Digest, Digest = Digest>,
    {
        let mut db = db.into_dirty();

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

        assert_eq!(db.op_count(), 5); // 4 updates, 1 deletion.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();

        // Make sure create won't modify active keys.
        assert!(!db.create(d1, v1).await.unwrap());
        assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

        // Should have moved 3 active operations to tip, leading to floor of 6.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(6));
        assert_eq!(db.op_count(), 9); // floor of 6 + 2 active keys + 1 commit.

        // Delete all keys.
        assert!(db.delete(d1).await.unwrap());
        assert!(db.delete(d2).await.unwrap());
        assert!(db.get(&d1).await.unwrap().is_none());
        assert!(db.get(&d2).await.unwrap().is_none());
        assert_eq!(db.op_count(), 11); // 2 new delete ops.
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(6));

        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(11));
        assert_eq!(db.op_count(), 12); // only commit should remain.

        // Multiple deletions of the same key should be a no-op.
        assert!(!db.delete(d1).await.unwrap());
        assert_eq!(db.op_count(), 12);

        // Deletions of non-existent keys should be a no-op.
        let d3 = Sha256::fill(3u8);
        assert!(!db.delete(d3).await.unwrap());
        assert_eq!(db.op_count(), 12);

        // Make sure closing/reopening gets us back to the same state.
        let mut db = db.merkleize();
        db.commit(None).await.unwrap();
        assert_eq!(db.op_count(), 13);
        let root = db.root();
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 13);
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Re-activate the keys by updating them.
        db.update(d1, v1).await.unwrap();
        db.update(d2, v2).await.unwrap();
        db.delete(d1).await.unwrap();
        db.update(d2, v1).await.unwrap();
        db.update(d1, v2).await.unwrap();

        // Make sure last_commit is updated by changing the metadata back to None.
        let mut db = db.merkleize();
        db.commit(None).await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        assert_eq!(db.op_count(), 22);
        let root = db.root();
        let mut db = reopen_db(context.clone()).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), 22);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        db.commit(None).await.unwrap();

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
            let db = open_fixed_db(context.clone()).await;
            test_any_db_basic(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("INFO")]
    fn test_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }
}
