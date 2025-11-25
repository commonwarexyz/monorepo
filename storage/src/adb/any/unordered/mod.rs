use crate::{
    adb::{
        any::AnyDb,
        build_snapshot_from_log, create_key, delete_key,
        operation::{Committable, Keyed},
        store::Db,
        update_key, Error, FloorHelper, Index,
    },
    journal::{
        authenticated,
        contiguous::{MutableContiguous, PersistableContiguous},
    },
    mmr::{
        mem::{Clean, State},
        Location, Proof,
    },
    translator::Translator,
    AuthenticatedBitMap,
};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use core::{marker::PhantomData, num::NonZeroU64};
use tracing::debug;

pub mod fixed;
pub mod sync;
pub mod variable;

type AuthenticatedLog<E, C, O, H, S = Clean<DigestOf<H>>> = authenticated::Journal<E, C, O, H, S>;

/// A trait implemented by the unordered Any db operation type.
pub trait Operation: Committable + Keyed {
    /// Return a new update operation variant.
    fn new_update(key: Self::Key, value: Self::Value) -> Self;

    /// Return a new delete operation variant.
    fn new_delete(key: Self::Key) -> Self;

    /// Return a new commit-floor operation variant.
    fn new_commit_floor(inactivity_floor_loc: Location) -> Self;
}

/// An indexed, authenticated log of [Keyed] database operations.
pub struct IndexedLog<
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item = O>,
    O: Operation,
    I: Index<T>,
    H: Hasher,
    T: Translator,
    S: State<DigestOf<H>> = Clean<DigestOf<H>>,
> {
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    pub(crate) log: AuthenticatedLog<E, C, O, H, S>,

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

    pub(crate) translator: PhantomData<T>,
}

impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = O>,
        O: Operation,
        I: Index<T, Value = Location>,
        H: Hasher,
        T: Translator,
        S: State<DigestOf<H>>,
    > IndexedLog<E, C, O, I, H, T, S>
{
    fn op_count(&self) -> Location {
        self.log.size()
    }

    /// Returns the inactivity floor from an authenticated log known to be in a consistent state by
    /// reading it from the last commit, which is assumed to be the last operation in the log.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub(crate) async fn recover_inactivity_floor(
        log: &AuthenticatedLog<E, C, O, H, S>,
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
    pub fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Returns the active operation for `key` with its location, or None if the key is not active.
    pub(crate) async fn get_key_op_loc(
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
    ///
    /// # Panics
    ///
    /// Panics if the operation is not a delete operation.
    pub(crate) async fn delete_key(&mut self, op: O) -> Result<Option<Location>, Error> {
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
    pub(crate) async fn update_loc(
        &mut self,
        key: &O::Key,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        update_key(&mut self.snapshot, &self.log, key, new_loc).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: MutableContiguous<Item = O>,
        O: Operation,
        I: Index<T, Value = Location>,
        H: Hasher,
        T: Translator,
    > IndexedLog<E, C, O, I, H, T>
{
    /// Returns a [IndexedLog] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub async fn init_from_log<F>(
        context: E,
        translator: T,
        log: AuthenticatedLog<E, C, O, H>,
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
        let mut snapshot = I::init(context, translator);
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

    /// Returns an [IndexedLog] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last commit location is set to None and it is the responsibility of the
    /// caller to ensure it is set correctly.
    async fn from_components(
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
    pub(crate) fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, T, I, AuthenticatedLog<E, C, O, H>, O> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
            translator: PhantomData,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item = O>,
        O: Operation,
        I: Index<T, Value = Location>,
        T: Translator,
        H: Hasher,
    > IndexedLog<E, C, O, I, H, T>
{
    /// Applies the given commit operation to the log and commits it to disk. Does not raise the
    /// inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(crate) async fn apply_commit_op(&mut self, op: O) -> Result<(), Error> {
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
}

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item = O>,
        O: Operation,
        I: Index<T, Value = Location>,
        T: Translator,
        H: Hasher,
    > AnyDb<O, H::Digest> for IndexedLog<E, C, O, I, H, T>
{
    /// Returns the root of the authenticated log.
    fn root(&self) -> H::Digest {
        self.log.root()
    }

    /// Whether the snapshot currently has no active keys.
    fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count`.
    async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<O>), Error> {
        let size = self.op_count();
        self.historical_proof(size, start_loc, max_ops).await
    }

    /// Returns a proof of inclusion of all operations in the range starting at (and including)
    /// location `start_loc`, and ending at the first of either:
    /// - the last operation performed, or
    /// - the operation `max_ops` from the start.
    ///
    /// Also returns a vector of operations corresponding to this range.
    async fn historical_proof(
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

impl<
        E: Storage + Clock + Metrics,
        C: PersistableContiguous<Item = O>,
        O: Operation,
        I: Index<T, Value = Location>,
        H: Hasher,
        T: Translator,
    > Db<O::Key, O::Value> for IndexedLog<E, C, O, I, H, T>
{
    fn op_count(&self) -> Location {
        self.log.size()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    async fn get(&self, key: &O::Key) -> Result<Option<O::Value>, Error> {
        self.get_key_op_loc(key)
            .await
            .map(|op| op.map(|(v, _)| v.into_value().expect("update operation must have value")))
    }

    async fn update(&mut self, key: O::Key, value: O::Value) -> Result<(), Error> {
        self.update_key_with_op(O::new_update(key, value))
            .await
            .map(|_| ())
    }

    async fn create(&mut self, key: O::Key, value: O::Value) -> Result<bool, Error> {
        self.create_key_with_op(O::new_update(key, value)).await
    }

    async fn delete(&mut self, key: O::Key) -> Result<bool, Error> {
        self.delete_key(O::new_delete(key))
            .await
            .map(|o| o.is_some())
    }

    async fn commit(&mut self) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.raise_floor().await?;

        // Commit the log to ensure this commit is durable.
        self.apply_commit_op(O::new_commit_floor(inactivity_floor_loc))
            .await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        self.log.prune(prune_loc).await?;

        Ok(())
    }

    async fn close(self) -> Result<(), Error> {
        self.log.close().await.map_err(Into::into)
    }

    async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }
}

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        adb::{
            any::{FixedConfig, VariableConfig},
            verify_proof,
        },
        mmr::{mem::Mmr as MemMmr, Proof, StandardHasher},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use core::{future::Future, pin::Pin};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    pub(crate) fn fixed_db_config(suffix: &str) -> FixedConfig<TwoCap> {
        FixedConfig {
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

    pub(crate) fn variable_db_config(suffix: &str) -> VariableConfig<TwoCap, ()> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

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

    async fn test_any_db_empty<O, D>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn std::future::Future<Output = D> + Send>>,
    ) where
        O: Keyed<Key = Digest, Value = Digest>,
        D: AnyDb<O, Digest>,
    {
        assert_eq!(db.op_count(), 0);
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
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
        db.update(k1, v1).await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 0);
        assert_eq!(db.root(), empty_root);

        let empty_proof = Proof::default();
        let empty_ops: [O; 0] = [];
        assert!(verify_proof(
            &mut hasher,
            &empty_proof,
            Location::new_unchecked(0),
            &empty_ops,
            &empty_root
        ));

        // Test calling commit on an empty db which should make it (durably) non-empty.
        db.commit().await.unwrap();
        assert_eq!(db.op_count(), 1); // commit op added
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
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
        db.update(k1, v1).await.unwrap();
        for _ in 1..100 {
            db.commit().await.unwrap();
            // Distance should equal 3 after the second commit, with inactivity_floor
            // referencing the previous commit operation.
            assert!(db.op_count() - db.inactivity_floor_loc() <= 3);
        }

        // Confirm the inactivity floor is raised to tip when the db becomes empty.
        db.delete(k1).await.unwrap();
        db.commit().await.unwrap();
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

    async fn test_any_db_basic<O, D>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        O: Keyed<Key = Digest, Value = Digest>,
        D: AnyDb<O, Digest>,
    {
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
        db.commit().await.unwrap();

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

        db.commit().await.unwrap();
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
        db.commit().await.unwrap();
        assert_eq!(db.op_count(), 13);
        let root = db.root();
        db.close().await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 13);
        assert_eq!(db.root(), root);

        // Re-activate the keys by updating them.
        db.update(d1, v1).await.unwrap();
        db.update(d2, v2).await.unwrap();
        db.delete(d1).await.unwrap();
        db.update(d2, v1).await.unwrap();
        db.update(d1, v2).await.unwrap();

        // Make sure last_commit is updated by changing the metadata back to None.
        db.commit().await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        assert_eq!(db.op_count(), 22);
        let root = db.root();
        db.close().await.unwrap();
        let mut db = reopen_db(context.clone()).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), 22);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        db.commit().await.unwrap();

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
