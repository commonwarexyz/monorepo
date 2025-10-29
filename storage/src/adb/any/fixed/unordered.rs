//! An Any database implementation with an unordered key space and fixed-size values.

use crate::{
    adb::{
        any::fixed::{
            historical_proof, init_mmr_and_log, prune_db, Config, SNAPSHOT_READ_BUFFER_SIZE,
        },
        operation::fixed::unordered::Operation,
        store::{self, Db},
        Error,
    },
    index::{Index as _, Unordered as Index},
    journal::fixed::Journal,
    mmr::{journaled::Mmr, Location, Proof, StandardHasher as Standard},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{Array, NZUsize};
use futures::{pin_mut, try_join, StreamExt as _, TryFutureExt as _};
use std::num::NonZeroU64;
use tracing::debug;

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key.
pub struct Any<
    E: Storage + Clock + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()>,
    H: CHasher,
    T: Translator,
> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// - The number of leaves in this MMR always equals the number of operations in the unpruned
    ///   `log`.
    /// - The MMR is never pruned beyond the inactivity floor.
    pub(crate) mmr: Mmr<E, H>,

    /// A (pruned) log of all operations applied to the db in order of occurrence. The position of
    /// each operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - An operation's location is always equal to the number of the MMR leaf storing the digest
    ///   of the operation.
    /// - The log is never pruned beyond the inactivity floor.
    pub(crate) log: Journal<E, Operation<K, V>>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Update].
    pub(crate) snapshot: Index<T, Location>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(crate) inactivity_floor_loc: Location,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    pub(crate) hasher: Standard<H>,
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()>,
        H: CHasher,
        T: Translator,
    > Any<E, K, V, H, T>
{
    /// Returns an [Any] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
        let mut snapshot: Index<T, Location> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let mut hasher = Standard::<H>::new();
        let (inactivity_floor_loc, mmr, log) = init_mmr_and_log(context, cfg, &mut hasher).await?;

        Self::build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;

        let db = Any {
            mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            steps: 0,
            hasher,
        };

        Ok(db)
    }

    /// Builds the database's snapshot by replaying the log starting at the inactivity floor.
    /// Assumes the log and mmr have the same number of operations and are not pruned beyond the
    /// inactivity floor. The callback is invoked for each replayed operation, indicating activity
    /// status updates. The first argument of the callback is the activity status of the operation,
    /// and the second argument is the location of the operation it inactivates (if any).
    pub(crate) async fn build_snapshot_from_log<F>(
        inactivity_floor_loc: Location,
        log: &Journal<E, Operation<K, V>>,
        snapshot: &mut Index<T, Location>,
        mut callback: F,
    ) -> Result<(), Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        let stream = log
            .replay(NZUsize!(SNAPSHOT_READ_BUFFER_SIZE), *inactivity_floor_loc)
            .await?;
        pin_mut!(stream);
        let last_commit_loc = log.size().await?.saturating_sub(1);
        while let Some(result) = stream.next().await {
            let (i, op) = result?;
            match op {
                Operation::Delete(key) => {
                    let result = super::delete_key(snapshot, log, &key).await?;
                    callback(false, result);
                }
                Operation::Update(key, _) => {
                    let new_loc = Location::new_unchecked(i);
                    let old_loc = super::update_loc(snapshot, log, &key, new_loc).await?;
                    callback(true, old_loc);
                }
                Operation::CommitFloor(_) => callback(i == last_commit_loc, None),
            }
        }

        Ok(())
    }

    /// Get the update operation from `log` corresponding to a known location.
    async fn get_update_op(
        log: &Journal<E, Operation<K, V>>,
        loc: Location,
    ) -> Result<(K, V), Error> {
        let Operation::Update(k, v) = log.read(*loc).await? else {
            unreachable!("location does not reference update operation. loc={loc}");
        };

        Ok((k, v))
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.get_key_loc(key).await?.map(|(v, _)| v))
    }

    /// Get the value & location of the active operation for `key` in the db, or None if it has no
    /// value.
    pub(crate) async fn get_key_loc(&self, key: &K) -> Result<Option<(V, Location)>, Error> {
        for &loc in self.snapshot.get(key) {
            let (k, v) = Self::get_update_op(&self.log, loc).await?;
            if k == *key {
                return Ok(Some((v, loc)));
            }
        }

        Ok(None)
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> Location {
        self.mmr.leaves()
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.snapshot.keys() == 0
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        self.update_return_loc(key, value).await?;

        Ok(())
    }

    /// Updates `key` to have value `value`, returning the old location of the key if it was
    /// previously assigned some value, and None otherwise.
    pub(crate) async fn update_return_loc(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<Location>, Error> {
        let new_loc = self.op_count();
        let res = super::update_loc(&mut self.snapshot, &self.log, &key, new_loc).await?;

        let op = Operation::Update(key, value);
        self.as_shared().apply_op(op).await?;
        if res.is_some() {
            self.steps += 1;
        }

        Ok(res)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns the location of the deleted value for the key (if any).
    pub async fn delete(&mut self, key: K) -> Result<Option<Location>, Error> {
        let r = super::delete_key(&mut self.snapshot, &self.log, &key).await?;
        if r.is_some() {
            self.as_shared().apply_op(Operation::Delete(key)).await?;
            self.steps += 1;
        };

        Ok(r)
    }

    /// Returns a wrapper around the db's state that can be used to perform shared functions.
    pub(crate) fn as_shared(
        &mut self,
    ) -> super::Shared<'_, E, Index<T, Location>, Operation<K, V>, H> {
        super::Shared {
            snapshot: &mut self.snapshot,
            mmr: &mut self.mmr,
            log: &mut self.log,
            hasher: &mut self.hasher,
        }
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut Standard<H>) -> H::Digest {
        self.mmr.root(hasher)
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
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count`.
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
        historical_proof(&self.mmr, &self.log, op_count, start_loc, max_ops).await
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
                self.inactivity_floor_loc = self.as_shared().raise_floor(loc).await?;
            }
        }
        self.steps = 0;

        // Apply the commit operation with the new inactivity floor.
        let loc = self.inactivity_floor_loc;
        let mut shared = self.as_shared();
        shared.apply_op(Operation::CommitFloor(loc)).await?;

        // Sync the log and process the updates to the MMR.
        shared.sync_and_process_updates().await
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.as_shared().sync().await
    }

    /// Prune historical operations prior to `target_prune_loc`. This does not affect the db's root
    /// or current snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [crate::mmr::Error::LocationOverflow] if `target_prune_loc` >
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [crate::mmr::Error::RangeOutOfBounds] if `target_prune_loc` is greater than the
    ///   inactivity floor.
    pub async fn prune(&mut self, target_prune_loc: Location) -> Result<(), Error> {
        let op_count = self.op_count();
        prune_db(
            &mut self.mmr,
            &mut self.log,
            &mut self.hasher,
            target_prune_loc,
            self.inactivity_floor_loc,
            op_count,
        )
        .await
    }

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    pub async fn close(mut self) -> Result<(), Error> {
        try_join!(
            self.log.close().map_err(Error::Journal),
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.log.destroy().map_err(Error::Journal),
            self.mmr.destroy().map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Simulate an unclean shutdown by consuming the db without syncing (or only partially syncing)
    /// the log and/or mmr. When _not_ fully syncing the mmr, the `write_limit` parameter dictates
    /// how many mmr nodes to write during a partial sync (can be 0).
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(
        mut self,
        sync_log: bool,
        sync_mmr: bool,
        write_limit: usize,
    ) -> Result<(), Error> {
        if sync_log {
            self.log.sync().await?;
        }
        if sync_mmr {
            assert_eq!(write_limit, 0);
            self.mmr.sync(&mut self.hasher).await?;
        } else if write_limit > 0 {
            self.mmr
                .simulate_partial_sync(&mut self.hasher, write_limit)
                .await?;
        }

        Ok(())
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: CodecFixed<Cfg = ()>,
        H: CHasher,
        T: Translator,
    > Db<E, K, V, T> for Any<E, K, V, H, T>
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, store::Error> {
        self.get(key).await.map_err(Into::into)
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), store::Error> {
        self.update(key, value).await.map_err(Into::into)
    }

    async fn delete(&mut self, key: K) -> Result<(), store::Error> {
        self.delete(key).await.map(|_| ()).map_err(Into::into)
    }

    async fn commit(&mut self) -> Result<(), store::Error> {
        self.commit().await.map_err(Into::into)
    }

    async fn sync(&mut self) -> Result<(), store::Error> {
        self.sync().await.map_err(Into::into)
    }

    async fn prune(&mut self, target_prune_loc: Location) -> Result<(), store::Error> {
        self.prune(target_prune_loc).await.map_err(Into::into)
    }

    async fn close(self) -> Result<(), store::Error> {
        self.close().await.map_err(Into::into)
    }

    async fn destroy(self) -> Result<(), store::Error> {
        self.destroy().await.map_err(Into::into)
    }
}

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        adb::{
            operation::fixed::{unordered::Operation, FixedOperation as _},
            verify_proof,
        },
        index::{Index as IndexTrait, Unordered as Index},
        mmr::{bitmap::BitMap, mem::Mmr as MemMmr, Position, StandardHasher as Standard},
        translator::TwoCap,
    };
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::NZU64;
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    use std::collections::{HashMap, HashSet};
    use tracing::warn;

    const SHA256_SIZE: usize = <Sha256 as CHasher>::Digest::SIZE;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    pub(crate) fn any_db_config(suffix: &str) -> Config<TwoCap> {
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
    pub(crate) type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    pub(crate) fn create_test_config(seed: u64) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: NZU64!(13), // intentionally small and janky size
            mmr_write_buffer: NZUsize!(64),
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: NZU64!(11), // intentionally small and janky size
            log_write_buffer: NZUsize!(64),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(key, value));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Digest>>) {
        for op in ops {
            match op {
                Operation::Update(key, value) => {
                    db.update(key, value).await.unwrap();
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

    #[test_traced("INFO")]
    fn test_any_fixed_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            let empty_root = db.root(&mut hasher);
            assert_eq!(empty_root, MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an
            // uncommitted op, and even without a clean shutdown.
            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            db.update(d1, d2).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), empty_root);

            let empty_proof = Proof::default();
            assert!(verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &empty_root
            ));

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

            // Re-opening the DB without a clean shutdown should still recover the correct state.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(&mut hasher), root);

            // Empty proof should no longer verify.
            assert!(!verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &root
            ));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            db.update(d1, d2).await.unwrap();
            for _ in 1..100 {
                db.commit().await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.op_count() - db.inactivity_floor_loc <= 3);
            }

            // Confirm the inactivity floor is raised to tip when the db becomes empty.
            db.delete(d1).await.unwrap();
            db.commit().await.unwrap();
            assert!(db.is_empty());
            assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);

            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());

            db.update(d1, d2).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d2);
            assert!(db.get(&d2).await.unwrap().is_none());

            db.update(d2, d1).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d2);
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            db.delete(d1).await.unwrap(); // inactivates op 0
            assert!(db.get(&d1).await.unwrap().is_none());
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            db.update(d1, d1).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d1);

            db.update(d2, d2).await.unwrap(); // inactivates op  1
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d2);

            assert_eq!(db.log.size().await.unwrap(), 5); // 4 updates, 1 deletion.
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(0));
            db.sync().await.unwrap();

            // take one floor raising step, which should move the first active op (at location 3) to
            // tip, leaving the floor at the next location (4).
            let loc = db.inactivity_floor_loc;
            db.inactivity_floor_loc = db.as_shared().raise_floor(loc).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(4));
            assert_eq!(db.log.size().await.unwrap(), 6); // 4 updates, 1 deletion, 1 commit
            db.sync().await.unwrap();

            // Delete all keys.
            db.delete(d1).await.unwrap();
            db.delete(d2).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8); // 4 updates, 3 deletions, 1 commit

            db.commit().await.unwrap();
            // Since this db no longer has any active keys, the inactivity floor should have been
            // set to tip.
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);
            let root = db.root(&mut hasher);

            // Multiple deletions of the same key should be a no-op.
            db.delete(d1).await.unwrap();
            assert_eq!(db.log.size().await.unwrap(), 9); // one more commit op added.
            assert_eq!(db.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let d3 = <Sha256 as CHasher>::Digest::decode(vec![2u8; SHA256_SIZE].as_ref()).unwrap();
            assert!(db.delete(d3).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 9);
            db.sync().await.unwrap();
            assert_eq!(db.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            assert_eq!(db.log.size().await.unwrap(), 9);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.log.size().await.unwrap(), 9);
            assert_eq!(db.root(&mut hasher), root);

            // Re-activate the keys by updating them.
            db.update(d1, d1).await.unwrap();
            db.update(d2, d2).await.unwrap();
            db.delete(d1).await.unwrap();
            db.update(d2, d1).await.unwrap();
            db.update(d1, d2).await.unwrap();
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

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_build_and_authenticate() {
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

            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(0));
            assert_eq!(db.log.size().await.unwrap(), 1477);
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            db.commit().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(837));
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(837));
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
            let start_pos = db.mmr.pruned_to_pos();
            let start_loc = Location::try_from(start_pos).unwrap();
            // Raise the inactivity floor via commit and make sure historical inactive operations
            // are still provable.
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);

            for loc in *start_loc..*end_loc {
                let loc = Location::new_unchecked(loc);
                let (proof, log) = db.proof(loc, max_ops).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, loc, &log, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_non_empty_db_recovery() {
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
            db.simulate_failure(false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log and only 10 elements of the mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true, false, 10).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time only fully sync the mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, true, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
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
    fn test_any_fixed_empty_db_recovery() {
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

            // Insert operations without commit then simulate failure, syncing nothing except one
            // element of the mmr.
            apply_ops(&mut db).await;
            db.simulate_failure(false, false, 1).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the mmr.
            apply_ops(&mut db).await;
            db.simulate_failure(false, true, 0).await.unwrap();
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
    fn test_any_fixed_db_log_replay() {
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
    fn test_any_fixed_db_multiple_commits_delete_gets_replayed() {
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

    /// This test builds a random database, and makes sure that its state can be replayed by
    /// `build_snapshot_from_log` with a bitmap to correctly capture the active operations.
    #[test_traced("WARN")]
    fn test_any_fixed_db_build_snapshot_with_bitmap() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        // Use a non-deterministic rng seed to ensure each run is different.
        let rng_seed = OsRng.next_u64();
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&rng.next_u32().to_be_bytes());
                db.update(k, v).await.unwrap();
            }

            // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
            // frequency.
            for _ in 0u64..ELEMENTS * 10 {
                let rand_key = Sha256::hash(&(rng.next_u64() % ELEMENTS).to_be_bytes());
                if rng.next_u32() % 7 == 0 {
                    db.delete(rand_key).await.unwrap();
                    continue;
                }
                let v = Sha256::hash(&rng.next_u32().to_be_bytes());
                db.update(rand_key, v).await.unwrap();
                if rng.next_u32() % 20 == 0 {
                    // Commit every ~20 updates.
                    db.commit().await.unwrap();
                }
            }
            db.commit().await.unwrap();

            let root = db.root(&mut hasher);
            let inactivity_floor_loc = db.inactivity_floor_loc;

            // Close the db, then replay its operations with a bitmap.
            db.close().await.unwrap();
            // Initialize the bitmap based on the current db's inactivity floor.
            let mut bitmap = BitMap::<_, SHA256_SIZE>::new();
            for _ in 0..*inactivity_floor_loc {
                bitmap.push(false);
            }
            bitmap.merkleize(&mut hasher).await.unwrap();

            // Initialize the db's mmr/log.
            let cfg = any_db_config("partition");
            let (inactivity_floor_loc, mmr, log) =
                init_mmr_and_log(context.clone(), cfg, &mut hasher)
                    .await
                    .unwrap();

            // Replay log to populate the bitmap. Use a TwoCap instead of EightCap here so we exercise some collisions.
            let mut snapshot = Index::init(context.with_label("snapshot"), TwoCap);
            AnyTest::build_snapshot_from_log(
                inactivity_floor_loc,
                &log,
                &mut snapshot,
                |append, loc| {
                    bitmap.push(append);
                    if let Some(loc) = loc {
                        bitmap.set_bit(*loc, false);
                    }
                },
            )
            .await
            .unwrap();

            // Check the recovered state is correct.
            let db = AnyTest {
                mmr,
                log,
                snapshot,
                inactivity_floor_loc,
                steps: 0,
                hasher: Standard::<Sha256>::new(),
            };
            assert_eq!(db.root(&mut hasher), root);

            // Check the bitmap state matches that of the snapshot.
            let items = db.log.size().await.unwrap();
            assert_eq!(bitmap.len(), items);
            let mut active_positions = HashSet::new();
            // This loop checks that the expected true bits are true in the bitmap.
            for pos in *db.inactivity_floor_loc..items {
                let item = db.log.read(pos).await.unwrap();
                let Some(item_key) = item.key() else {
                    // `item` is a commit
                    continue;
                };
                let iter = db.snapshot.get(item_key);
                for loc in iter {
                    if *loc == pos {
                        // Found an active op.
                        active_positions.insert(pos);
                        assert!(bitmap.get_bit(pos));
                        break;
                    }
                }
            }
            // This loop checks that the expected false bits are false in the bitmap.
            for pos in *db.inactivity_floor_loc..items - 1 {
                assert_eq!(bitmap.get_bit(pos), active_positions.contains(&pos));
            }
            assert!(bitmap.get_bit(items - 1)); // last commit should always be active

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_basic() {
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
            assert_eq!(historical_ops, ops[5..15]);
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

            // Try to get historical proof with op_count > number of operations and confirm it
            // returns RangeOutOfBounds error.
            assert!(matches!(
                db.historical_proof(db.op_count() + 1, Location::new_unchecked(5), NZU64!(10))
                    .await,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_edge_cases() {
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
            assert_eq!(limited_ops, ops[5..10]);

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
            assert_eq!(min_ops, ops[0..3]);

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let mut hasher = Standard::<Sha256>::new();

            // Test historical proof generation for several historical states.
            let start_loc = Location::new_unchecked(20);
            let max_ops = NZU64!(10);
            for end_loc in 31..50 {
                let end_loc = Location::new_unchecked(end_loc);
                let (historical_proof, historical_ops) = db
                    .historical_proof(end_loc, start_loc, max_ops)
                    .await
                    .unwrap();

                assert_eq!(historical_proof.size, Position::try_from(end_loc).unwrap());

                // Create  reference database at the given historical size
                let mut ref_db = create_test_db(context.clone()).await;
                apply_ops(&mut ref_db, ops[0..*end_loc as usize].to_vec()).await;
                // Sync to process dirty nodes but don't commit - commit changes the root due to commit operations
                ref_db.sync().await.unwrap();

                let (ref_proof, ref_ops) = ref_db.proof(start_loc, max_ops).await.unwrap();
                assert_eq!(ref_proof.size, historical_proof.size);
                assert_eq!(ref_ops, historical_ops);
                assert_eq!(ref_proof.digests, historical_proof.digests);
                let end_loc = std::cmp::min(start_loc.checked_add(max_ops.get()).unwrap(), end_loc);
                assert_eq!(ref_ops, ops[*start_loc as usize..*end_loc as usize]);

                // Verify proof against reference root
                let ref_root = ref_db.root(&mut hasher);
                assert!(verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &ref_root
                ),);

                ref_db.destroy().await.unwrap();
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_invalid() {
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
            {
                let mut ops = ops.clone();
                ops[0] = Operation::Update(Sha256::hash(b"key1"), Sha256::hash(b"value1"));
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
                ops.push(Operation::Update(
                    Sha256::hash(b"key1"),
                    Sha256::hash(b"value1"),
                ));
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
                proof.size = Position::new(100);
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
}
