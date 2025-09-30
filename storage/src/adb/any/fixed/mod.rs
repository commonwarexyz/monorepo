//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [Mmr] over a log of state-change operations backed
//! by a [Journal].
//!
//! In the [Any] db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::Error,
    index::{Cursor, Index as _, Unordered as Index},
    journal::fixed::{Config as JConfig, Journal},
    mmr::{
        bitmap::Bitmap,
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
    store::operation::Fixed as Operation,
    translator::Translator,
};
use commonware_codec::{CodecFixed, Encode as _};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use commonware_utils::{Array, NZUsize};
use futures::{
    future::{try_join_all, TryFutureExt},
    pin_mut, try_join, StreamExt,
};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

pub mod sync;

/// Indicator that the generic parameter N is unused by the call. N is only
/// needed if the caller is providing the optional bitmap.
const UNUSED_N: usize = 0;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

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

    /// The number of operations that are pending commit.
    pub(crate) uncommitted_ops: u64,

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
        let (inactivity_floor_loc, mmr, log) =
            Self::init_mmr_and_log(context, cfg, &mut hasher).await?;

        Self::build_snapshot_from_log(
            inactivity_floor_loc,
            &log,
            &mut snapshot,
            None::<&mut Bitmap<H, UNUSED_N>>,
        )
        .await?;

        let db = Any {
            mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            hasher,
        };

        Ok(db)
    }

    /// Initialize and return the mmr and log from the given config, correcting any inconsistencies
    /// between them. Any uncommitted operations in the log will be rolled back and the state of the
    /// db will be as of the last committed operation.
    pub(crate) async fn init_mmr_and_log(
        context: E,
        cfg: Config<T>,
        hasher: &mut Standard<H>,
    ) -> Result<(Location, Mmr<E, H>, Journal<E, Operation<K, V>>), Error> {
        let mut mmr = Mmr::init(
            context.with_label("mmr"),
            hasher,
            MmrConfig {
                journal_partition: cfg.mmr_journal_partition,
                metadata_partition: cfg.mmr_metadata_partition,
                items_per_blob: cfg.mmr_items_per_blob,
                write_buffer: cfg.mmr_write_buffer,
                thread_pool: cfg.thread_pool,
                buffer_pool: cfg.buffer_pool.clone(),
            },
        )
        .await?;

        let mut log = Journal::init(
            context.with_label("log"),
            JConfig {
                partition: cfg.log_journal_partition,
                items_per_blob: cfg.log_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        // Back up over / discard any uncommitted operations in the log.
        let mut log_size = log.size().await?;
        let mut rewind_leaf_loc = log_size;
        let mut inactivity_floor_loc = Location::new(0);
        while rewind_leaf_loc > 0 {
            if let Operation::CommitFloor(loc) = log.read(rewind_leaf_loc - 1).await? {
                inactivity_floor_loc = loc;
                break;
            }
            rewind_leaf_loc -= 1;
        }
        if rewind_leaf_loc != log_size {
            let op_count = log_size - rewind_leaf_loc;
            warn!(
                log_size,
                op_count, "rewinding over uncommitted log operations"
            );
            log.rewind(rewind_leaf_loc).await?;
            log.sync().await?;
            log_size = rewind_leaf_loc;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        let mut next_mmr_leaf_loc = *mmr.leaves();
        if next_mmr_leaf_loc > log_size {
            let num_to_pop = (next_mmr_leaf_loc - log_size) as usize;
            warn!(log_size, num_to_pop, "popping uncommitted MMR operations");
            mmr.pop(num_to_pop).await?;
            next_mmr_leaf_loc = log_size;
        }

        // If the MMR is behind, replay log operations to catch up.
        if next_mmr_leaf_loc < log_size {
            warn!(
                log_size,
                next_mmr_leaf_loc, "MMR lags behind log, replaying log to catch up"
            );
            while next_mmr_leaf_loc < log_size {
                let op = log.read(next_mmr_leaf_loc).await?;
                mmr.add_batched(hasher, &op.encode()).await?;
                next_mmr_leaf_loc += 1;
            }
            mmr.sync(hasher).await.map_err(Error::Mmr)?;
        }

        // At this point the MMR and log should be consistent.
        assert_eq!(log.size().await?, mmr.leaves());

        Ok((inactivity_floor_loc, mmr, log))
    }

    /// Builds the database's snapshot by replaying the log starting at the inactivity floor.
    /// Assumes the log and mmr have the same number of operations and are not pruned beyond the
    /// inactivity floor.
    ///
    /// If a bitmap is provided, then a bit is appended for each operation in the operation log,
    /// with its value reflecting its activity status. The caller is responsible for syncing any
    /// changes made to the bitmap.
    pub(crate) async fn build_snapshot_from_log<const N: usize>(
        inactivity_floor_loc: Location,
        log: &Journal<E, Operation<K, V>>,
        snapshot: &mut Index<T, Location>,
        mut bitmap: Option<&mut Bitmap<H, N>>,
    ) -> Result<(), Error> {
        if let Some(ref bitmap) = bitmap {
            assert_eq!(inactivity_floor_loc, bitmap.bit_count());
        }

        let stream = log
            .replay(NZUsize!(SNAPSHOT_READ_BUFFER_SIZE), *inactivity_floor_loc)
            .await?;
        pin_mut!(stream);
        while let Some(result) = stream.next().await {
            match result {
                Err(e) => {
                    return Err(Error::Journal(e));
                }
                Ok((i, op)) => {
                    match op {
                        Operation::Delete(key) => {
                            let result = Any::<E, K, V, H, T>::delete_key(
                                snapshot,
                                log,
                                &key,
                                Location::new(i),
                            )
                            .await?;
                            if let Some(ref mut bitmap) = bitmap {
                                // Mark previous location (if any) of the deleted key as inactive.
                                if let Some(old_loc) = result {
                                    bitmap.set_bit(*old_loc, false);
                                }
                            }
                        }
                        Operation::Update(key, _) => {
                            let result = Any::<E, K, V, H, T>::update_loc(
                                snapshot,
                                log,
                                &key,
                                Location::new(i),
                            )
                            .await?;
                            if let Some(ref mut bitmap) = bitmap {
                                if let Some(old_loc) = result {
                                    bitmap.set_bit(*old_loc, false);
                                }
                                bitmap.append(true);
                            }
                        }
                        Operation::CommitFloor(_) => {}
                    }
                    if let Some(ref mut bitmap) = bitmap {
                        // If we reach this point and a bit hasn't been added for the operation, then it's
                        // an inactive operation and we need to tag it as such in the bitmap.
                        if bitmap.bit_count() == i {
                            bitmap.append(false);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Update the location of `key` to `new_loc` in the snapshot and return its old location, or
    /// insert it if the key isn't already present.
    async fn update_loc(
        snapshot: &mut Index<T, Location>,
        log: &Journal<E, Operation<K, V>>,
        key: &K,
        new_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
        // cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut_or_insert(key, new_loc) else {
            return Ok(None);
        };

        // Iterate over conflicts in the snapshot.
        while let Some(&loc) = cursor.next() {
            let (k, _) = Self::get_update_op(log, loc).await?;
            if k == *key {
                // Found the key in the snapshot.
                assert!(new_loc > loc);
                cursor.update(new_loc);
                return Ok(Some(loc));
            }
        }

        // The key wasn't in the snapshot, so add it to the cursor.
        cursor.insert(new_loc);

        Ok(None)
    }

    /// Get the update operation corresponding to a location from the snapshot.
    ///
    /// # Warning
    ///
    /// Panics if the location does not reference an update operation. This should never happen
    /// unless the snapshot is buggy, or this method is being used to look up an operation
    /// independent of the snapshot contents.
    async fn get_update_op(
        log: &Journal<E, Operation<K, V>>,
        loc: Location,
    ) -> Result<(K, V), Error> {
        let Operation::Update(k, v) = log.read(*loc).await? else {
            panic!("location does not reference update operation. loc={loc}");
        };

        Ok((k, v))
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.get_key_loc(key).await?.map(|(v, _)| v))
    }

    /// Get the value of the operation with location `loc` in the db. Returns [Error::OperationPruned]
    /// if the location precedes the oldest retained location. The location is otherwise assumed
    /// valid.
    pub async fn get_loc(&self, loc: Location) -> Result<Option<V>, Error> {
        assert!(loc < self.op_count());
        if loc < self.inactivity_floor_loc {
            return Err(Error::OperationPruned(loc));
        }

        Ok(self.log.read(*loc).await?.into_value())
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
        let res =
            Any::<_, _, _, H, T>::update_loc(&mut self.snapshot, &self.log, &key, new_loc).await?;

        let op = Operation::Update(key, value);
        self.apply_op(op).await?;

        Ok(res)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns the location of the deleted value for the key (if any).
    pub async fn delete(&mut self, key: K) -> Result<Option<Location>, Error> {
        let loc = self.op_count();
        let r = Self::delete_key(&mut self.snapshot, &self.log, &key, loc).await?;
        if r.is_some() {
            self.apply_op(Operation::Delete(key)).await?;
        };

        Ok(r)
    }

    /// Delete `key` from the snapshot if it exists, returning the location that was previously
    /// associated with it.
    async fn delete_key(
        snapshot: &mut Index<T, Location>,
        log: &Journal<E, Operation<K, V>>,
        key: &K,
        delete_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is in the snapshot, get a cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return Ok(None);
        };
        // Iterate over all conflicting keys in the snapshot.
        while let Some(&loc) = cursor.next() {
            let (k, _) = Self::get_update_op(log, loc).await?;
            if k == *key {
                // The key is in the snapshot, so delete it.
                //
                // If there are no longer any conflicting keys in the cursor, it will
                // automatically be removed from the snapshot.
                assert!(loc < delete_loc);
                cursor.delete();
                return Ok(Some(loc));
            }
        }

        // The key isn't in the conflicting keys, so this is a no-op.
        Ok(None)
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut Standard<H>) -> H::Digest {
        self.mmr.root(hasher)
    }

    /// Append `op` to the log and add it to the MMR. The operation will be subject to rollback
    /// until the next successful `commit`.
    pub(crate) async fn apply_op(&mut self, op: Operation<K, V>) -> Result<(), Error> {
        let encoded_op = op.encode();

        // Append operation to the log and update the MMR in parallel.
        try_join!(
            self.mmr
                .add_batched(&mut self.hasher, &encoded_op)
                .map_err(Error::Mmr),
            self.log.append(op).map_err(Error::Journal)
        )?;
        self.uncommitted_ops += 1;

        Ok(())
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
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        let end_loc = std::cmp::min(op_count, start_loc.saturating_add(max_ops.get()));

        let mmr_size = Position::from(op_count);
        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_loc..end_loc)
            .await?;
        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        let futures = (*start_loc..*end_loc)
            .map(|i| self.log.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        Ok((proof, ops))
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // commit op that will be appended.
        self.raise_inactivity_floor(self.uncommitted_ops + 1)
            .await?;

        // Sync the log and process the updates to the MMR in parallel.
        let mmr_fut = async {
            self.mmr.process_updates(&mut self.hasher);
            Ok::<(), Error>(())
        };
        try_join!(self.log.sync().map_err(Error::Journal), mmr_fut)?;
        self.uncommitted_ops = 0;

        Ok(())
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::Journal),
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
        )?;

        Ok(())
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    pub(crate) async fn move_op_if_active(
        &mut self,
        op: Operation<K, V>,
        old_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.key() else {
            return Ok(None); // operations without keys cannot be active
        };
        let new_loc = self.op_count();
        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        // Iterate over all conflicting keys in the snapshot.
        while let Some(&loc) = cursor.next() {
            if loc == old_loc {
                // Update the location of the operation in the snapshot.
                cursor.update(new_loc);
                drop(cursor);

                // Update the MMR with the operation.
                self.apply_op(op).await?;
                return Ok(Some(old_loc));
            }
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the db's snapshot, but it always changes the root
    /// since it applies at least one operation.
    async fn raise_inactivity_floor(&mut self, max_steps: u64) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.log.read(*self.inactivity_floor_loc).await?;
            self.move_op_if_active(op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(Operation::CommitFloor(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune historical operations prior to `target_prune_loc`. This does not affect the db's root
    /// or current snapshot.
    ///
    /// # Panic
    ///
    /// Panics if `target_prune_loc` is greater than the inactivity floor.
    pub async fn prune(&mut self, target_prune_loc: Location) -> Result<(), Error> {
        assert!(target_prune_loc <= self.inactivity_floor_loc);
        if self.mmr.size() == 0 {
            // DB is empty, nothing to prune.
            return Ok(());
        };

        // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the log pruning boundary.
        self.mmr.sync(&mut self.hasher).await?;

        if !self.log.prune(*target_prune_loc).await? {
            return Ok(());
        }

        debug!(
            log_size = ?self.op_count(),
            ?target_prune_loc,
            "pruned inactive ops"
        );

        self.mmr
            .prune_to_pos(&mut self.hasher, Position::from(target_prune_loc))
            .await?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    pub async fn close(mut self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing db with uncommitted operations"
            );
        }

        self.sync().await?;

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
    #[cfg(test)]
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

// pub(super) so helpers can be used by the sync module.
#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        adb::verify_proof,
        mmr::{mem::Mmr as MemMmr, StandardHasher as Standard},
        translator::TwoCap,
    };
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::NZU64;
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    use std::collections::{HashMap, HashSet};

    const SHA256_SIZE: usize = <Sha256 as CHasher>::Digest::SIZE;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    pub(super) fn any_db_config(suffix: &str) -> Config<TwoCap> {
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
    pub(super) type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    pub(super) fn create_test_config(seed: u64) -> Config<TwoCap> {
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
    pub(super) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    pub(super) fn create_test_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
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
    pub(super) async fn apply_ops(db: &mut AnyTest, ops: Vec<Operation<Digest, Digest>>) {
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

    #[test_traced("WARN")]
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
            assert_eq!(db.root(&mut hasher), empty_root);
            assert_eq!(db.op_count(), 0);

            let empty_proof = Proof::default();
            assert!(verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new(0),
                &[] as &[Operation<Digest, Digest>],
                &empty_root
            ));

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
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
                Location::new(0),
                &[] as &[Operation<Digest, Digest>],
                &root
            ));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit().await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);
            }

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

            db.delete(d1).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            db.update(d1, d1).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d1);

            db.update(d2, d2).await.unwrap();
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d2);

            assert_eq!(db.log.size().await.unwrap(), 5); // 4 updates, 1 deletion.
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc, Location::new(0));
            db.sync().await.unwrap();

            // Advance over 3 inactive operations.
            db.raise_inactivity_floor(3).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, Location::new(3));
            assert_eq!(db.log.size().await.unwrap(), 6); // 4 updates, 1 deletion, 1 commit
            db.sync().await.unwrap();

            // Delete all keys.
            db.delete(d1).await.unwrap();
            db.delete(d2).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8); // 4 updates, 3 deletions, 1 commit
            assert_eq!(db.inactivity_floor_loc, Location::new(3));

            db.sync().await.unwrap();
            let root = db.root(&mut hasher);

            // Multiple deletions of the same key should be a no-op.
            db.delete(d1).await.unwrap();
            assert_eq!(db.log.size().await.unwrap(), 8);
            assert_eq!(db.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let d3 = <Sha256 as CHasher>::Digest::decode(vec![2u8; SHA256_SIZE].as_ref()).unwrap();
            assert!(db.delete(d3).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8);
            db.sync().await.unwrap();
            assert_eq!(db.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            db.commit().await.unwrap();
            assert_eq!(db.log.size().await.unwrap(), 9);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.log.size().await.unwrap(), 9);
            assert_eq!(db.root(&mut hasher), root);

            // Since this db no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive commit op remains).
            db.raise_inactivity_floor(100).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);

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
            assert_eq!(db.inactivity_floor_loc, Location::new(0));
            assert_eq!(db.log.size().await.unwrap(), 1477);
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            db.commit().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.inactivity_floor_loc, Location::new(1478));
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.inactivity_floor_loc, Location::new(1478));
            assert_eq!(db.snapshot.items(), 857);

            // Raise the inactivity floor to the point where all inactive operations can be pruned.
            db.raise_inactivity_floor(3000).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, Location::new(4478));
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(db.op_count(), 4478 + 858);
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
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.raise_inactivity_floor(100).await.unwrap();
            db.sync().await.unwrap();
            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);

            for loc in *start_loc..*end_loc {
                let loc = Location::new(loc);
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
            let mut bitmap = Bitmap::<_, SHA256_SIZE>::new();
            for _ in 0..*inactivity_floor_loc {
                bitmap.append(false);
            }
            bitmap.sync(&mut hasher).await.unwrap();

            // Initialize the db's mmr/log.
            let cfg = any_db_config("partition");
            let (inactivity_floor_loc, mmr, log) =
                AnyTest::init_mmr_and_log(context.clone(), cfg, &mut hasher)
                    .await
                    .unwrap();

            // Replay log to populate the bitmap. Use a TwoCap instead of EightCap here so we exercise some collisions.
            let mut snapshot = Index::init(context.with_label("snapshot"), TwoCap);
            AnyTest::build_snapshot_from_log::<SHA256_SIZE>(
                inactivity_floor_loc,
                &log,
                &mut snapshot,
                Some(&mut bitmap),
            )
            .await
            .unwrap();

            // Check the recovered state is correct.
            let db = AnyTest {
                mmr,
                log,
                snapshot,
                inactivity_floor_loc,
                uncommitted_ops: 0,
                hasher: Standard::<Sha256>::new(),
            };
            assert_eq!(db.root(&mut hasher), root);

            // Check the bitmap state matches that of the snapshot.
            let items = db.log.size().await.unwrap();
            assert_eq!(bitmap.bit_count(), items);
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
            for pos in *db.inactivity_floor_loc..items {
                if !active_positions.contains(&pos) {
                    assert!(!bitmap.get_bit(pos));
                }
            }

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
                .historical_proof(original_op_count, Location::new(5), max_ops)
                .await
                .unwrap();
            let (regular_proof, regular_ops) = db.proof(Location::new(5), max_ops).await.unwrap();

            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert_eq!(historical_ops, ops[5..15]);
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new(5),
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            let more_ops = create_test_ops(5);
            apply_ops(&mut db, more_ops.clone()).await;
            db.commit().await.unwrap();

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new(5), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(historical_proof.size, Position::from(original_op_count));
            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_ops.len(), 10);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof(
                &mut hasher,
                &historical_proof,
                Location::new(5),
                &historical_ops,
                &root_hash
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
                .historical_proof(Location::new(1), Location::new(0), NZU64!(1))
                .await
                .unwrap();
            assert_eq!(single_proof.size, Position::from(Location::new(1)));
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
                Location::new(0),
                &single_ops,
                &single_root
            ));

            // Test requesting more operations than available in historical position
            let (_limited_proof, limited_ops) = db
                .historical_proof(Location::new(10), Location::new(5), NZU64!(20))
                .await
                .unwrap();
            assert_eq!(limited_ops.len(), 5); // Should be limited by historical position
            assert_eq!(limited_ops, ops[5..10]);

            // Test proof at minimum historical position
            let (min_proof, min_ops) = db
                .historical_proof(Location::new(3), Location::new(0), NZU64!(3))
                .await
                .unwrap();
            assert_eq!(min_proof.size, Position::from(Location::new(3)));
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
            let start_loc = Location::new(20);
            let max_ops = NZU64!(10);
            for end_loc in 31..50 {
                let end_loc = Location::new(end_loc);
                let (historical_proof, historical_ops) = db
                    .historical_proof(end_loc, start_loc, max_ops)
                    .await
                    .unwrap();

                assert_eq!(historical_proof.size, Position::from(end_loc));

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

            let (proof, ops) = db
                .historical_proof(Location::new(5), Location::new(1), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(proof.size, Position::from(Location::new(5)));
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
                    Location::new(0),
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
                    Location::new(0),
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
                    Location::new(0),
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
                    Location::new(0),
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
                    Location::new(1),
                    &ops,
                    &root_hash
                ));
            }

            // Changing the root digest should cause verification to fail
            {
                assert!(!verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new(0),
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
                    Location::new(0),
                    &ops,
                    &root_hash
                ));
            }

            db.destroy().await.unwrap();
        });
    }
}
