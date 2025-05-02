//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [Mmr] over a log of state-change operations backed
//! by a [Journal].
//!
//! In the [Any] db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::{
        operation::{Operation, Type},
        Error,
    },
    index::{translator::EightCap, Index, Translator},
    journal::fixed::{Config as JConfig, Journal},
    mmr::{
        bitmap::Bitmap,
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        verification::Proof,
    },
};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use futures::{
    future::{try_join_all, TryFutureExt},
    try_join,
};
use tracing::{debug, warn};

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config {
    /// The name of the `Storage` partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: u64,

    /// The name of the `Storage` partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the `Storage` partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: u64,
}

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key.
pub struct Any<
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Array,
    H: CHasher,
    T: Translator = EightCap,
> {
    /// An MMR over digests of the operations applied to the db. The number of leaves in this MMR
    /// always equals the number of operations in the unpruned `log`.
    ops: Mmr<E, H>,

    /// A (pruned) log of all operations applied to the db in order of occurrence. The position
    /// of each operation in the log is called its _location_, which is a stable identifier. Pruning
    /// is indicated by a non-zero value for `pruned_loc`, which provides the location of the first
    /// operation in the log.
    ///
    /// Invariant: An operation's location is always equal to the number of the MMR leaf storing the
    /// digest of the operation.
    log: Journal<E, Operation<K, V>>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: u64,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update. Only contains the keys that currently
    /// have a value (that is, deleted keys are not in the map).
    snapshot: Index<T, u64>,

    /// The number of operations that are pending commit.
    uncommitted_ops: u64,
}

/// The result of a database `update` operation.
pub enum UpdateResult {
    /// Tried to set a key to its current value.
    NoOp,
    /// Key was not previously in the snapshot & its new loc is the wrapped value.
    Inserted(u64),
    /// Key was previously in the snapshot & its (old, new) loc pair is wrapped.
    Updated(u64, u64),
}

impl<E: RStorage + Clock + Metrics, K: Array, V: Array, H: CHasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns any `Any` adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        hasher: &mut H,
        cfg: Config,
        translator: T,
    ) -> Result<Self, Error> {
        let mut snapshot: Index<T, u64> = Index::init(context.with_label("snapshot"), translator);
        let (mmr, log) = Self::init_mmr_and_log(context, hasher, cfg).await?;

        let start_leaf_num = leaf_pos_to_num(mmr.pruned_to_pos()).unwrap();
        let inactivity_floor_loc = Self::build_snapshot_from_log::<0 /* value is unused*/>(
            hasher,
            start_leaf_num,
            &log,
            &mut snapshot,
            None,
        )
        .await?;

        let db = Any {
            ops: mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
        };

        Ok(db)
    }

    /// Initialize and return the mmr and log from the given config, correcting any inconsistencies
    /// between them. Any uncommitted operations in the log will be rolled back and the state of the
    /// db will be as of the last committed operation.
    pub(crate) async fn init_mmr_and_log(
        context: E,
        hasher: &mut H,
        cfg: Config,
    ) -> Result<(Mmr<E, H>, Journal<E, Operation<K, V>>), Error> {
        let mut mmr = Mmr::init(
            context.with_label("mmr"),
            MmrConfig {
                journal_partition: cfg.mmr_journal_partition,
                metadata_partition: cfg.mmr_metadata_partition,
                items_per_blob: cfg.mmr_items_per_blob,
            },
        )
        .await?;

        let mut log = Journal::init(
            context.with_label("log"),
            JConfig {
                partition: cfg.log_journal_partition,
                items_per_blob: cfg.log_items_per_blob,
            },
        )
        .await?;

        // Back up over / discard any uncommitted operations in the log.
        let mut log_size = log.size().await?;
        let mut rewind_leaf_num = log_size;
        while rewind_leaf_num > 0 {
            let op: Operation<K, V> = log.read(rewind_leaf_num - 1).await?;
            match op.to_type() {
                Type::Commit(_) => {
                    break; // floor is our commit indicator
                }
                _other => {
                    rewind_leaf_num -= 1;
                }
            }
        }
        if rewind_leaf_num != log_size {
            let op_count = log_size - rewind_leaf_num;
            warn!(op_count, "rewinding over uncommitted log operations");
            log.rewind(rewind_leaf_num).await?;
            log_size = rewind_leaf_num;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        let mut next_mmr_leaf_num = leaf_pos_to_num(mmr.size()).unwrap();
        if next_mmr_leaf_num > log_size {
            let op_count = next_mmr_leaf_num - log_size;
            warn!(op_count, "popping uncommitted MMR operations");
            mmr.pop(op_count as usize).await?;
            next_mmr_leaf_num = log_size;
        }

        // If the MMR is behind, replay log operations to catch up.
        if next_mmr_leaf_num < log_size {
            let op_count = log_size - next_mmr_leaf_num;
            warn!(op_count, "MMR lags behind log, replaying log to catch up");
            while next_mmr_leaf_num < log_size {
                let op = log.read(next_mmr_leaf_num).await?;
                let digest = Self::op_digest(&mut H::new(), &op);
                mmr.add(hasher, &digest);
                next_mmr_leaf_num += 1;
            }
        }

        // At this point the MMR and log should be consistent.
        assert_eq!(log.size().await?, leaf_pos_to_num(mmr.size()).unwrap());

        Ok((mmr, log))
    }

    /// Builds the database's snapshot by replaying the log starting at `start_leaf_num`. If a bitmap is
    /// provided, then a bit is appended for each operation in the operation log, with its value
    /// reflecting its activity status. The bitmap is expected to already have a number of bits
    /// corresponding to the portion of the database below the inactivity floor, and this method
    /// will panic otherwise.
    pub(crate) async fn build_snapshot_from_log<const N: usize>(
        hasher: &mut H,
        start_leaf_num: u64,
        log: &Journal<E, Operation<K, V>>,
        snapshot: &mut Index<T, u64>,
        mut bitmap: Option<&mut Bitmap<H, N>>,
    ) -> Result<u64, Error> {
        let mut inactivity_floor_loc = start_leaf_num;
        let log_size = log.size().await.unwrap();
        if let Some(ref bitmap) = bitmap {
            assert_eq!(start_leaf_num, bitmap.bit_count());
        }

        // TODO: Because all operations are idempotent, we could potentially parallelize this via
        // replay_all by keeping track of the location of each operation and only applying it if it
        // is more recent than the last operation for the same key.
        for i in start_leaf_num..log_size {
            let op: Operation<K, V> = log.read(i).await?;
            match op.to_type() {
                Type::Deleted(key) => {
                    // If the translated key is in the snapshot, get a cursor to look for the key.
                    if let Some(mut cursor) = snapshot.get_mut(&key) {
                        while let Some(loc) = cursor.next() {
                            let op = log.read(*loc).await?;
                            if op.to_key() != key {
                                continue;
                            }
                            if let Some(ref mut bitmap_ref) = bitmap {
                                bitmap_ref.set_bit(hasher, *loc, false);
                            }

                            // If the mapped key is the same, delete it from the snapshot.
                            cursor.delete();
                            break;
                        }
                    }
                }
                Type::Update(key, _) => {
                    let update_result =
                        Any::<E, K, V, H, T>::update_loc(snapshot, log, key, None, i).await?;
                    if let Some(ref mut bitmap_ref) = bitmap {
                        match update_result {
                            UpdateResult::NoOp => unreachable!("unexpected no-op update"),
                            UpdateResult::Inserted(_) => {
                                bitmap_ref.append(hasher, true);
                            }
                            UpdateResult::Updated(old_loc, _) => {
                                bitmap_ref.set_bit(hasher, old_loc, false);
                                bitmap_ref.append(hasher, true);
                            }
                        }
                    }
                }
                Type::Commit(loc) => inactivity_floor_loc = loc,
            }
            if let Some(ref mut bitmap_ref) = bitmap {
                // If we reach this point and a bit hasn't been added for the operation, then it's
                // an inactive operation and we need to tag it as such in the bitmap.
                if bitmap_ref.bit_count() == i {
                    bitmap_ref.append(hasher, false);
                }
            }
        }

        Ok(inactivity_floor_loc)
    }

    /// Update the location of `key` to `new_loc` in the snapshot and return its old location, or
    /// insert it if the key isn't already present. If a `value` is provided, then it is used to see
    /// if the key is already assigned that value, in which case this is a no-op, and `None` is
    /// returned.
    async fn update_loc(
        snapshot: &mut Index<T, u64>,
        log: &Journal<E, Operation<K, V>>,
        key: K,
        value: Option<&V>,
        new_loc: u64,
    ) -> Result<UpdateResult, Error> {
        // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
        // cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut_or_insert(&key, new_loc) else {
            return Ok(UpdateResult::Inserted(new_loc));
        };

        // Iterate over conflicts in the snapshot.
        while let Some(loc) = cursor.next() {
            let op = log.read(*loc).await?;
            if op.to_key() != key {
                continue;
            }
            if let Some(v) = value {
                if op.to_value().unwrap() == *v {
                    // The key value is the same as the previous one: treat as a no-op.
                    return Ok(UpdateResult::NoOp);
                }
            }

            // Update the location of the matching operation in the snapshot.
            let old_loc = *loc;
            cursor.update(new_loc);
            return Ok(UpdateResult::Updated(old_loc, new_loc));
        }

        // The key wasn't in the snapshot, so add it to the cursor.
        cursor.insert(new_loc);
        Ok(UpdateResult::Inserted(new_loc))
    }

    /// Return a digest of the operation.
    pub fn op_digest(hasher: &mut H, op: &Operation<K, V>) -> H::Digest {
        hasher.update(op);
        hasher.finalize()
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        for loc in self.snapshot.get(key) {
            let op = self.log.read(*loc).await?;
            match op.to_type() {
                Type::Update(k, v) => {
                    if k == *key {
                        return Ok(Some(v));
                    }
                }
                _ => {
                    unreachable!(
                        "snapshot should only reference update operations. key={}",
                        key
                    );
                }
            }
        }

        Ok(None)
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> u64 {
        leaf_pos_to_num(self.ops.size()).unwrap()
    }

    /// Return the oldest location that remains readable & provable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        self.ops
            .oldest_retained_pos()
            .map(|pos| leaf_pos_to_num(pos).unwrap())
    }

    /// Updates `key` to have value `value`. If the key already has this same value, then this is a
    /// no-op. The operation is reflected in the snapshot, but will be subject to rollback until the
    /// next successful `commit`.
    pub async fn update(
        &mut self,
        hasher: &mut H,
        key: K,
        value: V,
    ) -> Result<UpdateResult, Error> {
        let new_loc = self.op_count();
        let res = Any::<_, _, _, H, _>::update_loc(
            &mut self.snapshot,
            &self.log,
            key.clone(),
            Some(&value),
            new_loc,
        )
        .await?;
        match res {
            UpdateResult::NoOp => {
                // The key already has this value, so this is a no-op.
                return Ok(res);
            }
            UpdateResult::Inserted(_) => (),
            UpdateResult::Updated(_, _) => (),
        }

        let op = Operation::update(key, value);
        self.apply_op(hasher, op).await?;

        Ok(res)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns the location of the deleted value for the key (if any).
    pub async fn delete(&mut self, hasher: &mut H, key: K) -> Result<Option<u64>, Error> {
        // If the translated key is in the snapshot, get a cursor to look for the key.
        let Some(mut cursor) = self.snapshot.get_mut(&key) else {
            return Ok(None);
        };

        // Iterate over all conflicting keys in the snapshot.
        while let Some(loc) = cursor.next() {
            let op = self.log.read(*loc).await?;
            match op.to_type() {
                Type::Update(k, _) => {
                    if k == key {
                        // The key is in the snapshot, so delete it.
                        //
                        // If there are no longer any conflicting keys in the cursor, it will
                        // automatically be removed from the snapshot.
                        let old_loc = *loc;
                        cursor.delete();
                        drop(cursor);
                        self.apply_op(hasher, Operation::delete(key)).await?;
                        return Ok(Some(old_loc));
                    }
                }
                _ => {
                    unreachable!(
                        "snapshot should only reference update operations. key={}",
                        key
                    );
                }
            }
        }

        // The key isn't in the conflicting keys, so this is a no-op.
        Ok(None)
    }

    /// Return the root hash of the db.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.ops.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    pub(crate) async fn apply_op(
        &mut self,
        hasher: &mut H,
        op: Operation<K, V>,
    ) -> Result<u64, Error> {
        // Update the ops MMR.
        let digest = Self::op_digest(hasher, &op);
        self.ops.add(hasher, &digest);
        self.uncommitted_ops += 1;

        // Append the operation to the log.
        self.log.append(op).await.map_err(Error::JournalError)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    pub async fn proof(
        &self,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H>, Vec<Operation<K, V>>), Error> {
        let start_pos = leaf_num_to_pos(start_loc);
        let end_pos_last = self.ops.last_leaf_pos().unwrap();
        let end_pos_max = leaf_num_to_pos(start_loc + max_ops - 1);
        let (end_pos, end_loc) = if end_pos_last < end_pos_max {
            (end_pos_last, leaf_pos_to_num(end_pos_last).unwrap())
        } else {
            (end_pos_max, start_loc + max_ops - 1)
        };

        let proof = self.ops.range_proof(start_pos, end_pos).await?;
        let mut ops = Vec::with_capacity((end_loc - start_loc + 1) as usize);
        let futures = (start_loc..=end_loc)
            .map(|i| self.log.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        Ok((proof, ops))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root hash.
    pub fn verify_proof(
        hasher: &mut H,
        proof: &Proof<H>,
        start_loc: u64,
        ops: &[Operation<K, V>],
        root_hash: &H::Digest,
    ) -> bool {
        let start_pos = leaf_num_to_pos(start_loc);
        let end_loc = start_loc + ops.len() as u64 - 1;
        let end_pos = leaf_num_to_pos(end_loc);

        let digests = ops
            .iter()
            .map(|op| Any::<E, _, _, _, T>::op_digest(hasher, op))
            .collect::<Vec<_>>();

        proof.verify_range_inclusion(hasher, digests, start_pos, end_pos, root_hash)
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable
    /// upon return from this function. Also raises the inactivity floor according to the schedule,
    /// and prunes those operations below it. If an old_locs vector is provided, then any locations
    /// that were flipped from active to inactive during this operation are added to it.
    pub async fn commit(&mut self, hasher: &mut H) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // commit op that will be appended.
        self.raise_inactivity_floor(hasher, self.uncommitted_ops + 1, None)
            .await?;
        self.uncommitted_ops = 0;
        self.sync().await?;

        // TODO: Make the frequency with which we prune known inactive items configurable in case
        // this turns out to be a significant part of commit overhead, or the user wants to ensure
        // the log is backed up externally before discarding.
        self.prune_inactive().await
    }

    /// Sync the db to disk ensuring the current state is persisted.
    async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::JournalError),
            self.ops.sync().map_err(Error::MmrError),
        )?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing db with uncommitted operations"
            );
        }
        try_join!(
            self.log.close().map_err(Error::JournalError),
            self.ops.close().map_err(Error::MmrError),
        )?;

        Ok(())
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    async fn move_op_if_active(
        &mut self,
        hasher: &mut H,
        op: Operation<K, V>,
        old_loc: u64,
    ) -> Result<Option<u64>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let key = op.to_key();
        let new_loc = self.op_count();
        let Some(mut cursor) = self.snapshot.get_mut(&key) else {
            return Ok(None);
        };

        // Iterate over all conflicting keys in the snapshot.
        while let Some(loc) = cursor.next() {
            if *loc == old_loc {
                // Update the location of the operation in the snapshot.
                cursor.update(new_loc);
                drop(cursor);

                // Update the MMR with the operation.
                self.apply_op(hasher, op).await?;
                return Ok(Some(old_loc));
            }
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it. If old_locs is non-None, then any locations
    /// that were flipped from active to inactive are added to the provided vector.
    ///
    /// This method does not change the state of the db's snapshot, but it always changes the root
    /// since it applies at least one operation.
    pub(crate) async fn raise_inactivity_floor(
        &mut self,
        hasher: &mut H,
        max_steps: u64,
        mut old_locs: Option<&mut Vec<u64>>,
    ) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.log.read(self.inactivity_floor_loc).await?;
            let old_loc = self
                .move_op_if_active(hasher, op, self.inactivity_floor_loc)
                .await?;
            if let (Some(old_locs_vec), Some(old_loc_value)) = (old_locs.as_mut(), old_loc) {
                old_locs_vec.push(old_loc_value);
            }
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(hasher, Operation::commit(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune any historical operations that are known to be inactive (those preceding the
    /// inactivity floor). This does not affect the db's root or current snapshot.
    pub(crate) async fn prune_inactive(&mut self) -> Result<(), Error> {
        let Some(oldest_retained_loc) = self.log.oldest_retained_pos().await? else {
            return Ok(());
        };

        let pruned_ops = self.inactivity_floor_loc - oldest_retained_loc;
        if pruned_ops == 0 {
            return Ok(());
        }
        debug!(pruned = pruned_ops, "pruning inactive ops");

        // Prune the MMR, whose pruning boundary serves as the "source of truth" for proving.
        let prune_to_pos = leaf_num_to_pos(self.inactivity_floor_loc);
        self.ops.prune_to_pos(prune_to_pos).await?;

        // Because the log's pruning boundary will be blob-size aligned, we cannot use it as a
        // source of truth for the min provable element.
        self.log.prune(self.inactivity_floor_loc).await?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the log to the commit point, but without
    /// fully committing the MMR's cached elements to trigger MMR node recovery on reopening. The
    /// root hash of the db at the point of a successful commit will be returned in the result.
    #[cfg(test)]
    pub async fn simulate_failed_commit_mmr(
        mut self,
        hasher: &mut H,
        write_limit: usize,
    ) -> Result<H::Digest, Error> {
        self.apply_op(hasher, Operation::commit(self.inactivity_floor_loc))
            .await?;
        let root = self.root(hasher);
        self.log.close().await?;
        self.ops.simulate_partial_sync(write_limit).await?;

        Ok(root)
    }

    /// Simulate a failed commit that successfully writes the MMR to the commit point, but without
    /// fully committing the log, requiring rollback of the MMR and log upon reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_log(mut self, hasher: &mut H) -> Result<(), Error> {
        self.apply_op(hasher, Operation::commit(self.inactivity_floor_loc))
            .await?;
        self.ops.close().await?;
        // Rewind the operation log over the commit op to force rollback to the previous commit.
        self.log.rewind(self.log.size().await? - 1).await?;
        self.log.close().await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        index::translator::{EightCap, TwoCap},
        mmr::mem::Mmr as MemMmr,
    };
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{hash, sha256::Digest, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    use std::collections::{HashMap, HashSet};

    fn any_db_config() -> Config {
        Config {
            mmr_journal_partition: "journal_partition".into(),
            mmr_metadata_partition: "metadata_partition".into(),
            mmr_items_per_blob: 11,
            log_journal_partition: "log_journal_partition".into(),
            log_items_per_blob: 7,
        }
    }

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db<E: RStorage + Clock + Metrics>(
        context: E,
        hasher: &mut Sha256,
    ) -> Any<E, Digest, Digest, Sha256, EightCap> {
        Any::<E, Digest, Digest, Sha256, EightCap>::init(context, hasher, any_db_config(), EightCap)
            .await
            .unwrap()
    }

    #[test_traced]
    pub fn test_any_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert!(matches!(db.prune_inactive().await, Ok(())));
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = <Sha256 as CHasher>::Digest::decode(vec![1u8; 32].as_ref()).unwrap();
            let d2 = <Sha256 as CHasher>::Digest::decode(vec![2u8; 32].as_ref()).unwrap();
            let root = db.root(&mut hasher);
            db.update(&mut hasher, d1, d2).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(&mut hasher).await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune_inactive().await, Ok(())));
            let mut db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(db.root(&mut hasher), root);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit(&mut hasher).await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);
            }
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;

            let d1 = <Sha256 as CHasher>::Digest::decode(vec![1u8; 32].as_ref()).unwrap();
            let d2 = <Sha256 as CHasher>::Digest::decode(vec![2u8; 32].as_ref()).unwrap();

            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());

            assert!(matches!(
                db.update(&mut hasher, d1, d2).await.unwrap(),
                UpdateResult::Inserted(0)
            ));
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d2);
            assert!(db.get(&d2).await.unwrap().is_none());

            assert!(matches!(
                db.update(&mut hasher, d2, d1).await.unwrap(),
                UpdateResult::Inserted(1)
            ));
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d2);
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            assert!(matches!(db.delete(&mut hasher, d1).await.unwrap(), Some(0)));
            assert!(db.get(&d1).await.unwrap().is_none());
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            assert!(matches!(
                db.update(&mut hasher, d1, d1).await.unwrap(),
                UpdateResult::Inserted(3)
            ));
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d1);

            assert!(matches!(
                db.update(&mut hasher, d2, d2).await.unwrap(),
                UpdateResult::Updated(1, 4)
            ));
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d2);

            assert_eq!(db.log.size().await.unwrap(), 5); // 4 updates, 1 deletion.
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc, 0);
            db.sync().await.unwrap();

            // Advance over 3 inactive operations.
            let mut old_locs = Vec::new();
            db.raise_inactivity_floor(&mut hasher, 3, Some(&mut old_locs))
                .await
                .unwrap();
            assert!(old_locs.is_empty()); // no active ops were moved
            assert_eq!(db.inactivity_floor_loc, 3);
            assert_eq!(db.log.size().await.unwrap(), 6); // 4 updates, 1 deletion, 1 commit

            let root = db.root(&mut hasher);

            // Multiple assignments of the same value should be a no-op.
            assert!(matches!(
                db.update(&mut hasher, d1, d1).await.unwrap(),
                UpdateResult::NoOp
            ));
            assert!(matches!(
                db.update(&mut hasher, d2, d2).await.unwrap(),
                UpdateResult::NoOp
            ));
            // Log and root should be unchanged.
            assert_eq!(db.log.size().await.unwrap(), 6);
            assert_eq!(db.root(&mut hasher), root);

            // Delete all keys.
            assert!(matches!(db.delete(&mut hasher, d1).await.unwrap(), Some(3)));
            assert!(matches!(db.delete(&mut hasher, d2).await.unwrap(), Some(4)));
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8); // 4 updates, 3 deletions, 1 commit
            assert_eq!(db.inactivity_floor_loc, 3);

            let root = db.root(&mut hasher);

            // Multiple deletions of the same key should be a no-op.
            assert!(db.delete(&mut hasher, d1).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8);
            assert_eq!(db.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let d3 = <Sha256 as CHasher>::Digest::decode(vec![2u8; 32].as_ref()).unwrap();
            assert!(db.delete(&mut hasher, d3).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8);
            assert_eq!(db.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            db.commit(&mut hasher).await.unwrap();
            assert_eq!(db.log.size().await.unwrap(), 9);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(db.log.size().await.unwrap(), 9);
            assert_eq!(db.root(&mut hasher), root);

            // Since this db no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive commit op remains).
            db.raise_inactivity_floor(&mut hasher, 100, None)
                .await
                .unwrap();
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);

            // Re-activate the keys by updating them.
            db.update(&mut hasher, d1, d1).await.unwrap();
            db.update(&mut hasher, d2, d2).await.unwrap();
            db.delete(&mut hasher, d1).await.unwrap();
            db.update(&mut hasher, d2, d1).await.unwrap();
            db.update(&mut hasher, d1, d2).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);

            // Confirm close/reopen gets us back to the same state.
            db.commit(&mut hasher).await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context, &mut hasher).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.snapshot.keys(), 2);

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit(&mut hasher).await.unwrap();

            assert!(db.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root(&mut hasher);
            db.prune_inactive().await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.inactivity_floor_loc, db.oldest_retained_loc().unwrap());
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                db.delete(&mut hasher, k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert_eq!(db.log.size().await.unwrap(), 1477);
            assert_eq!(db.oldest_retained_loc().unwrap(), 0); // no pruning yet
            assert_eq!(db.snapshot.keys(), 857);

            // Test that commit will raise the activity floor.
            db.commit(&mut hasher).await.unwrap();
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.oldest_retained_loc().unwrap(), 1478);
            assert_eq!(db.snapshot.keys(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root_hash = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(root_hash, db.root(&mut hasher));
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.inactivity_floor_loc, 1478);
            assert_eq!(db.snapshot.keys(), 857);

            // Raise the inactivity floor to the point where all inactive operations can be pruned.
            let mut old_locs = Vec::new();
            db.raise_inactivity_floor(&mut hasher, 3000, Some(&mut old_locs))
                .await
                .unwrap();
            assert_eq!(old_locs.len(), 2999);
            db.prune_inactive().await.unwrap();
            assert_eq!(db.inactivity_floor_loc, 4478);
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(db.op_count(), 4478 + 858);
            assert_eq!(db.snapshot.keys(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {}", k);
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.op_count();
            let start_pos = db.ops.pruned_to_pos();
            let start_loc = leaf_pos_to_num(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            old_locs.clear();
            db.raise_inactivity_floor(&mut hasher, 100, Some(&mut old_locs))
                .await
                .unwrap();
            assert_eq!(old_locs.len(), 100);
            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);
            for i in start_loc..end_loc {
                let (proof, log) = db.proof(i, max_ops).await.unwrap();
                assert!(
                    Any::<deterministic::Context, _, _, _, EightCap>::verify_proof(
                        &mut hasher,
                        &proof,
                        i,
                        &log,
                        &root
                    )
                );
            }
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
            }
            db.sync().await.unwrap();

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
            }

            // We partially write 101 of the cached MMR nodes to simulate a failure that leaves the
            // MMR in a state with an orphaned leaf.
            let root = db
                .simulate_failed_commit_mmr(&mut hasher, 101)
                .await
                .unwrap();

            // Journaled MMR recovery should read the orphaned leaf & its parents, then log
            // replaying will restore the rest.
            let mut db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(db.root(&mut hasher), root);

            // Write some additional nodes, simulate failed log commit, and test we recover to the previous commit point.
            for i in 0u64..100 {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 2) * 10000).to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
            }
            db.simulate_failed_commit_log(&mut hasher).await.unwrap();
            let db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(db.root(&mut hasher), root);
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    pub fn test_any_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = hash(&(i * 1000).to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
            }
            db.commit(&mut hasher).await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone(), &mut hasher).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(&mut hasher), root);
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = hash(&(j * 1000 + i).to_be_bytes());
                    let v = hash(&(i * 1000).to_be_bytes());
                    db.update(&mut hasher, k, v).await.unwrap();
                    map.insert(k, v);
                }
                db.commit(&mut hasher).await.unwrap();
            }
            let k = hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(&mut hasher, k).await.unwrap();
            db.commit(&mut hasher).await.unwrap();
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root_hash = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone(), &mut hasher).await;
            assert_eq!(root_hash, db.root(&mut hasher));
            assert!(db.get(&k).await.unwrap().is_none());
        });
    }

    /// This test builds a random database, and makes sure that its state can be replayed by
    /// `build_snapshot_from_log` with a bitmap to correctly capture the active operations.
    #[test_traced("WARN")]
    pub fn test_any_db_build_snapshot_with_bitmap() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        // Use a non-deterministic rng seed to ensure each run is different.
        let rng_seed = OsRng.next_u64();
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Sha256::new();
            let mut db = open_db(context.clone(), &mut hasher).await;

            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&rng.next_u32().to_be_bytes());
                db.update(&mut hasher, k, v).await.unwrap();
            }

            // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
            // frequency.
            for _ in 0u64..ELEMENTS * 10 {
                let rand_key = hash(&(rng.next_u64() % ELEMENTS).to_be_bytes());
                if rng.next_u32() % 7 == 0 {
                    db.delete(&mut hasher, rand_key).await.unwrap();
                    continue;
                }
                let v = hash(&rng.next_u32().to_be_bytes());
                db.update(&mut hasher, rand_key, v).await.unwrap();
                if rng.next_u32() % 20 == 0 {
                    // Commit every ~20 updates.
                    db.commit(&mut hasher).await.unwrap();
                }
            }
            db.commit(&mut hasher).await.unwrap();

            // Close the db, then replay its operations with a bitmap.
            let root = db.root(&mut hasher);
            // Create a bitmap based on the current db's pruned/inactive state.
            let mut bitmap = Bitmap::<_, 32>::new();
            for _ in 0..db.inactivity_floor_loc {
                bitmap.append(&mut hasher, false);
            }
            assert_eq!(bitmap.bit_count(), db.inactivity_floor_loc);
            db.close().await.unwrap();

            // Initialize the db's mmr/log.
            let cfg = any_db_config();
            let (mmr, log) = Any::<_, Digest, Digest, _, TwoCap>::init_mmr_and_log(
                context.clone(),
                &mut hasher,
                cfg,
            )
            .await
            .unwrap();
            let start_leaf_num = leaf_pos_to_num(mmr.pruned_to_pos()).unwrap();

            // Replay log to populate the bitmap.  Use a TwoCap instead of
            // EightCap here so we exercise some collisions.
            let mut snapshot: Index<TwoCap, u64> =
                Index::init(context.with_label("snapshot"), TwoCap);
            let inactivity_floor_loc = Any::build_snapshot_from_log(
                &mut hasher,
                start_leaf_num,
                &log,
                &mut snapshot,
                Some(&mut bitmap),
            )
            .await
            .unwrap();

            // Check the recovered state is correct.
            let db = Any::<_, _, _, _, TwoCap> {
                ops: mmr,
                log,
                snapshot,
                inactivity_floor_loc,
                uncommitted_ops: 0,
            };
            assert_eq!(db.root(&mut hasher), root);

            // Check the bitmap state matches that of the snapshot.
            let items = db.log.size().await.unwrap();
            assert_eq!(bitmap.bit_count(), items);
            let mut active_positions = HashSet::new();
            // This loop checks that the expected true bits are true in the bitmap.
            for pos in db.inactivity_floor_loc..items {
                let item = db.log.read(pos).await.unwrap();
                let iter = db.snapshot.get(&item.to_key());
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
            for pos in db.inactivity_floor_loc..items {
                if !active_positions.contains(&pos) {
                    assert!(!bitmap.get_bit(pos));
                }
            }
        });
    }
}
