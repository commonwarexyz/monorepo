//! An authenticatable & mutable key-value store based on an MMR over the log of state-change
//! operations.
//!
//! # Terminology
//!
//! A _key_ in the store either has a _value_ or it doesn't. Two types of _operations_ can be
//! applied to the store to modify the state of a specific key. A key that has a value can change to
//! one without a value through the _delete_ operation. The _update_ operation gives a key a
//! specific value whether it previously had no value or had a different value.
//!
//! Keys with values are called _active_, and an operation is called _active_ if (1) its key is
//! active, (2) it is an update operation, and (3) it is the most recent operation for that key.

use crate::{
    index::{translator::EightCap, Index},
    journal::fixed::{Config as JConfig, Journal},
    mmr::{
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        operation::{Operation, Type},
        verification::Proof,
        Error,
    },
};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Blob, Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use futures::{
    future::{try_join_all, TryFutureExt},
    try_join,
};
use tracing::{debug, warn};

/// Configuration for a Mutable MMR.
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

/// A mutable key-value store based on an MMR over its log of operations.
pub struct MutableMmr<B: Blob, E: RStorage<B> + Clock + Metrics, K: Array, V: Array, H: CHasher> {
    /// An MMR over digests of the operations applied to the store. The number of leaves in this MMR
    /// always equals the number of operations in the unpruned `log`.
    ops: Mmr<B, E, H>,

    /// A (pruned) log of all operations applied to the store in order of occurrence. The position
    /// of each operation in the log is called its _location_, which is a stable identifier. Pruning
    /// is indicated by a non-zero value for `pruned_loc`, which provides the location of the first
    /// operation in the log.
    ///
    /// Invariant: An operation's location is always equal to the number of the MMR leaf storing the
    /// digest of the operation.
    log: Journal<B, E, Operation<K, V>>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: u64,

    /// A map from each key to the location in the log containing its most recent update. Only
    /// contains the keys that currently have a value (that is, deleted keys are not in the map).
    snapshot: Index<EightCap, u64>,

    /// The number of operations that are pending commit.
    uncommitted_ops: u64,
}

impl<B: Blob, E: RStorage<B> + Clock + Metrics, K: Array, V: Array, H: CHasher>
    MutableMmr<B, E, K, V, H>
{
    /// Return an MMR initialized from `cfg`. Any uncommitted operations in the log will be
    /// discarded and the state of the store will be as of the last committed operation.
    pub async fn init(context: E, hasher: &mut H, cfg: Config) -> Result<Self, Error> {
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

        // Replay the log to generate the snapshot. TODO: Because all operations are idempotent, we
        // could parallelize this via replay_all by keeping track of the location of each operation
        // and only applying it if it is more recent than the last operation for the same key.
        let mut snapshot: Index<EightCap, u64> =
            Index::init(context.with_label("snapshot"), EightCap);
        let mut inactivity_floor_loc = 0;
        let oldest_retained_pos = mmr.oldest_retained_pos().unwrap_or(mmr.size());
        let start_leaf_num = leaf_pos_to_num(oldest_retained_pos).unwrap();

        for i in start_leaf_num..log_size {
            let op: Operation<K, V> = log.read(i).await?;
            match op.to_type() {
                Type::Deleted(key) => {
                    snapshot.remove(&key, |loc| *loc == i);
                }
                Type::Update(key, _) => {
                    // If the key is already in the snapshot, then update its location.
                    let mut snapshot_updated = false;
                    for loc in snapshot.get_mut(&key) {
                        let op = log.read(*loc).await?;
                        if op.to_key() == key {
                            snapshot_updated = true;
                            *loc = i;
                            break;
                        }
                    }
                    if !snapshot_updated {
                        // The key was not already in the snapshot, so add it.
                        snapshot.insert(&key, i);
                    }
                }
                Type::Commit(loc) => {
                    inactivity_floor_loc = loc;
                }
            }
        }

        let store = MutableMmr {
            ops: mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
        };

        Ok(store)
    }

    /// Return a digest of the operation.
    pub fn op_digest(hasher: &mut H, op: &Operation<K, V>) -> H::Digest {
        hasher.update(op);
        hasher.finalize()
    }

    /// Get the value of `key` in the store, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let loc_iter = self.snapshot.get(key);

        for loc in loc_iter {
            let op = self.log.read(*loc).await?;
            match op.to_type() {
                Type::Update(k, v) => {
                    if k == *key {
                        return Ok(Some(v));
                    }
                }
                _ => {
                    panic!(
                        "snapshot should only reference update operations. key={}",
                        key
                    );
                }
            }
        }

        Ok(None)
    }

    /// Get the number of operations that have been applied to this store, including those that are
    /// not yet committed.
    pub fn op_count(&self) -> u64 {
        leaf_pos_to_num(self.ops.size()).unwrap()
    }

    /// Return the oldest location that remains readable & provable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        self.ops
            .oldest_retained_pos()
            .map(|pos| leaf_pos_to_num(pos).unwrap())
    }

    /// Updates `key` to have value `value`.  If the key already has this same value, then this is a
    /// no-op. The operation is reflected in the snapshot, but will be subject to rollback until the
    /// next successful `commit`.
    pub async fn update(&mut self, hasher: &mut H, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();

        // Update the snapshot if the key is already in it.
        let mut snapshot_updated = false;
        let loc_iter = self.snapshot.get_mut(&key);
        for loc in loc_iter {
            let op = self.log.read(*loc).await?;
            match op.to_type() {
                Type::Update(k, v) => {
                    if k == key {
                        if v == value {
                            // Trying to assign the same value is a no-op.
                            return Ok(());
                        }
                        *loc = new_loc;
                        snapshot_updated = true;
                        break;
                    }
                }
                _ => {
                    panic!(
                        "snapshot should only reference update operations. key={}",
                        key
                    );
                }
            }
        }

        if !snapshot_updated {
            // The key was not already in the snapshot, so add it.
            self.snapshot.insert(&key, new_loc);
        }
        let op = Operation::update(key, value);
        self.apply_op(hasher, op).await?;

        Ok(())
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op. The operation is reflected in the snapshot, but will be subject to rollback until the
    /// next successful `commit`.
    pub async fn delete(&mut self, hasher: &mut H, key: K) -> Result<(), Error> {
        let mut old_loc: Option<u64> = None;
        for loc in self.snapshot.get(&key) {
            let op = self.log.read(*loc).await?;
            match op.to_type() {
                Type::Update(k, _) => {
                    if k == key {
                        old_loc = Some(*loc);
                        break;
                    }
                }
                _ => {
                    panic!(
                        "snapshot should only reference update operations. key={}",
                        key
                    );
                }
            }
        }

        let Some(old_loc) = old_loc else {
            // The key wasn't in the snapshot, so this is a no-op.
            return Ok(());
        };

        self.snapshot.remove(&key, |loc| *loc == old_loc);
        self.apply_op(hasher, Operation::delete(key)).await?;

        Ok(())
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.ops.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    async fn apply_op(&mut self, hasher: &mut H, op: Operation<K, V>) -> Result<u64, Error> {
        // Update the ops MMR.
        let digest = Self::op_digest(hasher, &op);
        self.ops.add(hasher, &digest);
        self.uncommitted_ops += 1;

        // Append the operation to the log.
        self.log.append(op).await.map_err(Error::JournalError)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the store in the range starting at (and including)
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
    /// the store with the provided root hash.
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
            .map(|op| MutableMmr::<_, E, _, _, _>::op_digest(hasher, op))
            .collect::<Vec<_>>();

        proof.verify_range_inclusion(hasher, &digests, start_pos, end_pos, root_hash)
    }

    /// Commit any pending operations to the store, ensuring they are persisted to disk &
    /// recoverable upon return from this function.
    pub async fn commit(&mut self, hasher: &mut H) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // floor op that will be appended.
        self.raise_inactivity_floor(hasher, self.uncommitted_ops + 1)
            .await?;
        self.uncommitted_ops = 0;
        self.sync().await?;

        // TODO: Make the frequency with which we prune known inactive items configurable in case
        // this turns out to be a significant part of commit overhead, or the user wants to ensure
        // the log is backed up externally before discarding.
        self.prune_inactive().await
    }

    /// Sync the store to disk ensuring the current state is persisted.
    async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::JournalError),
            self.ops.sync()
        )?;

        Ok(())
    }

    /// Close the store. Operations that have not been committed will be lost.
    pub async fn close(self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing store with uncommitted operations"
            );
        }
        try_join!(
            self.log.close().map_err(Error::JournalError),
            self.ops.close()
        )?;

        Ok(())
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op.
    async fn move_op_if_active(
        &mut self,
        hasher: &mut H,
        op: Operation<K, V>,
        old_loc: u64,
    ) -> Result<(), Error> {
        let key = op.to_key();
        let new_loc = self.op_count();
        let iter = self.snapshot.get_mut(&key);
        let mut loc_found = false;
        for loc in iter {
            if *loc == old_loc {
                loc_found = true;
                *loc = new_loc;
                break;
            }
        }
        if !loc_found {
            // The operation wasn't active, so no need to move it to the tip.
            return Ok(());
        };

        self.apply_op(hasher, op).await?;

        Ok(())
    }

    /// Raise the inactivity floor by exactly `max_steps` steps. Each step either advances over an
    /// inactive operation, or re-applies an active operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the store's snapshot, but it always changes the
    /// root since it applies at least one (floor) operation.
    async fn raise_inactivity_floor(
        &mut self,
        hasher: &mut H,
        max_steps: u64,
    ) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.log.read(self.inactivity_floor_loc).await?;
            self.move_op_if_active(hasher, op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(hasher, Operation::commit(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune any historical operations that are known to be inactive (those preceding the
    /// inactivity floor). This does not affect the store's root or current snapshot.
    async fn prune_inactive(&mut self) -> Result<(), Error> {
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
    /// root hash of the store at the point of a successful commit will be returned in the result.
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
    use crate::mmr::mem::Mmr as MemMmr;
    use commonware_cryptography::{hash, sha256::Digest, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Context, deterministic::Executor, Runner};
    use std::collections::HashMap;

    /// Return a store initialized with a fixed config.
    async fn open_store<B: Blob, E: RStorage<B> + Clock + Metrics>(
        context: E,
        hasher: &mut Sha256,
    ) -> MutableMmr<B, E, Digest, Digest, Sha256> {
        let cfg = Config {
            mmr_journal_partition: "journal_partition".into(),
            mmr_metadata_partition: "metadata_partition".into(),
            mmr_items_per_blob: 11,
            log_journal_partition: "log_journal_partition".into(),
            log_items_per_blob: 7,
        };
        MutableMmr::<B, E, Digest, Digest, Sha256>::init(context, hasher, cfg)
            .await
            .unwrap()
    }

    #[test_traced]
    pub fn test_mutable_mmr_empty() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.op_count(), 0);
            assert_eq!(store.oldest_retained_loc(), None);
            assert!(matches!(store.prune_inactive().await, Ok(())));
            assert_eq!(store.root(&mut hasher), MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            let d2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
            let root = store.root(&mut hasher);
            store.update(&mut hasher, d1, d2).await.unwrap();
            store.close().await.unwrap();
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);
            assert_eq!(store.op_count(), 0);

            // Test calling commit on an empty store which should make it (durably) non-empty.
            store.commit(&mut hasher).await.unwrap();
            assert_eq!(store.op_count(), 1); // floor op added
            let root = store.root(&mut hasher);
            assert!(matches!(store.prune_inactive().await, Ok(())));
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                store.commit(&mut hasher).await.unwrap();
                assert_eq!(store.op_count() - 1, store.inactivity_floor_loc);
            }
        });
    }

    #[test_traced("WARN")]
    pub fn test_mutable_mmr_build_basic() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            // Build a store with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = Sha256::new();
            let mut store = open_store(context.clone(), &mut hasher).await;

            let d1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            let d2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();

            assert!(store.get(&d1).await.unwrap().is_none());
            assert!(store.get(&d2).await.unwrap().is_none());

            store.update(&mut hasher, d1, d2).await.unwrap();
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d2);
            assert!(store.get(&d2).await.unwrap().is_none());

            store.update(&mut hasher, d2, d1).await.unwrap();
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d2);
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d1);

            store.delete(&mut hasher, d1).await.unwrap();
            assert!(store.get(&d1).await.unwrap().is_none());
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d1);

            store.update(&mut hasher, d1, d1).await.unwrap();
            assert_eq!(store.get(&d1).await.unwrap().unwrap(), d1);

            store.update(&mut hasher, d2, d2).await.unwrap();
            assert_eq!(store.get(&d2).await.unwrap().unwrap(), d2);

            assert_eq!(store.log.size().await.unwrap(), 5); // 4 updates, 1 deletion.
            assert_eq!(store.snapshot.len(), 2);
            assert_eq!(store.inactivity_floor_loc, 0);
            store.sync().await.unwrap();

            // Advance over 3 inactive operations.
            store.raise_inactivity_floor(&mut hasher, 3).await.unwrap();
            assert_eq!(store.inactivity_floor_loc, 3);
            assert_eq!(store.log.size().await.unwrap(), 6); // 4 updates, 1 deletion, 1 commit

            let root = store.root(&mut hasher);

            // Multiple assignments of the same value should be a no-op.
            store.update(&mut hasher, d1, d1).await.unwrap();
            store.update(&mut hasher, d2, d2).await.unwrap();
            // Log and root should be unchanged.
            assert_eq!(store.log.size().await.unwrap(), 6);
            assert_eq!(store.root(&mut hasher), root);

            // Delete all keys.
            store.delete(&mut hasher, d1).await.unwrap();
            store.delete(&mut hasher, d2).await.unwrap();
            assert!(store.get(&d1).await.unwrap().is_none());
            assert!(store.get(&d2).await.unwrap().is_none());
            assert_eq!(store.log.size().await.unwrap(), 8); // 4 updates, 3 deletions, 1 commit
            assert_eq!(store.inactivity_floor_loc, 3);

            let root = store.root(&mut hasher);

            // Multiple deletions of the same key should be a no-op.
            store.delete(&mut hasher, d1).await.unwrap();
            assert_eq!(store.log.size().await.unwrap(), 8);
            assert_eq!(store.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let d3 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
            store.delete(&mut hasher, d3).await.unwrap();
            assert_eq!(store.log.size().await.unwrap(), 8);
            assert_eq!(store.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            store.commit(&mut hasher).await.unwrap();
            assert_eq!(store.log.size().await.unwrap(), 9);
            let root = store.root(&mut hasher);
            store.close().await.unwrap();
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.log.size().await.unwrap(), 9);
            assert_eq!(store.root(&mut hasher), root);

            // Since this store no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive commit op remains).
            store
                .raise_inactivity_floor(&mut hasher, 100)
                .await
                .unwrap();
            assert_eq!(store.inactivity_floor_loc, store.op_count() - 1);

            // Re-activate the keys by updating them.
            store.update(&mut hasher, d1, d1).await.unwrap();
            store.update(&mut hasher, d2, d2).await.unwrap();
            store.delete(&mut hasher, d1).await.unwrap();
            store.update(&mut hasher, d2, d1).await.unwrap();
            store.update(&mut hasher, d1, d2).await.unwrap();
            assert_eq!(store.snapshot.len(), 2);

            // Confirm close/reopen gets us back to the same state.
            store.commit(&mut hasher).await.unwrap();
            let root = store.root(&mut hasher);
            store.close().await.unwrap();
            let mut store = open_store(context, &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            store.commit(&mut hasher).await.unwrap();
            assert_eq!(store.snapshot.len(), 2);
            assert!(store.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = store.root(&mut hasher);
            store.prune_inactive().await.unwrap();
            assert_eq!(store.snapshot.len(), 2);
            assert_eq!(store.root(&mut hasher), root);
            assert_eq!(
                store.inactivity_floor_loc,
                store.oldest_retained_loc().unwrap()
            );
        });
    }

    #[test_traced("WARN")]
    pub fn test_mutable_mmr_build_and_authenticate() {
        let (executor, context, _) = Executor::default();
        // Build a store with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the store matches that of an identically updated hashmap.
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = open_store(context.clone(), &mut hasher).await;

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                store.update(&mut hasher, k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                store.update(&mut hasher, k, v).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                store.delete(&mut hasher, k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(store.op_count(), 1477);
            assert_eq!(store.inactivity_floor_loc, 0);
            assert_eq!(store.log.size().await.unwrap(), 1477);
            assert_eq!(store.oldest_retained_loc().unwrap(), 0); // no pruning yet
            assert_eq!(store.snapshot.len(), 857);

            // Test that commit will raise the activity floor.
            store.commit(&mut hasher).await.unwrap();
            assert_eq!(store.op_count(), 2336);
            assert_eq!(store.oldest_retained_loc().unwrap(), 1478);
            assert_eq!(store.snapshot.len(), 857);

            // Close & reopen the store, making sure the re-opened store has exactly the same state.
            let root_hash = store.root(&mut hasher);
            store.close().await.unwrap();
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(root_hash, store.root(&mut hasher));
            assert_eq!(store.op_count(), 2336);
            assert_eq!(store.inactivity_floor_loc, 1478);
            assert_eq!(store.snapshot.len(), 857);

            // Raise the inactivity floor to the point where all inactive operations can be pruned.
            store
                .raise_inactivity_floor(&mut hasher, 3000)
                .await
                .unwrap();
            store.prune_inactive().await.unwrap();
            assert_eq!(store.inactivity_floor_loc, 4478);
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(store.op_count(), 4478 + 858);
            assert_eq!(store.snapshot.len(), 857);

            // Confirm the store's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(store_value) = store.get(&k).await.unwrap() else {
                        panic!("key not found in store: {}", k);
                    };
                    assert_eq!(*map_value, store_value);
                } else {
                    assert!(store.get(&k).await.unwrap().is_none());
                }
            }

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = store.op_count();
            let start_pos = store.ops.oldest_retained_pos().unwrap_or(store.ops.size());
            let start_loc = leaf_pos_to_num(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            store
                .raise_inactivity_floor(&mut hasher, 100)
                .await
                .unwrap();
            let root = store.root(&mut hasher);
            assert!(start_loc < store.inactivity_floor_loc);
            for i in start_loc..end_loc {
                let (proof, log) = store.proof(i, max_ops).await.unwrap();
                assert!(MutableMmr::<_, Context, _, _, _>::verify_proof(
                    &mut hasher,
                    &proof,
                    i,
                    &log,
                    &root
                ));
            }
        });
    }

    #[test_traced("WARN")]
    pub fn test_mutable_mmr_recovery() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = open_store(context.clone(), &mut hasher).await;

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                store.update(&mut hasher, k, v).await.unwrap();
            }
            store.sync().await.unwrap();

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                store.update(&mut hasher, k, v).await.unwrap();
            }

            // We partially write 101 of the cached MMR nodes to simulate a failure that leaves the
            // MMR in a state with an orphaned leaf.
            let root = store
                .simulate_failed_commit_mmr(&mut hasher, 101)
                .await
                .unwrap();

            // Journaled MMR recovery should restore the orphaned leaf & its parents, then log
            // replaying will restore the rest.
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);

            // Write some additional nodes, simulate failed log commit, and test we recover to the previous commit point.
            for i in 0u64..100 {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 2) * 10000).to_be_bytes());
                store.update(&mut hasher, k, v).await.unwrap();
            }
            store.simulate_failed_commit_log(&mut hasher).await.unwrap();
            let store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    pub fn test_mutable_mmr_log_replay() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = open_store(context.clone(), &mut hasher).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = hash(&(i * 1000).to_be_bytes());
                store.update(&mut hasher, k, v).await.unwrap();
            }
            store.commit(&mut hasher).await.unwrap();
            let root = store.root(&mut hasher);
            store.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let store = open_store(context.clone(), &mut hasher).await;
            let iter = store.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(store.root(&mut hasher), root);
        });
    }
}
