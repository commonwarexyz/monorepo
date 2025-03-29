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

use crate::journal::fixed::{Config as JConfig, Journal};
use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num},
    journaled::{Config as MmrConfig, Mmr},
    operation::{Operation, Type},
    verification::Proof,
    Error,
};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{Blob, Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use futures::future::try_join_all;
use std::collections::HashMap;
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
    snapshot: HashMap<K, u64>,
}

impl<B: Blob, E: RStorage<B> + Clock + Metrics, K: Array, V: Array, H: CHasher>
    MutableMmr<B, E, K, V, H>
{
    /// Return an MMR initialized from `cfg`.
    pub async fn init(context: E, hasher: &mut H, cfg: Config) -> Result<Self, Error> {
        let mut mmr = Mmr::init(
            context.clone(),
            MmrConfig {
                journal_partition: cfg.mmr_journal_partition,
                metadata_partition: cfg.mmr_metadata_partition,
                items_per_blob: cfg.mmr_items_per_blob,
            },
        )
        .await?;

        let log = Journal::init(
            context,
            JConfig {
                partition: cfg.log_journal_partition,
                items_per_blob: cfg.log_items_per_blob,
            },
        )
        .await?;

        let log_size = log.size().await?;
        let mut next_leaf_num = leaf_pos_to_num(mmr.size()).unwrap();
        if log_size != next_leaf_num {
            // Because we always sync the log of operations before the ops MMR, the number of log
            // elements should always be at least that as the number of leaves in the MMR.
            assert!(
                next_leaf_num < log_size,
                "mmr should never have more leafs than there are log operations"
            );
            warn!(
                log_size,
                next_leaf_num, "recovering missing mmr leaves from log"
            );
            // Recover from any log/mmr inconsistencies by inserting the missing operations.
            while next_leaf_num < log_size {
                let op = log.read(next_leaf_num).await?;
                let digest = Self::op_digest(&mut H::new(), &op);
                mmr.add(hasher, &digest);
                next_leaf_num += 1;
            }
        }

        // Replay the log to generate the snapshot. TODO: Because all operations are idempotent, we
        // could parallelize this via replay_all by keeping track of the location of each operation
        // and only applying it if it is more recent than the last operation for the same key.
        let mut snapshot = HashMap::new();
        let mut inactivity_floor_loc = 0;
        let oldest_retained_pos = mmr.oldest_retained_pos().unwrap_or(mmr.size());
        let start_leaf_num = leaf_pos_to_num(oldest_retained_pos).unwrap();

        for i in start_leaf_num..next_leaf_num {
            let op: Operation<K, V> = log.read(i).await?;
            match op.to_type() {
                Type::Deleted(key) => {
                    snapshot.remove(&key);
                }
                Type::Update(key, _) => {
                    snapshot.insert(key, i);
                }
                Type::Floor(loc) => {
                    inactivity_floor_loc = loc;
                }
            }
        }

        let store = MutableMmr {
            ops: mmr,
            log,
            snapshot,
            inactivity_floor_loc,
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
        let loc = match self.snapshot.get(key) {
            Some(loc) => loc,
            None => return Ok(None),
        };

        let op = self.log.read(*loc).await?;
        let v = op.to_value();
        assert!(
            v.is_some(),
            "snapshot should only reference non-empty values {:?}",
            key
        );

        Ok(v)
    }

    /// Get the number of operations that have been applied to this store.
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
    /// no-op.
    pub async fn update(&mut self, hasher: &mut H, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();

        // Update the snapshot.
        if let Some(loc) = self.snapshot.get_mut(&key) {
            let op = self.log.read(*loc).await?;
            let last_value = op.to_value();
            assert!(
                last_value.is_some(),
                "snapshot should only reference non-empty values {:?}",
                key
            );
            if value == last_value.unwrap() {
                // Trying to assign the same value is a no-op.
                return Ok(());
            }
            *loc = new_loc;
        } else {
            self.snapshot.insert(key.clone(), new_loc);
        }

        let op = Operation::update(key, value);
        self.apply_op(hasher, op).await?;

        Ok(())
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op.
    pub async fn delete(&mut self, hasher: &mut H, key: K) -> Result<(), Error> {
        if self.snapshot.remove(&key).is_none() {
            return Ok(());
        };

        self.apply_op(hasher, Operation::delete(key)).await?;

        Ok(())
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.ops.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log.
    async fn apply_op(&mut self, hasher: &mut H, op: Operation<K, V>) -> Result<(), Error> {
        // Update the ops MMR.
        let digest = Self::op_digest(hasher, &op);
        self.ops.add(hasher, &digest);

        // Append the operation to the log.
        self.log.append(op).await?;

        Ok(())
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the store in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    pub async fn proof_to_tip(
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

    /// Sync the store to disk ensuring the current state is persisted.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Always sync the log first to ensure ability to recover should the mmr sync fail (by
        // replaying the log items).
        self.log.sync().await?;

        self.ops.sync().await
    }

    /// Close the store, syncing all data to disk.
    pub async fn close(self) -> Result<(), Error> {
        // Always sync the log first to ensure ability to recover should the mmr sync fail (by
        // replaying the log items).
        self.log.close().await?;

        self.ops.close().await
    }

    /// Raise the inactivity floor by exactly `max_steps` steps. Each step either advances over an
    /// inactive operation, or re-applies an active operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the store's snapshot, but it always changes the
    /// root since it applies at least one (floor) operation.
    pub async fn raise_inactivity_floor(
        &mut self,
        hasher: &mut H,
        max_steps: u64,
    ) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }

            let op = self.log.read(self.inactivity_floor_loc).await?;
            let op_count = self.op_count();
            let key = op.to_key();
            if let Some(loc) = self.snapshot.get_mut(&key) {
                if *loc == self.inactivity_floor_loc {
                    // This operation is active, move it to tip to allow us to continue raising the
                    // inactivity floor.
                    *loc = op_count;
                    self.apply_op(hasher, op.clone()).await?;
                }
            }
            self.inactivity_floor_loc += 1;
        }
        self.apply_op(hasher, Operation::floor(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune any historical operations that are known to be inactive (those preceding the
    /// inactivity floor). This does not affect the store's root or current snapshot.
    pub async fn prune_known_inactive(&mut self) -> Result<(), Error> {
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

    /// Close the store but without fully syncing the MMR's cached elements to simulate an
    /// interrupted close for recovery testing.  At most `write_limit` of the cached MMR nodes will
    /// be written.
    #[cfg(test)]
    pub async fn simulate_failed_close(self, write_limit: usize) -> Result<(), Error> {
        self.log.close().await?;
        self.ops.simulate_partial_sync(write_limit).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mmr::mem::Mmr as MemMmr;
    use commonware_cryptography::{hash, sha256::Digest, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Context, deterministic::Executor, Runner};

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
            assert!(matches!(store.prune_known_inactive().await, Ok(())));
            assert_eq!(store.root(&mut hasher), MemMmr::default().root(&mut hasher));
            assert!(matches!(
                store.raise_inactivity_floor(&mut hasher, 10).await,
                Ok(())
            ));
            assert_eq!(store.op_count(), 1); // floor op added
            let root = store.root(&mut hasher);

            // Make sure closing/reopening gets us back to the same state.
            store.close().await.unwrap();
            let store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);
        });
    }

    #[test_traced]
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
            assert_eq!(store.log.size().await.unwrap(), 6); // 4 updates, 1 deletion, 1 floor

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
            assert_eq!(store.log.size().await.unwrap(), 8); // 4 updates, 3 deletions, 1 floor
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
            store.close().await.unwrap();
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.log.size().await.unwrap(), 8);
            assert_eq!(store.root(&mut hasher), root);

            // Since this store no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive floor op remains).
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
            let root = store.root(&mut hasher);
            store.close().await.unwrap();
            let mut store = open_store(context, &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);

            // Raising inactivity floor won't affect state but will affect the root.
            store.raise_inactivity_floor(&mut hasher, 2).await.unwrap();
            assert_eq!(store.snapshot.len(), 2);
            assert!(store.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = store.root(&mut hasher);
            store.prune_known_inactive().await.unwrap();
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

            // Test raising the inactivity floor by 100 and pruning known inactive ops.
            store
                .raise_inactivity_floor(&mut hasher, 100)
                .await
                .unwrap();
            store.prune_known_inactive().await.unwrap();
            assert_eq!(store.op_count(), 1534);
            assert_eq!(store.oldest_retained_loc().unwrap(), 100);
            assert_eq!(store.snapshot.len(), 857);

            // Close & reopen the store, making sure the re-opened store has exactly the same state.
            let root_hash = store.root(&mut hasher);
            store.close().await.unwrap();
            let mut store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(root_hash, store.root(&mut hasher));
            assert_eq!(store.op_count(), 1534);
            assert_eq!(store.inactivity_floor_loc, 100);
            assert_eq!(store.snapshot.len(), 857);

            // Raise the inactivity floor to the point where all inactive operations can be pruned.
            store
                .raise_inactivity_floor(&mut hasher, 3000)
                .await
                .unwrap();
            store.prune_known_inactive().await.unwrap();
            assert_eq!(store.inactivity_floor_loc, 3100);
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(store.op_count(), 3100 + 858);
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
            let root = store.root(&mut hasher);
            let end_loc = store.op_count();
            let start_pos = store.ops.oldest_retained_pos().unwrap_or(store.ops.size());
            let start_loc = leaf_pos_to_num(start_pos).unwrap();
            for i in start_loc..end_loc {
                let (proof, log) = store.proof_to_tip(i, max_ops).await.unwrap();
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
            let root = store.root(&mut hasher);

            // We partially write 101 of the cached MMR nodes to simulate a failure that leaves the
            // MMR in a state with an orphaned leaf.
            store.simulate_failed_close(101).await.unwrap();

            // Journaled MMR recovery should restore the orphaned leaf & its parents, then log
            // replaying will restore the rest.
            let store = open_store(context.clone(), &mut hasher).await;
            assert_eq!(store.root(&mut hasher), root);
        });
    }
}
