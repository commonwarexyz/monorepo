//! An authenticatable & mutable key-value store based on an MMR over the log of state-change
//! operations.
//!
//! # Terminology
//!
//! A _key_ in the store either has a _value_ or it doesn't. Two types of _operations_ can be
//! applied to the store to modify the state of a specific key. A key that has a value can change to
//! one without a value through the _delete_ operation. The _update_ operation gives a key a
//! specific value whether it previously had no value or had a different value.

use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num},
    mem::Mmr,
    operation::{Operation, Type},
    verification::Proof,
    Error,
};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::Array;
use std::collections::{HashMap, VecDeque};
use tracing::debug;

/// A structure from which the current state of the store can be fully recovered.
pub struct StoreState<K: Array, V: Array, H: CHasher> {
    log: Vec<Operation<K, V>>,
    pruned_loc: u64,
    pinned_nodes: Vec<H::Digest>,
}

/// A mutable key-value store based on an MMR over its log of operations.
pub struct MutableMmr<K: Array, V: Array, H: CHasher> {
    /// An MMR over digests of the operations applied to the store. The number of leaves in this MMR
    /// always equals the number of operations in the unpruned `log`.
    ops: Mmr<H>,

    /// A (pruned) log of all operations applied to the store in order of occurrence. The position
    /// of each operation in the log is called its _location_, which is a stable identifier. Pruning
    /// is indicated by a non-zero value for `pruned_loc`, which provides the location of the first
    /// operation in the log.
    ///
    /// Invariant: An operation's location is always equal to the number of the MMR leaf storing the
    /// digest of the operation.
    log: VecDeque<Operation<K, V>>,

    /// The location before which all operations have been pruned.
    pruned_loc: u64,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    ///
    /// Invariant: inactivity_floor_loc >= pruned_loc.
    inactivity_floor_loc: u64,

    /// A map from each key to the location in the log containing its most recent update. Only
    /// contains the keys that currently have a value (that is, deleted keys are not in the map).
    snapshot: HashMap<K, u64>,
}

impl<K: Array, V: Array, H: CHasher> Default for MutableMmr<K, V, H> {
    /// Return a new, empty store.
    fn default() -> Self {
        MutableMmr::new()
    }
}

impl<K: Array, V: Array, H: CHasher> MutableMmr<K, V, H> {
    /// Return a new, empty store.
    pub fn new() -> Self {
        MutableMmr {
            ops: Mmr::new(),
            log: VecDeque::<Operation<K, V>>::new(),
            snapshot: HashMap::new(),
            inactivity_floor_loc: 0,
            pruned_loc: 0,
        }
    }

    /// Return an MMR initialized from `store_state`.
    pub fn init_from_state(
        hasher: &mut H,
        store_state: StoreState<K, V, H>,
    ) -> Result<Self, Error> {
        let oldest_retained_pos = leaf_num_to_pos(store_state.pruned_loc);
        let mut store = MutableMmr {
            ops: Mmr::<H>::init(vec![], oldest_retained_pos, store_state.pinned_nodes),
            log: store_state.log.into(),
            snapshot: HashMap::new(),
            inactivity_floor_loc: 0,
            pruned_loc: store_state.pruned_loc,
        };

        for (i, op) in store.log.iter().enumerate() {
            let digest = Self::op_digest(hasher, op);
            store.ops.add(hasher, &digest);

            match op.to_type() {
                Type::Deleted(key) => {
                    store.snapshot.remove(&key);
                }
                Type::Update(key, _) => {
                    let loc = store_state.pruned_loc + i as u64;
                    store.snapshot.insert(key, loc);
                }
                Type::Floor(loc) => {
                    store.inactivity_floor_loc = loc;
                }
            };
        }

        Ok(store)
    }

    /// Return a digest of the operation.
    pub fn op_digest(hasher: &mut H, op: &Operation<K, V>) -> H::Digest {
        hasher.update(op);
        hasher.finalize()
    }

    /// Converts an operation's location to its index in the (pruned) log.
    fn loc_to_op_index(&self, loc: u64) -> usize {
        assert!(loc >= self.pruned_loc);
        (loc - self.pruned_loc) as usize
    }

    /// Get the value of `key` in the store, or None if it has no value.
    pub fn get(&self, key: &K) -> Option<V> {
        let loc = self.snapshot.get(key)?;
        let i = self.loc_to_op_index(*loc);
        let v = self.log[i].to_value();
        assert!(
            v.is_some(),
            "snapshot should only reference non-empty values {:?}",
            key
        );

        v
    }

    /// Get the number of operations that have been applied to this store.
    pub fn op_count(&self) -> u64 {
        self.log.len() as u64 + self.pruned_loc
    }

    /// Updates `key` to have value `value`.  If the key already has this same value, then this is a
    /// no-op.
    pub fn update(&mut self, hasher: &mut H, key: K, value: V) {
        let new_loc = self.log.len() as u64 + self.pruned_loc;

        // Update the snapshot.
        if let Some(loc) = self.snapshot.get_mut(&key) {
            let i = *loc - self.pruned_loc;
            let last_value = self.log[i as usize].to_value();
            assert!(
                last_value.is_some(),
                "snapshot should only reference non-empty values {:?}",
                key
            );
            if value == last_value.unwrap() {
                // Trying to assign the same value is a no-op.
                return;
            }
            *loc = new_loc;
        } else {
            self.snapshot.insert(key.clone(), new_loc);
        }

        let op = Operation::update(key, value);
        self.apply_op(hasher, op);
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op.
    pub fn delete(&mut self, hasher: &mut H, key: K) {
        // Remove the key from the snapshot.
        if self.snapshot.remove(&key).is_none() {
            return;
        };

        self.apply_op(hasher, Operation::delete(key));
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.ops.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log.
    fn apply_op(&mut self, hasher: &mut H, op: Operation<K, V>) {
        // Update the ops MMR.
        let digest = Self::op_digest(hasher, &op);
        self.ops.add(hasher, &digest);

        // Append the operation to the log.
        self.log.push_back(op);
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
        let start_i = self.loc_to_op_index(start_loc);
        let end_i = self.loc_to_op_index(end_loc);
        let ops = self.log.range(start_i..=end_i).cloned().collect();

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
            .map(|op| MutableMmr::op_digest(hasher, op))
            .collect::<Vec<_>>();

        proof.verify_range_inclusion(hasher, &digests, start_pos, end_pos, root_hash)
    }

    /// Consume the store and return a [StoreState] from which the current active state of the store
    /// can be fully recovered and fully proven.
    pub fn to_state(mut self) -> StoreState<K, V, H> {
        self.prune_known_inactive();

        let prune_to_pos = leaf_num_to_pos(self.pruned_loc);
        let pinned_nodes = self.ops.node_digests_to_pin(prune_to_pos);

        StoreState {
            log: self.log.into(),
            pruned_loc: self.pruned_loc,
            pinned_nodes,
        }
    }

    /// Raise the inactivity floor by exactly `max_steps` steps. Each step either advances over an
    /// inactive operation, or re-applies an active operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the store's snapshot, but it always changes the
    /// root since it applies at least one (floor) operation.
    #[allow(dead_code)] // TODO: Remove when method gets used.
    pub fn raise_inactivity_floor(&mut self, hasher: &mut H, max_steps: u64) {
        for _ in 0..max_steps {
            let i = self.loc_to_op_index(self.inactivity_floor_loc);
            if i == self.log.len() {
                break;
            }
            let op = &self.log[i];
            let op_count = self.op_count();
            let key = op.to_key();
            if let Some(loc) = self.snapshot.get_mut(&key) {
                if *loc == self.inactivity_floor_loc {
                    // This operation is active, move it to tip to allow us to continue raising the
                    // inactivity floor.
                    *loc = op_count;
                    self.apply_op(hasher, op.clone());
                }
            }
            self.inactivity_floor_loc += 1;
        }
        self.apply_op(hasher, Operation::floor(self.inactivity_floor_loc));
    }

    /// Prune any historical operations that are known to be inactive (those preceding the
    /// inactivity floor). This does not affect the store's root or current snapshot.
    pub fn prune_known_inactive(&mut self) {
        let pruned_ops = self.inactivity_floor_loc - self.pruned_loc;
        if pruned_ops == 0 {
            return;
        }

        debug!(pruned = pruned_ops, "pruning inactive ops");
        let prune_to_pos = leaf_num_to_pos(self.inactivity_floor_loc);
        self.ops.prune_to_pos(prune_to_pos);
        self.log.drain(0..pruned_ops as usize);
        self.pruned_loc = self.inactivity_floor_loc;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mmr::iterator::leaf_num_to_pos;
    use commonware_cryptography::{hash, sha256::Digest, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Runner};

    /// Return an empty store for use in tests.
    fn empty_store() -> MutableMmr<Digest, Digest, Sha256> {
        MutableMmr::new()
    }

    #[test_traced]
    pub fn test_mutable_mmr_build_basic() {
        // Build a store with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let mut store = empty_store();
        let mut hasher = Sha256::new();

        let d1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
        let d2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();

        assert!(store.get(&d1).is_none());
        assert!(store.get(&d2).is_none());

        store.update(&mut hasher, d1, d2);
        assert_eq!(store.get(&d1).unwrap(), d2);
        assert!(store.get(&d2).is_none());

        store.update(&mut hasher, d2, d1);
        assert_eq!(store.get(&d1).unwrap(), d2);
        assert_eq!(store.get(&d2).unwrap(), d1);

        store.delete(&mut hasher, d1);
        assert!(store.get(&d1).is_none());
        assert_eq!(store.get(&d2).unwrap(), d1);

        store.update(&mut hasher, d1, d1);
        assert_eq!(store.get(&d1).unwrap(), d1);

        store.update(&mut hasher, d2, d2);
        assert_eq!(store.get(&d2).unwrap(), d2);

        assert_eq!(store.log.len(), 5); // 4 updates, 1 deletion.
        assert_eq!(store.snapshot.len(), 2);
        assert_eq!(store.inactivity_floor_loc, 0);

        // We should be able to advance over the 3 inactive operations.
        store.raise_inactivity_floor(&mut hasher, 3);
        assert_eq!(store.inactivity_floor_loc, 3);
        assert_eq!(store.log.len(), 6); // 4 updates, 1 deletion, 1 floor

        let root = store.root(&mut hasher);

        // multiple assignments of the same value should be a no-op.
        store.update(&mut hasher, d1, d1);
        store.update(&mut hasher, d2, d2);
        // Log and root should be unchanged.
        assert_eq!(store.log.len(), 6);
        assert_eq!(store.root(&mut hasher), root);

        // The MMR's size should always be greater than the position of the last leaf.
        let last_leaf_pos = leaf_num_to_pos(4);
        assert!(store.ops.size() > last_leaf_pos);

        store.delete(&mut hasher, d1);
        store.delete(&mut hasher, d2);
        assert!(store.get(&d1).is_none());
        assert!(store.get(&d2).is_none());
        assert_eq!(store.log.len(), 8); // 4 updates, 3 deletions, 1 floor
        assert_eq!(store.inactivity_floor_loc, 3);

        let root = store.root(&mut hasher);

        // multiple deletions of the same key should be a no-op.
        store.delete(&mut hasher, d1);
        assert_eq!(store.log.len(), 8);
        assert_eq!(store.root(&mut hasher), root);

        // deletions of non-existent keys should be a no-op.
        let d3 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
        store.delete(&mut hasher, d3);
        assert_eq!(store.root(&mut hasher), root);

        // Make sure converting to/from store_state works with a non-zero inactivity floor and no
        // active elements.
        let store_state: StoreState<Digest, Digest, Sha256> = store.to_state();
        assert_eq!(store_state.pruned_loc, 3);
        let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
        assert_eq!(store.log.len(), 5);
        assert_eq!(store.root(&mut hasher), root);

        store.raise_inactivity_floor(&mut hasher, 10);
        let root = store.root(&mut hasher);
        let store_state: StoreState<Digest, Digest, Sha256> = store.to_state();
        let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
        assert_eq!(store.log.len(), 1); // 1 inactivity floor op
        assert_eq!(store.root(&mut hasher), root);

        // Make sure converting to/from store_state works with some active elements.
        store.update(&mut hasher, d1, d1);
        store.update(&mut hasher, d2, d2);
        store.delete(&mut hasher, d1);
        store.update(&mut hasher, d2, d1);
        store.update(&mut hasher, d1, d2);
        assert_eq!(store.log.len(), 6);
        assert_eq!(store.snapshot.len(), 2);
        let root = store.root(&mut hasher);

        let store_state: StoreState<Digest, Digest, Sha256> = store.to_state();
        assert_eq!(store_state.pruned_loc, 8);
        let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
        assert_eq!(store.pruned_loc, 8);
        assert_eq!(store.root(&mut hasher), root);

        // Pruning inactive ops should not affect root or current state.
        let old_pruned_loc = store.pruned_loc;
        store.raise_inactivity_floor(&mut hasher, 2);
        let root = store.root(&mut hasher);
        store.prune_known_inactive();
        assert!(old_pruned_loc < store.pruned_loc);
        assert_eq!(store.root(&mut hasher), root);
        assert_eq!(store.snapshot.len(), 2);
    }

    #[test_traced]
    pub fn test_mutable_mmr_build_and_authenticate() {
        let (executor, _, _) = Executor::default();
        // Build a store with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the store matches that of an identically updated hashmap.
        executor.start(async move {
            let mut store = empty_store();
            let mut hasher = Sha256::new();

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                store.update(&mut hasher, k, v);
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                store.update(&mut hasher, k, v);
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                store.delete(&mut hasher, k);
                map.remove(&k);
            }

            assert_eq!(store.op_count(), 1477);
            assert_eq!(store.pruned_loc, 0);
            assert_eq!(store.inactivity_floor_loc, 0);
            assert_eq!(store.log.len(), 1477); // no pruning yet
            assert_eq!(store.snapshot.len(), 857);

            // Test we can recreate the store from its store_state.
            store.raise_inactivity_floor(&mut hasher, 100);
            let root_hash = store.root(&mut hasher);
            let store_state = store.to_state();
            let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
            assert_eq!(root_hash, store.root(&mut hasher));

            // Confirm the recreated store has an operations log that was pruned of all operations
            // preceding the last known inactivity floor.
            assert_eq!(store.op_count(), 1534);
            assert_eq!(store.pruned_loc, 100);
            assert_eq!(store.inactivity_floor_loc, 100);
            assert_eq!(store.log.len(), 1534 - 100);
            assert_eq!(store.snapshot.len(), 857);

            // Raise the inactivity floor to the point where all inactive operations can be pruned.
            store.raise_inactivity_floor(&mut hasher, 3000);
            assert_eq!(store.inactivity_floor_loc, 3100);
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(store.op_count(), 3100 + 858);
            assert_eq!(store.snapshot.len(), 857);

            // Confirm the store's state matches that of the separate map we computed independently.
            store.prune_known_inactive();
            for i in 0u64..1000 {
                let k = hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(store_value) = store.get(&k) else {
                        panic!("key not found in store: {}", k);
                    };
                    assert_eq!(*map_value, store_value);
                } else {
                    assert!(store.get(&k).is_none());
                }
            }

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let root = store.root(&mut hasher);
            let end = store.op_count();
            for i in store.pruned_loc as u64..end {
                let (proof, log) = store.proof_to_tip(i, max_ops).await.unwrap();
                assert!(MutableMmr::verify_proof(
                    &mut hasher,
                    &proof,
                    i,
                    &log,
                    &root
                ));
            }
        });
    }
}
