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
    verification::Proof,
    Error,
};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::Array;
use std::collections::{HashMap, VecDeque};
use tracing::debug;

/// The types of operations that change a key's state in the store.
#[derive(Clone)]
pub enum Type<V: Array> {
    /// Indicates the key no longer has a value.
    Deleted,

    /// Indicates the key now has the wrapped value.
    Update(V),
}

/// An operation applied to the store.
#[derive(Clone)]
pub struct Operation<K: Array, V: Array> {
    /// The key whose state is changed by this operation.
    pub key: K,

    /// The new state of the key.
    pub op_type: Type<V>,
}

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
            inactivity_floor_loc: store_state.pruned_loc,
            pruned_loc: store_state.pruned_loc,
        };

        for (i, op) in store.log.iter().enumerate() {
            let digest = Self::op_digest(hasher, op);
            store.ops.add(hasher, &digest);

            match op.op_type {
                Type::Deleted => store.snapshot.remove(&op.key),
                Type::Update(_) => {
                    let loc = store_state.pruned_loc + i as u64;
                    store.snapshot.insert(op.key.clone(), loc)
                }
            };
        }

        Ok(store)
    }

    const DELETE_CONTEXT: u8 = 0;
    const UPDATE_CONTEXT: u8 = 1;

    /// Return a digest of the operation.
    ///
    /// The first byte of the digest material is an operation type byte: 0 for Delete and 1 for
    /// Update. For an update, the value is appended next, followed by the key. For deletion, the
    /// key is appended without any value.
    pub fn op_digest(hasher: &mut H, op: &Operation<K, V>) -> H::Digest {
        match op.op_type {
            Type::Deleted => hasher.update(&[Self::DELETE_CONTEXT]),
            Type::Update(ref value) => {
                hasher.update(&[Self::UPDATE_CONTEXT]);
                hasher.update(value);
            }
        }
        hasher.update(&op.key);
        hasher.finalize()
    }

    /// Converts an operation's location to its index in the (pruned) log.
    fn loc_to_op_index(&self, loc: u64) -> usize {
        (loc - self.pruned_loc) as usize
    }

    /// Get the value of `key` in the store, or None if it has no value.
    pub fn get(&self, key: &K) -> Option<&V> {
        let loc = self.snapshot.get(key)?;
        let i = self.loc_to_op_index(*loc);
        let op = &self.log[i];
        match &op.op_type {
            Type::Deleted => panic!("deleted key should not be in snapshot: {}", key),
            Type::Update(ref v) => Some(v),
        }
    }

    /// Get the number of operations that have been applied to this store.
    pub fn op_count(&self) -> u64 {
        self.log.len() as u64 + self.pruned_loc
    }

    /// Updates `key` to have value `value`.  If the key already has this same value, then this is a
    /// no-op.
    ///
    /// Also move exactly one active operation to tip if at least one is movable.
    pub fn update(&mut self, hasher: &mut H, key: K, value: V) {
        let new_loc = self.log.len() as u64 + self.pruned_loc;

        // Update the snapshot.
        if let Some(loc) = self.snapshot.get_mut(&key) {
            let i = *loc - self.pruned_loc;
            let last_value = match self.log[i as usize].op_type {
                Type::Deleted => panic!("deleted key should not be in snapshot: {}", key),
                Type::Update(ref v) => v,
            };
            if value == *last_value {
                // Trying to assign the same value is a no-op.
                return;
            }
            if *loc == self.inactivity_floor_loc {
                self.inactivity_floor_loc += 1;
            }
            *loc = new_loc;
        } else {
            self.snapshot.insert(key.clone(), new_loc);
        }

        let op = Type::Update(value.clone());
        self.apply_op(hasher, key, op);

        // Move exactly one active operation to tip if at least one is movable.
        self.raise_inactivity_floor(hasher, 1);
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op.
    ///
    /// Also move exactly one active operation to tip if at least one is movable.
    pub fn delete(&mut self, hasher: &mut H, key: K) {
        // Remove the key from the snapshot.
        let Some(loc) = self.snapshot.remove(&key) else {
            return;
        };
        if loc == self.inactivity_floor_loc {
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(hasher, key, Type::Deleted);

        // Move exactly one active operation to tip if at least one is movable.
        self.raise_inactivity_floor(hasher, 1);
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.ops.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log.
    fn apply_op(&mut self, hasher: &mut H, key: K, op_type: Type<V>) {
        let op = Operation { key, op_type };

        // Update the ops MMR.
        let digest = Self::op_digest(hasher, &op);
        self.ops.add(hasher, &digest);

        // Append the operation to the log.
        self.log.push_back(op);
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the store in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///         - the last operation performed, or
    ///         - the operation `max_ops` from the start.
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

    /// Raise the inactivity floor as high as we can without moving more than `max_moves` ops to
    /// tip. This method does not change the state of the store's snapshot, but it does change the
    /// root hash of the store because of the moved operations.
    fn raise_inactivity_floor(&mut self, hasher: &mut H, mut max_moves: usize) {
        let active_ops = self.snapshot.len() as u64;
        while max_moves > 0 && self.inactivity_floor_loc < self.op_count() - active_ops {
            let i = self.loc_to_op_index(self.inactivity_floor_loc);
            let op = &self.log[i];
            let Some(loc) = self.snapshot.get(&op.key) else {
                // This key has been deleted by its most recent operation, no need to move to tip.
                self.inactivity_floor_loc += 1;
                continue;
            };
            if *loc != self.inactivity_floor_loc {
                // There's a later operation that's active for this key, no need to move to tip.
                self.inactivity_floor_loc += 1;
                continue;
            }

            // This operation is active, move it to tip to allow us to continue raising the
            // inactivity floor.
            self.apply_op(hasher, op.key.clone(), op.op_type.clone());
            max_moves -= 1;
            self.inactivity_floor_loc += 1;
        }
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
        assert_eq!(store.get(&d1).unwrap(), &d2);
        assert!(store.get(&d2).is_none());

        store.update(&mut hasher, d2, d1);
        assert_eq!(store.get(&d1).unwrap(), &d2);
        assert_eq!(store.get(&d2).unwrap(), &d1);

        store.delete(&mut hasher, d1);
        assert!(store.get(&d1).is_none());
        assert_eq!(store.get(&d2).unwrap(), &d1);

        store.update(&mut hasher, d1, d1);
        assert_eq!(store.get(&d1).unwrap(), &d1);

        store.update(&mut hasher, d2, d2);
        assert_eq!(store.get(&d2).unwrap(), &d2);

        assert_eq!(store.log.len(), 6); // 4 updates, 1 deletion, 1 move to tip.
        assert_eq!(store.snapshot.len(), 2);

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
        assert_eq!(store.log.len(), 9); // 4 updates, 3 deletions, 2 move to tip.
        assert_eq!(store.inactivity_floor_loc, 9); // no more active ops.

        let root = store.root(&mut hasher);

        // multiple deletions of the same key should be a no-op.
        store.delete(&mut hasher, d1);
        assert_eq!(store.log.len(), 9);
        assert_eq!(store.root(&mut hasher), root);

        // deletions of non-existent keys should be a no-op.
        let d3 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
        store.delete(&mut hasher, d3);
        assert_eq!(store.root(&mut hasher), root);

        // Make sure converting to/from store_state works with a non-zero inactivity floor and no
        // active elements.
        let store_state: StoreState<Digest, Digest, Sha256> = store.to_state();
        assert_eq!(store_state.pruned_loc, 9);
        let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
        assert_eq!(store.log.len(), 0);
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
        assert_eq!(store_state.pruned_loc, 13);
        let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
        assert_eq!(store.pruned_loc, 13);
        assert_eq!(store.root(&mut hasher), root);

        // Update a few keys to force inactivity floor to rise.
        store.update(&mut hasher, d1, d1);
        store.update(&mut hasher, d2, d2);
        let root = store.root(&mut hasher);
        let pruned_loc = store.pruned_loc;

        // Pruning inactive ops should not affect root or current state.
        store.prune_known_inactive();
        assert!(pruned_loc < store.pruned_loc);
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

            // Confirm we are always compacting active operations to tip allowing the inactivity
            // floor to rise.
            assert_eq!(store.op_count(), 1953);
            assert_eq!(store.pruned_loc, 0);
            assert_eq!(store.log.len(), 1953); // no pruning yet
            assert_eq!(store.snapshot.len(), 857);
            assert_eq!(store.inactivity_floor_loc, 728);

            // Test we can recreate the store from its store_state.
            let root_hash = store.root(&mut hasher);
            let store_state = store.to_state();
            let mut store = MutableMmr::init_from_state(&mut hasher, store_state).unwrap();
            assert_eq!(root_hash, store.root(&mut hasher));

            // Confirm the recreated store has an operations log that was pruned of all operations
            // preceding the last known inactivity floor.
            assert_eq!(store.op_count(), 1953);
            assert_eq!(store.pruned_loc, 728);
            assert_eq!(store.log.len(), 1953 - 728);
            assert_eq!(store.snapshot.len(), 857);
            assert_eq!(store.inactivity_floor_loc, 728);

            // Raise the inactivity floor as high as possible, confirm active operations are fully
            // compacted.
            store.raise_inactivity_floor(&mut hasher, 1000);
            assert_eq!(store.op_count(), 2809);
            // Inactivity floor should be 857 operations from tip since 857 operations are active.
            assert_eq!(store.inactivity_floor_loc, 2809 - 857);

            // Confirm the store's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(store_value) = store.get(&k) else {
                        panic!("key not found in store: {}", k);
                    };
                    assert_eq!(map_value, store_value);
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
