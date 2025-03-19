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
use std::collections::HashMap;
use tracing::error;

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

/// A mutable key-value store based on an MMR over its log of operations.
pub struct MutableMmr<K: Array, V: Array, H: CHasher> {
    /// An MMR over digests of the operations applied to the store. The number of leaves in this MMR
    /// always equals the number of operations in the `log`.
    ops: Mmr<H>,

    /// A log of all operations applied to the store in order of occurrence. The index of each
    /// operation in this vector is called its _location_.
    ///
    /// Invariant: An operation's location is always equal to the number of the MMR leaf storing the
    /// digest of the operation.
    log: Vec<Operation<K, V>>,

    /// A map from each key to the location in the log containing its most recent update. Only
    /// contains the keys that currently have a value (that is, deleted keys are not in the map).
    snapshot: HashMap<K, usize>,
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
            log: Vec::<Operation<K, V>>::new(),
            snapshot: HashMap::new(),
        }
    }

    /// Return a store initialized to the state corresponding to the operation sequence given by
    /// `log`.
    ///
    /// Performs some checks that the log constitutes a valid sequence of operations, and returns
    /// [Error::InvalidUpdate] if an invalid sequence is encountered.
    pub fn init_from_log(hasher: &mut H, log: Vec<Operation<K, V>>) -> Result<Self, Error> {
        let mut store = MutableMmr {
            ops: Mmr::new(),
            log,
            snapshot: HashMap::new(),
        };

        for (i, op) in store.log.iter().enumerate() {
            let digest = Self::op_digest(hasher, op);
            store.ops.add(hasher, &digest);

            match op.op_type {
                Type::Deleted => {
                    let loc = store.snapshot.remove(&op.key);
                    if loc.is_none() {
                        // Shouldn't be allowed to delete a key that already has no value.
                        error!("deleted key {} not found in snapshot", op.key);
                        return Err(Error::InvalidUpdate);
                    }
                }
                Type::Update(_) => {
                    store.snapshot.insert(op.key.clone(), i);
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

    /// Get the value of `key` in the store, or None if it has no value.
    pub fn get(&self, key: &K) -> Option<&V> {
        let pos = self.snapshot.get(key)?;
        let op = &self.log[*pos];
        match &op.op_type {
            Type::Deleted => panic!("deleted key should not be in snapshot: {}", key),
            Type::Update(ref v) => Some(v),
        }
    }

    /// Get the number of operations that have been applied to this store.
    pub fn op_count(&self) -> u64 {
        self.log.len() as u64
    }

    /// Updates `key` to have value `value`.  If the key already has this same value, then this is a
    /// no-op.
    pub fn update(&mut self, hasher: &mut H, key: K, value: V) {
        let new_loc = self.log.len();

        // Update the snapshot.
        if let Some(loc) = self.snapshot.get_mut(&key) {
            let last_value = match self.log[*loc].op_type {
                Type::Deleted => panic!("deleted key should not be in snapshot: {}", key),
                Type::Update(ref v) => v,
            };
            if value == *last_value {
                // Trying to assign the same value is a no-op.
                return;
            }
            *loc = new_loc;
        } else {
            self.snapshot.insert(key.clone(), new_loc);
        }

        let op = Type::Update(value.clone());
        self.apply_op(hasher, key, op);
    }

    /// Update the log and operations MMR with the given key and operation.
    fn apply_op(&mut self, hasher: &mut H, key: K, op_type: Type<V>) {
        let op = Operation { key, op_type };

        // Update the ops MMR.
        let digest = Self::op_digest(hasher, &op);
        self.ops.add(hasher, &digest);

        // Append the operation to the log.
        self.log.push(op);
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op.
    pub fn delete(&mut self, hasher: &mut H, key: K) {
        // Remove the key from the snapshot.
        if self.snapshot.remove(&key).is_none() {
            return;
        }

        self.apply_op(hasher, key, Type::Deleted);
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.ops.root(hasher)
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
        let ops = self.log[start_loc as usize..=end_loc as usize].to_vec();

        Ok((proof, ops))
    }

    /// Return true if the given sequence of `ops` took place starting at location `start_loc` in
    /// the MMR with the provided root hash.
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

    /// Consume the store and return its log of operations, from which the state of the store can be
    /// recovered.
    pub fn to_log(self) -> Vec<Operation<K, V>> {
        self.log
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mmr::iterator::leaf_num_to_pos;
    use commonware_cryptography::{hash, sha256::Digest, Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic::Executor, Runner};

    /// Return an empty store for use in tests.
    fn empty_store() -> MutableMmr<Digest, Digest, Sha256> {
        MutableMmr::new()
    }

    #[test]
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

        assert_eq!(store.log.len(), 5); // 4 updates, 1 deletion
        assert_eq!(store.snapshot.len(), 2);

        let root = store.root(&mut hasher);

        // multiple assignments of the same value should be a no-op.
        store.update(&mut hasher, d1, d1);
        store.update(&mut hasher, d2, d2);
        assert_eq!(store.root(&mut hasher), root);

        // The MMR's size should always be greater than the position of the last leaf.
        let last_leaf_pos = leaf_num_to_pos(4);
        assert!(store.ops.size() > last_leaf_pos);

        store.delete(&mut hasher, d1);
        store.delete(&mut hasher, d2);
        assert!(store.get(&d1).is_none());
        assert!(store.get(&d2).is_none());

        let root = store.root(&mut hasher);

        // multiple deletions of the same key should be a no-op.
        store.delete(&mut hasher, d1);
        assert_eq!(store.root(&mut hasher), root);

        // deletions of non-existent keys should be a no-op.
        let d3 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
        store.delete(&mut hasher, d3);
        assert_eq!(store.root(&mut hasher), root);
    }

    #[test]
    pub fn test_mutable_mmr_build_and_authenticate() {
        let (executor, _, _) = Executor::default();
        // Build a store with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the store matches that of an identically updated hashmap.
        executor.start(async move {
            let mut store = empty_store();
            let mut hasher = Sha256::new();
            // Store the store's root for every (non-no-op) update.
            let mut roots = Vec::new();

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                store.update(&mut hasher, k, v);
                roots.push(store.root(&mut hasher));
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
                roots.push(store.root(&mut hasher));
                map.insert(k, v);
            }
            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                store.delete(&mut hasher, k);
                roots.push(store.root(&mut hasher));
                map.remove(&k);
            }

            // Confirm the store's state matches that of the map.
            let root_hash = roots.last().unwrap();
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

            // Test we can recreate the store purely from its log.
            let log = store.to_log();
            let store = MutableMmr::init_from_log(&mut hasher, log).unwrap();
            assert_eq!(*root_hash, store.root(&mut hasher));

            // Make sure size-constrained batches of operations are provable from inception to tip.
            let end = store.op_count();
            assert_eq!(roots.len() as u64, end);
            let max_ops = 4;
            let root = store.root(&mut hasher);
            for i in 0..end {
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
