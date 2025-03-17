//! An in-memory authenticatable & updatable key-value store.
//!
//! A _mutable MMR_ is an authenticatable and updatable key-value store based on an [Mmr] over all
//! updates called the _update tree_.

use crate::mmr::{iterator::leaf_pos_to_num, mem::Mmr, verification::UpdateProof, Error};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::Array;
use std::collections::HashMap;
use tracing::error;

#[derive(Clone)]
pub enum UpdateOp<V: Array> {
    /// Indicates a key was deleted.
    Deleted,

    /// Indicates the wrapped value was assigned to a key.
    Assign(V),
}

/// A record representing one key/value assignment or deletion.
#[derive(Clone)]
pub struct UpdateRecord<K: Array, V: Array> {
    tree_pos: u64,

    /// The key that was updated.
    pub key: K,

    /// The update operation that was performed.
    pub update_op: UpdateOp<V>,
}

/// A mutable MMR based key-value store.
pub struct MutableMmr<K: Array, V: Array, H: CHasher> {
    /// An MMR over digests of the updates made to the store. The number of leaves in this MMR
    /// always equals the number of update records.
    updates: Mmr<H>,

    /// All updates made to the store in order of execution. The index of each record in this vector
    /// is called its _location_.
    records: Vec<UpdateRecord<K, V>>,

    /// A map from each key to the record location containing its most recently assigned value. Keys
    /// that have been deleted are not stored in this map.
    snapshot: HashMap<K, usize>,
}

impl<K: Array, V: Array, H: CHasher> Default for MutableMmr<K, V, H> {
    fn default() -> Self {
        MutableMmr::new()
    }
}

impl<K: Array, V: Array, H: CHasher> MutableMmr<K, V, H> {
    /// Create a new, empty mutable MMR.
    pub fn new() -> Self {
        MutableMmr {
            updates: Mmr::new(),
            snapshot: HashMap::new(),
            records: Vec::<UpdateRecord<K, V>>::new(),
        }
    }

    /// Return a mutable MMR store initialized to the state corresponding to the update sequence
    /// given by `records`.
    ///
    /// Performs some checks that the records constitute a valid sequence of updates, and returns
    /// [Error::InvalidUpdate] if an invalid sequence is encountered. These checks are not
    /// exhaustive.
    pub fn init_from_records(
        hasher: &mut H,
        records: Vec<UpdateRecord<K, V>>,
    ) -> Result<Self, Error> {
        let mut store = MutableMmr {
            updates: Mmr::new(),
            snapshot: HashMap::new(),
            records,
        };

        for (i, record) in store.records.iter().enumerate() {
            let digest = Self::key_update_digest(hasher, &record.key, &record.update_op);
            let pos = store.updates.add(hasher, &digest);
            if pos != record.tree_pos {
                error!("record.tree pos invalid");
                return Err(Error::InvalidUpdate);
            }

            let old_location = match record.update_op {
                UpdateOp::Deleted => {
                    let location = store.snapshot.remove(&record.key);
                    if location.is_none() {
                        error!(
                            "deleted key {} at location {} not found in snapshot",
                            record.key,
                            location.unwrap()
                        );
                        return Err(Error::InvalidUpdate);
                    }
                    location
                }
                UpdateOp::Assign(_) => store.snapshot.insert(record.key.clone(), i),
            };

            let Some(old_location) = old_location else {
                continue;
            };
            let old_record = &store.records[old_location];

            if old_record.key != record.key {
                error!("record.key doesn't match old record");
                return Err(Error::InvalidUpdate);
            }
        }

        Ok(store)
    }

    const DELETE_CONTEXT: u8 = 0;
    const ASSIGN_CONTEXT: u8 = 1;

    /// Return a digest of the key plus its update operation.
    ///
    /// The first byte of the key material is an operation type byte, 0 for Delete and 1 for Assign.
    /// For assignment, the value is appended next, followed by the key. For deletion, the key
    /// alone is appended.
    pub fn key_update_digest(hasher: &mut H, key: &K, update_op: &UpdateOp<V>) -> H::Digest {
        match update_op {
            UpdateOp::Deleted => hasher.update(&[Self::DELETE_CONTEXT]),
            UpdateOp::Assign(value) => {
                hasher.update(&[Self::ASSIGN_CONTEXT]);
                hasher.update(value);
            }
        }
        hasher.update(key);
        hasher.finalize()
    }

    /// Compute the key update digest for `record`.
    pub fn record_digest(hasher: &mut H, record: &UpdateRecord<K, V>) -> H::Digest {
        Self::key_update_digest(hasher, &record.key, &record.update_op)
    }

    /// Get the value of `key` in the store, or None if it has no value.
    pub fn get(&self, key: &K) -> Option<&V> {
        let pos = self.snapshot.get(key)?;
        let record = &self.records[*pos];
        match &record.update_op {
            UpdateOp::Deleted => panic!("deleted key should not be in snapshot: {}", key),
            UpdateOp::Assign(ref v) => Some(v),
        }
    }

    /// Get the update corresponding to the mmr leaf at `pos`, or None if the
    /// position is not for a leaf.
    pub fn get_update(&self, pos: u64) -> Option<&UpdateOp<V>> {
        assert!(pos < self.updates.size());
        let leaf_num = leaf_pos_to_num(pos)?;
        let record = &self.records[leaf_num as usize];

        Some(&record.update_op)
    }

    /// Assigns `value` to `key` in the store.  If the key is already assigned the same value, then
    /// this is a no-op.
    pub fn assign(&mut self, hasher: &mut H, key: K, value: V) {
        let new_location = self.records.len();

        // Update the snapshot.
        if let Some(location) = self.snapshot.get_mut(&key) {
            let last_value = match self.records[*location].update_op {
                UpdateOp::Deleted => panic!("deleted key should not be in snapshot: {}", key),
                UpdateOp::Assign(ref v) => v,
            };
            if value == *last_value {
                // Trying to assign the same value is a no-op.
                return;
            }
            *location = new_location;
        } else {
            self.snapshot.insert(key.clone(), new_location);
        }

        let update_op = UpdateOp::Assign(value.clone());
        self.update_work(hasher, key, update_op);
    }

    /// Update the updates tree and records vector with the given key and update operation.
    fn update_work(&mut self, hasher: &mut H, key: K, update_op: UpdateOp<V>) {
        // Update the updates tree
        let record_digest = Self::key_update_digest(hasher, &key, &update_op);
        let tree_pos = self.updates.add(hasher, &record_digest);

        // Append the new record to the records vector.
        let new_record = UpdateRecord {
            tree_pos,
            key,
            update_op,
        };
        self.records.push(new_record);
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op.
    pub fn delete(&mut self, hasher: &mut H, key: K) {
        // Remove the key from the snapshot.
        if self.snapshot.remove(&key).is_none() {
            return;
        }

        let update_op = UpdateOp::Deleted;
        self.update_work(hasher, key, update_op);
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        self.updates.root(hasher)
    }

    /// Return the size of the underlying MMR.
    ///
    /// This value will be the position of the next leaf to be added to the underlying MMR, and can
    /// be used to retrieve a starting position value for generating a proof over the next batch of
    /// updates.
    pub fn size(&self) -> u64 {
        self.updates.size()
    }

    /// Return a proof of all updates to the store starting at (and including) the leaf at position
    /// `start_pos`, along with all update records from the range.
    pub async fn proof_to_tip(
        &self,
        start_pos: u64,
    ) -> Result<(UpdateProof<K, V, H>, Vec<UpdateRecord<K, V>>), Error> {
        let Some(start_leaf_num) = leaf_pos_to_num(start_pos) else {
            panic!("start_pos is not a leaf");
        };
        assert!(start_pos < self.updates.size());

        let end_pos = self.updates.last_leaf_pos().unwrap();
        let updates_proof = self.updates.range_proof(start_pos, end_pos).await?;
        let proof = UpdateProof::new(start_pos, updates_proof);

        let end_leaf_num = leaf_pos_to_num(end_pos).unwrap();

        Ok((
            proof,
            self.records[start_leaf_num as usize..=end_leaf_num as usize + 1].to_vec(),
        ))
    }

    /// Consume the store and return its update records.
    pub fn to_records(self) -> Vec<UpdateRecord<K, V>> {
        self.records
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

        store.assign(&mut hasher, d1, d2);
        assert_eq!(store.get(&d1).unwrap(), &d2);
        assert!(store.get(&d2).is_none());

        store.assign(&mut hasher, d2, d1);
        assert_eq!(store.get(&d1).unwrap(), &d2);
        assert_eq!(store.get(&d2).unwrap(), &d1);

        store.delete(&mut hasher, d1);
        assert!(store.get(&d1).is_none());
        assert_eq!(store.get(&d2).unwrap(), &d1);

        store.assign(&mut hasher, d1, d1);
        assert_eq!(store.get(&d1).unwrap(), &d1);

        store.assign(&mut hasher, d2, d2);
        assert_eq!(store.get(&d2).unwrap(), &d2);

        assert_eq!(store.records.len(), 5); // 4 updates, 1 deletion
        assert_eq!(store.snapshot.len(), 2);

        let root = store.root(&mut hasher);

        // multiple assignments of the same value should be a no-op.
        store.assign(&mut hasher, d1, d1);
        store.assign(&mut hasher, d2, d2);
        assert_eq!(store.root(&mut hasher), root);

        // The update tree's size should always be greater than the position of the last leaf.
        let last_leaf_pos = leaf_num_to_pos(4);
        assert!(store.updates.size() > last_leaf_pos);

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

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                store.assign(&mut hasher, k, v);
                map.insert(k, v);
            }
            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 10000).to_be_bytes());
                store.assign(&mut hasher, k, v);
                map.insert(k, v);
            }
            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                store.delete(&mut hasher, k);
                map.remove(&k);
            }

            // Make sure the contents of the store match that of the map, and that each active value
            // can be authenticated against the root.
            let root_hash = store.root(&mut hasher);
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

            // Test we can recreate the store purely from its records.
            let records = store.to_records();
            let store2 = MutableMmr::init_from_records(&mut hasher, records).unwrap();
            assert_eq!(root_hash, store2.root(&mut hasher));
        });
    }
}
