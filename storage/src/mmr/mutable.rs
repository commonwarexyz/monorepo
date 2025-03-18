//! An in-memory authenticatable & updatable key-value store.
//!
//! A _mutable MMR_ is an authenticatable and updatable key-value store based on an [Mmr] over all
//! updates called the _update tree_, and an authenticatable [Bitmap] that indicates which leaves in
//! the update tree correspond to the latest value of each key. For example, if the same key K was
//! updated at positions X, Y, and Z in that order, then the bitmap will store 0s for the bits
//! corresponding to X and Y, and a 1 for the bit corresponding to Z. The root hash of the mutable
//! MMR is the result of hashing together the roots of these two structures.

use crate::mmr::{
    bitmap::Bitmap, hasher::Hasher, iterator::leaf_pos_to_num, mem::Mmr,
    verification::KeyValueProof, Error,
};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::Array;
use std::collections::HashMap;
use tracing::error;

/// A record representing one key/value update or deletion.
pub struct UpdateRecord<K: Array, V: Array> {
    /// The position of the leaf representing this record in the updates tree, or
    /// [MutableMmr::DELETED] if this record corresponds to a deletion of the key.
    tree_pos: u64,

    /// The key that was updated or deleted.
    key: K,

    /// The value the key was assigned in this update. For deletions, the value is the previously
    /// active value for the key.
    value: V,
}

/// A mutable MMR based key-value store.
pub struct MutableMmr<K: Array, V: Array, H: CHasher> {
    /// An MMR over digests of the key/value pairs from each UpdateRecord. The number of leaves in
    /// this MMR always equals the number of records.
    updates: Mmr<H>,

    /// An authenticatable bitmap where a 1 indicates the corresponding update record contains the
    /// active value for its key. The bit count of this bitmap always equals the number of records.
    is_active: Bitmap<H>,

    /// All updates and deletions made to the store in order of execution. The index of each record
    /// in this vector is called its _location_.
    records: Vec<UpdateRecord<K, V>>,

    /// A map from each key to the record location containing its most recent update. Keys in the
    /// deleted state are not stored in this map.
    snapshot: HashMap<K, usize>,
}

impl<K: Array, V: Array, H: CHasher> MutableMmr<K, V, H> {
    /// DELETED is used as a deletion indicator. Its value is guaranteed to be reserved for use as
    /// either a record location or a tree position.
    const DELETED: u64 = 0;

    /// Create a new, empty mutable MMR. The `key` and `value` are used for initialization -- their
    /// specific values are unimportant other than behaving as seeds for the root hash.
    pub fn new(hasher: &mut H, key: K, value: V) -> Self {
        let mut store = MutableMmr {
            updates: Mmr::new(),
            is_active: Bitmap::new(),
            snapshot: HashMap::new(),
            records: Vec::<UpdateRecord<K, V>>::new(),
        };

        // Add a dummy first record to reserve position and location 0 as a DELETED indicator.
        let digest = Self::key_value_hash(hasher, &key, &value);
        store.updates.add(hasher, &digest);
        store.is_active.append(hasher, false);
        store.records.push(UpdateRecord {
            tree_pos: Self::DELETED,
            key,
            value,
        });

        store
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
            is_active: Bitmap::new(),
            snapshot: HashMap::new(),
            records,
        };

        for (i, record) in store.records.iter().enumerate() {
            let digest = Self::key_value_hash(hasher, &record.key, &record.value);
            let pos = store.updates.add(hasher, &digest);

            let old_record = if record.tree_pos != Self::DELETED {
                if pos != record.tree_pos {
                    error!("record.tree pos invalid");
                    return Err(Error::InvalidUpdate);
                }
                store.is_active.append(hasher, true);
                let Some(old_location) = store.snapshot.insert(record.key.clone(), i) else {
                    continue;
                };
                &store.records[old_location]
            } else {
                // This record deletes the key from the store.
                store.is_active.append(hasher, false);
                if i == 0 {
                    // Record 0 is a placeholder and not an actual deletion.
                    continue;
                }
                let Some(old_location) = store.snapshot.remove(&record.key) else {
                    error!("record deletes non-existent key");
                    return Err(Error::InvalidUpdate);
                };
                &store.records[old_location]
            };

            if old_record.key != record.key {
                error!("record.key doesn't match old record");
                return Err(Error::InvalidUpdate);
            }

            let bit_offset = leaf_pos_to_num(old_record.tree_pos);
            assert!(store.is_active.get_bit(bit_offset));
            store.is_active.set_bit(hasher, bit_offset, false);
        }

        assert_eq!(store.is_active.bit_count() as usize, store.records.len());

        Ok(store)
    }

    /// Return a digest of the `key` `value` pair.
    pub fn key_value_hash(hasher: &mut H, key: &K, value: &V) -> H::Digest {
        hasher.update(key);
        hasher.update(value);
        hasher.finalize()
    }

    /// Get the value of `key` in the store, or None if it has no value.
    pub fn get(&self, key: &K) -> Option<&V> {
        let pos = self.snapshot.get(key)?;
        let record = &self.records[*pos];

        Some(&record.value)
    }

    /// Set the value of `key` to `value`.
    pub fn update(&mut self, hasher: &mut H, key: K, value: V) {
        // Update the updates tree
        let record_digest = Self::key_value_hash(hasher, &key, &value);
        let tree_pos = self.updates.add(hasher, &record_digest);

        // Set the is_active bit of the new record to 1.
        self.is_active.append(hasher, true);

        // Update the snapshot.
        let new_location = self.records.len();
        if let Some(old_location) = self.snapshot.insert(key.clone(), new_location) {
            // Flip the is_active bit of the old record to 0.
            let record = &self.records[old_location];
            assert_eq!(record.key, key);
            let bit_offset = leaf_pos_to_num(record.tree_pos);
            assert!(self.is_active.get_bit(bit_offset));
            self.is_active.set_bit(hasher, bit_offset, false);
        }

        // Append the new record to the records vector.
        let new_record = UpdateRecord {
            tree_pos,
            key,
            value,
        };
        self.records.push(new_record);
        assert_eq!(self.records.len(), self.is_active.bit_count() as usize);
    }

    /// Delete `key` and its value from the store. Deleting a key that already has no value is a
    /// no-op.
    pub fn delete(&mut self, hasher: &mut H, key: K) {
        // Remove the key from the snapshot.
        let old_location = match self.snapshot.remove(&key) {
            Some(location) => location,
            None => return,
        };

        // Flip the is_active bit of the old record to 0.
        let old_record = &self.records[old_location];
        assert_eq!(old_record.key, key);
        let bit_offset = leaf_pos_to_num(old_record.tree_pos);
        assert!(self.is_active.get_bit(bit_offset));
        self.is_active.set_bit(hasher, bit_offset, false);

        // We include a new record for the deletion operation so that we can derive all of the
        // store's state from the records structure alone.
        let new_record = UpdateRecord {
            tree_pos: Self::DELETED,
            key,
            value: old_record.value.clone(),
        };
        let record_digest = Self::key_value_hash(hasher, &new_record.key, &new_record.value);
        self.records.push(new_record);
        println!("pos!! {} {}", self.updates.size(), record_digest);

        // Update the updates tree
        self.updates.add(hasher, &record_digest);

        // Set the is_active bit of the deletion record to 0.
        self.is_active.append(hasher, false);
        assert_eq!(self.records.len(), self.is_active.bit_count() as usize);
    }

    /// Return the root hash of the mutable MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        let updates_root = self.updates.root(hasher);
        let is_active_root = self.is_active.root(hasher);
        let mut h = Hasher::new(hasher);
        // We use 0 for position in node_hash to generate the root since it won't ever be used for
        // node_hash by the underlying MMRs (non-leaf nodes always have position > 0).
        h.node_hash(0, &updates_root, &is_active_root)
    }

    /// Return a proof of the current value of `key` along with its current value. Panic if `key`
    /// has no value.
    pub async fn proof(
        &self,
        hasher: &mut H,
        key: &K,
    ) -> Result<(KeyValueProof<K, V, H>, V), Error> {
        let location = match self.snapshot.get(key) {
            Some(location) => location,
            None => panic!("key has no value {}", key),
        };
        let record = &self.records[*location];
        assert_eq!(record.key, *key);

        let updates_proof = self.updates.proof(record.tree_pos).await?;

        let bit_offset = leaf_pos_to_num(record.tree_pos);
        assert!(self.is_active.get_bit(bit_offset));
        let (is_active_proof, state_bitmap_chunk) =
            self.is_active.proof(hasher, bit_offset).await?;

        let proof = KeyValueProof::new(
            record.tree_pos,
            updates_proof,
            is_active_proof,
            state_bitmap_chunk,
        );

        Ok((proof, record.value.clone()))
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
    fn empty_store(hasher: &mut Sha256) -> MutableMmr<Digest, Digest, Sha256> {
        let k = Digest::try_from(&vec![123u8; 32]).unwrap();
        let v = Digest::try_from(&vec![45; 32]).unwrap();
        MutableMmr::new(hasher, k, v)
    }

    #[test]
    pub fn test_mutable_mmr_build_basic() {
        // Build a store with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let mut hasher = Sha256::new();
        let mut store = empty_store(&mut hasher);

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

        assert_eq!(store.records.len(), 6); // 4 updates, 1 dummy record, 1 deletion
        assert_eq!(store.is_active.bit_count(), store.records.len() as u64);
        assert_eq!(store.snapshot.len(), 2);

        // The update tree's size should always be greater than the position of the last leaf.
        let last_leaf_pos = leaf_num_to_pos(5);
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
    #[should_panic(expected = "key has no value")]
    pub fn test_mutable_mmr_panic_on_proving_nonexistent_key() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = empty_store(&mut hasher);

            let d1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            let d2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
            store.update(&mut hasher, d1, d1);
            store.proof(&mut hasher, &d2).await.unwrap();
        });
    }

    #[test]
    #[should_panic(expected = "key has no value")]
    pub fn test_mutable_mmr_panic_on_proving_deleted_key() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = empty_store(&mut hasher);

            let d1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            store.update(&mut hasher, d1, d1);
            store.delete(&mut hasher, d1);
            store.proof(&mut hasher, &d1).await.unwrap();
        });
    }

    #[test]
    pub fn test_mutable_mmr_data_authentication_basic() {
        // Create a store with 2 keys that we update and delete, and make sure proving their current
        // values against the root works as expected after each operation.
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = empty_store(&mut hasher);

            let k1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            let k2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();

            let v1 = <Sha256 as CHasher>::Digest::try_from(&vec![103u8; 32]).unwrap();
            let v2 = <Sha256 as CHasher>::Digest::try_from(&vec![104u8; 32]).unwrap();
            let v3 = <Sha256 as CHasher>::Digest::try_from(&vec![105u8; 32]).unwrap();

            store.update(&mut hasher, k1, v1);
            store.update(&mut hasher, k2, v2);

            let root_hash = store.root(&mut hasher);

            // Make sure we can prove that each key has its correct value and not any other.
            let (proof, value) = store.proof(&mut hasher, &k1).await.unwrap();
            assert_eq!(value, v1);
            assert!(proof.verify(&mut hasher, &k1, &v1, &root_hash));
            assert!(!proof.verify(&mut hasher, &k1, &v2, &root_hash));
            assert!(!proof.verify(&mut hasher, &k2, &v1, &root_hash));
            assert!(!proof.verify(&mut hasher, &k2, &v2, &root_hash));

            let (proof, value) = store.proof(&mut hasher, &k2).await.unwrap();
            assert_eq!(value, v2);
            assert!(proof.verify(&mut hasher, &k2, &v2, &root_hash));
            assert!(!proof.verify(&mut hasher, &k2, &v1, &root_hash));
            assert!(!proof.verify(&mut hasher, &k1, &v1, &root_hash));
            assert!(!proof.verify(&mut hasher, &k1, &v2, &root_hash));

            // Update the keys and make sure we can only prove the latest value
            store.update(&mut hasher, k1, v3);
            store.delete(&mut hasher, k2);
            store.update(&mut hasher, k2, v3);

            let root_hash = store.root(&mut hasher);
            let (proof, value) = store.proof(&mut hasher, &k1).await.unwrap();
            assert_eq!(value, v3);
            assert!(proof.verify(&mut hasher, &k1, &v3, &root_hash));
            assert!(!proof.verify(&mut hasher, &k1, &v1, &root_hash));
            assert!(!proof.verify(&mut hasher, &k1, &v2, &root_hash));

            let (proof, value) = store.proof(&mut hasher, &k2).await.unwrap();
            assert_eq!(value, v3);
            assert!(proof.verify(&mut hasher, &k2, &v3, &root_hash));
            assert!(!proof.verify(&mut hasher, &k2, &v1, &root_hash));
            assert!(!proof.verify(&mut hasher, &k2, &v2, &root_hash));

            // Confirm proofs fail after deleting.
            store.delete(&mut hasher, k1);
            store.delete(&mut hasher, k2);

            let root_hash = store.root(&mut hasher);
            assert!(!proof.verify(&mut hasher, &k1, &v3, &root_hash));
            assert!(!proof.verify(&mut hasher, &k2, &v3, &root_hash));
        });
    }

    #[test]
    pub fn test_mutable_mmr_build_and_authenticate() {
        let (executor, _, _) = Executor::default();
        // Build a store with 1000 keys, some of which we update and some of which we delete, and
        // confirm that:
        //   1. the end state of the store matches that of an identically updated hashmap.
        //   2. the value of any key in the end state of the store can be verified against the root.
        executor.start(async move {
            let mut hasher = Sha256::new();
            let mut store = empty_store(&mut hasher);

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
                let v = hash(&(i * 10000).to_be_bytes());
                store.update(&mut hasher, k, v);
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
                        panic!("key {} not found in store", k);
                    };
                    assert_eq!(map_value, store_value);
                    let (proof, proof_value) = store.proof(&mut hasher, &k).await.unwrap();
                    assert_eq!(*map_value, proof_value);
                    assert!(proof.verify(&mut hasher, &k, &proof_value, &root_hash));
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
